//! 再開意思の追記だけの明示復旧。完全な既存snapshotだけを使いguardを保持する。
use super::*;

fn moved_metadata(file: &HeldFile) -> Result<Metadata> {
    let after = io(file.file.metadata())?;
    let mut actual = KeyFileIdentity::from_metadata(&after);
    let original = KeyFileIdentity::from_metadata(&file.metadata);
    actual.ctime_seconds = original.ctime_seconds;
    actual.ctime_nanoseconds = original.ctime_nanoseconds;
    if actual != original {
        return Err(KeyFileError::RecoveryChanged);
    }
    Ok(after)
}
fn bound(
    file: &HeldFile,
    source: &KeyDirectory,
    name: &str,
    moved: Option<&Metadata>,
) -> Result<()> {
    file.check(source, name, moved.is_none())?;
    if let Some(expected) = moved {
        let current = io(file.file.metadata())?;
        if fingerprint(expected) != fingerprint(&current) {
            return Err(KeyFileError::RecoveryChanged);
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn check_layout(
    context: &PreparedKeyResume<'_>,
    temporary: Option<&HeldFile>,
    name: &str,
    exchanged: bool,
    removed: bool,
    fixed_moved: Option<&Metadata>,
    temporary_moved: Option<&Metadata>,
) -> Result<()> {
    context.check(Some(name))?;
    if !exchanged || !removed {
        bound(
            &context.state,
            context.source,
            if exchanged {
                name
            } else {
                initial_state::STATE
            },
            fixed_moved,
        )?;
    }
    if let Some(file) = temporary {
        if !removed || exchanged {
            bound(
                file,
                context.source,
                if exchanged {
                    initial_state::STATE
                } else {
                    name
                },
                temporary_moved,
            )?;
        }
    }
    if removed {
        absent(context.source, name)?;
    }
    Ok(())
}
impl KeyDirectory {
    /// 明示した旧新hash/IDと全保全を再検査し、再開意思の保存だけを復旧する。
    /// 成功後もguard/変更停止を維持する。guard不在・不完全候補は拒否する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_key_resume_record(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        intent: &KeyResumeIntent,
    ) -> Result<KeyStateDiagnostic> {
        self.recover_key_resume_record_with(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            intent,
            &mut |_| Ok(()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(in super::super::super) fn recover_key_resume_record_with(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        intent: &KeyResumeIntent,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        use ResumeStage as S;
        name(current_name)?;
        name(backup_name)?;
        if expected.state != intent.before
            || intent.before.state != KeyHistoryState::Held
            || intent.after.initial != intent.before.initial
            || intent.before.generation.checked_add(1) != Some(intent.after.generation)
            || intent.after.state
                != (KeyHistoryState::Ready {
                    resumed_operation_id: intent.operation_id,
                })
        {
            return invalid();
        }
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        );
        inventory(self, Some(&temp))?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let temporary = match HeldFile::open(self, &temp, initial_state::STATE_LIMIT) {
            Ok(file) => Some(file),
            Err(KeyFileError::Missing) => None,
            Err(e) => return Err(e),
        };
        let marker = self.state_bytes(recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        if marker.len() != 105 || !marker.starts_with(b"lngnb:key-recovery:2\0") {
            return invalid();
        }
        let mut source_marker = marker[..73].to_vec();
        source_marker[19] = b'1';
        let initial = intent.before.initial;
        if self.marker_area_id(&source_marker)? != initial.area_id
            || marker[73..] != initial.snapshot_hash
        {
            return invalid();
        }
        let decode = |bytes: &[u8]| {
            state_history::decode_history(
                bytes,
                &source_marker,
                initial.area_id,
                initial.snapshot_hash,
            )
        };
        let fixed_state = decode(&fixed.bytes)?;
        let needs_exchange = fixed_state == intent.before;
        let new_bytes = if needs_exchange {
            let file = temporary
                .as_ref()
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            if decode(&file.bytes)? != intent.after {
                return invalid();
            }
            file.bytes.clone()
        } else {
            if fixed_state != intent.after {
                return invalid();
            }
            if let Some(file) = &temporary {
                if decode(&file.bytes)? != intent.before {
                    return invalid();
                }
            }
            fixed.bytes.clone()
        };
        // prefix再構成はhash/全件照合だけに使う。保存/欠損補完には使わない。
        let mut prefix =
            cbor::decode(&new_bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let Value::Map(items) = &mut prefix else {
            return invalid();
        };
        let Some((_, Value::Array(events))) = items.iter_mut().find(|(k, _)| k == "events") else {
            return invalid();
        };
        let event = events.pop().ok_or(KeyFileError::RecoveryStateInvalid)?;
        if field(&event, "kind")? != &text("key_changes_resumed")
            || field(&event, "operation_id")? != &bytes(intent.operation_id)
        {
            return invalid();
        }
        let old_bytes = encoded(&prefix)?;
        if decode(&old_bytes)? != intent.before
            || (needs_exchange && fixed.bytes != old_bytes)
            || (!needs_exchange && temporary.as_ref().is_some_and(|f| f.bytes != old_bytes))
        {
            return invalid();
        }
        let context = self.prepare_resume_snapshot(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            ResumeSnapshot::Existing {
                old_bytes,
                new_bytes,
                intent,
            },
        )?;
        if context.state.bytes != fixed.bytes
            || fingerprint(&context.state.metadata) != fingerprint(&fixed.metadata)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        let mut exchanged = false;
        let mut removed = temporary.is_none();
        let mut fixed_moved = None;
        let mut temporary_moved = None;
        check_layout(
            &context,
            temporary.as_ref(),
            &temp,
            exchanged,
            removed,
            None,
            None,
        )?;
        let mut durable = false;
        let recovered = (|| -> Result<KeyStateDiagnostic> {
            context.qualify(Some(&temp), hook, &mut || {
                check_layout(
                    &context,
                    temporary.as_ref(),
                    &temp,
                    false,
                    removed,
                    None,
                    None,
                )
            })?;
            if let Some(file) = &temporary {
                file.sync()?;
            }
            hook(S::SnapshotsSynced)?;
            check_layout(
                &context,
                temporary.as_ref(),
                &temp,
                exchanged,
                removed,
                None,
                None,
            )?;
            io(context.source.dir.sync_all())?;
            hook(S::Prepared)?;
            check_layout(
                &context,
                temporary.as_ref(),
                &temp,
                exchanged,
                removed,
                None,
                None,
            )?;
            if needs_exchange {
                hook(S::BeforeExchange)?;
                check_layout(
                    &context,
                    temporary.as_ref(),
                    &temp,
                    false,
                    false,
                    None,
                    None,
                )?;
                os(fs::renameat_with(
                    &context.source.dir,
                    temp.as_str(),
                    &context.source.dir,
                    initial_state::STATE,
                    RenameFlags::EXCHANGE,
                ))?;
                exchanged = true;
                fixed_moved = Some(moved_metadata(&context.state)?);
                temporary_moved = Some(moved_metadata(
                    temporary
                        .as_ref()
                        .ok_or(KeyFileError::RecoveryStateInvalid)?,
                )?);
                hook(S::Exchanged)?;
            }
            check_layout(
                &context,
                temporary.as_ref(),
                &temp,
                exchanged,
                removed,
                fixed_moved.as_ref(),
                temporary_moved.as_ref(),
            )?;
            io(context.source.dir.sync_all())?;
            check_layout(
                &context,
                temporary.as_ref(),
                &temp,
                exchanged,
                removed,
                fixed_moved.as_ref(),
                temporary_moved.as_ref(),
            )?;
            durable = true;
            hook(S::StateSynced)?;
            hook(S::BeforeCleanup)?;
            check_layout(
                &context,
                temporary.as_ref(),
                &temp,
                exchanged,
                removed,
                fixed_moved.as_ref(),
                temporary_moved.as_ref(),
            )?;
            if !removed {
                os(fs::unlinkat(
                    &context.source.dir,
                    temp.as_str(),
                    AtFlags::empty(),
                ))?;
                removed = true;
                hook(S::OldSnapshotRemoved)?;
            }
            io(context.source.dir.sync_all())?;
            hook(S::CleanupSynced)?;
            check_layout(
                &context,
                temporary.as_ref(),
                &temp,
                exchanged,
                removed,
                fixed_moved.as_ref(),
                temporary_moved.as_ref(),
            )?;
            context.check(None)?;
            if context.source.key_state_history(&initial.area_id)? != intent.after {
                return invalid();
            }
            Ok(intent.after)
        })();
        recovered.map_err(|_| {
            if durable {
                KeyFileError::RecoveryStateCleanupUncertain
            } else {
                KeyFileError::RecoveryStateUncertain
            }
        })
    }
}
