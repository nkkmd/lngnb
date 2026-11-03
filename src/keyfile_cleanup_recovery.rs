//! 開始追記だけの明示復旧。現存する完全snapshot以外は保存しない。
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum CleanupRecoveryStage {
    TargetSynced,
    PreservedSynced,
    DirectoriesSynced,
    ControlsSynced,
    SnapshotsSynced,
    Prepared,
    BeforeExchange,
    Exchanged,
    StateSynced,
    BeforeCleanup,
    OldSnapshotRemoved,
    CleanupSynced,
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    if let Value::Map(m) = v {
        if let Some((_, value)) = m.iter().find(|(k, _)| k == key) {
            return Ok(value);
        }
    }
    invalid()
}
fn equal(a: &Value, b: &Value) -> Result<bool> {
    let encode = |v: &Value| cbor::encode(v).map_err(|_| KeyFileError::RecoveryStateInvalid);
    Ok(encode(a)? == encode(b)?)
}
fn absent(dir: &KeyDirectory, name: &str) -> Result<()> {
    match fs::statat(&dir.dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => invalid(),
    }
}

impl KeyDirectory {
    /// 控えた開始intentと現在の両現物で追記中断だけを復旧する。
    /// 成功もActive/停止を維持し、対象unlink・通常変更許可は与えない。
    pub fn recover_residue_cleanup_start(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        intent: &KeyCleanupStart,
    ) -> Result<KeyStateDiagnostic> {
        self.recover_residue_cleanup_start_with(
            residue,
            passphrase,
            backup,
            backup_name,
            expected,
            intent,
            &mut |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn recover_residue_cleanup_start_with(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        intent: &KeyCleanupStart,
        hook: &mut impl FnMut(CleanupRecoveryStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        use CleanupRecoveryStage as S;
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(backup_name)?;
        self.secure()?;
        backup.secure()?;
        let source_identity = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        if expected.state != intent.before
            || intent.before.state != KeyHistoryState::Held
            || intent.after.initial != intent.before.initial
            || intent.before.generation.checked_add(1) != Some(intent.after.generation)
            || intent.after.state
                != (KeyHistoryState::Active {
                    started_operation_id: intent.operation_id,
                })
            || KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?)
                != expected.preserved_directory
            || source_identity == expected.preserved_directory
        {
            return invalid();
        }
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        );
        self.only_cleanup_update(&temp)?;
        let marker = HeldFile::open(self, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        let guard = HeldFile::open(self, recovery_hold::GUARD, MAX_KEYFILE_BYTES)?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let temporary = match HeldFile::open(self, &temp, initial_state::STATE_LIMIT) {
            Ok(f) => Some(f),
            Err(KeyFileError::Missing) => None,
            Err(e) => return Err(e),
        };
        if marker.bytes.len() != 105 || !marker.bytes.starts_with(b"lngnb:key-recovery:2\0") {
            return invalid();
        }
        let mut source = marker.bytes[..73].to_vec();
        source[19] = b'1';
        let initial = intent.before.initial;
        let mut expected_guard = b"lngnb:key-hold:1\0".to_vec();
        expected_guard.extend_from_slice(&initial.area_id);
        if self.marker_area_id(&source)? != initial.area_id
            || marker.bytes[73..] != initial.snapshot_hash
            || guard.bytes != expected_guard
        {
            return invalid();
        }
        let decode = |b: &[u8]| {
            state_history::decode_history(b, &source, initial.area_id, initial.snapshot_hash)
        };
        let fixed_state = decode(&fixed.bytes)?;
        let needs_exchange = fixed_state == intent.before;
        let new_bytes = if needs_exchange {
            let Some(t) = &temporary else {
                return invalid();
            };
            if decode(&t.bytes)? != intent.after {
                return invalid();
            }
            t.bytes.clone()
        } else {
            if fixed_state != intent.after {
                return invalid();
            }
            if let Some(t) = &temporary {
                if decode(&t.bytes)? != intent.before {
                    return invalid();
                }
            }
            fixed.bytes.clone()
        };
        // 全prefixの値とhashを検査するためだけに旧snapshotを再構成する。
        // このbytesを保存・欠損補完には決して使わない。
        let mut prefix =
            cbor::decode(&new_bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let Value::Map(m) = &mut prefix else {
            return invalid();
        };
        let Some((_, Value::Array(events))) = m.iter_mut().find(|(k, _)| k == "events") else {
            return invalid();
        };
        let event = events.pop().ok_or(KeyFileError::RecoveryStateInvalid)?;
        let old_bytes = cbor::encode(&prefix).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        if decode(&old_bytes)? != intent.before
            || (needs_exchange && fixed.bytes != old_bytes)
            || (!needs_exchange && temporary.as_ref().is_some_and(|t| t.bytes != old_bytes))
        {
            return invalid();
        }
        let target = HeldFile::open(self, residue, MAX_KEYFILE_BYTES)?;
        let preserved = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
        if KeyFileIdentity::from_metadata(&target.metadata) != expected.target
            || KeyFileIdentity::from_metadata(&preserved.metadata) != expected.preserved
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        if unlock(&target.bytes, passphrase)?.public_key() != expected.public_key {
            return Err(KeyFileError::UnexpectedPublicKey);
        }
        if target.bytes != preserved.bytes {
            return Err(KeyFileError::PreservationMismatch);
        }
        if field(&event, "kind")? != &text("residue_cleanup_started")
            || field(&event, "operation_id")? != &bytes(intent.operation_id)
            || !equal(
                field(&event, "target")?,
                &map(vec![
                    ("name", text(residue)),
                    ("identity", expected.target.value()),
                    (
                        "ciphertext_sha256",
                        bytes(<[u8; 32]>::from(Sha256::digest(&target.bytes))),
                    ),
                    ("public_key", bytes(expected.public_key)),
                ]),
            )?
            || !equal(
                field(&event, "preserved")?,
                &map(vec![
                    ("directory", expected.preserved_directory.value()),
                    ("name", text(backup_name)),
                    ("identity", expected.preserved.value()),
                ]),
            )?
        {
            return invalid();
        }
        let context = PreparedKeyCleanup {
            source: self,
            backup,
            target_name: residue.into(),
            preserved_name: backup_name.into(),
            expected: *expected,
            source_identity,
            target,
            preserved,
            marker,
            guard,
            state: fixed,
            new_bytes,
            receipt: *intent,
        };
        let mut exchanged = false;
        let mut removed = temporary.is_none();
        let check = |exchanged: bool, removed: bool| -> Result<()> {
            context.recheck()?;
            context.source.only_cleanup_update(&temp)?;
            let fixed_name = if exchanged {
                temp.as_str()
            } else {
                initial_state::STATE
            };
            // 交換によるctime変更は許すが、fd/path/全bytes・private属性は再検査する。
            if !exchanged || !removed {
                context
                    .state
                    .check(context.source, fixed_name, !exchanged)?;
            }
            if let Some(t) = &temporary {
                if !removed {
                    t.check(
                        context.source,
                        if exchanged {
                            initial_state::STATE
                        } else {
                            &temp
                        },
                        !exchanged,
                    )?;
                } else if exchanged {
                    t.check(context.source, initial_state::STATE, false)?;
                }
            }
            if removed {
                absent(context.source, &temp)?;
            }
            Ok(())
        };
        check(exchanged, removed)?;
        let mut durable = false;
        let recovered = (|| -> Result<KeyStateDiagnostic> {
            context.target.sync()?;
            hook(S::TargetSynced)?;
            check(exchanged, removed)?;
            context.preserved.sync()?;
            hook(S::PreservedSynced)?;
            io(context.backup.dir.sync_all())?;
            io(context.source.dir.sync_all())?;
            hook(S::DirectoriesSynced)?;
            check(exchanged, removed)?;
            context.marker.sync()?;
            context.guard.sync()?;
            hook(S::ControlsSynced)?;
            context.state.sync()?;
            if let Some(t) = &temporary {
                t.sync()?;
            }
            hook(S::SnapshotsSynced)?;
            check(exchanged, removed)?;
            io(context.source.dir.sync_all())?;
            hook(S::Prepared)?;
            check(exchanged, removed)?;
            if needs_exchange {
                hook(S::BeforeExchange)?;
                check(exchanged, removed)?;
                os(fs::renameat_with(
                    &context.source.dir,
                    temp.as_str(),
                    &context.source.dir,
                    initial_state::STATE,
                    RenameFlags::EXCHANGE,
                ))?;
                exchanged = true;
                hook(S::Exchanged)?;
                check(exchanged, removed)?;
            }
            io(context.source.dir.sync_all())?;
            check(exchanged, removed)?;
            durable = true;
            hook(S::StateSynced)?;
            hook(S::BeforeCleanup)?;
            check(exchanged, removed)?;
            if !removed {
                // Aではfixedの旧fd、Bではtemporaryの旧fdを直前照合した一名だけ。
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
            check(exchanged, removed)?;
            context.source.reject_state_artifacts(true)?;
            let installed = context
                .source
                .state_bytes(initial_state::STATE, initial_state::STATE_LIMIT)?;
            if decode(&installed)? != intent.after {
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
