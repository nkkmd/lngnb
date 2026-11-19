//! 完全な完了snapshotだけを採用する。不在完了の新規生成へ切り替えない。
use super::*;

impl KeyDirectory {
    /// 完了控えと既存履歴を照合し、完了追記だけを復旧する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_cleanup_completion_from_receipt(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
        public_key: [u8; 32],
        area_id: [u8; 32],
        generation: u64,
        before_hash: [u8; 32],
        after_hash: [u8; 32],
        started_operation_id: [u8; 32],
        operation_id: [u8; 32],
        disposition: KeyCleanupDisposition,
    ) -> Result<KeyStateDiagnostic> {
        name(backup_name)?;
        let marker = HeldFile::open(self, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        if marker.bytes.len() != 105 || !marker.bytes.starts_with(b"lngnb:key-recovery:2\0") {
            return invalid();
        }
        let mut source_marker = marker.bytes[..73].to_vec();
        source_marker[19] = b'1';
        if self.marker_area_id(&source_marker)? != area_id {
            return invalid();
        }
        let root = marker.bytes[73..]
            .try_into()
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let state = state_history::decode_history(&fixed.bytes, &source_marker, area_id, root)?;
        let before = KeyStateDiagnostic {
            initial: state.initial,
            generation,
            snapshot_hash: before_hash,
            state: KeyHistoryState::Active {
                started_operation_id,
            },
        };
        let intent = KeyCleanupCompletion {
            before,
            after: KeyStateDiagnostic {
                initial: state.initial,
                generation: generation
                    .checked_add(1)
                    .ok_or(KeyFileError::RecoveryStateInvalid)?,
                snapshot_hash: after_hash,
                state: KeyHistoryState::Held,
            },
            started_operation_id,
            operation_id,
            disposition,
        };
        let mut snapshot = decoded(&fixed.bytes)?;
        let events = events_mut(&mut snapshot)?;
        if state == intent.after {
            events.pop().ok_or(KeyFileError::RecoveryStateInvalid)?;
        } else if state != before {
            return invalid();
        }
        let start = events.last().ok_or(KeyFileError::RecoveryStateInvalid)?;
        let target =
            state_history::recorded_file_identity(field(field(start, "target")?, "identity")?)?;
        let preserved = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
        let expected = KeyCleanupExpected {
            state: before,
            target,
            public_key,
            preserved_directory: KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?),
            preserved: KeyFileIdentity::from_metadata(&preserved.metadata),
        };
        self.recover_residue_cleanup_completion(
            residue,
            passphrase,
            backup,
            backup_name,
            &expected,
            &intent,
        )
    }

    /// 明示した一件の完了追記中断を復旧。鍵unlink・停止解除はしない。
    pub fn recover_residue_cleanup_completion(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        intent: &KeyCleanupCompletion,
    ) -> Result<KeyStateDiagnostic> {
        self.recover_residue_cleanup_completion_with(
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
    pub(in super::super::super) fn recover_residue_cleanup_completion_with(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        intent: &KeyCleanupCompletion,
        hook: &mut impl FnMut(CompletionStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        use CompletionStage as S;
        if expected.state != intent.before
            || active_id(&intent.before)? != intent.started_operation_id
            || intent.after.state != KeyHistoryState::Held
            || intent.after.initial != intent.before.initial
            || intent.before.generation.checked_add(1) != Some(intent.after.generation)
        {
            return invalid();
        }
        let temp = update_name(&intent.operation_id);
        self.only_cleanup_update(&temp)?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let temporary = match HeldFile::open(self, &temp, initial_state::STATE_LIMIT) {
            Ok(file) => Some(file),
            Err(KeyFileError::Missing) => None,
            Err(e) => return Err(e),
        };
        let hash = |b: &[u8]| <[u8; 32]>::from(Sha256::digest(b));
        let needs_exchange = hash(&fixed.bytes) == intent.before.snapshot_hash;
        let new_bytes = if needs_exchange {
            let Some(t) = &temporary else {
                return invalid();
            };
            if hash(&t.bytes) != intent.after.snapshot_hash {
                return invalid();
            }
            t.bytes.clone()
        } else {
            if hash(&fixed.bytes) != intent.after.snapshot_hash {
                return invalid();
            }
            if temporary
                .as_ref()
                .is_some_and(|t| hash(&t.bytes) != intent.before.snapshot_hash)
            {
                return invalid();
            }
            fixed.bytes.clone()
        };
        let mut prefix = decoded(&new_bytes)?;
        let event = events_mut(&mut prefix)?
            .pop()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let active_bytes = encoded(&prefix)?;
        if hash(&active_bytes) != intent.before.snapshot_hash
            || (needs_exchange && fixed.bytes != active_bytes)
            || (!needs_exchange && temporary.as_ref().is_some_and(|t| t.bytes != active_bytes))
            || field(&event, "kind")? != &text("residue_cleanup_completed")
            || field(&event, "operation_id")? != &bytes(intent.operation_id)
            || field(&event, "started_operation_id")? != &bytes(intent.started_operation_id)
            || field(&event, "disposition")? != &text(intent.disposition.text())
        {
            return invalid();
        }
        let context = CompletionContext::open(
            self,
            backup,
            residue,
            backup_name,
            passphrase,
            expected,
            &active_bytes,
        )?;
        if context.validate(&new_bytes)? != intent.after
            || context.validate(&fixed.bytes)?
                != if needs_exchange {
                    intent.before
                } else {
                    intent.after
                }
        {
            return invalid();
        }
        if let Some(t) = &temporary {
            if context.validate(&t.bytes)?
                != if needs_exchange {
                    intent.after
                } else {
                    intent.before
                }
            {
                return invalid();
            }
        }
        let mut exchanged = false;
        let mut removed = temporary.is_none();
        let check = |exchanged: bool, removed: bool| -> Result<()> {
            context.check()?;
            context.source.only_cleanup_update(&temp)?;
            if !exchanged || !removed {
                fixed.check(
                    context.source,
                    if exchanged {
                        &temp
                    } else {
                        initial_state::STATE
                    },
                    !exchanged,
                )?;
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
        let result = (|| -> Result<KeyStateDiagnostic> {
            context.sync_controls(hook)?;
            fixed.sync()?;
            if let Some(t) = &temporary {
                t.sync()?;
            }
            hook(S::SnapshotsSynced)?;
            check(exchanged, removed)?;
            io(context.source.dir.sync_all())?;
            hook(S::Qualified)?;
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
            if context.validate(
                &context
                    .source
                    .state_bytes(initial_state::STATE, initial_state::STATE_LIMIT)?,
            )? != intent.after
            {
                return invalid();
            }
            Ok(intent.after)
        })();
        result.map_err(|_| {
            if durable {
                KeyFileError::RecoveryStateCleanupUncertain
            } else {
                KeyFileError::RecoveryStateUncertain
            }
        })
    }
}
