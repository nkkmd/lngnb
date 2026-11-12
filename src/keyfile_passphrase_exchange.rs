//! 固定準備記録に束縛した二つの暗号文の交換と、その配置の明示確認。
use super::*;

/// 今回保存を確認した交換結果。旧暗号文とguardは保持する。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPassphraseExchange {
    Exchanged,
    ConfirmedExchanged,
}

impl KeyDirectory {
    /// 旧通常名と新一時名を交換するか、交換済みの両名を再認証して保存を確認する。
    #[allow(clippy::too_many_arguments)]
    pub fn exchange_key_passphrase(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
    ) -> Result<KeyPassphraseExchange> {
        self.exchange_key_passphrase_with(
            current_name,
            old_passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            prepared,
            &mut |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super::super::super) fn exchange_key_passphrase_with(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<KeyPassphraseExchange> {
        name(current_name)?;
        check_start_intent(resume, start)?;
        check_prepared_intent(start, prepared)?;
        let key_name = staged_name(&start.operation_id);
        inventory_with_key(self, None, Some(&key_name))?;
        let marker = source_marker(self, resume)?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        if decode_snapshot(&fixed.bytes, &marker, resume)? != prepared.after {
            return invalid();
        }
        let started = verify_event_prefix(
            &fixed.bytes,
            &marker,
            &KeyResumeIntent {
                before: prepared.before,
                after: prepared.after,
                operation_id: prepared.operation_id,
            },
            PREPARED,
        )?;
        let ready = verify_event_prefix(
            &started,
            &marker,
            &KeyResumeIntent {
                before: start.before,
                after: start.after,
                operation_id: start.operation_id,
            },
            START,
        )?;
        let old_bytes = verify_prefix(&ready, &marker, resume)?;
        let start_value = cbor::decode(&started).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let event = array(field(&start_value, "events")?)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        if string(field(event, "name")?)? != current_name
            || !equal(field(event, "old_identity")?, &expected.current.value())?
        {
            return invalid();
        }
        let guard = state_history::recorded_guard_identity(event)?;
        let prepared_value =
            cbor::decode(&fixed.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let preparation = array(field(&prepared_value, "events")?)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let new_identity = field(preparation, "new_identity")?;
        let normal = HeldFile::open(self, current_name, MAX_KEYFILE_BYTES)?;
        let temporary = HeldFile::open(self, &key_name, MAX_KEYFILE_BYTES)?;
        let before_exchange = KeyFileIdentity::from_metadata(&normal.metadata) == expected.current;
        let (new_name, new, moved_old) = if before_exchange {
            (key_name.as_str(), temporary, None)
        } else {
            (current_name, normal, Some((key_name.as_str(), temporary)))
        };
        let mut identity = KeyFileIdentity::from_metadata(&new.metadata).value();
        if !before_exchange {
            let Value::Map(fields) = &mut identity else {
                return invalid();
            };
            for (key, value) in fields {
                if matches!(key.as_str(), "ctime_seconds" | "ctime_nanoseconds") {
                    *value = field(new_identity, key)?.clone();
                }
            }
        }
        if !equal(new_identity, &identity)? {
            return Err(KeyFileError::RecoveryChanged);
        }
        authenticate_staged(&new.bytes, event, new_passphrase)?;
        let mut context = self.prepare_resume_snapshot_with_moved_key(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            ResumeSnapshot::Existing {
                old_bytes,
                new_bytes: ready,
                intent: resume,
                allow_absent_guard: false,
                expected_guard: Some(guard),
            },
            moved_old,
        )?;
        if context.state.bytes != fixed.bytes
            || fingerprint(&context.state.metadata) != fingerprint(&fixed.metadata)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        // 一覧で許す予約名は交換の前後とも開始ID由来の一名だけ。
        let mut staged = (new_name.to_owned(), new);
        let check = |context: &PreparedKeyResume<'_>, staged: &(String, HeldFile)| -> Result<()> {
            context.check(Some(&key_name))?;
            context
                .state
                .check(context.source, initial_state::STATE, true)?;
            staged.1.check(context.source, &staged.0, true)
        };
        check(&context, &staged)?;
        staged.1.sync()?;
        context.qualify(Some(&key_name), false, hook, &mut || {
            check(&context, &staged)
        })?;
        if !before_exchange {
            return Ok(KeyPassphraseExchange::ConfirmedExchanged);
        }
        hook(ResumeStage::BeforeKeyExchange)?;
        check(&context, &staged)?;
        (|| -> Result<_> {
            os(fs::renameat_with(
                &context.source.dir,
                current_name,
                &context.source.dir,
                key_name.as_str(),
                RenameFlags::EXCHANGE,
            ))?;
            context.current.metadata = recovery::moved_metadata(&context.current)?;
            staged.1.metadata = recovery::moved_metadata(&staged.1)?;
            std::mem::swap(&mut context.current_name, &mut staged.0);
            hook(ResumeStage::KeyExchanged)?;
            check(&context, &staged)?;
            io(context.source.dir.sync_all())?;
            hook(ResumeStage::KeyExchangeDirectorySynced)?;
            check(&context, &staged)?;
            Ok(KeyPassphraseExchange::Exchanged)
        })()
        .map_err(|_| KeyFileError::CommitUncertain)
    }
}
