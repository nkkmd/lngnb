//! 履歴付き領域の初回更新と追記前の控え出力。
use super::*;
use std::io::Write;

impl KeyDirectory {
    /// 同じ排他で初回パスフレーズ変更を行い、解除の保存確認後に結果を返す。
    /// 各追記前に一行の控えを書き、flushが失敗した場合は停止する。
    #[allow(clippy::too_many_arguments)]
    pub fn change_first_key_passphrase(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        resume: &KeyResumeIntent,
        receipts: &mut impl Write,
    ) -> Result<release::KeyResumeRelease> {
        let expected = self.first_passphrase_expected(current_name, backup_name, resume)?;
        let mut start = self
            .prepare_first_passphrase_change(
                current_name,
                old_passphrase,
                new_passphrase,
                backups,
                current_backup,
                backup_name,
                proofs,
                &expected,
                resume,
            )?
            .prepare_start()?;
        let started = start.intent();
        receipt(
            receipts,
            "started",
            started.before,
            started.after,
            started.operation_id,
        )?;
        start.record()?;

        let preparation = start.prepare_ciphertext(new_passphrase)?;
        let prepared = preparation.intent();
        receipt(
            receipts,
            "prepared",
            prepared.before,
            prepared.after,
            prepared.operation_id,
        )?;
        preparation.record()?;

        self.exchange_key_passphrase(
            current_name,
            old_passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            &expected,
            resume,
            &started,
            &prepared,
        )?;
        let completion = self.prepare_key_passphrase_completion(
            current_name,
            old_passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            &expected,
            resume,
            &started,
            &prepared,
        )?;
        let completed = completion.intent();
        receipt(
            receipts,
            "completed",
            completed.before,
            completed.after,
            completed.operation_id,
        )?;
        completion.record()?;

        self.recover_key_passphrase_release(
            current_name,
            old_passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            &expected,
            resume,
            &started,
            &prepared,
            &completed,
        )
    }

    fn first_passphrase_expected(
        &self,
        current_name: &str,
        backup_name: &str,
        resume: &KeyResumeIntent,
    ) -> Result<KeyResumeExpected> {
        let marker = source_marker(self, resume)?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        if decode_snapshot(&fixed.bytes, &marker, resume)? != resume.after {
            return invalid();
        }
        verify_prefix(&fixed.bytes, &marker, resume)?;
        let snapshot =
            cbor::decode(&fixed.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let event = array(field(&snapshot, "events")?)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let current = field(event, "current")?;
        let preserved = field(event, "preserved")?;
        if string(field(current, "name")?)? != current_name
            || string(field(preserved, "name")?)? != backup_name
        {
            return invalid();
        }
        let directory = field(preserved, "directory")?;
        Ok(KeyResumeExpected {
            state: resume.before,
            current: state_history::recorded_file_identity(field(current, "identity")?)?,
            ciphertext_sha256: id(field(current, "ciphertext_sha256")?)?,
            public_key: id(field(current, "public_key")?)?,
            preserved_directory: KeyDirectoryIdentity {
                dev: u64::from_be_bytes(fixed_bytes(field(directory, "dev")?)?),
                ino: u64::from_be_bytes(fixed_bytes(field(directory, "ino")?)?),
                uid: u32::from_be_bytes(fixed_bytes(field(directory, "uid")?)?),
            },
            preserved: state_history::recorded_file_identity(field(preserved, "identity")?)?,
            guard: state_history::recorded_guard_identity(event)?,
        })
    }
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyFileError::RecoveryStateInvalid),
        _ => invalid(),
    }
}

fn receipt(
    output: &mut impl Write,
    stage: &str,
    before: KeyStateDiagnostic,
    after: KeyStateDiagnostic,
    operation: [u8; 32],
) -> Result<()> {
    // 三段階に共通する初回rootと、段階ごとの前後の控え。
    io(writeln!(
        output,
        "key_passphrase_change_{stage} area_id={} root={} initial_operation_id={} initial_generation={} before_generation={} before_hash={} after_generation={} after_hash={} operation_id={}",
        data_encoding::HEXLOWER.encode(&before.initial.area_id),
        data_encoding::HEXLOWER.encode(&before.initial.snapshot_hash),
        data_encoding::HEXLOWER.encode(&before.initial.operation_id),
        before.initial.generation,
        before.generation,
        data_encoding::HEXLOWER.encode(&before.snapshot_hash),
        after.generation,
        data_encoding::HEXLOWER.encode(&after.snapshot_hash),
        data_encoding::HEXLOWER.encode(&operation),
    ))?;
    io(output.flush())
}
