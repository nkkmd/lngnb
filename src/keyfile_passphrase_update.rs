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

impl KeyPassphraseStartIntent {
    /// 追記前に出力した一行を再開控えと照合する。復旧資格は付与しない。
    pub fn parse_receipt(line: &str, resume: &KeyResumeIntent) -> Result<Self> {
        let (after, operation_id) =
            parse_receipt(line, "key_passphrase_change_started", resume.after, |id| {
                KeyHistoryState::PassphraseChangeStarted {
                    started_operation_id: id,
                }
            })?;
        let intent = Self {
            before: resume.after,
            after,
            operation_id,
        };
        check_start_intent(resume, &intent)?;
        Ok(intent)
    }
}

impl KeyPassphrasePreparedIntent {
    /// 追記前に出力した一行を開始控えと照合する。復旧資格は付与しない。
    pub fn parse_receipt(line: &str, start: &KeyPassphraseStartIntent) -> Result<Self> {
        let (after, operation_id) =
            parse_receipt(line, "key_passphrase_change_prepared", start.after, |id| {
                KeyHistoryState::PassphraseChangePrepared {
                    prepared_operation_id: id,
                }
            })?;
        let intent = Self {
            before: start.after,
            after,
            operation_id,
        };
        check_prepared_intent(start, &intent)?;
        Ok(intent)
    }
}

impl KeyPassphraseCompletedIntent {
    /// 追記前に出力した一行を準備控えと照合する。復旧資格は付与しない。
    pub fn parse_receipt(
        line: &str,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
    ) -> Result<Self> {
        let (after, operation_id) = parse_receipt(
            line,
            "key_passphrase_change_completed",
            prepared.after,
            |id| KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id: id,
            },
        )?;
        let intent = Self {
            before: prepared.after,
            after,
            operation_id,
        };
        check_completed_intent(start, prepared, &intent)?;
        Ok(intent)
    }
}

fn parse_receipt(
    line: &str,
    stage: &str,
    before: KeyStateDiagnostic,
    state: impl FnOnce([u8; 32]) -> KeyHistoryState,
) -> Result<(KeyStateDiagnostic, [u8; 32])> {
    if line.len() > 1024 {
        return invalid();
    }
    let mut fields = line.strip_suffix('\n').unwrap_or(line).split(' ');
    if fields.next() != Some(stage) {
        return invalid();
    }
    let mut field = |prefix| {
        fields
            .next()
            .and_then(|field| field.strip_prefix(prefix))
            .ok_or(KeyFileError::RecoveryStateInvalid)
    };
    let area = receipt_id(field("area_id=")?)?;
    let root = receipt_id(field("root=")?)?;
    let initial_operation = receipt_id(field("initial_operation_id=")?)?;
    let initial_generation = field("initial_generation=")?;
    let before_generation = field("before_generation=")?;
    let before_hash = receipt_id(field("before_hash=")?)?;
    let after_generation = field("after_generation=")?;
    let snapshot_hash = receipt_id(field("after_hash=")?)?;
    let operation_id = receipt_id(field("operation_id=")?)?;
    let generation = before
        .generation
        .checked_add(1)
        .ok_or(KeyFileError::RecoveryStateInvalid)?;
    if fields.next().is_some()
        || area != before.initial.area_id
        || root != before.initial.snapshot_hash
        || initial_operation != before.initial.operation_id
        || initial_generation != before.initial.generation.to_string()
        || before_generation != before.generation.to_string()
        || before_hash != before.snapshot_hash
        || after_generation != generation.to_string()
    {
        return invalid();
    }
    Ok((
        KeyStateDiagnostic {
            initial: before.initial,
            generation,
            snapshot_hash,
            state: state(operation_id),
        },
        operation_id,
    ))
}

fn receipt_id(field: &str) -> Result<[u8; 32]> {
    let mut value = [0; 32];
    if field.len() != 64
        || data_encoding::HEXLOWER
            .decode_mut(field.as_bytes(), &mut value)
            .is_err()
    {
        return invalid();
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_round_trip_and_strict_chain() {
        let initial = KeyInitialState {
            area_id: [0x11; 32],
            operation_id: [0x22; 32],
            snapshot_hash: [0x33; 32],
            generation: 1,
        };
        let held = KeyStateDiagnostic {
            initial,
            generation: 3,
            snapshot_hash: [0x44; 32],
            state: KeyHistoryState::Held,
        };
        let resume = KeyResumeIntent {
            before: held,
            after: KeyStateDiagnostic {
                generation: 4,
                snapshot_hash: [0x55; 32],
                state: KeyHistoryState::Ready {
                    resumed_operation_id: [0x66; 32],
                },
                ..held
            },
            operation_id: [0x66; 32],
        };
        let mut bytes = Vec::new();
        let started = KeyStateDiagnostic {
            generation: 5,
            snapshot_hash: [0x77; 32],
            state: KeyHistoryState::PassphraseChangeStarted {
                started_operation_id: [0x88; 32],
            },
            ..held
        };
        let prepared = KeyStateDiagnostic {
            generation: 6,
            snapshot_hash: [0x99; 32],
            state: KeyHistoryState::PassphraseChangePrepared {
                prepared_operation_id: [0xaa; 32],
            },
            ..held
        };
        let completed = KeyStateDiagnostic {
            generation: 7,
            snapshot_hash: [0xbb; 32],
            state: KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id: [0xcc; 32],
            },
            ..held
        };
        receipt(&mut bytes, "started", resume.after, started, [0x88; 32]).unwrap();
        receipt(&mut bytes, "prepared", started, prepared, [0xaa; 32]).unwrap();
        receipt(&mut bytes, "completed", prepared, completed, [0xcc; 32]).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let lines: Vec<_> = text.lines().collect();
        let start = KeyPassphraseStartIntent::parse_receipt(lines[0], &resume).unwrap();
        let prepare = KeyPassphrasePreparedIntent::parse_receipt(lines[1], &start).unwrap();
        let complete =
            KeyPassphraseCompletedIntent::parse_receipt(lines[2], &start, &prepare).unwrap();
        assert_eq!(
            (start.after, prepare.after, complete.after),
            (started, prepared, completed)
        );

        for bad in [
            text.to_owned(),
            lines[0].replace("started", "prepared"),
            lines[0].replace("before_generation=4", "before_generation=04"),
            lines[0].replace("after_generation=5", "after_generation=6"),
            lines[0].replace(&"33".repeat(32), &"ff".repeat(32)),
            lines[0].replace(&"77".repeat(32), &"AB".repeat(32)),
            format!("{} extra=1", lines[0]),
            lines[0][..lines[0].len() - 1].to_owned(),
        ] {
            assert_eq!(
                KeyPassphraseStartIntent::parse_receipt(&bad, &resume),
                Err(KeyFileError::RecoveryStateInvalid)
            );
        }
        let wrong_start = KeyPassphraseStartIntent {
            after: KeyStateDiagnostic {
                snapshot_hash: [0xdd; 32],
                ..started
            },
            ..start
        };
        assert!(KeyPassphrasePreparedIntent::parse_receipt(lines[1], &wrong_start).is_err());
        assert!(
            KeyPassphraseCompletedIntent::parse_receipt(lines[2], &wrong_start, &prepare).is_err()
        );
    }
}
