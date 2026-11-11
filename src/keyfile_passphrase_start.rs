//! §5.113: 最初の通常変更の開始記録と、その追記だけの復旧。
use super::recovery::{
    decode_snapshot, recover_snapshot, source_marker, verify_event_prefix, verify_prefix,
};
use super::*;

const START: &str = "key_passphrase_change_started";

/// 開始追記の明示復旧に使う控え。ファイルの変更資格を保持しない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPassphraseStartIntent {
    pub before: KeyStateDiagnostic,
    pub after: KeyStateDiagnostic,
    pub operation_id: [u8; 32],
}

/// 保存済みguardと旧鍵を保持した開始追記の準備。
/// 破棄後もguardが残り、開始候補のない状態は保全停止となる。
pub struct PreparedKeyPassphraseStart<'a> {
    context: PreparedKeyResume<'a>,
    // 後続の準備段階は同じ暗号文を使用する必要がある。
    new_ciphertext: Vec<u8>,
}

impl<'a> release::PreparedFirstPassphraseChange<'a> {
    /// guardを保存し、開始snapshotの作成前に控えを返せる状態にする。
    pub fn prepare_start(self) -> Result<PreparedKeyPassphraseStart<'a>> {
        self.prepare_start_with(&mut |_| Ok(()))
    }

    pub(in super::super::super) fn prepare_start_with(
        self,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<PreparedKeyPassphraseStart<'a>> {
        self.recheck()?;
        let mut operation = [0; 32];
        crate::keyfile::random(&mut operation)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let mut context = self.context;
        let before = context.intent.after;
        let marker = source_marker(context.source, &context.intent)?;
        let mut guard_bytes = b"lngnb:key-hold:1\0".to_vec();
        guard_bytes.extend(before.initial.area_id);
        let saved = (|| -> Result<HeldFile> {
            let mut file = File::from(os(fs::openat(
                &context.source.dir,
                recovery_hold::GUARD,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ))?);
            hook(ResumeStage::StartGuardCreated)?;
            os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
            io(file.write_all(&guard_bytes))?;
            io(file.sync_all())?;
            let metadata = io(file.metadata())?;
            let guard = HeldFile {
                file,
                metadata,
                bytes: guard_bytes,
            };
            guard.check(context.source, recovery_hold::GUARD, true)?;
            io(context.source.dir.sync_all())?;
            hook(ResumeStage::StartGuardSynced)?;
            guard.check(context.source, recovery_hold::GUARD, true)?;
            Ok(guard)
        })();
        context.guard = Some(saved.map_err(|_| KeyFileError::RecoveryHoldUncertain)?);
        if context.check(None)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
        }
        context
            .state
            .check(context.source, initial_state::STATE, true)?;
        let mut snapshot =
            cbor::decode(&context.state.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let Value::Map(fields) = &mut snapshot else {
            return invalid();
        };
        let Some((_, Value::Array(events))) = fields.iter_mut().find(|(k, _)| k == "events") else {
            return invalid();
        };
        let resumed = events.last().ok_or(KeyFileError::RecoveryStateInvalid)?;
        let current = field(resumed, "current")?;
        let guard = context
            .guard
            .as_ref()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let start = map(vec![
            ("sequence", Value::Int((before.generation + 1) as i64)),
            ("operation_id", bytes(operation)),
            ("kind", text(START)),
            (
                "actor_uid",
                bytes(context.source_identity.uid.to_be_bytes()),
            ),
            ("recorded_unix_seconds", Value::Int(now)),
            ("rules", text("lngnb-key-operations-1")),
            ("previous_snapshot_sha256", bytes(before.snapshot_hash)),
            ("name", field(current, "name")?.clone()),
            ("old_identity", field(current, "identity")?.clone()),
            (
                "old_ciphertext_sha256",
                field(current, "ciphertext_sha256")?.clone(),
            ),
            ("new_ciphertext_sha256", bytes(self.new_hash)),
            (
                "new_ciphertext_length",
                Value::Int(self.new_ciphertext.len() as i64),
            ),
            ("public_key", field(current, "public_key")?.clone()),
            (
                "guard_identity",
                KeyFileIdentity::from_metadata(&guard.metadata).value(),
            ),
        ]);
        events.push(start);
        context.new_bytes = encoded(&snapshot)?;
        let after = decode_snapshot(&context.new_bytes, &marker, &context.intent)?;
        context.intent = KeyResumeIntent {
            before,
            after,
            operation_id: operation,
        };
        Ok(PreparedKeyPassphraseStart {
            context,
            new_ciphertext: self.new_ciphertext,
        })
    }
}

impl PreparedKeyPassphraseStart<'_> {
    pub fn intent(&self) -> KeyPassphraseStartIntent {
        let KeyResumeIntent {
            before,
            after,
            operation_id,
        } = self.context.intent;
        KeyPassphraseStartIntent {
            before,
            after,
            operation_id,
        }
    }

    pub fn new_ciphertext_metadata(&self) -> (usize, [u8; 32]) {
        (
            self.new_ciphertext.len(),
            Sha256::digest(&self.new_ciphertext).into(),
        )
    }

    /// 開始履歴のみ保存する。guardと元の鍵を保持する。
    pub fn record(&mut self) -> Result<KeyStateDiagnostic> {
        self.record_with(&mut |_| Ok(()))
    }

    pub(in super::super::super) fn record_with(
        &mut self,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        self.context.record_snapshot_with(hook, false)
    }
}

impl KeyDirectory {
    /// 指定した完全な開始snapshotだけを復旧する。新暗号文の生成や採用は行わない。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_key_passphrase_start(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
    ) -> Result<KeyStateDiagnostic> {
        if start.before != resume.after
            || start.after.initial != start.before.initial
            || start.before.generation.checked_add(1) != Some(start.after.generation)
            || start.after.state
                != (KeyHistoryState::PassphraseChangeStarted {
                    started_operation_id: start.operation_id,
                })
        {
            return invalid();
        }
        let intent = KeyResumeIntent {
            before: start.before,
            after: start.after,
            operation_id: start.operation_id,
        };
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&start.operation_id)
        );
        inventory(self, Some(&temp))?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let temporary = match HeldFile::open(self, &temp, initial_state::STATE_LIMIT) {
            Ok(file) => Some(file),
            Err(KeyFileError::Missing) => None,
            Err(e) => return Err(e),
        };
        let marker = source_marker(self, resume)?;
        let decode = |file: &HeldFile| decode_snapshot(&file.bytes, &marker, resume);
        let fixed_diagnostic = decode(&fixed)?;
        let needs_exchange = fixed_diagnostic == start.before;
        let started = if needs_exchange {
            let candidate = temporary
                .as_ref()
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            if decode(candidate)? != start.after {
                return invalid();
            }
            candidate
        } else {
            if fixed_diagnostic != start.after {
                return invalid();
            }
            &fixed
        };
        let ready = verify_event_prefix(&started.bytes, &marker, &intent, START)?;
        let old_ready = if needs_exchange {
            Some(&fixed)
        } else {
            temporary.as_ref()
        };
        if old_ready.is_some_and(|held| held.bytes != ready) {
            return invalid();
        }
        let old_bytes = verify_prefix(&ready, &marker, resume)?;
        let value = cbor::decode(&started.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let event = array(field(&value, "events")?)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let guard = state_history::recorded_guard_identity(event)?;
        let context = self.prepare_resume_snapshot(
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
        )?;
        if context.state.bytes != fixed.bytes
            || fingerprint(&context.state.metadata) != fingerprint(&fixed.metadata)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        recover_snapshot(
            context,
            temporary.as_ref(),
            &temp,
            needs_exchange,
            &intent,
            &mut |_| Ok(()),
            false,
        )
    }
}
