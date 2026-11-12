//! §5.113: 最初の通常変更の開始記録と、その追記だけの復旧。
use super::recovery::{
    decode_snapshot, recover_snapshot, source_marker, verify_event_prefix, verify_prefix,
};
use super::*;

const COMPLETED: &str = "key_passphrase_change_completed";
const PREPARED: &str = "key_passphrase_change_prepared";
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
    recorded: bool,
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
            recorded: false,
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
        if self.recorded {
            return invalid();
        }
        let diagnostic = self.context.record_snapshot_with(hook, false)?;
        self.recorded = true;
        Ok(diagnostic)
    }
}

fn staged_name(started_operation_id: &[u8; 32]) -> String {
    format!(
        ".lngnb-key-passphrase-{}",
        data_encoding::HEXLOWER.encode(started_operation_id)
    )
}

fn authenticate_staged(bytes: &[u8], event: &Value, passphrase: &str) -> Result<()> {
    if field(event, "new_ciphertext_length")? != &Value::Int(bytes.len() as i64)
        || id(field(event, "new_ciphertext_sha256")?)? != <[u8; 32]>::from(Sha256::digest(bytes))
    {
        return invalid();
    }
    if unlock(bytes, passphrase)?.public_key() != id(field(event, "public_key")?)? {
        return Err(KeyFileError::UnexpectedPublicKey);
    }
    Ok(())
}

/// 準備追記の明示復旧に使う控え。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPassphrasePreparedIntent {
    pub before: KeyStateDiagnostic,
    pub after: KeyStateDiagnostic,
    pub operation_id: [u8; 32],
}

/// 新暗号文の保存を確認し、追記前の控えを取得できる状態。
pub struct PreparedKeyPassphraseRecord<'a>(PreparedKeyResume<'a>);

impl PreparedKeyPassphraseRecord<'_> {
    pub fn intent(&self) -> KeyPassphrasePreparedIntent {
        let intent = self.0.intent;
        KeyPassphrasePreparedIntent {
            before: intent.before,
            after: intent.after,
            operation_id: intent.operation_id,
        }
    }

    pub fn record(self) -> Result<KeyStateDiagnostic> {
        self.record_with(&mut |_| Ok(()))
    }

    pub(in super::super::super) fn record_with(
        mut self,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        self.0.record_snapshot_with(hook, false)
    }
}

impl<'a> PreparedKeyPassphraseStart<'a> {
    /// 開始追記に成功した同じ排他の下で新暗号文を一時保存する。
    pub fn prepare_ciphertext(
        self,
        new_passphrase: &str,
    ) -> Result<PreparedKeyPassphraseRecord<'a>> {
        self.prepare_ciphertext_with(new_passphrase, &mut |_| Ok(()))
    }

    pub(in super::super::super) fn prepare_ciphertext_with(
        self,
        new_passphrase: &str,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<PreparedKeyPassphraseRecord<'a>> {
        if !self.recorded {
            return invalid();
        }
        let mut context = self.context;
        let before = context.intent.after;
        let marker = source_marker(context.source, &context.intent)?;
        let name = staged_name(&context.intent.operation_id);
        let mut snapshot =
            cbor::decode(&context.new_bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        authenticate_staged(
            &self.new_ciphertext,
            array(field(&snapshot, "events")?)?
                .last()
                .ok_or(KeyFileError::RecoveryStateInvalid)?,
            new_passphrase,
        )?;
        let mut operation = [0; 32];
        crate::keyfile::random(&mut operation)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        context
            .state
            .check(context.source, initial_state::STATE, true)?;
        if context.check(None)? > SCAN_LIMIT - 2 {
            return Err(KeyFileError::ScanLimit);
        }
        absent(context.source, &name)?;
        let result = (|| -> Result<_> {
            let mut file = File::from(os(fs::openat(
                &context.source.dir,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ))?);
            hook(ResumeStage::StagedKeyCreated)?;
            os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
            io(file.write_all(&self.new_ciphertext))?;
            hook(ResumeStage::StagedKeyWritten)?;
            let held = HeldFile {
                metadata: io(file.metadata())?,
                file,
                bytes: self.new_ciphertext,
            };
            held.check(context.source, &name, true)?;
            held.sync()?;
            hook(ResumeStage::StagedKeyFileSynced)?;
            held.check(context.source, &name, true)?;
            context.staged_key = Some((name, held));
            context.check(None)?;
            context
                .state
                .check(context.source, initial_state::STATE, true)?;
            io(context.source.dir.sync_all())?;
            hook(ResumeStage::StagedKeyDirectorySynced)?;
            if context.check(None)? >= SCAN_LIMIT {
                return Err(KeyFileError::ScanLimit);
            }
            context
                .state
                .check(context.source, initial_state::STATE, true)?;
            let (_, held) = context
                .staged_key
                .as_ref()
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            let Value::Map(fields) = &mut snapshot else {
                return invalid();
            };
            let Some((_, Value::Array(events))) = fields.iter_mut().find(|(k, _)| k == "events")
            else {
                return invalid();
            };
            events.push(map(vec![
                ("sequence", Value::Int((before.generation + 1) as i64)),
                ("operation_id", bytes(operation)),
                ("kind", text(PREPARED)),
                (
                    "actor_uid",
                    bytes(context.source_identity.uid.to_be_bytes()),
                ),
                ("recorded_unix_seconds", Value::Int(now)),
                ("rules", text("lngnb-key-operations-1")),
                ("previous_snapshot_sha256", bytes(before.snapshot_hash)),
                ("started_operation_id", bytes(context.intent.operation_id)),
                (
                    "new_identity",
                    KeyFileIdentity::from_metadata(&held.metadata).value(),
                ),
            ]));
            context.new_bytes = encoded(&snapshot)?;
            let after = decode_snapshot(&context.new_bytes, &marker, &context.intent)?;
            context.intent = KeyResumeIntent {
                before,
                after,
                operation_id: operation,
            };
            Ok(PreparedKeyPassphraseRecord(context))
        })();
        result.map_err(|_| KeyFileError::RecoveryStateUncertain)
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
        self.recover_passphrase_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            None,
            None,
        )
    }

    /// 準備追記を完全な既存snapshotと記録済み新一時鍵から復旧する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_key_passphrase_prepared(
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
    ) -> Result<KeyStateDiagnostic> {
        check_prepared_intent(start, prepared)?;
        self.recover_passphrase_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            Some((prepared, new_passphrase)),
            None,
        )
    }

    /// 完全な完了候補だけを、記録guardを保持したまま復旧する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_key_passphrase_completed(
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
        completed: &KeyPassphraseCompletedIntent,
    ) -> Result<KeyStateDiagnostic> {
        check_completed_intent(start, prepared, completed)?;
        self.recover_passphrase_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            Some((prepared, new_passphrase)),
            Some(completed),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_passphrase_snapshot(
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
        prepared: Option<(&KeyPassphrasePreparedIntent, &str)>,
        completed: Option<&KeyPassphraseCompletedIntent>,
    ) -> Result<KeyStateDiagnostic> {
        self.with_passphrase_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            prepared,
            completed,
            false,
            |context, temporary, temp, exchange, intent| {
                recover_snapshot(
                    context,
                    temporary,
                    temp,
                    exchange,
                    intent,
                    &mut |_| Ok(()),
                    false,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_passphrase_snapshot<T>(
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
        prepared: Option<(&KeyPassphrasePreparedIntent, &str)>,
        completed: Option<&KeyPassphraseCompletedIntent>,
        release: bool,
        apply: impl FnOnce(
            PreparedKeyResume<'_>,
            Option<&HeldFile>,
            &str,
            bool,
            &KeyResumeIntent,
        ) -> Result<T>,
    ) -> Result<T> {
        check_start_intent(resume, start)?;
        let start_intent = KeyResumeIntent {
            before: start.before,
            after: start.after,
            operation_id: start.operation_id,
        };
        let prepared_intent = prepared.map_or(start_intent, |(prepared, _)| KeyResumeIntent {
            before: prepared.before,
            after: prepared.after,
            operation_id: prepared.operation_id,
        });
        let intent = completed.map_or(prepared_intent, |completed| KeyResumeIntent {
            before: completed.before,
            after: completed.after,
            operation_id: completed.operation_id,
        });
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        );
        let key_name = prepared.map(|_| staged_name(&start.operation_id));
        inventory_with_key(
            self,
            (!release).then_some(temp.as_str()),
            if completed.is_none() {
                key_name.as_deref()
            } else {
                None
            },
        )?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let temporary = if release {
            absent(self, &temp)?;
            None
        } else {
            match HeldFile::open(self, &temp, initial_state::STATE_LIMIT) {
                Ok(file) => Some(file),
                Err(KeyFileError::Missing) => None,
                Err(e) => return Err(e),
            }
        };
        let marker = source_marker(self, resume)?;
        let decode = |file: &HeldFile| decode_snapshot(&file.bytes, &marker, resume);
        let fixed_diagnostic = decode(&fixed)?;
        let needs_exchange = fixed_diagnostic == intent.before;
        let (new, old) = if needs_exchange {
            (
                temporary
                    .as_ref()
                    .ok_or(KeyFileError::RecoveryStateInvalid)?,
                Some(&fixed),
            )
        } else {
            (&fixed, temporary.as_ref())
        };
        if decode(new)? != intent.after {
            return invalid();
        }
        let prefix = verify_event_prefix(
            &new.bytes,
            &marker,
            &intent,
            if completed.is_some() {
                COMPLETED
            } else if prepared.is_some() {
                PREPARED
            } else {
                START
            },
        )?;
        if old.is_some_and(|held| held.bytes != prefix) {
            return invalid();
        }
        let (started, ready) = if prepared.is_some() {
            let started = if completed.is_some() {
                verify_event_prefix(&prefix, &marker, &prepared_intent, PREPARED)?
            } else {
                prefix
            };
            let ready = verify_event_prefix(&started, &marker, &start_intent, START)?;
            (started, ready)
        } else {
            (new.bytes.clone(), prefix)
        };
        let old_bytes = verify_prefix(&ready, &marker, resume)?;
        let value = cbor::decode(&started).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let event = array(field(&value, "events")?)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let guard = state_history::recorded_guard_identity(event)?;
        let mut binding = ResumeCurrent::Original;
        let mut absent_key = None;
        let staged_key = if let (Some(key_name), Some((_, passphrase))) = (key_name, prepared) {
            let value = cbor::decode(&new.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
            let preparation = array(field(&value, "events")?)?
                .last()
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            let (path, identity_key) = if completed.is_some() {
                absent(self, &key_name)?;
                (current_name, "installed_identity")
            } else {
                (key_name.as_str(), "new_identity")
            };
            let held = HeldFile::open(self, path, MAX_KEYFILE_BYTES)?;
            if !equal(
                field(preparation, identity_key)?,
                &KeyFileIdentity::from_metadata(&held.metadata).value(),
            )? {
                return Err(KeyFileError::RecoveryChanged);
            }
            authenticate_staged(&held.bytes, event, passphrase)?;
            held.check(self, path, true)?;
            if completed.is_some() {
                binding = ResumeCurrent::Installed(held);
                absent_key = Some(key_name);
                None
            } else {
                held.sync()?;
                held.check(self, path, true)?;
                Some((key_name, held))
            }
        } else {
            None
        };
        let mut context = self.prepare_resume_snapshot_with_current(
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
                allow_absent_guard: release,
                expected_guard: Some(guard),
            },
            binding,
        )?;
        if context.state.bytes != fixed.bytes
            || fingerprint(&context.state.metadata) != fingerprint(&fixed.metadata)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        context.staged_key = staged_key;
        context.absent_names.extend(absent_key);
        apply(context, temporary.as_ref(), &temp, needs_exchange, &intent)
    }
}

fn check_completed_intent(
    start: &KeyPassphraseStartIntent,
    prepared: &KeyPassphrasePreparedIntent,
    completed: &KeyPassphraseCompletedIntent,
) -> Result<()> {
    check_prepared_intent(start, prepared)?;
    if completed.before != prepared.after
        || completed.after.initial != completed.before.initial
        || completed.before.generation.checked_add(1) != Some(completed.after.generation)
        || completed.after.state
            != (KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id: completed.operation_id,
            })
    {
        return invalid();
    }
    Ok(())
}

#[path = "keyfile_passphrase_release.rs"]
mod passphrase_release;

fn check_start_intent(resume: &KeyResumeIntent, start: &KeyPassphraseStartIntent) -> Result<()> {
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
    Ok(())
}

fn check_prepared_intent(
    start: &KeyPassphraseStartIntent,
    prepared: &KeyPassphrasePreparedIntent,
) -> Result<()> {
    if prepared.before != start.after
        || prepared.after.initial != prepared.before.initial
        || prepared.before.generation.checked_add(1) != Some(prepared.after.generation)
        || prepared.after.state
            != (KeyHistoryState::PassphraseChangePrepared {
                prepared_operation_id: prepared.operation_id,
            })
    {
        return invalid();
    }
    Ok(())
}

#[path = "keyfile_passphrase_exchange.rs"]
mod exchange;
pub use exchange::{KeyPassphraseCleanup, KeyPassphraseExchange};

/// 完了追記の中断を明示復旧するための控え。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPassphraseCompletedIntent {
    pub before: KeyStateDiagnostic,
    pub after: KeyStateDiagnostic,
    pub operation_id: [u8; 32],
}

/// 同じ排他と現物fdに束縛した完了追記の準備。
pub struct PreparedKeyPassphraseCompletion<'a>(PreparedKeyResume<'a>);

impl<'a> PreparedKeyPassphraseCompletion<'a> {
    fn new(
        mut context: PreparedKeyResume<'a>,
        cleanup: KeyPassphraseCleanup,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
    ) -> Result<Self> {
        context.check_held()?;
        let marker = source_marker(context.source, resume)?;
        let mut operation = [0; 32];
        crate::keyfile::random(&mut operation)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let mut snapshot =
            cbor::decode(&context.state.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let Value::Map(fields) = &mut snapshot else {
            return invalid();
        };
        let Some((_, Value::Array(events))) = fields.iter_mut().find(|(key, _)| key == "events")
        else {
            return invalid();
        };
        let disposition = match cleanup {
            KeyPassphraseCleanup::RemovedRetainedOldCiphertext => "removed_retained_old_ciphertext",
            KeyPassphraseCleanup::ConfirmedOldCiphertextAbsent => "confirmed_old_ciphertext_absent",
        };
        let before = prepared.after;
        events.push(map(vec![
            ("sequence", Value::Int((before.generation + 1) as i64)),
            ("operation_id", bytes(operation)),
            ("kind", text(COMPLETED)),
            (
                "actor_uid",
                bytes(context.source_identity.uid.to_be_bytes()),
            ),
            ("recorded_unix_seconds", Value::Int(now)),
            ("rules", text("lngnb-key-operations-1")),
            ("previous_snapshot_sha256", bytes(before.snapshot_hash)),
            ("started_operation_id", bytes(start.operation_id)),
            ("prepared_operation_id", bytes(prepared.operation_id)),
            (
                "installed_identity",
                KeyFileIdentity::from_metadata(&context.current.metadata).value(),
            ),
            ("disposition", text(disposition)),
        ]));
        context.new_bytes = encoded(&snapshot)?;
        let after = decode_snapshot(&context.new_bytes, &marker, resume)?;
        context.intent = KeyResumeIntent {
            before,
            after,
            operation_id: operation,
        };
        Ok(Self(context))
    }

    pub fn intent(&self) -> KeyPassphraseCompletedIntent {
        KeyPassphraseCompletedIntent {
            before: self.0.intent.before,
            after: self.0.intent.after,
            operation_id: self.0.intent.operation_id,
        }
    }

    pub fn record(self) -> Result<KeyStateDiagnostic> {
        self.record_with(&mut |_| Ok(()))
    }

    pub(in super::super::super) fn record_with(
        mut self,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        self.0.record_snapshot_with(hook, false)
    }
}
