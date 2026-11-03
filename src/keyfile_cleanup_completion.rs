//! §5.104: 不在/正常整理に共通する資格と完了追記。停止解除なし。
use super::recovery::{absent, equal, field};
use super::*;
#[path = "keyfile_completion_recovery.rs"]
mod completion_recovery;
#[path = "keyfile_cleanup_remove.rs"]
pub(super) mod removal;
pub use removal::PreparedResidueRemoval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCleanupDisposition {
    RemovedPresent,
    ConfirmedAbsentOnRecovery,
}
impl KeyCleanupDisposition {
    fn text(self) -> &'static str {
        match self {
            Self::RemovedPresent => "removed_present",
            Self::ConfirmedAbsentOnRecovery => "confirmed_absent_on_recovery",
        }
    }
}
/// 控える未保存の選択値。過去のunlink/保存成功や通常変更許可の証明ではない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCleanupCompletion {
    pub before: KeyStateDiagnostic,
    pub after: KeyStateDiagnostic,
    pub started_operation_id: [u8; 32],
    pub operation_id: [u8; 32],
    pub disposition: KeyCleanupDisposition,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum CompletionStage {
    PreservedSynced,
    DirectoriesSynced,
    ControlsSynced,
    SnapshotsSynced,
    Qualified,
    BeforeCreate,
    Created,
    Written,
    FileSynced,
    Prepared,
    BeforeExchange,
    Exchanged,
    StateSynced,
    BeforeCleanup,
    OldSnapshotRemoved,
    CleanupSynced,
}
fn update_name(id: &[u8; 32]) -> String {
    format!(
        ".lngnb-key-state-update-{}",
        data_encoding::HEXLOWER.encode(id)
    )
}
fn events_mut(v: &mut Value) -> Result<&mut Vec<Value>> {
    let Value::Map(m) = v else { return invalid() };
    let Some((_, Value::Array(events))) = m.iter_mut().find(|(k, _)| k == "events") else {
        return invalid();
    };
    Ok(events)
}
fn encoded(v: &Value) -> Result<Vec<u8>> {
    cbor::encode(v).map_err(|_| KeyFileError::RecoveryStateInvalid)
}
fn decoded(b: &[u8]) -> Result<Value> {
    cbor::decode(b).map_err(|_| KeyFileError::RecoveryStateInvalid)
}
fn active_id(state: &KeyStateDiagnostic) -> Result<[u8; 32]> {
    match state.state {
        KeyHistoryState::Active {
            started_operation_id,
        } => Ok(started_operation_id),
        _ => invalid(),
    }
}

struct CompletionContext<'a> {
    source: &'a mut KeyDirectory,
    backup: &'a mut KeyDirectory,
    residue: String,
    backup_name: String,
    expected: KeyCleanupExpected,
    source_identity: KeyDirectoryIdentity,
    preserved: HeldFile,
    marker: HeldFile,
    guard: HeldFile,
    removed_target: Option<removal::RemovedTarget>,
}
impl<'a> CompletionContext<'a> {
    fn open(
        source: &'a mut KeyDirectory,
        backup: &'a mut KeyDirectory,
        residue: &str,
        backup_name: &str,
        passphrase: &str,
        expected: &KeyCleanupExpected,
        active_bytes: &[u8],
    ) -> Result<Self> {
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(backup_name)?;
        source.secure()?;
        backup.secure()?;
        absent(source, residue)?;
        let context =
            Self::open_controls(source, backup, residue, backup_name, expected, active_bytes)?;
        if unlock(&context.preserved.bytes, passphrase)?.public_key() != expected.public_key {
            return Err(KeyFileError::UnexpectedPublicKey);
        }
        context.check()?;
        Ok(context)
    }
    fn open_controls(
        source: &'a mut KeyDirectory,
        backup: &'a mut KeyDirectory,
        residue: &str,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        active_bytes: &[u8],
    ) -> Result<Self> {
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(backup_name)?;
        source.secure()?;
        backup.secure()?;
        let source_identity = KeyDirectoryIdentity::from_metadata(&io(source.dir.metadata())?);
        if source_identity == expected.preserved_directory
            || KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?)
                != expected.preserved_directory
        {
            return invalid();
        }
        let marker = HeldFile::open(source, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        let guard = HeldFile::open(source, recovery_hold::GUARD, MAX_KEYFILE_BYTES)?;
        let preserved = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
        if KeyFileIdentity::from_metadata(&preserved.metadata) != expected.preserved {
            return Err(KeyFileError::RecoveryChanged);
        }
        let context = Self {
            source,
            backup,
            residue: residue.into(),
            backup_name: backup_name.into(),
            expected: *expected,
            source_identity,
            preserved,
            marker,
            guard,
            removed_target: None,
        };
        if context.validate(active_bytes)? != expected.state {
            return invalid();
        }
        let mut active = decoded(active_bytes)?;
        let event = events_mut(&mut active)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        if field(event, "kind")? != &text("residue_cleanup_started")
            || field(event, "operation_id")? != &bytes(active_id(&expected.state)?)
            || !equal(
                field(event, "target")?,
                &map(vec![
                    ("name", text(residue)),
                    ("identity", expected.target.value()),
                    (
                        "ciphertext_sha256",
                        bytes(<[u8; 32]>::from(Sha256::digest(&context.preserved.bytes))),
                    ),
                    ("public_key", bytes(expected.public_key)),
                ]),
            )?
            || !equal(
                field(event, "preserved")?,
                &map(vec![
                    ("directory", expected.preserved_directory.value()),
                    ("name", text(backup_name)),
                    ("identity", expected.preserved.value()),
                ]),
            )?
        {
            return invalid();
        }
        context.check_controls()?;
        Ok(context)
    }
    fn validate(&self, snapshot: &[u8]) -> Result<KeyStateDiagnostic> {
        let initial = self.expected.state.initial;
        if self.marker.bytes.len() != 105
            || !self.marker.bytes.starts_with(b"lngnb:key-recovery:2\0")
        {
            return invalid();
        }
        let mut source = self.marker.bytes[..73].to_vec();
        source[19] = b'1';
        let mut guard = b"lngnb:key-hold:1\0".to_vec();
        guard.extend_from_slice(&initial.area_id);
        if self.source.marker_area_id(&source)? != initial.area_id
            || self.marker.bytes[73..] != initial.snapshot_hash
            || self.guard.bytes != guard
        {
            return invalid();
        }
        state_history::decode_history(snapshot, &source, initial.area_id, initial.snapshot_hash)
    }
    fn check(&self) -> Result<()> {
        self.check_controls()?;
        absent(self.source, &self.residue)?;
        if let Some(target) = &self.removed_target {
            target.check()?;
        }
        Ok(())
    }
    fn check_controls(&self) -> Result<()> {
        self.source.secure()?;
        self.backup.secure()?;
        if KeyDirectoryIdentity::from_metadata(&io(self.source.dir.metadata())?)
            != self.source_identity
            || KeyDirectoryIdentity::from_metadata(&io(self.backup.dir.metadata())?)
                != self.expected.preserved_directory
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        self.preserved.check(self.backup, &self.backup_name, true)?;
        self.marker
            .check(self.source, recovery_hold::MARKER, true)?;
        self.guard.check(self.source, recovery_hold::GUARD, true)
    }
    fn sync_controls(&self, hook: &mut impl FnMut(CompletionStage) -> Result<()>) -> Result<()> {
        self.check()?;
        self.preserved.sync()?;
        hook(CompletionStage::PreservedSynced)?;
        self.check()?;
        io(self.backup.dir.sync_all())?;
        io(self.source.dir.sync_all())?;
        hook(CompletionStage::DirectoriesSynced)?;
        self.check()?;
        self.marker.sync()?;
        self.guard.sync()?;
        hook(CompletionStage::ControlsSynced)?;
        self.check()
    }
}

/// 現在の不在と保全先/制御file・両directoryを保持する完了準備。Dropは追記/削除しない。
/// 不在専用APIはconfirmed_absentのみ。正常unlink APIは保存確認後にremoved_presentを準備する。
pub struct PreparedAbsentCleanup<'a> {
    context: CompletionContext<'a>,
    state: HeldFile,
    new_bytes: Vec<u8>,
    intent: KeyCleanupCompletion,
}
impl PreparedAbsentCleanup<'_> {
    pub fn intent(&self) -> KeyCleanupCompletion {
        self.intent
    }
    pub fn record(self) -> Result<KeyStateDiagnostic> {
        self.record_with(&mut |_| Ok(()))
    }
    pub(in super::super) fn record_with(
        self,
        hook: &mut impl FnMut(CompletionStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        use CompletionStage as S;
        let context = &self.context;
        let before = || -> Result<()> {
            context.check()?;
            self.state
                .check(context.source, initial_state::STATE, true)?;
            if context.source.reject_state_artifacts(true)? >= SCAN_LIMIT {
                return Err(KeyFileError::ScanLimit);
            }
            Ok(())
        };
        before()?;
        hook(S::BeforeCreate)?;
        before()?;
        let temp = update_name(&self.intent.operation_id);
        let mut durable = false;
        let result = (|| -> Result<KeyStateDiagnostic> {
            let mut file = File::from(os(fs::openat(
                &context.source.dir,
                temp.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ))?);
            os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
            hook(S::Created)?;
            io(file.write_all(&self.new_bytes))?;
            hook(S::Written)?;
            io(file.sync_all())?;
            hook(S::FileSynced)?;
            context
                .source
                .state_binding(&temp, &self.new_bytes, &file)?;
            io(context.source.dir.sync_all())?;
            hook(S::Prepared)?;
            hook(S::BeforeExchange)?;
            context.check()?;
            self.state
                .check(context.source, initial_state::STATE, true)?;
            context
                .source
                .state_binding(&temp, &self.new_bytes, &file)?;
            context.source.only_cleanup_update(&temp)?;
            os(fs::renameat_with(
                &context.source.dir,
                temp.as_str(),
                &context.source.dir,
                initial_state::STATE,
                RenameFlags::EXCHANGE,
            ))?;
            hook(S::Exchanged)?;
            context
                .source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(context.source, &temp, false)?;
            io(context.source.dir.sync_all())?;
            context.check()?;
            context
                .source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(context.source, &temp, false)?;
            durable = true;
            hook(S::StateSynced)?;
            hook(S::BeforeCleanup)?;
            context.check()?;
            context.source.only_cleanup_update(&temp)?;
            context
                .source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(context.source, &temp, false)?;
            os(fs::unlinkat(
                &context.source.dir,
                temp.as_str(),
                AtFlags::empty(),
            ))?;
            hook(S::OldSnapshotRemoved)?;
            io(context.source.dir.sync_all())?;
            hook(S::CleanupSynced)?;
            context.check()?;
            context
                .source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            context.source.reject_state_artifacts(true)?;
            if context.validate(
                &context
                    .source
                    .state_bytes(initial_state::STATE, initial_state::STATE_LIMIT)?,
            )? != self.intent.after
            {
                return invalid();
            }
            Ok(self.intent.after)
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

fn completion_identity() -> Result<([u8; 32], i64)> {
    let mut operation_id = [0; 32];
    super::super::super::random(&mut operation_id)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KeyFileError::RecoveryStateInvalid)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    Ok((operation_id, now))
}

fn completion_value(
    context: &CompletionContext<'_>,
    state: &HeldFile,
    operation_id: [u8; 32],
    now: i64,
    disposition: KeyCleanupDisposition,
) -> Result<(Vec<u8>, KeyCleanupCompletion)> {
    let started_operation_id = active_id(&context.expected.state)?;
    let mut value = decoded(&state.bytes)?;
    events_mut(&mut value)?.push(map(vec![
        (
            "sequence",
            Value::Int(context.expected.state.generation as i64 + 1),
        ),
        ("operation_id", bytes(operation_id)),
        ("kind", text("residue_cleanup_completed")),
        (
            "actor_uid",
            bytes(rustix::process::geteuid().as_raw().to_be_bytes()),
        ),
        ("recorded_unix_seconds", Value::Int(now)),
        ("rules", text("lngnb-key-operations-1")),
        ("started_operation_id", bytes(started_operation_id)),
        ("disposition", text(disposition.text())),
    ]));
    let new_bytes = encoded(&value)?;
    let after = context.validate(&new_bytes)?;
    Ok((
        new_bytes,
        KeyCleanupCompletion {
            before: context.expected.state,
            after,
            started_operation_id,
            operation_id,
            disposition,
        },
    ))
}

impl KeyDirectory {
    /// 対象を削除せず、現在の不在と保全先を再資格化して新規不在完了を準備する。
    pub fn prepare_absent_residue_completion<'a>(
        &'a mut self,
        residue: &str,
        passphrase: &str,
        backup: &'a mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
    ) -> Result<PreparedAbsentCleanup<'a>> {
        let (operation_id, now) = completion_identity()?;
        self.prepare_absent_residue_completion_with(
            residue,
            passphrase,
            backup,
            backup_name,
            expected,
            operation_id,
            now,
            &mut |_| Ok(()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn prepare_absent_residue_completion_with<'a>(
        &'a mut self,
        residue: &str,
        passphrase: &str,
        backup: &'a mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        operation_id: [u8; 32],
        now: i64,
        hook: &mut impl FnMut(CompletionStage) -> Result<()>,
    ) -> Result<PreparedAbsentCleanup<'a>> {
        active_id(&expected.state)?;
        if self.reject_state_artifacts(true)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
        }
        let state = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let context = CompletionContext::open(
            self,
            backup,
            residue,
            backup_name,
            passphrase,
            expected,
            &state.bytes,
        )?;
        let (new_bytes, intent) = completion_value(
            &context,
            &state,
            operation_id,
            now,
            KeyCleanupDisposition::ConfirmedAbsentOnRecovery,
        )?;
        context.sync_controls(hook)?;
        state.check(context.source, initial_state::STATE, true)?;
        state.sync()?;
        hook(CompletionStage::SnapshotsSynced)?;
        context.check()?;
        state.check(context.source, initial_state::STATE, true)?;
        io(context.source.dir.sync_all())?;
        hook(CompletionStage::Qualified)?;
        context.check()?;
        state.check(context.source, initial_state::STATE, true)?;
        context.source.reject_state_artifacts(true)?;
        Ok(PreparedAbsentCleanup {
            context,
            state,
            new_bytes,
            intent,
        })
    }
}
