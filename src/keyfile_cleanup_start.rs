//! §5.100: 一対象の保持fd/認証/今回fsyncと開始追記。鍵unlink/解除なし。
#[path = "keyfile_cleanup_completion.rs"]
pub(super) mod completion;
#[path = "keyfile_cleanup_recovery.rs"]
pub(super) mod recovery;
use super::*;
use crate::cbor::{self, Value};
pub use completion::{
    KeyCleanupCompletion, KeyCleanupDisposition, PreparedAbsentCleanup, PreparedResidueRemoval,
};
use sha2::{Digest, Sha256};
use std::{
    fs::Metadata,
    time::{SystemTime, UNIX_EPOCH},
};

/// 期待するローカル現物の記録。構築/一致だけで保存・整理資格にはならない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyFileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub length: u64,
    pub nlink: u64,
    pub uid: u32,
    pub mode: u32,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}
impl KeyFileIdentity {
    pub fn from_metadata(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            length: m.len(),
            nlink: m.nlink(),
            uid: m.uid(),
            mode: m.mode(),
            mtime_seconds: m.mtime(),
            mtime_nanoseconds: m.mtime_nsec(),
            ctime_seconds: m.ctime(),
            ctime_nanoseconds: m.ctime_nsec(),
        }
    }
    fn value(self) -> Value {
        map(vec![
            ("dev", bytes(self.dev.to_be_bytes())),
            ("ino", bytes(self.ino.to_be_bytes())),
            ("length", bytes(self.length.to_be_bytes())),
            ("nlink", bytes(self.nlink.to_be_bytes())),
            ("uid", bytes(self.uid.to_be_bytes())),
            ("mode", bytes(self.mode.to_be_bytes())),
            ("mtime_seconds", Value::Int(self.mtime_seconds)),
            ("mtime_nanoseconds", Value::Int(self.mtime_nanoseconds)),
            ("ctime_seconds", Value::Int(self.ctime_seconds)),
            ("ctime_nanoseconds", Value::Int(self.ctime_nanoseconds)),
        ])
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDirectoryIdentity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
}
impl KeyDirectoryIdentity {
    pub fn from_metadata(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
        }
    }
    fn value(self) -> Value {
        map(vec![
            ("dev", bytes(self.dev.to_be_bytes())),
            ("ino", bytes(self.ino.to_be_bytes())),
            ("uid", bytes(self.uid.to_be_bytes())),
        ])
    }
}
/// 呼出し側の明示選択。観測値を資格へ格上げせず、現物/認証を独立に再検査する。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCleanupExpected {
    pub state: KeyStateDiagnostic,
    pub target: KeyFileIdentity,
    pub preserved_directory: KeyDirectoryIdentity,
    pub preserved: KeyFileIdentity,
    pub public_key: [u8; 32],
}
/// 追記前に控えられる期待値。存在/確定の証明ではなく、将来の明示復旧の選択値。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCleanupStart {
    pub before: KeyStateDiagnostic,
    pub after: KeyStateDiagnostic,
    pub operation_id: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CleanupStartStage {
    TargetFileSynced,
    PreservedFileSynced,
    TargetDirectoriesSynced,
    StateFilesSynced,
    StateDirectorySynced,
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
fn map(v: Vec<(&str, Value)>) -> Value {
    Value::Map(v.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn bytes<const N: usize>(v: [u8; N]) -> Value {
    Value::Bytes(v.to_vec())
}
fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn invalid<T>() -> Result<T> {
    Err(KeyFileError::RecoveryStateInvalid)
}

struct HeldFile {
    file: File,
    metadata: Metadata,
    bytes: Vec<u8>,
}
impl HeldFile {
    fn open(dir: &KeyDirectory, name: &str, limit: usize) -> Result<Self> {
        let bytes = dir.state_bytes(name, limit)?;
        let file = File::from(os(fs::openat(
            &dir.dir,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ))?);
        let metadata = io(file.metadata())?;
        let held = Self {
            file,
            metadata,
            bytes,
        };
        held.check(dir, name, true)?;
        Ok(held)
    }
    fn check(&self, dir: &KeyDirectory, name: &str, original_metadata: bool) -> Result<()> {
        dir.state_binding(name, &self.bytes, &self.file)?;
        if original_metadata
            && fingerprint(&io(self.file.metadata())?) != fingerprint(&self.metadata)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        io(self.file.sync_all())
    }
}

/// 両領域・5つの既存現物fdを保持する一回限りの準備。秘密/復号鍵を保持しない。
/// Dropは追記/削除しない。start成功も鍵の削除資格・通常変更許可ではない。
pub struct PreparedKeyCleanup<'a> {
    source: &'a mut KeyDirectory,
    backup: &'a mut KeyDirectory,
    target_name: String,
    preserved_name: String,
    expected: KeyCleanupExpected,
    source_identity: KeyDirectoryIdentity,
    target: HeldFile,
    preserved: HeldFile,
    marker: HeldFile,
    guard: HeldFile,
    state: HeldFile,
    new_bytes: Vec<u8>,
    receipt: KeyCleanupStart,
}
impl PreparedKeyCleanup<'_> {
    pub fn intent(&self) -> KeyCleanupStart {
        self.receipt
    }
    fn recheck(&self) -> Result<()> {
        self.source.secure()?;
        self.backup.secure()?;
        if KeyDirectoryIdentity::from_metadata(&io(self.source.dir.metadata())?)
            != self.source_identity
            || KeyDirectoryIdentity::from_metadata(&io(self.backup.dir.metadata())?)
                != self.expected.preserved_directory
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        self.target.check(self.source, &self.target_name, true)?;
        self.preserved
            .check(self.backup, &self.preserved_name, true)?;
        self.marker
            .check(self.source, recovery_hold::MARKER, true)?;
        self.guard.check(self.source, recovery_hold::GUARD, true)?;
        Ok(())
    }
    /// 完全prefixを保持した開始eventだけを追記。鍵/guard/markerは変更しない。
    pub fn start(self) -> Result<KeyStateDiagnostic> {
        self.start_with(&mut |_| Ok(()))
    }
    pub(super) fn start_with(
        self,
        hook: &mut impl FnMut(CleanupStartStage) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        self.recheck()?;
        self.state.check(self.source, initial_state::STATE, true)?;
        if self.source.reject_state_artifacts(true)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
        }
        hook(CleanupStartStage::BeforeCreate)?;
        self.recheck()?;
        self.state.check(self.source, initial_state::STATE, true)?;
        if self.source.reject_state_artifacts(true)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
        }
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&self.receipt.operation_id)
        );
        let mut durable = false;
        let appended = (|| -> Result<KeyStateDiagnostic> {
            let mut file = File::from(os(fs::openat(
                &self.source.dir,
                temp.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ))?);
            os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
            hook(CleanupStartStage::Created)?;
            io(file.write_all(&self.new_bytes))?;
            hook(CleanupStartStage::Written)?;
            io(file.sync_all())?;
            hook(CleanupStartStage::FileSynced)?;
            self.source.state_binding(&temp, &self.new_bytes, &file)?;
            io(self.source.dir.sync_all())?;
            hook(CleanupStartStage::Prepared)?;
            hook(CleanupStartStage::BeforeExchange)?;
            self.recheck()?;
            self.state.check(self.source, initial_state::STATE, true)?;
            self.source.state_binding(&temp, &self.new_bytes, &file)?;
            self.source.only_cleanup_update(&temp)?;
            os(fs::renameat_with(
                &self.source.dir,
                temp.as_str(),
                &self.source.dir,
                initial_state::STATE,
                RenameFlags::EXCHANGE,
            ))?;
            hook(CleanupStartStage::Exchanged)?;
            self.source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(self.source, &temp, false)?;
            io(self.source.dir.sync_all())?;
            self.recheck()?;
            self.source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(self.source, &temp, false)?;
            durable = true;
            hook(CleanupStartStage::StateSynced)?;
            hook(CleanupStartStage::BeforeCleanup)?;
            self.recheck()?;
            self.source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(self.source, &temp, false)?;
            self.source.only_cleanup_update(&temp)?;
            os(fs::unlinkat(
                &self.source.dir,
                temp.as_str(),
                AtFlags::empty(),
            ))?;
            hook(CleanupStartStage::OldSnapshotRemoved)?;
            io(self.source.dir.sync_all())?;
            hook(CleanupStartStage::CleanupSynced)?;
            self.recheck()?;
            self.source
                .state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            if self
                .source
                .key_state_history(&self.receipt.after.initial.area_id)?
                != self.receipt.after
            {
                return invalid();
            }
            Ok(self.receipt.after)
        })();
        appended.map_err(|_| {
            if durable {
                KeyFileError::RecoveryStateCleanupUncertain
            } else {
                KeyFileError::RecoveryStateUncertain
            }
        })
    }
}

impl KeyDirectory {
    // 初回専用APIの走査は変更しない。ここだけ今回の一時名を厳密に許す。
    fn only_cleanup_update(&self, temp: &str) -> Result<()> {
        self.secure()?;
        let before = fingerprint(&io(self.dir.metadata())?);
        let entries = io(std::fs::read_dir(format!(
            "/proc/self/fd/{}",
            self.dir.as_raw_fd()
        )))?;
        for (i, entry) in entries.enumerate() {
            if i >= SCAN_LIMIT {
                return Err(KeyFileError::ScanLimit);
            }
            let n = io(entry)?.file_name();
            let n = n.as_encoded_bytes();
            if n.starts_with(b".lngnb-key-state")
                && n != initial_state::STATE.as_bytes()
                && n != temp.as_bytes()
            {
                return invalid();
            }
        }
        self.secure()?;
        if fingerprint(&io(self.dir.metadata())?) != before {
            return Err(KeyFileError::RecoveryChanged);
        }
        Ok(())
    }
    /// 明示した一対象を認証・現物照合し、今回のfsyncを行って両領域を保持する。
    /// 返却後intentを控えてからstartを呼べる。準備だけでは履歴/鍵を変更しない。
    pub fn prepare_residue_cleanup<'a>(
        &'a mut self,
        residue: &str,
        passphrase: &str,
        backup: &'a mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
    ) -> Result<PreparedKeyCleanup<'a>> {
        let mut operation_id = [0; 32];
        super::super::random(&mut operation_id)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        self.prepare_residue_cleanup_with(
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
    pub(super) fn prepare_residue_cleanup_with<'a>(
        &'a mut self,
        residue: &str,
        passphrase: &str,
        backup: &'a mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        operation_id: [u8; 32],
        now: i64,
        hook: &mut impl FnMut(CleanupStartStage) -> Result<()>,
    ) -> Result<PreparedKeyCleanup<'a>> {
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(backup_name)?;
        self.secure()?;
        backup.secure()?;
        let source_identity = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        let backup_identity = KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?);
        if backup_identity != expected.preserved_directory
            || source_identity == backup_identity
            || expected.state.state != KeyHistoryState::Held
            || self.key_state_history(&expected.state.initial.area_id)? != expected.state
        {
            return invalid();
        }
        if self.reject_state_artifacts(true)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
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
        let marker = HeldFile::open(self, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        let guard = HeldFile::open(self, recovery_hold::GUARD, MAX_KEYFILE_BYTES)?;
        let state = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        if marker.bytes.len() != 105 || !marker.bytes.starts_with(b"lngnb:key-recovery:2\0") {
            return invalid();
        }
        let mut source_marker = marker.bytes[..73].to_vec();
        source_marker[19] = b'1';
        let mut expected_guard = b"lngnb:key-hold:1\0".to_vec();
        expected_guard.extend_from_slice(&expected.state.initial.area_id);
        if self.marker_area_id(&source_marker)? != expected.state.initial.area_id
            || marker.bytes[73..] != expected.state.initial.snapshot_hash
            || guard.bytes != expected_guard
            || state_history::decode_history(
                &state.bytes,
                &source_marker,
                expected.state.initial.area_id,
                expected.state.initial.snapshot_hash,
            )? != expected.state
        {
            return invalid();
        }
        let mut value =
            cbor::decode(&state.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let Value::Map(ref mut items) = value else {
            return invalid();
        };
        let Some((_, Value::Array(events))) = items.iter_mut().find(|(k, _)| k == "events") else {
            return invalid();
        };
        events.push(map(vec![
            ("sequence", Value::Int(expected.state.generation as i64 + 1)),
            ("operation_id", bytes(operation_id)),
            ("kind", text("residue_cleanup_started")),
            (
                "actor_uid",
                bytes(rustix::process::geteuid().as_raw().to_be_bytes()),
            ),
            ("recorded_unix_seconds", Value::Int(now)),
            ("rules", text("lngnb-key-operations-1")),
            (
                "target",
                map(vec![
                    ("name", text(residue)),
                    ("identity", expected.target.value()),
                    (
                        "ciphertext_sha256",
                        bytes(<[u8; 32]>::from(Sha256::digest(&target.bytes))),
                    ),
                    ("public_key", bytes(expected.public_key)),
                ]),
            ),
            (
                "preserved",
                map(vec![
                    ("directory", expected.preserved_directory.value()),
                    ("name", text(backup_name)),
                    ("identity", expected.preserved.value()),
                ]),
            ),
        ]));
        let new_bytes = cbor::encode(&value).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let after = state_history::decode_history(
            &new_bytes,
            &source_marker,
            expected.state.initial.area_id,
            expected.state.initial.snapshot_hash,
        )?;
        let prepared = PreparedKeyCleanup {
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
            state,
            new_bytes,
            receipt: KeyCleanupStart {
                before: expected.state,
                after,
                operation_id,
            },
        };
        prepared.recheck()?;
        prepared
            .state
            .check(prepared.source, initial_state::STATE, true)?;
        prepared.target.sync()?;
        hook(CleanupStartStage::TargetFileSynced)?;
        prepared.recheck()?;
        prepared.preserved.sync()?;
        hook(CleanupStartStage::PreservedFileSynced)?;
        prepared.recheck()?;
        io(prepared.backup.dir.sync_all())?;
        io(prepared.source.dir.sync_all())?;
        hook(CleanupStartStage::TargetDirectoriesSynced)?;
        prepared.recheck()?;
        prepared.marker.sync()?;
        prepared.guard.sync()?;
        prepared.state.sync()?;
        hook(CleanupStartStage::StateFilesSynced)?;
        prepared.recheck()?;
        prepared
            .state
            .check(prepared.source, initial_state::STATE, true)?;
        io(prepared.source.dir.sync_all())?;
        hook(CleanupStartStage::StateDirectorySynced)?;
        prepared.recheck()?;
        prepared
            .state
            .check(prepared.source, initial_state::STATE, true)?;
        prepared.source.reject_state_artifacts(true)?;
        Ok(prepared)
    }
}
