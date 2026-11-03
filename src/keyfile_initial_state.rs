//! §5.97: 初回Held一件だけ。追記・通常変更許可・中断の自動復旧は提供しない。
use super::*;
use crate::cbor::{self, Value};
use sha2::{Digest, Sha256};

pub(super) const STATE: &str = ".lngnb-key-state";
const STATE_PREFIX: &[u8] = b".lngnb-key-state";
pub(super) const STATE_LIMIT: usize = 1_048_576;
const V2_MAGIC: &[u8] = b"lngnb:key-recovery:2\0";

/// 現在検査した初回Heldの情報。公開/変更再開・過去の保存確定の資格ではない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInitialState {
    pub area_id: [u8; 32],
    pub operation_id: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateStage {
    StateCreated,
    StateWritten,
    StateFileSynced,
    StatePrepared,
    MarkerCreated,
    MarkerWritten,
    MarkerFileSynced,
    MarkerPrepared,
    BeforeExchange,
    MarkerExchanged,
    MarkerSynced,
    StateInstalled,
    StateSynced,
    BeforeCleanup,
    OldMarkerRemoved,
    CleanupSynced,
}

fn invalid<T>() -> Result<T> {
    Err(KeyFileError::RecoveryStateInvalid)
}
fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn initial_value(source: &[u8], area_id: [u8; 32], operation_id: [u8; 32]) -> Value {
    map(vec![
        ("format", Value::Text("lngnb-key-state-1".into())),
        ("area_id", Value::Bytes(area_id.to_vec())),
        ("source_marker", Value::Bytes(source.to_vec())),
        ("events", Value::Array(vec![map(vec![
            ("sequence", Value::Int(1)),
            ("operation_id", Value::Bytes(operation_id.to_vec())),
            ("kind", Value::Text("initial_hold_confirmed".into())),
        ])])),
    ])
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    if let Value::Map(m) = v {
        if let Some((_, v)) = m.iter().find(|(k, _)| k == name) {
            return Ok(v);
        }
    }
    invalid()
}
pub(super) fn decode_initial(bytes: &[u8], source: &[u8], area_id: [u8; 32]) -> Result<KeyInitialState> {
    if bytes.len() > STATE_LIMIT || source.len() != 73
        || !source.starts_with(b"lngnb:key-recovery:1\0") || source[21..53] != area_id {
        return invalid();
    }
    let value = cbor::decode(bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    let Value::Array(events) = field(&value, "events")? else { return invalid() };
    // profile上限1024より狭く、実装済みの初回kind一件だけを受理する。
    if events.len() != 1 {
        return invalid();
    }
    let Value::Bytes(id) = field(&events[0], "operation_id")? else { return invalid() };
    let operation_id: [u8; 32] = id.as_slice().try_into().map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    let expected = cbor::encode(&initial_value(source, area_id, operation_id))
        .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    if bytes != expected {
        return invalid();
    }
    Ok(KeyInitialState {
        area_id,
        operation_id,
        snapshot_hash: Sha256::digest(bytes).into(),
        generation: 1,
    })
}

impl KeyDirectory {
    /// 初期専用の導入/復旧に履歴やその一時名を混ぜない。部分一覧を成功にしない。
    pub(super) fn reject_state_artifacts(&self, allow_state: bool) -> Result<()> {
        self.secure()?;
        let before = fingerprint(&io(self.dir.metadata())?);
        let entries = io(std::fs::read_dir(format!("/proc/self/fd/{}", self.dir.as_raw_fd())))?;
        for (i, entry) in entries.enumerate() {
            if i >= SCAN_LIMIT { return Err(KeyFileError::ScanLimit); }
            let name = io(entry)?.file_name();
            let bytes = name.as_encoded_bytes();
            if bytes.starts_with(STATE_PREFIX) && !(allow_state && bytes == STATE.as_bytes()) {
                return invalid();
            }
        }
        self.secure()?;
        if before != fingerprint(&io(self.dir.metadata())?) {
            return Err(KeyFileError::RecoveryChanged);
        }
        Ok(())
    }

    // 鍵の4096 byte上限は変えず、この管理snapshot専用の上限付き読取りに分ける。
    fn state_bytes(&self, n: &str, limit: usize) -> Result<Vec<u8>> {
        self.secure()?;
        let fd = fs::openat(&self.dir, n, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| if e == rustix::io::Errno::NOENT { KeyFileError::Missing } else { KeyFileError::UnsafePath })?;
        let mut file = File::from(fd);
        let before = io(file.metadata())?;
        private_file(&before, rustix::process::geteuid().as_raw())?;
        if before.len() > limit as u64 { return invalid(); }
        let mut bytes = Vec::new();
        io((&mut file).take(limit as u64 + 1).read_to_end(&mut bytes))?;
        let after = io(file.metadata())?;
        if bytes.len() > limit || before.len() != bytes.len() as u64
            || fingerprint(&before) != fingerprint(&after) {
            return invalid();
        }
        Ok(bytes)
    }

    fn state_binding(&self, n: &str, bytes: &[u8], file: &File) -> Result<()> {
        let before = io(file.metadata())?;
        private_file(&before, rustix::process::geteuid().as_raw())?;
        let path = os(fs::statat(&self.dir, n, AtFlags::SYMLINK_NOFOLLOW))?;
        if path.st_dev != before.dev() || path.st_ino != before.ino()
            || self.state_bytes(n, bytes.len())? != bytes
            || fingerprint(&io(file.metadata())?) != fingerprint(&before) {
            return Err(KeyFileError::RecoveryChanged);
        }
        Ok(())
    }

    /// marker v2と固定stateの初回Heldだけを診断。欠損/一時名を補完しない。
    pub fn initial_key_state(&mut self, expected_area_id: &[u8; 32]) -> Result<KeyInitialState> {
        self.reject_state_artifacts(true)?;
        let marker = self.read(recovery_hold::MARKER)?;
        if marker.len() != 105 || !marker.starts_with(V2_MAGIC) { return invalid(); }
        let mut source = marker[..73].to_vec();
        source[19] = b'1';
        let area_id = self.marker_area_id(&source)?;
        if &area_id != expected_area_id { return invalid(); }
        let guard = self.read(recovery_hold::GUARD)?;
        let mut expected_guard = b"lngnb:key-hold:1\0".to_vec();
        expected_guard.extend_from_slice(&area_id);
        if guard != expected_guard { return invalid(); }
        let bytes = self.state_bytes(STATE, STATE_LIMIT)?;
        let result = decode_initial(&bytes, &source, area_id)?;
        if marker[73..] != result.snapshot_hash { return invalid(); }
        if self.read(recovery_hold::MARKER)? != marker || self.read(recovery_hold::GUARD)? != guard
            || self.state_bytes(STATE, STATE_LIMIT)? != bytes {
            return Err(KeyFileError::RecoveryChanged);
        }
        self.reject_state_artifacts(true)?;
        Ok(result)
    }

    /// 完全v1/guardから履歴付き初回Heldへ明示導入。鍵・guardを変更しない。
    pub fn initialize_key_state(&mut self, expected_area_id: &[u8; 32]) -> Result<KeyInitialState> {
        let mut operation_id = [0; 32];
        super::super::random(&mut operation_id)?;
        self.initialize_key_state_with(expected_area_id, operation_id, &mut |_| Ok(()))
    }

    fn prepare_state_file(
        &self, n: &str, bytes: &[u8], stages: [StateStage; 4],
        hook: &mut impl FnMut(StateStage) -> Result<()>,
    ) -> Result<File> {
        let fd = os(fs::openat(&self.dir, n, OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR))?;
        let mut file = File::from(fd);
        os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
        hook(stages[0])?;
        io(file.write_all(bytes))?;
        hook(stages[1])?;
        io(file.sync_all())?;
        hook(stages[2])?;
        self.state_binding(n, bytes, &file)?;
        io(self.dir.sync_all())?;
        hook(stages[3])?;
        self.state_binding(n, bytes, &file)?;
        Ok(file)
    }

    pub(super) fn initialize_key_state_with(
        &mut self, expected_area_id: &[u8; 32], operation_id: [u8; 32],
        hook: &mut impl FnMut(StateStage) -> Result<()>,
    ) -> Result<KeyInitialState> {
        self.reject_state_artifacts(false)?;
        let source = self.read(recovery_hold::MARKER)?;
        let area_id = self.marker_area_id(&source)?;
        if &area_id != expected_area_id { return invalid(); }
        let mut guard = b"lngnb:key-hold:1\0".to_vec();
        guard.extend_from_slice(&area_id);
        if self.read(recovery_hold::GUARD)? != guard { return invalid(); }
        let (old_marker, old_meta) = self.checked_hold_handle(recovery_hold::MARKER, &source)?;
        let (guard_file, guard_meta) = self.checked_hold_handle(recovery_hold::GUARD, &guard)?;
        // 準備名生成前に既存の初期停止を今回fsyncする。失敗しても作り直さない。
        io(old_marker.sync_all()).map_err(|_| KeyFileError::RecoveryStateUncertain)?;
        io(guard_file.sync_all()).map_err(|_| KeyFileError::RecoveryStateUncertain)?;
        io(self.dir.sync_all()).map_err(|_| KeyFileError::RecoveryStateUncertain)?;
        let bytes = cbor::encode(&initial_value(&source, area_id, operation_id)).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let result = decode_initial(&bytes, &source, area_id)?;
        let mut marker = V2_MAGIC.to_vec();
        marker.extend_from_slice(&source[21..]);
        marker.extend_from_slice(&result.snapshot_hash);
        let id = data_encoding::HEXLOWER.encode(&operation_id);
        let state_temp = format!(".lngnb-key-state-snapshot-{id}");
        let marker_temp = format!(".lngnb-key-state-marker-{id}");
        let mut durable = false;
        let installed = (|| -> Result<KeyInitialState> {
            let state_file = self.prepare_state_file(&state_temp, &bytes, [StateStage::StateCreated, StateStage::StateWritten, StateStage::StateFileSynced, StateStage::StatePrepared], hook)?;
            let new_marker = self.prepare_state_file(&marker_temp, &marker, [StateStage::MarkerCreated, StateStage::MarkerWritten, StateStage::MarkerFileSynced, StateStage::MarkerPrepared], hook)?;
            hook(StateStage::BeforeExchange)?;
            self.recheck_hold_handle(recovery_hold::MARKER, &source, &old_marker, &old_meta)?;
            self.recheck_hold_handle(recovery_hold::GUARD, &guard, &guard_file, &guard_meta)?;
            self.state_binding(&state_temp, &bytes, &state_file)?;
            self.state_binding(&marker_temp, &marker, &new_marker)?;
            os(fs::renameat_with(&self.dir, &marker_temp, &self.dir, recovery_hold::MARKER, RenameFlags::EXCHANGE))?;
            hook(StateStage::MarkerExchanged)?;
            self.state_binding(recovery_hold::MARKER, &marker, &new_marker)?;
            self.state_binding(&marker_temp, &source, &old_marker)?;
            io(self.dir.sync_all())?;
            hook(StateStage::MarkerSynced)?;
            self.state_binding(recovery_hold::MARKER, &marker, &new_marker)?;
            self.state_binding(&state_temp, &bytes, &state_file)?;
            os(fs::renameat_with(&self.dir, &state_temp, &self.dir, STATE, RenameFlags::NOREPLACE))?;
            hook(StateStage::StateInstalled)?;
            self.state_binding(STATE, &bytes, &state_file)?;
            io(self.dir.sync_all())?;
            self.state_binding(recovery_hold::MARKER, &marker, &new_marker)?;
            self.state_binding(STATE, &bytes, &state_file)?;
            self.recheck_hold_handle(recovery_hold::GUARD, &guard, &guard_file, &guard_meta)?;
            durable = true;
            hook(StateStage::StateSynced)?;
            hook(StateStage::BeforeCleanup)?;
            self.state_binding(recovery_hold::MARKER, &marker, &new_marker)?;
            self.state_binding(STATE, &bytes, &state_file)?;
            self.recheck_hold_handle(recovery_hold::GUARD, &guard, &guard_file, &guard_meta)?;
            self.state_binding(&marker_temp, &source, &old_marker)?;
            os(fs::unlinkat(&self.dir, &marker_temp, AtFlags::empty()))?;
            hook(StateStage::OldMarkerRemoved)?;
            io(self.dir.sync_all())?;
            hook(StateStage::CleanupSynced)?;
            self.state_binding(recovery_hold::MARKER, &marker, &new_marker)?;
            self.state_binding(STATE, &bytes, &state_file)?;
            self.recheck_hold_handle(recovery_hold::GUARD, &guard, &guard_file, &guard_meta)?;
            self.reject_state_artifacts(true)?;
            Ok(result)
        })();
        installed.map_err(|_| if durable { KeyFileError::RecoveryStateCleanupUncertain } else { KeyFileError::RecoveryStateUncertain })
    }
}
