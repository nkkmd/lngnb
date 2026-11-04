//! §5.108: 全保全を保持/認証/今回fsyncし、再開意思一件だけを記録。guard解除なし。
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyResumeExpected {
    pub state: KeyStateDiagnostic,
    pub current: KeyFileIdentity,
    pub ciphertext_sha256: [u8; 32],
    pub public_key: [u8; 32],
    pub preserved_directory: KeyDirectoryIdentity,
    pub preserved: KeyFileIdentity,
    pub guard: KeyFileIdentity,
}
/// 非秘密の照合値だけ。再開保存/認証/通常変更許可の証明ではない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyResumeIntent {
    pub before: KeyStateDiagnostic,
    pub after: KeyStateDiagnostic,
    pub operation_id: [u8; 32],
}
/// 完了eventへ対応する明示保全先。秘密を含むためDebug/Cloneを提供しない。
/// 入力は準備呼出しだけで使い、返却される資格や履歴にはパスフレーズを保持しない。
pub struct KeyResumePreservation<'p> {
    pub completed_operation_id: [u8; 32],
    pub directory_index: usize,
    pub name: &'p str,
    pub passphrase: &'p str,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum ResumeStage {
    CurrentSynced, PreservationSynced(usize), DirectoriesSynced, ControlsSynced, Qualified,
    BeforeCreate, Created, Written, FileSynced, Prepared, BeforeExchange, Exchanged,
    StateSynced, BeforeCleanup, OldSnapshotRemoved, CleanupSynced,
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    if let Value::Map(items) = v {
        if let Some((_, value)) = items.iter().find(|(k, _)| k == key) { return Ok(value); }
    }
    invalid()
}
fn array(v: &Value) -> Result<&[Value]> {
    if let Value::Array(items) = v { Ok(items) } else { invalid() }
}
fn string(v: &Value) -> Result<&str> {
    if let Value::Text(s) = v { Ok(s) } else { invalid() }
}
fn id(v: &Value) -> Result<[u8; 32]> {
    if let Value::Bytes(bytes) = v { bytes.as_slice().try_into().map_err(|_| KeyFileError::RecoveryStateInvalid) } else { invalid() }
}
fn encoded(v: &Value) -> Result<Vec<u8>> {
    cbor::encode(v).map_err(|_| KeyFileError::RecoveryStateInvalid)
}
fn equal(a: &Value, b: &Value) -> Result<bool> { Ok(encoded(a)? == encoded(b)?) }
fn absent(source: &KeyDirectory, n: &str) -> Result<()> {
    match fs::statat(&source.dir, n, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => Err(KeyFileError::RecoveryChanged),
        Err(_) => Err(KeyFileError::Io),
    }
}
// 初回/整理APIの走査は緩めない。今回の指定一時名だけを別途許す。
fn inventory(source: &KeyDirectory, temporary: Option<&str>) -> Result<usize> {
    source.secure()?;
    let before = fingerprint(&io(source.dir.metadata())?);
    let entries = io(std::fs::read_dir(format!("/proc/self/fd/{}", source.dir.as_raw_fd())))?;
    let mut count = 0;
    for (i, entry) in entries.enumerate() {
        if i >= SCAN_LIMIT { return Err(KeyFileError::ScanLimit); }
        count = i + 1;
        let n = io(entry)?.file_name(); let n = n.as_encoded_bytes();
        if n.starts_with(PREFIX.as_bytes())
            && ![recovery_hold::MARKER.as_bytes(), recovery_hold::GUARD.as_bytes(), initial_state::STATE.as_bytes()].contains(&n)
            && temporary.map(str::as_bytes) != Some(n) { return Err(KeyFileError::PendingRecovery); }
    }
    source.secure()?;
    if fingerprint(&io(source.dir.metadata())?) != before { return Err(KeyFileError::RecoveryChanged); }
    Ok(count)
}
struct Preservation {
    directory: usize,
    name: String,
    held: HeldFile,
}
/// 全flock/現物fdを保持する一回限りの準備。秘密/復号鍵は保持しない。
/// Dropは追記/解除しない。record成功もguardを残し通常変更を拒否する。
pub struct PreparedKeyResume<'a> {
    source: &'a mut KeyDirectory,
    backups: &'a mut [KeyDirectory],
    source_identity: KeyDirectoryIdentity,
    backup_identities: Vec<KeyDirectoryIdentity>,
    current_name: String,
    current: HeldFile,
    preservations: Vec<Preservation>,
    absent_names: Vec<String>,
    marker: HeldFile,
    guard: HeldFile,
    state: HeldFile,
    new_bytes: Vec<u8>,
    intent: KeyResumeIntent,
}
impl PreparedKeyResume<'_> {
    pub fn intent(&self) -> KeyResumeIntent { self.intent }
    fn check_held(&self) -> Result<()> {
        if self.check(None)? >= SCAN_LIMIT { return Err(KeyFileError::ScanLimit); }
        self.state.check(self.source, initial_state::STATE, true)
    }
    fn check_old_copy(&self, temporary: &str, after_exchange: &Metadata) -> Result<()> {
        self.state.check(self.source, temporary, false)?;
        if fingerprint(&io(self.state.file.metadata())?) != fingerprint(after_exchange) { return Err(KeyFileError::RecoveryChanged); }
        Ok(())
    }
    fn check(&self, temporary: Option<&str>) -> Result<usize> {
        self.source.secure()?;
        if KeyDirectoryIdentity::from_metadata(&io(self.source.dir.metadata())?) != self.source_identity { return Err(KeyFileError::RecoveryChanged); }
        for (directory, expected) in self.backups.iter().zip(&self.backup_identities) {
            directory.secure()?;
            if KeyDirectoryIdentity::from_metadata(&io(directory.dir.metadata())?) != *expected { return Err(KeyFileError::RecoveryChanged); }
        }
        self.current.check(self.source, &self.current_name, true)?;
        for proof in &self.preservations { proof.held.check(&self.backups[proof.directory], &proof.name, true)?; }
        self.marker.check(self.source, recovery_hold::MARKER, true)?;
        self.guard.check(self.source, recovery_hold::GUARD, true)?;
        for n in &self.absent_names { absent(self.source, n)?; }
        inventory(self.source, temporary)
    }
    /// 再開意思の一eventと全履歴だけを保存。guard/鍵/保全先を削除しない。
    pub fn record(self) -> Result<KeyStateDiagnostic> { self.record_with(&mut |_| Ok(())) }
    pub(in super::super) fn record_with(self, hook: &mut impl FnMut(ResumeStage) -> Result<()>) -> Result<KeyStateDiagnostic> {
        use ResumeStage as S;
        if self.check(None)? >= SCAN_LIMIT { return Err(KeyFileError::ScanLimit); }
        self.state.check(self.source, initial_state::STATE, true)?;
        hook(S::BeforeCreate)?;
        if self.check(None)? >= SCAN_LIMIT { return Err(KeyFileError::ScanLimit); }
        self.state.check(self.source, initial_state::STATE, true)?;
        let temp = format!(".lngnb-key-state-update-{}", data_encoding::HEXLOWER.encode(&self.intent.operation_id));
        let mut durable = false;
        let result = (|| -> Result<KeyStateDiagnostic> {
            let mut file = File::from(os(fs::openat(&self.source.dir, temp.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR))?);
            os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
            hook(S::Created)?; io(file.write_all(&self.new_bytes))?;
            hook(S::Written)?; io(file.sync_all())?;
            hook(S::FileSynced)?; self.source.state_binding(&temp, &self.new_bytes, &file)?;
            io(self.source.dir.sync_all())?; hook(S::Prepared)?; hook(S::BeforeExchange)?;
            self.check(Some(&temp))?; self.state.check(self.source, initial_state::STATE, true)?;
            self.source.state_binding(&temp, &self.new_bytes, &file)?;
            os(fs::renameat_with(&self.source.dir, temp.as_str(), &self.source.dir, initial_state::STATE, RenameFlags::EXCHANGE))?;
            hook(S::Exchanged)?;
            self.source.state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.state.check(self.source, &temp, false)?;
            let after_exchange = io(self.state.file.metadata())?;
            let mut moved = KeyFileIdentity::from_metadata(&after_exchange);
            let original = KeyFileIdentity::from_metadata(&self.state.metadata);
            moved.ctime_seconds = original.ctime_seconds;
            moved.ctime_nanoseconds = original.ctime_nanoseconds;
            if moved != original { return Err(KeyFileError::RecoveryChanged); }
            io(self.source.dir.sync_all())?;
            self.check(Some(&temp))?;
            self.source.state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.check_old_copy(&temp, &after_exchange)?;
            durable = true;
            hook(S::StateSynced)?; hook(S::BeforeCleanup)?;
            self.check(Some(&temp))?;
            self.source.state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            self.check_old_copy(&temp, &after_exchange)?;
            os(fs::unlinkat(&self.source.dir, temp.as_str(), AtFlags::empty()))?;
            hook(S::OldSnapshotRemoved)?;
            io(self.source.dir.sync_all())?; hook(S::CleanupSynced)?;
            self.check(None)?;
            self.source.state_binding(initial_state::STATE, &self.new_bytes, &file)?;
            if self.source.key_state_history(&self.intent.after.initial.area_id)? != self.intent.after { return invalid(); }
            Ok(self.intent.after)
        })();
        result.map_err(|_| if durable { KeyFileError::RecoveryStateCleanupUncertain } else { KeyFileError::RecoveryStateUncertain })
    }
}

impl KeyDirectory {
    /// backup sliceは異なる領域を一つずつ開いて渡す。同じ領域の複数保全fileはindexを共有する。
    /// 入力の全過去保全を認証し、今回のfile/directory fsyncを確認して保持する。
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_key_resume<'a>(&'a mut self, current_name: &str, passphrase: &str,
        backups: &'a mut [KeyDirectory], current_backup: usize, backup_name: &str,
        proofs: &[KeyResumePreservation<'_>], expected: &KeyResumeExpected) -> Result<PreparedKeyResume<'a>> {
        let mut operation = [0; 32]; super::super::super::random(&mut operation)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| KeyFileError::RecoveryStateInvalid)?.as_secs();
        let now = i64::try_from(now).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        self.prepare_key_resume_with(current_name, passphrase, backups, current_backup, backup_name, proofs, expected, operation, now, &mut |_| Ok(()))
    }
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn prepare_key_resume_with<'a>(&'a mut self, current_name: &str, passphrase: &str,
        backups: &'a mut [KeyDirectory], current_backup: usize, backup_name: &str,
        proofs: &[KeyResumePreservation<'_>], expected: &KeyResumeExpected,
        operation: [u8; 32], now: i64, hook: &mut impl FnMut(ResumeStage) -> Result<()>) -> Result<PreparedKeyResume<'a>> {
        use ResumeStage as S;
        name(current_name)?; name(backup_name)?;
        if backups.is_empty() || backups.len() > 512 || proofs.len() > 511 { return invalid(); }
        if expected.state.state != KeyHistoryState::Held || self.key_state_history(&expected.state.initial.area_id)? != expected.state { return invalid(); }
        if inventory(self, None)? >= SCAN_LIMIT { return Err(KeyFileError::ScanLimit); }
        let source_identity = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        let mut backup_identities = Vec::new();
        for dir in backups.iter() {
            dir.secure()?;
            let identity = KeyDirectoryIdentity::from_metadata(&io(dir.dir.metadata())?);
            if identity == source_identity || backup_identities.contains(&identity) { return invalid(); }
            backup_identities.push(identity);
        }
        if backup_identities.get(current_backup) != Some(&expected.preserved_directory) { return invalid(); }
        let marker = HeldFile::open(self, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        let guard = HeldFile::open(self, recovery_hold::GUARD, MAX_KEYFILE_BYTES)?;
        let state = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        if marker.bytes.len() != 105 || !marker.bytes.starts_with(b"lngnb:key-recovery:2\0") { return invalid(); }
        let mut source_marker = marker.bytes[..73].to_vec(); source_marker[19] = b'1';
        let mut guard_bytes = b"lngnb:key-hold:1\0".to_vec(); guard_bytes.extend(expected.state.initial.area_id);
        if self.marker_area_id(&source_marker)? != expected.state.initial.area_id
            || marker.bytes[73..] != expected.state.initial.snapshot_hash || guard.bytes != guard_bytes
            || KeyFileIdentity::from_metadata(&guard.metadata) != expected.guard
            || state_history::decode_history(&state.bytes, &source_marker, expected.state.initial.area_id, expected.state.initial.snapshot_hash)? != expected.state { return invalid(); }
        let mut value = cbor::decode(&state.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let events = array(field(&value, "events")?)?;
        let completed: Vec<_> = events.iter().filter(|v| field(v, "kind").and_then(string) == Ok("residue_cleanup_completed")).collect();
        if proofs.len() != completed.len() { return invalid(); }
        // 名前/全対応とdirectoryを認証より先に照合。未使用の領域も曖昧な入力として拒否。
        let mut used = vec![false; backups.len()]; used[current_backup] = true;
        let mut required = Vec::new(); let mut absent_names = Vec::new(); let mut references = Vec::new();
        for (proof, event) in proofs.iter().zip(completed) {
            name(proof.name)?;
            let complete_id = id(field(event, "operation_id")?)?;
            if complete_id != proof.completed_operation_id { return invalid(); }
            let started_id = id(field(event, "started_operation_id")?)?;
            let started = events.iter().find(|e| field(e, "operation_id").and_then(id) == Ok(started_id)).ok_or(KeyFileError::RecoveryStateInvalid)?;
            let target = field(started, "target")?; let preserved = field(started, "preserved")?;
            let directory = backup_identities.get(proof.directory_index).ok_or(KeyFileError::RecoveryStateInvalid)?;
            if proof.name != string(field(preserved, "name")?)? || !equal(&directory.value(), field(preserved, "directory")?)? { return invalid(); }
            used[proof.directory_index] = true;
            let target_name = string(field(target, "name")?)?; absent(self, target_name)?;
            absent_names.push(target_name.to_owned()); references.push(bytes(complete_id));
            required.push((proof, target, preserved));
        }
        if used.iter().any(|v| !v) { return invalid(); }
        let current = HeldFile::open(self, current_name, MAX_KEYFILE_BYTES)?;
        let current_preserved = HeldFile::open(&backups[current_backup], backup_name, MAX_KEYFILE_BYTES)?;
        if KeyFileIdentity::from_metadata(&current.metadata) != expected.current
            || KeyFileIdentity::from_metadata(&current_preserved.metadata) != expected.preserved
            || <[u8; 32]>::from(Sha256::digest(&current.bytes)) != expected.ciphertext_sha256 { return Err(KeyFileError::RecoveryChanged); }
        if current.bytes != current_preserved.bytes { return Err(KeyFileError::PreservationMismatch); }
        for bytes in [&current.bytes, &current_preserved.bytes] {
            if unlock(bytes, passphrase)?.public_key() != expected.public_key { return Err(KeyFileError::UnexpectedPublicKey); }
        }
        let mut preservations = vec![Preservation { directory: current_backup, name: backup_name.into(), held: current_preserved }];
        for (proof, target, preserved) in required {
            let held = HeldFile::open(&backups[proof.directory_index], proof.name, MAX_KEYFILE_BYTES)?;
            if !equal(&KeyFileIdentity::from_metadata(&held.metadata).value(), field(preserved, "identity")?)?
                || <[u8; 32]>::from(Sha256::digest(&held.bytes)) != id(field(target, "ciphertext_sha256")?)? { return Err(KeyFileError::RecoveryChanged); }
            if unlock(&held.bytes, proof.passphrase)?.public_key() != id(field(target, "public_key")?)? { return Err(KeyFileError::UnexpectedPublicKey); }
            preservations.push(Preservation { directory: proof.directory_index, name: proof.name.into(), held });
        }
        let event = map(vec![("sequence", Value::Int(expected.state.generation as i64 + 1)),
            ("operation_id", bytes(operation)), ("kind", text("key_changes_resumed")),
            ("actor_uid", bytes(rustix::process::geteuid().as_raw().to_be_bytes())),
            ("recorded_unix_seconds", Value::Int(now)), ("rules", text("lngnb-key-operations-1")),
            ("reason", text("reviewed_current_key_and_preservations")),
            ("current", map(vec![("name", text(current_name)), ("identity", expected.current.value()),
                ("ciphertext_sha256", bytes(expected.ciphertext_sha256)), ("public_key", bytes(expected.public_key))])),
            ("preserved", map(vec![("directory", expected.preserved_directory.value()), ("name", text(backup_name)), ("identity", expected.preserved.value())])),
            ("guard_identity", expected.guard.value()), ("cleanup_operations", Value::Array(references))]);
        let Value::Map(items) = &mut value else { return invalid(); };
        let Some((_, Value::Array(events))) = items.iter_mut().find(|(k, _)| k == "events") else { return invalid(); };
        events.push(event);
        let new_bytes = encoded(&value)?;
        let after = state_history::decode_history(&new_bytes, &source_marker, expected.state.initial.area_id, expected.state.initial.snapshot_hash)?;
        let prepared = PreparedKeyResume { source: self, backups, source_identity, backup_identities,
            current_name: current_name.into(), current, preservations, absent_names, marker, guard, state, new_bytes,
            intent: KeyResumeIntent { before: expected.state, after, operation_id: operation } };
        prepared.check_held()?;
        prepared.current.sync()?; hook(S::CurrentSynced)?; prepared.check_held()?;
        for (i, proof) in prepared.preservations.iter().enumerate() {
            proof.held.sync()?; hook(S::PreservationSynced(i))?; prepared.check_held()?;
        }
        for dir in prepared.backups.iter() { io(dir.dir.sync_all())?; }
        io(prepared.source.dir.sync_all())?; hook(S::DirectoriesSynced)?; prepared.check_held()?;
        prepared.marker.sync()?; prepared.guard.sync()?; prepared.state.sync()?;
        hook(S::ControlsSynced)?; prepared.check_held()?;
        prepared.state.check(prepared.source, initial_state::STATE, true)?;
        io(prepared.source.dir.sync_all())?; hook(S::Qualified)?; prepared.check_held()?;
        prepared.state.check(prepared.source, initial_state::STATE, true)?;
        Ok(prepared)
    }
}
