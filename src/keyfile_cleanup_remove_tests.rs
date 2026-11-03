//! 公開A14/隔離領域だけ。実EIO/電源断相当・完全消去や鍵失効は検証しない。
use super::*;
use super::super::super::cleanup_start::completion::{CompletionStage as C, removal::RemovalStage as R};
use std::os::unix::fs::FileExt;

struct Fixture {
    a: Area,
    b: Area,
    source: Option<KeyDirectory>,
    backup: Option<KeyDirectory>,
    expected: KeyCleanupExpected,
    key: Vec<u8>,
    pass: String,
    before: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let (a, b, mut source, mut backup, mut expected, key, pass) = setup();
        expected.state = prepare(&mut source, &mut backup, &pass, &expected).unwrap().start().unwrap();
        let before = snapshot(&a);
        Self { a, b, source: Some(source), backup: Some(backup), expected, key, pass, before }
    }
    fn prepare(&mut self) -> Result<PreparedResidueRemoval<'_>> {
        self.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, &self.pass,
            self.backup.as_mut().unwrap(), "saved", &self.expected)
    }
    fn reopen(&mut self) {
        self.source.take(); self.backup.take();
        self.source = Some(KeyDirectory::open(&self.a.0).unwrap());
        self.backup = Some(KeyDirectory::open(&self.b.0).unwrap());
    }
    fn retained(&mut self, present: bool) {
        assert_eq!(stdfs::symlink_metadata(self.a.0.join(RESIDUE)).is_ok(), present);
        assert_eq!(stdfs::read(self.a.0.join("publisher")).unwrap(), self.key);
        assert_eq!(stdfs::read(self.a.0.join(".lngnb-key-other")).unwrap(), b"unknown preserved residue");
        assert_eq!(stdfs::read(self.b.0.join("saved")).unwrap(), self.key);
        assert!(self.a.0.join(recovery_hold::MARKER).exists());
        assert!(self.a.0.join(recovery_hold::GUARD).exists());
        e(self.source.as_mut().unwrap().create("later", &self.pass), KeyFileError::PendingRecovery);
        assert!(self.source.as_mut().unwrap().recover_initial_key_state(&self.expected.state.initial).is_err());
    }
    fn absent_completion(&mut self) -> KeyCleanupCompletion {
        let p = self.source.as_mut().unwrap().prepare_absent_residue_completion_with(RESIDUE, &self.pass,
            self.backup.as_mut().unwrap(), "saved", &self.expected, [0x77; 32], 43, &mut |_| Ok(())).unwrap();
        let intent = p.intent(); p.record().unwrap(); intent
    }
    fn recover(&mut self, intent: &KeyCleanupCompletion) -> Result<KeyStateDiagnostic> {
        self.source.as_mut().unwrap().recover_residue_cleanup_completion(RESIDUE, &self.pass,
            self.backup.as_mut().unwrap(), "saved", &self.expected, intent)
    }
}
fn identify() -> Result<([u8; 32], i64)> { Ok(([0x77; 32], 43)) }
fn update() -> String { format!(".lngnb-key-state-update-{}", data_encoding::HEXLOWER.encode(&[0x77; 32])) }
fn independent(f: &Fixture, intent: &KeyCleanupCompletion) {
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    let input = serde_json::json!({"source": f.a.0, "backup": f.b.0, "target": RESIDUE, "preserved": "saved",
        "old": hex(&f.before), "new": hex(&snapshot(&f.a)), "operation": hex(&intent.operation_id),
        "started": hex(&intent.started_operation_id), "hash": hex(&intent.after.snapshot_hash),
        "disposition": if intent.disposition == KeyCleanupDisposition::RemovedPresent { "removed_present" } else { "confirmed_absent_on_recovery" }});
    let mut child = Command::new(std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("reference checker required"))
        .args(["tests/key_history_reference.py", "--completed"]).stdin(Stdio::piped()).stdout(Stdio::piped())
        .stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    assert!(child.wait_with_output().unwrap().status.success(), "independent normal completion check failed (details suppressed)");
}

#[test]
fn residue_removal_drop_then_success_retains_fd_prefix_and_permanent_hold() {
    let mut f = Fixture::new();
    let marker = stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap();
    let guard = stdfs::read(f.a.0.join(recovery_hold::GUARD)).unwrap();
    let source_path = f.a.0.clone(); let backup_path = f.b.0.clone();
    let prepared = f.prepare().unwrap();
    e(KeyDirectory::open(&source_path), KeyFileError::Busy);
    e(KeyDirectory::open(&backup_path), KeyFileError::Busy);
    drop(prepared);
    assert_eq!(stdfs::read(f.a.0.join(RESIDUE)).unwrap(), f.key);
    assert_eq!(snapshot(&f.a), f.before);
    let witness = File::open(f.a.0.join(RESIDUE)).unwrap();
    let synced = std::cell::Cell::new(false);
    let p = f.prepare().unwrap().remove_with(&mut || {
        assert!(synced.get()); assert_eq!(witness.metadata().unwrap().nlink(), 0); identify()
    }, &mut |s| { if s == R::RemovalSynced { synced.set(true); } Ok(()) }).unwrap();
    let intent = p.intent();
    assert_eq!(intent.disposition, KeyCleanupDisposition::RemovedPresent);
    assert_eq!(intent.before.state, KeyHistoryState::Active { started_operation_id: [0x73; 32] });
    assert_eq!(p.record().unwrap(), intent.after);
    assert_eq!(witness.metadata().unwrap().nlink(), 0);
    independent(&f, &intent);
    assert_eq!(stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap(), marker);
    assert_eq!(stdfs::read(f.a.0.join(recovery_hold::GUARD)).unwrap(), guard);
    f.reopen(); f.retained(false);
    assert!(f.source.as_mut().unwrap().load("publisher", &f.pass).is_ok());
    stdfs::remove_file(f.a.0.join(".lngnb-key-other")).unwrap();
    e(f.source.as_mut().unwrap().create("after-all-residues", &f.pass), KeyFileError::PendingRecovery);
    assert_eq!(f.source.as_mut().unwrap().key_state_history(&f.expected.state.initial.area_id).unwrap(), intent.after);
    let mut g = Fixture::new();
    let unrecorded = g.prepare().unwrap().remove().unwrap();
    assert_eq!(unrecorded.intent().disposition, KeyCleanupDisposition::RemovedPresent);
    drop(unrecorded);
    assert_eq!(snapshot(&g.a), g.before);
    g.reopen();
    let observed = g.absent_completion();
    assert_eq!(observed.disposition, KeyCleanupDisposition::ConfirmedAbsentOnRecovery);
    independent(&g, &observed); g.retained(false);
}

#[test]
fn residue_removal_all_preparation_failures_and_before_unlink_failure_preserve_target() {
    let mut f = Fixture::new();
    for stage in [R::TargetSynced, R::PreservedSynced, R::DirectoriesSynced, R::ControlsSynced, R::StateSynced, R::Qualified] {
        assert!(f.source.as_mut().unwrap().prepare_residue_removal_with(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &f.expected,
            &mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }).is_err());
        f.retained(true); assert_eq!(snapshot(&f.a), f.before);
    }
    let calls = std::cell::Cell::new(0);
    e(f.prepare().unwrap().remove_with(&mut || { calls.set(calls.get()+1); identify() },
        &mut |s| if s == R::BeforeUnlink { Err(KeyFileError::Io) } else { Ok(()) }), KeyFileError::Io);
    assert_eq!(calls.get(), 0); f.retained(true);
    let area = &f.a;
    let p = f.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, &f.pass,
        f.backup.as_mut().unwrap(), "saved", &f.expected).unwrap();
    assert!(p.remove_with(&mut identify, &mut |s| { if s == R::BeforeUnlink {
        area.put(".lngnb-key-state-update-late", b"unknown pending candidate");
    } Ok(()) }).is_err());
    assert!(f.a.0.join(RESIDUE).exists());
}

#[test]
fn residue_removal_rejects_wrong_selection_authentication_and_unsafe_current_target() {
    let mut f = Fixture::new();
    for n in 0..8 {
        let mut expected = f.expected;
        match n { 0 => expected.state.generation += 1, 1 => expected.state.snapshot_hash[0] ^= 1,
            2 => expected.state.initial.area_id[0] ^= 1, 3 => expected.target.ino ^= 1,
            4 => expected.preserved.ino ^= 1, 5 => expected.preserved_directory.ino ^= 1,
            6 => expected.public_key[0] ^= 1, _ => expected.state.state = KeyHistoryState::Held }
        assert!(f.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &expected).is_err());
        assert_eq!(stdfs::read(f.a.0.join(RESIDUE)).unwrap(), f.key);
    }
    assert!(f.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, "wrong public test password",
        f.backup.as_mut().unwrap(), "saved", &f.expected).is_err());
    for (r,p) in [("publisher", "saved"), (RESIDUE, "../saved"), (RESIDUE, ".lngnb-key-other")] {
        assert!(f.source.as_mut().unwrap().prepare_residue_removal(r, &f.pass,
            f.backup.as_mut().unwrap(), p, &f.expected).is_err());
    }
    f.a.put(".lngnb-key-state-update-other", b"unresolved candidate");
    assert!(f.prepare().is_err());
    stdfs::remove_file(f.a.0.join(".lngnb-key-state-update-other")).unwrap();
    stdfs::hard_link(f.a.0.join(RESIDUE), f.a.0.join("hardlink")).unwrap();
    assert!(f.prepare().is_err()); stdfs::remove_file(f.a.0.join("hardlink")).unwrap();
    // 元identityがctime変化を検出するので、変更後を開始記録へ後付けしない。
    assert!(f.prepare().is_err());
    f.retained(true);
    let mut g = Fixture::new();
    let unlocked = unlock(&g.key, &g.pass).unwrap();
    let other = super::super::super::super::encrypt_with(&unlocked, &g.pass, [0x42;16], [0x24;12]).unwrap();
    stdfs::write(g.b.0.join("saved"), &other).unwrap();
    g.expected.preserved = KeyFileIdentity::from_metadata(&stdfs::metadata(g.b.0.join("saved")).unwrap());
    assert!(g.prepare().is_err()); assert_eq!(stdfs::read(g.a.0.join(RESIDUE)).unwrap(), g.key);
}

#[test]
fn residue_removal_after_unlink_failures_require_explicit_absent_completion() {
    for stage in [R::Unlinked, R::RemovalSynced, R::CompletionIdentified, R::CompletionPrepared] {
        let mut f = Fixture::new();
        e(f.prepare().unwrap().remove_with(&mut identify, &mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }),
            if stage == R::Unlinked { KeyFileError::ResidueRemovalUncertain } else { KeyFileError::ResidueCompletionRequired });
        assert_eq!(snapshot(&f.a), f.before); assert!(!f.a.0.join(update()).exists());
        f.reopen(); f.retained(false);
        assert!(f.prepare().is_err());
        let intent = f.absent_completion();
        assert_eq!(intent.disposition, KeyCleanupDisposition::ConfirmedAbsentOnRecovery);
        independent(&f, &intent); f.retained(false);
    }
    for n in 0..3 {
        let mut f = Fixture::new();
        e(f.prepare().unwrap().remove_with(&mut || match n {
            0 => Err(KeyFileError::Io), 1 => Ok(([0x73;32],43)), _ => Ok(([0x77;32],-1))
        }, &mut |_| Ok(())), KeyFileError::ResidueCompletionRequired);
        assert_eq!(snapshot(&f.a), f.before); f.retained(false);
        f.reopen(); f.absent_completion(); f.retained(false);
    }
}

#[test]
fn residue_removal_complete_append_interruption_and_partial_candidate_are_not_reclassified() {
    for stage in [C::Created, C::Prepared, C::Exchanged, C::OldSnapshotRemoved] {
        let mut f = Fixture::new();
        let p = f.prepare().unwrap().remove_with(&mut identify, &mut |_| Ok(())).unwrap();
        let intent = p.intent();
        assert!(p.record_with(&mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }).is_err());
        f.reopen(); f.retained(false);
        if stage == C::Created {
            assert!(f.recover(&intent).is_err());
            assert!(f.source.as_mut().unwrap().prepare_absent_residue_completion(RESIDUE, &f.pass,
                f.backup.as_mut().unwrap(), "saved", &f.expected).is_err());
            assert!(stdfs::read(f.a.0.join(update())).unwrap().is_empty());
        } else {
            assert_eq!(f.recover(&intent).unwrap(), intent.after);
            assert_eq!(intent.disposition, KeyCleanupDisposition::RemovedPresent);
            independent(&f, &intent);
        }
        f.retained(false);
    }
}

#[test]
fn residue_removal_detects_late_inodes_reappearance_and_changes_to_unlinked_fd() {
    for n in 0..5 {
        let mut f = Fixture::new();
        let path = match n { 0 => f.a.0.join(RESIDUE), 1 => f.b.0.join("saved"),
            2 => f.a.0.join(recovery_hold::MARKER), 3 => f.a.0.join(recovery_hold::GUARD), _ => f.a.0.join(initial_state::STATE) };
        let area = if n == 1 { &f.b } else { &f.a };
        let prepared = f.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &f.expected).unwrap();
        assert!(prepared.remove_with(&mut identify, &mut |s| {
            if s == R::BeforeUnlink {
                let bytes = stdfs::read(&path).unwrap(); stdfs::rename(&path, area.0.join("retained-original")).unwrap();
                area.put(path.file_name().unwrap().to_str().unwrap(), &bytes);
            }
            Ok(())
        }).is_err());
        assert_eq!(stdfs::read(f.a.0.join(RESIDUE)).unwrap(), f.key);
        assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), f.key);
    }
    let mut f = Fixture::new();
    let area = &f.a;
    let prepared = f.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, &f.pass,
        f.backup.as_mut().unwrap(), "saved", &f.expected).unwrap();
    assert!(prepared.remove_with(&mut identify, &mut |s| {
        if s == R::Unlinked { area.put(RESIDUE, b"reappeared independent file"); } Ok(())
    }).is_err());
    assert_eq!(stdfs::read(f.a.0.join(RESIDUE)).unwrap(), b"reappeared independent file");
    assert!(f.prepare().is_err());
    for stage in [C::BeforeCreate, C::BeforeExchange, C::BeforeCleanup] {
        let mut f = Fixture::new();
        let witness = stdfs::OpenOptions::new().read(true).write(true).open(f.a.0.join(RESIDUE)).unwrap();
        let p = f.prepare().unwrap().remove_with(&mut identify, &mut |_| Ok(())).unwrap();
        assert_eq!(witness.metadata().unwrap().nlink(), 0);
        assert!(p.record_with(&mut |s| {
            if s == stage {
                if stage == C::BeforeExchange { witness.set_permissions(stdfs::Permissions::from_mode(0o400)).unwrap(); }
                else { witness.write_all_at(b"changed",0).unwrap(); }
            } Ok(())
        }).is_err());
        f.retained(false);
    }
}

#[test]
fn residue_removal_capacity_and_held_directory_renames_leave_replacements_untouched() {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = Fixture::new();
    let count = stdfs::read_dir(&f.a.0).unwrap().count();
    for n in count..SCAN_LIMIT { stdfs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(f.a.0.join(format!("entry-{n}"))).unwrap(); }
    e(f.prepare(), KeyFileError::ScanLimit);
    assert!(f.a.0.join(RESIDUE).exists());
    stdfs::remove_file(f.a.0.join(format!("entry-{}",SCAN_LIMIT-1))).unwrap();
    let area = &f.a;
    let p = f.source.as_mut().unwrap().prepare_residue_removal(RESIDUE, &f.pass,
        f.backup.as_mut().unwrap(), "saved", &f.expected).unwrap();
    e(p.remove_with(&mut identify, &mut |s| { if s == R::BeforeUnlink { area.put("capacity-race",b"one entry"); } Ok(()) }), KeyFileError::ScanLimit);
    assert!(f.a.0.join(RESIDUE).exists()); stdfs::remove_file(f.a.0.join("capacity-race")).unwrap();
    let moved_a = f.a.0.with_extension("moved"); let moved_b = f.b.0.with_extension("moved");
    let p = f.prepare().unwrap();
    stdfs::rename(&source_path(&moved_a), &moved_a).unwrap();
    stdfs::rename(&source_path(&moved_b), &moved_b).unwrap();
    let source_original = source_path(&moved_a); let backup_original = source_path(&moved_b);
    stdfs::DirBuilder::new().mode(0o700).create(&source_original).unwrap();
    stdfs::DirBuilder::new().mode(0o700).create(&backup_original).unwrap();
    stdfs::write(source_original.join("unrelated"), b"replacement source").unwrap();
    stdfs::write(backup_original.join("unrelated"), b"replacement backup").unwrap();
    p.remove_with(&mut identify, &mut |_| Ok(())).unwrap().record().unwrap();
    assert!(!moved_a.join(RESIDUE).exists());
    assert_eq!(stdfs::read(moved_a.join("publisher")).unwrap(), f.key);
    assert_eq!(stdfs::read(moved_b.join("saved")).unwrap(), f.key);
    assert_eq!(stdfs::read(source_original.join("unrelated")).unwrap(), b"replacement source");
    assert_eq!(stdfs::read(backup_original.join("unrelated")).unwrap(), b"replacement backup");
    drop(f); stdfs::remove_dir_all(moved_a).unwrap(); stdfs::remove_dir_all(moved_b).unwrap();
}
fn source_path(moved: &Path) -> PathBuf { moved.with_extension("") }

#[test]
fn residue_removal_maximum_active_history_reaches_held_without_reset() {
    let mut f = Fixture::new();
    let mut value = cbor::decode(&f.before).unwrap();
    let Value::Map(m) = &mut value else { panic!() };
    let Value::Array(events) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    let start = events[1].clone();
    let done = Value::Map(vec![ ("sequence".into(), Value::Int(3)), ("operation_id".into(), Value::Bytes(event_id(3).to_vec())),
        ("kind".into(),Value::Text("residue_cleanup_completed".into())),
        ("actor_uid".into(), Value::Bytes(rustix::process::geteuid().as_raw().to_be_bytes().to_vec())),
        ("recorded_unix_seconds".into(), Value::Int(43)), ("rules".into(),Value::Text("lngnb-key-operations-1".into())),
        ("started_operation_id".into(),Value::Bytes(event_id(2).to_vec())), ("disposition".into(),Value::Text("removed_present".into())) ]);
    events.truncate(1);
    // 過去の完了は合成fixture。今回の最後の一対象は製品APIで実際に整理する。
    for n in 2..=1022 {
        let mut event = if n%2==0 { start.clone() } else { done.clone() };
        set_field(&mut event,"sequence",Value::Int(n as i64)); set_field(&mut event,"operation_id",Value::Bytes(event_id(n).to_vec()));
        if n%2==1 { set_field(&mut event,"started_operation_id",Value::Bytes(event_id(n-1).to_vec())); }
        events.push(event);
    }
    f.before = cbor::encode(&value).unwrap(); stdfs::write(f.a.0.join(initial_state::STATE), &f.before).unwrap();
    f.expected.state = f.source.as_mut().unwrap().key_state_history(&f.expected.state.initial.area_id).unwrap();
    let p = f.prepare().unwrap().remove_with(&mut identify, &mut |_| Ok(())).unwrap();
    let intent = p.intent(); assert_eq!(intent.before.generation,1022); assert_eq!(intent.after.generation,1023);
    p.record().unwrap(); independent(&f,&intent); f.retained(false);
    assert_eq!(f.source.as_mut().unwrap().key_state_history(&f.expected.state.initial.area_id).unwrap(),intent.after);
}

#[test]
fn residue_removal_process_kill_routes_to_explicit_recovery() {
    if let Some(path) = std::env::var_os("LNGNB_PUBLIC_REMOVAL_AREA") {
        let backup_path = std::env::var_os("LNGNB_PUBLIC_REMOVAL_BACKUP").unwrap();
        let point = std::env::var("LNGNB_PUBLIC_REMOVAL_POINT").unwrap();
        let mut source = KeyDirectory::open(Path::new(&path)).unwrap();
        let mut backup = KeyDirectory::open(Path::new(&backup_path)).unwrap();
        let marker = stdfs::read(Path::new(&path).join(recovery_hold::MARKER)).unwrap();
        let area_id = marker[21..53].try_into().unwrap();
        let expected = KeyCleanupExpected { state: source.key_state_history(&area_id).unwrap(),
            target: KeyFileIdentity::from_metadata(&stdfs::metadata(Path::new(&path).join(RESIDUE)).unwrap()),
            preserved_directory: KeyDirectoryIdentity::from_metadata(&stdfs::metadata(&backup_path).unwrap()),
            preserved: KeyFileIdentity::from_metadata(&stdfs::metadata(Path::new(&backup_path).join("saved")).unwrap()),
            public_key: intent_public_key() };
        let (_, pass) = fixture();
        let mut removal_hook = |s: R| {
            if format!("R:{s:?}") == point { println!("READY"); std::io::stdout().flush().unwrap(); loop { std::thread::park(); } }
            Ok(())
        };
        let p = source.prepare_residue_removal_with(RESIDUE, &pass, &mut backup, "saved", &expected, &mut removal_hook).unwrap();
        let q = p.remove_with(&mut identify, &mut removal_hook).unwrap();
        let _ = q.record_with(&mut |s| {
            if format!("C:{s:?}") == point { println!("READY"); std::io::stdout().flush().unwrap(); loop { std::thread::park(); } }
            Ok(())
        });
        panic!("kill point not reached");
    }
    for point in ["R:BeforeUnlink", "R:Unlinked", "R:RemovalSynced", "C:Prepared", "C:Exchanged", "C:OldSnapshotRemoved"] {
        let mut f = Fixture::new();
        f.source.take(); f.backup.take();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "keyfile::files::tests::cleanup_start_tests::removal_tests::residue_removal_process_kill_routes_to_explicit_recovery", "--nocapture"])
            .env("LNGNB_PUBLIC_REMOVAL_AREA", &f.a.0).env("LNGNB_PUBLIC_REMOVAL_BACKUP", &f.b.0)
            .env("LNGNB_PUBLIC_REMOVAL_POINT", point).stdout(Stdio::piped()).spawn().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap()); let mut line = String::new();
        loop { line.clear(); assert!(stdout.read_line(&mut line).unwrap() > 0); if line.trim() == "READY" { break; } }
        child.kill().unwrap(); assert!(!child.wait().unwrap().success());
        f.reopen();
        let intent = if f.a.0.join(RESIDUE).exists() {
            assert_eq!(point,"R:BeforeUnlink");
            let p = f.prepare().unwrap().remove_with(&mut identify, &mut |_| Ok(())).unwrap();
            let intent = p.intent(); p.record().unwrap(); intent
        } else if f.a.0.join(update()).exists() || snapshot(&f.a) != f.before {
            let new = if snapshot(&f.a) == f.before { stdfs::read(f.a.0.join(update())).unwrap() } else { snapshot(&f.a) };
            let marker = stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap();
            let mut origin = marker[..73].to_vec(); origin[19] = b'1';
            let after = state_history::decode_history(&new, &origin, f.expected.state.initial.area_id, f.expected.state.initial.snapshot_hash).unwrap();
            let intent = KeyCleanupCompletion { before: f.expected.state, after, operation_id: [0x77;32], started_operation_id: [0x73;32], disposition: KeyCleanupDisposition::RemovedPresent };
            assert_eq!(f.recover(&intent).unwrap(), after); intent
        } else {
            assert!(matches!(point,"R:Unlinked" | "R:RemovalSynced"));
            let intent = f.absent_completion();
            assert_eq!(intent.disposition,KeyCleanupDisposition::ConfirmedAbsentOnRecovery); intent
        };
        independent(&f,&intent); f.retained(false);
    }
}
