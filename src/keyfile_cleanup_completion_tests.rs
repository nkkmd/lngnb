//! 公開A14/隔離fixtureだけ。不在は試験側で作り、製品の対象unlink成功とはしない。
use super::*;
use super::super::super::cleanup_start::completion::CompletionStage as C;
use sha2::{Digest, Sha256};

struct Fixture {
    a: Area,
    b: Area,
    source: Option<KeyDirectory>,
    backup: Option<KeyDirectory>,
    expected: KeyCleanupExpected,
    key: Vec<u8>,
    pass: String,
    old: Vec<u8>,
    new: Vec<u8>,
    intent: KeyCleanupCompletion,
}
impl Fixture {
    fn new() -> Self {
        let (a, b, mut source, mut backup, mut expected, key, pass) = setup();
        expected.state = prepare(&mut source, &mut backup, &pass, &expected).unwrap().start().unwrap();
        let old = snapshot(&a);
        // 物理整理は未実装。公開fixtureの不在を試験側だけで作る。
        stdfs::remove_file(a.0.join(RESIDUE)).unwrap();
        File::open(&a.0).unwrap().sync_all().unwrap();
        let p = source.prepare_absent_residue_completion_with(RESIDUE, &pass, &mut backup, "saved", &expected,
            [0x77; 32], 43, &mut |_| Ok(())).unwrap();
        let intent = p.intent();
        e(p.record_with(&mut |s| if s == C::Prepared { Err(KeyFileError::Io) } else { Ok(()) }), KeyFileError::RecoveryStateUncertain);
        let name = update(&intent);
        let new = stdfs::read(a.0.join(&name)).unwrap();
        stdfs::remove_file(a.0.join(name)).unwrap();
        Self { a, b, source: Some(source), backup: Some(backup), expected, key, pass, old, new, intent }
    }
    fn prepare(&mut self) -> Result<PreparedAbsentCleanup<'_>> {
        self.source.as_mut().unwrap().prepare_absent_residue_completion_with(RESIDUE, &self.pass,
            self.backup.as_mut().unwrap(), "saved", &self.expected, [0x77; 32], 43, &mut |_| Ok(()))
    }
    fn recover(&mut self) -> Result<KeyStateDiagnostic> {
        self.source.as_mut().unwrap().recover_residue_cleanup_completion(RESIDUE, &self.pass,
            self.backup.as_mut().unwrap(), "saved", &self.expected, &self.intent)
    }
    fn layout(&mut self, n: u8) {
        let temp = self.a.0.join(update(&self.intent));
        if temp.exists() { stdfs::remove_file(temp).unwrap(); }
        stdfs::write(self.a.0.join(initial_state::STATE), if n == 0 { &self.old } else { &self.new }).unwrap();
        if n < 2 { self.a.put(&update(&self.intent), if n == 0 { &self.new } else { &self.old }); }
    }
    fn reopen(&mut self) {
        self.source.take(); self.backup.take();
        self.source = Some(KeyDirectory::open(&self.a.0).unwrap());
        self.backup = Some(KeyDirectory::open(&self.b.0).unwrap());
    }
    fn intact(&mut self) {
        assert!(!self.a.0.join(RESIDUE).exists());
        assert_eq!(stdfs::read(self.a.0.join("publisher")).unwrap(), self.key);
        assert_eq!(stdfs::read(self.a.0.join(".lngnb-key-other")).unwrap(), b"unknown preserved residue");
        assert_eq!(stdfs::read(self.b.0.join("saved")).unwrap(), self.key);
        let source = self.source.as_mut().unwrap();
        assert!(source.load("publisher", &self.pass).is_ok());
        e(source.create("later", &self.pass), KeyFileError::PendingRecovery);
        assert!(source.initial_key_state(&self.expected.state.initial.area_id).is_err());
        assert!(source.initialize_key_state(&self.expected.state.initial.area_id).is_err());
        assert!(source.recover_initial_key_state(&self.expected.state.initial).is_err());
    }
}
fn update(intent: &KeyCleanupCompletion) -> String {
    format!(".lngnb-key-state-update-{}", data_encoding::HEXLOWER.encode(&intent.operation_id))
}
fn independent(f: &Fixture) {
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    let input = serde_json::json!({"source": f.a.0, "backup": f.b.0, "target": RESIDUE, "preserved": "saved",
        "old": hex(&f.old), "new": hex(&snapshot(&f.a)), "operation": hex(&f.intent.operation_id),
        "started": hex(&f.intent.started_operation_id), "hash": hex(&f.intent.after.snapshot_hash),
        "disposition": if f.intent.disposition == KeyCleanupDisposition::RemovedPresent { "removed_present" } else { "confirmed_absent_on_recovery" }});
    let mut child = Command::new(std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"))
        .args(["tests/key_history_reference.py", "--completed"]).stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    assert!(child.wait_with_output().unwrap().status.success(), "independent completion check failed (details suppressed)");
}

#[test]
fn completion_absent_preparation_drop_and_success_preserve_every_prefix_and_stop() {
    let mut f = Fixture::new();
    let marker = stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap();
    let guard = stdfs::read(f.a.0.join(recovery_hold::GUARD)).unwrap();
    let paths = (f.a.0.clone(), f.b.0.clone());
    let p = f.prepare().unwrap();
    assert_eq!(p.intent().disposition, KeyCleanupDisposition::ConfirmedAbsentOnRecovery);
    e(KeyDirectory::open(&paths.0), KeyFileError::Busy);
    e(KeyDirectory::open(&paths.1), KeyFileError::Busy);
    drop(p);
    assert_eq!(snapshot(&f.a), f.old);
    let expected_after = f.intent.after;
    assert_eq!(f.prepare().unwrap().record().unwrap(), expected_after);
    assert_eq!(snapshot(&f.a), f.new);
    independent(&f);
    let mut fixed = cbor::decode(&f.new).unwrap();
    let Value::Map(m) = &mut fixed else { panic!() };
    let Value::Array(events) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    let event = events.last_mut().unwrap();
    set_field(event, "actor_uid", Value::Bytes(vec![0; 4]));
    for (disposition, length, hash) in [
        ("removed_present", 241, "2716e430130e27ce54acda271e51c53143ce7287b253ad14ef5326e6bbaac703"),
        ("confirmed_absent_on_recovery", 255, "a1231286fd5a965175db59eef08021f22664680a6da1a27edacd557a80f0a1dc"),
    ] {
        set_field(event, "disposition", Value::Text(disposition.into()));
        let bytes = cbor::encode(event).unwrap();
        assert_eq!(bytes.len(), length);
        assert_eq!(data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes)), hash);
    }
    assert_eq!(stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap(), marker);
    assert_eq!(stdfs::read(f.a.0.join(recovery_hold::GUARD)).unwrap(), guard);
    f.reopen(); f.intact();
    // Heldを新たな不在完了へ重複追記する迂回は拒否。
    assert!(f.prepare().is_err());
    assert_eq!(f.recover().unwrap(), expected_after);
    assert_eq!(snapshot(&f.a), f.new);
}

#[test]
fn completion_preparation_all_qualification_failures_do_not_append() {
    let mut f = Fixture::new();
    for stage in [C::PreservedSynced, C::DirectoriesSynced, C::ControlsSynced, C::SnapshotsSynced, C::Qualified] {
        assert!(f.source.as_mut().unwrap().prepare_absent_residue_completion_with(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &f.expected, [0x77; 32], 43,
            &mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }).is_err());
        assert_eq!(snapshot(&f.a), f.old);
        assert!(!f.a.0.join(update(&f.intent)).exists());
    }
    f.intact();
    let mut g = Fixture::new();
    let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let p = g.source.as_mut().unwrap().prepare_absent_residue_completion(RESIDUE, &g.pass,
        g.backup.as_mut().unwrap(), "saved", &g.expected).unwrap();
    let intent = p.intent();
    assert_ne!(intent.operation_id, intent.started_operation_id);
    assert_ne!(intent.operation_id, intent.before.initial.operation_id);
    assert_eq!(p.record().unwrap(), intent.after);
    let v = cbor::decode(&snapshot(&g.a)).unwrap();
    let Value::Array(events) = get(&v, "events") else { panic!() };
    let Value::Int(recorded) = get(events.last().unwrap(), "recorded_unix_seconds") else { panic!() };
    let after = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!((before..=after).contains(&(*recorded as u64)));
    g.intact();
}

#[test]
fn completion_record_all_failure_boundaries_reopen_and_explicitly_recover_only_complete_candidates() {
    let mut f = Fixture::new();
    for stage in [C::Created, C::Written, C::FileSynced, C::Prepared, C::BeforeExchange, C::Exchanged,
        C::StateSynced, C::BeforeCleanup, C::OldSnapshotRemoved, C::CleanupSynced] {
        f.layout(2);
        stdfs::write(f.a.0.join(initial_state::STATE), &f.old).unwrap();
        let durable = matches!(stage, C::StateSynced | C::BeforeCleanup | C::OldSnapshotRemoved | C::CleanupSynced);
        e(f.prepare().unwrap().record_with(&mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }),
            if durable { KeyFileError::RecoveryStateCleanupUncertain } else { KeyFileError::RecoveryStateUncertain });
        f.reopen();
        if stage == C::Created {
            assert!(f.recover().is_err());
            assert!(f.prepare().is_err());
            assert!(stdfs::read(f.a.0.join(update(&f.intent))).unwrap().is_empty());
        } else {
            assert_eq!(f.recover().unwrap(), f.intent.after);
            assert_eq!(snapshot(&f.a), f.new);
        }
        f.intact();
    }
}

#[test]
fn completion_recovery_all_three_layouts_and_failure_boundaries_retry_same_values() {
    let mut f = Fixture::new();
    for layout in 0..3 {
        for stage in [C::PreservedSynced, C::DirectoriesSynced, C::ControlsSynced, C::SnapshotsSynced,
            C::Qualified, C::BeforeExchange, C::Exchanged, C::StateSynced, C::BeforeCleanup,
            C::OldSnapshotRemoved, C::CleanupSynced] {
            if layout != 0 && matches!(stage, C::BeforeExchange | C::Exchanged) { continue; }
            if layout == 2 && stage == C::OldSnapshotRemoved { continue; }
            f.layout(layout);
            let durable = matches!(stage, C::StateSynced | C::BeforeCleanup | C::OldSnapshotRemoved | C::CleanupSynced);
            e(f.source.as_mut().unwrap().recover_residue_cleanup_completion_with(RESIDUE, &f.pass,
                f.backup.as_mut().unwrap(), "saved", &f.expected, &f.intent,
                &mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }),
                if durable { KeyFileError::RecoveryStateCleanupUncertain } else { KeyFileError::RecoveryStateUncertain });
            f.reopen();
            assert_eq!(f.recover().unwrap(), f.intent.after);
            assert_eq!(snapshot(&f.a), f.new);
            assert!(!f.a.0.join(update(&f.intent)).exists());
        }
    }
    f.intact(); independent(&f);
}

#[test]
fn completion_rejects_wrong_expected_ids_roots_hashes_names_authentication_and_state() {
    let mut f = Fixture::new();
    f.layout(0);
    for n in 0..14 {
        let mut exp = f.expected;
        let mut intent = f.intent;
        match n {
            0 => intent.operation_id[0] ^= 1,
            1 => intent.started_operation_id[0] ^= 1,
            2 => { intent.before.generation += 1; exp.state = intent.before; },
            3 => intent.after.generation += 1,
            4 => { intent.before.snapshot_hash[0] ^= 1; exp.state = intent.before; },
            5 => intent.after.snapshot_hash[0] ^= 1,
            6 => { intent.before.initial.area_id[0] ^= 1; intent.after.initial = intent.before.initial; exp.state = intent.before; },
            7 => { intent.before.initial.snapshot_hash[0] ^= 1; intent.after.initial = intent.before.initial; exp.state = intent.before; },
            8 => exp.target.ino ^= 1,
            9 => exp.preserved.ino ^= 1,
            10 => exp.preserved_directory.ino ^= 1,
            11 => exp.public_key[0] ^= 1,
            12 => intent.disposition = KeyCleanupDisposition::RemovedPresent,
            _ => { intent.before.state = KeyHistoryState::Held; exp.state = intent.before; },
        }
        assert!(f.source.as_mut().unwrap().recover_residue_cleanup_completion(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &exp, &intent).is_err());
        assert_eq!(snapshot(&f.a), f.old);
        assert_eq!(stdfs::read(f.a.0.join(update(&f.intent))).unwrap(), f.new);
    }
    assert!(f.source.as_mut().unwrap().recover_residue_cleanup_completion(RESIDUE, "wrong public test password",
        f.backup.as_mut().unwrap(), "saved", &f.expected, &f.intent).is_err());
    for (r, p) in [("publisher", "saved"), (RESIDUE, "../saved"), (RESIDUE, ".lngnb-key-other")] {
        assert!(f.source.as_mut().unwrap().recover_residue_cleanup_completion(r, &f.pass,
            f.backup.as_mut().unwrap(), p, &f.expected, &f.intent).is_err());
    }
    f.intact();
}

#[test]
fn completion_rejects_incomplete_missing_duplicate_and_extra_candidates_without_fallback() {
    let mut f = Fixture::new();
    for n in 0..9 {
        f.layout(0);
        let temp = f.a.0.join(update(&f.intent));
        match n {
            0 => stdfs::remove_file(&temp).unwrap(),
            1 => stdfs::write(&temp, b"").unwrap(),
            2 => stdfs::write(&temp, b"partial completion").unwrap(),
            3 => stdfs::write(&temp, &f.old).unwrap(),
            4 => stdfs::write(f.a.0.join(initial_state::STATE), &f.new).unwrap(),
            5 => stdfs::remove_file(f.a.0.join(initial_state::STATE)).unwrap(),
            6 => stdfs::write(&temp, vec![0; initial_state::STATE_LIMIT + 1]).unwrap(),
            7 => f.a.put(".lngnb-key-state-update-other", b"unknown candidate"),
            _ => { stdfs::remove_file(&temp).unwrap(); symlink("missing-target", &temp).unwrap(); },
        }
        let fixed = stdfs::read(f.a.0.join(initial_state::STATE)).ok();
        let prepared = stdfs::read(&temp).ok();
        assert!(f.recover().is_err());
        // 準備名不在でも既存intentの復旧を新規不在完了へ自動切替しない。
        assert_eq!(stdfs::read(f.a.0.join(initial_state::STATE)).ok(), fixed);
        assert_eq!(stdfs::read(&temp).ok(), prepared);
        if n == 7 { stdfs::remove_file(f.a.0.join(".lngnb-key-state-update-other")).unwrap(); }
        if n == 8 { stdfs::remove_file(&temp).unwrap(); }
        if n == 5 { f.a.put(initial_state::STATE, &f.old); }
    }
    f.intact();
}

#[test]
fn completion_target_existence_and_late_reappearance_never_delete_the_new_target() {
    let mut f = Fixture::new();
    for n in 0..4 {
        let path = f.a.0.join(RESIDUE);
        match n {
            0 => f.a.put(RESIDUE, &f.key),
            1 => symlink("missing-ciphertext", &path).unwrap(),
            2 => stdfs::create_dir(&path).unwrap(),
            _ => { os(fs::mknodat(&f.source.as_ref().unwrap().dir, RESIDUE, fs::FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)).unwrap(); },
        }
        assert!(f.prepare().is_err());
        f.layout(0);
        assert!(f.recover().is_err());
        assert!(stdfs::symlink_metadata(&path).is_ok());
        if n == 2 { stdfs::remove_dir(&path).unwrap(); } else { stdfs::remove_file(&path).unwrap(); }
        f.layout(2); stdfs::write(f.a.0.join(initial_state::STATE), &f.old).unwrap();
    }
    for stage in [C::BeforeCreate, C::BeforeExchange, C::BeforeCleanup, C::CleanupSynced] {
        f.layout(2); stdfs::write(f.a.0.join(initial_state::STATE), &f.old).unwrap();
        let target = f.a.0.join(RESIDUE);
        let area = &f.a;
        let p = f.source.as_mut().unwrap().prepare_absent_residue_completion_with(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &f.expected, [0x77; 32], 43, &mut |_| Ok(())).unwrap();
        assert!(p.record_with(&mut |s| { if s == stage { area.put(RESIDUE, b"late independent file"); } Ok(()) }).is_err());
        assert_eq!(stdfs::read(&target).unwrap(), b"late independent file");
        stdfs::remove_file(target).unwrap();
    }
    for layout in 0..3 {
        for stage in [C::Qualified, C::BeforeExchange, C::BeforeCleanup, C::CleanupSynced] {
            if layout != 0 && stage == C::BeforeExchange { continue; }
            for dangling in [false, true] {
                f.layout(layout);
                let area = &f.a;
                assert!(f.source.as_mut().unwrap().recover_residue_cleanup_completion_with(RESIDUE, &f.pass,
                    f.backup.as_mut().unwrap(), "saved", &f.expected, &f.intent, &mut |s| {
                        if s == stage {
                            if dangling { symlink("missing-new-ciphertext", area.0.join(RESIDUE)).unwrap(); }
                            else { area.put(RESIDUE, b"reappeared target"); }
                        }
                        Ok(())
                    }).is_err());
                assert!(stdfs::symlink_metadata(f.a.0.join(RESIDUE)).is_ok());
                if !dangling { assert_eq!(stdfs::read(f.a.0.join(RESIDUE)).unwrap(), b"reappeared target"); }
                stdfs::remove_file(f.a.0.join(RESIDUE)).unwrap();
            }
        }
    }
    f.intact();
}

#[test]
fn completion_rejects_changed_preservation_controls_and_held_inodes() {
    for n in 0..8 {
        let mut f = Fixture::new();
        f.layout(0);
        let path = match n { 0..=2 => f.b.0.join("saved"), 3..=4 => f.a.0.join(recovery_hold::MARKER),
            5 => f.a.0.join(recovery_hold::GUARD), 6 => f.a.0.join(initial_state::STATE), _ => f.a.0.join(update(&f.intent)) };
        let expected_fixed = snapshot(&f.a);
        match n {
            0 => { let unlocked = unlock(&f.key, &f.pass).unwrap(); let other = super::super::super::super::encrypt_with(&unlocked, &f.pass, [0x42; 16], [0x24; 12]).unwrap();
                stdfs::write(&path, &other).unwrap(); f.expected.preserved = KeyFileIdentity::from_metadata(&stdfs::metadata(&path).unwrap()); },
            1 => { stdfs::hard_link(&path, f.b.0.join("second-link")).unwrap(); },
            2 => { stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o644)).unwrap(); },
            3 => { let mut bytes = stdfs::read(&path).unwrap(); bytes[19] = b'1'; bytes.truncate(73); stdfs::write(&path, bytes).unwrap(); },
            4 => { let mut bytes = stdfs::read(&path).unwrap(); bytes[19] = b'9'; stdfs::write(&path, bytes).unwrap(); },
            5 => stdfs::remove_file(&path).unwrap(),
            _ => stdfs::write(&path, b"changed snapshot").unwrap(),
        }
        assert!(f.recover().is_err());
        if n != 6 { assert_eq!(snapshot(&f.a), expected_fixed); }
        assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), f.key);
    }
    for n in 0..5 {
        let mut f = Fixture::new(); f.layout(0);
        let path = match n { 0 => f.b.0.join("saved"), 1 => f.a.0.join(recovery_hold::MARKER),
            2 => f.a.0.join(recovery_hold::GUARD), 3 => f.a.0.join(initial_state::STATE), _ => f.a.0.join(update(&f.intent)) };
        let source_area = &f.a; let backup_area = &f.b;
        assert!(f.source.as_mut().unwrap().recover_residue_cleanup_completion_with(RESIDUE, &f.pass,
            f.backup.as_mut().unwrap(), "saved", &f.expected, &f.intent, &mut |s| {
                if s == if n >= 3 { C::BeforeCleanup } else { C::BeforeExchange } {
                    let contents = stdfs::read(&path).unwrap();
                    let area = if n == 0 { backup_area } else { source_area };
                    stdfs::rename(&path, area.0.join("retained-original")).unwrap();
                    area.put(path.file_name().unwrap().to_str().unwrap(), &contents);
                }
                Ok(())
            }).is_err());
        assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), f.key);
    }
}

#[test]
fn completion_preserves_existing_removed_disposition_without_generating_or_reclassifying_it() {
    let mut f = Fixture::new();
    let mut v = cbor::decode(&f.new).unwrap();
    let Value::Map(m) = &mut v else { panic!() };
    let Value::Array(evs) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    // 製品の物理整理成功ではない。完全な旧記録採用を検査する合成fixtureだけ。
    set_field(evs.last_mut().unwrap(), "disposition", Value::Text("removed_present".into()));
    f.new = cbor::encode(&v).unwrap();
    f.intent.after.snapshot_hash = Sha256::digest(&f.new).into();
    f.intent.disposition = KeyCleanupDisposition::RemovedPresent;
    for layout in 0..3 {
        f.layout(layout);
        assert_eq!(f.recover().unwrap(), f.intent.after);
        assert_eq!(snapshot(&f.a), f.new);
        independent(&f);
    }
    f.intact();
}

#[test]
fn completion_all_history_prefixes_include_maximum_active_to_held() {
    let mut f = Fixture::new();
    for count in [4, 1022] {
        let mut v = cbor::decode(&f.old).unwrap();
        let Value::Map(m) = &mut v else { panic!() };
        let Value::Array(evs) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
        let start = evs[1].clone();
        let mut completed = cbor::decode(&f.new).unwrap();
        let Value::Map(cm) = &mut completed else { panic!() };
        let Value::Array(ce) = &mut cm.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
        let done = ce.last().unwrap().clone();
        evs.truncate(1);
        for n in 2..=count {
            let mut event = if n % 2 == 0 { start.clone() } else { done.clone() };
            set_field(&mut event, "sequence", Value::Int(n as i64));
            set_field(&mut event, "operation_id", Value::Bytes(event_id(n).to_vec()));
            if n % 2 == 1 { set_field(&mut event, "started_operation_id", Value::Bytes(event_id(n-1).to_vec())); }
            evs.push(event);
        }
        f.old = cbor::encode(&v).unwrap();
        stdfs::write(f.a.0.join(initial_state::STATE), &f.old).unwrap();
        f.expected.state = f.source.as_mut().unwrap().key_state_history(&f.expected.state.initial.area_id).unwrap();
        let p = f.prepare().unwrap(); let intent = p.intent(); p.record().unwrap(); f.intent = intent;
        assert_eq!(f.intent.after.generation, count + 1);
        f.new = snapshot(&f.a);
        independent(&f);
        f.intact();
    }
}

#[test]
fn completion_entry_capacity_and_both_held_directory_renames_are_respected() {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = Fixture::new();
    let count = stdfs::read_dir(&f.a.0).unwrap().count();
    for n in count..SCAN_LIMIT { stdfs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(f.a.0.join(format!("entry-{n}"))).unwrap(); }
    e(f.prepare(), KeyFileError::ScanLimit);
    stdfs::remove_file(f.a.0.join(format!("entry-{}", SCAN_LIMIT-1))).unwrap();
    f.prepare().unwrap().record().unwrap();
    f.layout(0); // 既存完全候補だけの復旧は追加枠不要。一覧ちょうど上限。
    assert_eq!(stdfs::read_dir(&f.a.0).unwrap().count(), SCAN_LIMIT);
    f.a.put("overflow", b"extra");
    e(f.recover(), KeyFileError::ScanLimit);
    stdfs::remove_file(f.a.0.join("overflow")).unwrap();
    let moved_a = f.a.0.with_extension("moved"); let moved_b = f.b.0.with_extension("moved");
    stdfs::rename(&f.a.0, &moved_a).unwrap(); stdfs::rename(&f.b.0, &moved_b).unwrap();
    stdfs::DirBuilder::new().mode(0o700).create(&f.a.0).unwrap(); stdfs::DirBuilder::new().mode(0o700).create(&f.b.0).unwrap();
    f.a.put("unrelated", b"source replacement"); f.b.put("unrelated", b"backup replacement");
    assert_eq!(f.recover().unwrap(), f.intent.after);
    assert_eq!(stdfs::read(moved_a.join("publisher")).unwrap(), f.key);
    assert_eq!(stdfs::read(moved_b.join("saved")).unwrap(), f.key);
    assert_eq!(stdfs::read(f.a.0.join("unrelated")).unwrap(), b"source replacement");
    assert_eq!(stdfs::read(f.b.0.join("unrelated")).unwrap(), b"backup replacement");
    drop(f); stdfs::remove_dir_all(moved_a).unwrap(); stdfs::remove_dir_all(moved_b).unwrap();
}

#[test]
fn completion_codec_valid_new_hash_with_different_active_prefix_is_rejected() {
    let mut f = Fixture::new();
    f.layout(2);
    let mut v = cbor::decode(&f.new).unwrap();
    let Value::Map(m) = &mut v else { panic!() };
    let Value::Array(evs) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    set_field(&mut evs[1], "recorded_unix_seconds", Value::Int(99));
    let wrong = cbor::encode(&v).unwrap();
    stdfs::write(f.a.0.join(initial_state::STATE), &wrong).unwrap();
    f.intent.after.snapshot_hash = Sha256::digest(&wrong).into();
    assert_eq!(f.source.as_mut().unwrap().key_state_history(&f.expected.state.initial.area_id).unwrap(), f.intent.after);
    assert!(f.recover().is_err());
    assert_eq!(snapshot(&f.a), wrong);
    let mut unknown = cbor::decode(&f.new).unwrap();
    let Value::Map(m) = &mut unknown else { panic!() };
    let Value::Array(evs) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    set_field(evs.last_mut().unwrap(), "kind", Value::Text("unimplemented_completion".into()));
    let bad = cbor::encode(&unknown).unwrap();
    f.intent.after.snapshot_hash = Sha256::digest(&bad).into();
    stdfs::write(f.a.0.join(initial_state::STATE), &bad).unwrap();
    assert!(f.recover().is_err());
    assert_eq!(snapshot(&f.a), bad);
    f.intact();
}

fn recorded_identity(v: &Value) -> KeyFileIdentity {
    let get = |key: &str| {
        let Value::Map(m) = v else { panic!() };
        &m.iter().find(|(k, _)| k == key).unwrap().1
    };
    let u64_field = |key| { let Value::Bytes(b) = get(key) else { panic!() }; u64::from_be_bytes(b.as_slice().try_into().unwrap()) };
    let u32_field = |key| { let Value::Bytes(b) = get(key) else { panic!() }; u32::from_be_bytes(b.as_slice().try_into().unwrap()) };
    let int_field = |key| { let Value::Int(n) = get(key) else { panic!() }; *n };
    KeyFileIdentity { dev: u64_field("dev"), ino: u64_field("ino"), length: u64_field("length"), nlink: u64_field("nlink"),
        uid: u32_field("uid"), mode: u32_field("mode"), mtime_seconds: int_field("mtime_seconds"),
        mtime_nanoseconds: int_field("mtime_nanoseconds"), ctime_seconds: int_field("ctime_seconds"), ctime_nanoseconds: int_field("ctime_nanoseconds") }
}
fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    let Value::Map(m) = v else { panic!() };
    &m.iter().find(|(k, _)| k == key).unwrap().1
}

#[test]
fn completion_process_kill_recovery_keeps_snapshots_and_reopens_for_explicit_retry() {
    if let Some(path) = std::env::var_os("LNGNB_PUBLIC_COMPLETION_AREA") {
        let backup_path = std::env::var_os("LNGNB_PUBLIC_COMPLETION_BACKUP").unwrap();
        let mut source = KeyDirectory::open(Path::new(&path)).unwrap();
        let mut backup = KeyDirectory::open(Path::new(&backup_path)).unwrap();
        let marker = stdfs::read(Path::new(&path).join(recovery_hold::MARKER)).unwrap();
        let mut origin = marker[..73].to_vec(); origin[19] = b'1';
        let area_id = marker[21..53].try_into().unwrap(); let root = marker[73..].try_into().unwrap();
        let old = stdfs::read(Path::new(&path).join(initial_state::STATE)).unwrap();
        let before = state_history::decode_history(&old, &origin, area_id, root).unwrap();
        let value = cbor::decode(&old).unwrap();
        let Value::Array(events) = get(&value, "events") else { panic!() };
        let event = events.last().unwrap();
        let expected = KeyCleanupExpected { state: before,
            target: recorded_identity(get(get(event, "target"), "identity")),
            preserved_directory: KeyDirectoryIdentity::from_metadata(&stdfs::metadata(&backup_path).unwrap()),
            preserved: KeyFileIdentity::from_metadata(&stdfs::metadata(Path::new(&backup_path).join("saved")).unwrap()),
            public_key: intent_public_key() };
        let temp = format!(".lngnb-key-state-update-{}", data_encoding::HEXLOWER.encode(&[0x77; 32]));
        let new = stdfs::read(Path::new(&path).join(temp)).unwrap();
        let after = state_history::decode_history(&new, &origin, area_id, root).unwrap();
        let intent = KeyCleanupCompletion { before, after, operation_id: [0x77; 32], started_operation_id: [0x73; 32], disposition: KeyCleanupDisposition::ConfirmedAbsentOnRecovery };
        let (_, pass) = fixture();
        let point = std::env::var("LNGNB_PUBLIC_COMPLETION_POINT").unwrap();
        let _ = source.recover_residue_cleanup_completion_with(RESIDUE, &pass, &mut backup, "saved", &expected, &intent,
            &mut |s| {
                if format!("{s:?}") == point {
                    println!("READY"); std::io::stdout().flush().unwrap();
                    loop { std::thread::park(); }
                }
                Ok(())
            });
        panic!("kill point not reached");
    }
    let mut f = Fixture::new();
    for stage in [C::Qualified, C::Exchanged, C::StateSynced, C::OldSnapshotRemoved, C::CleanupSynced] {
        f.layout(0); f.source.take(); f.backup.take();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "keyfile::files::tests::cleanup_start_tests::completion_tests::completion_process_kill_recovery_keeps_snapshots_and_reopens_for_explicit_retry", "--nocapture"])
            .env("LNGNB_PUBLIC_COMPLETION_AREA", &f.a.0).env("LNGNB_PUBLIC_COMPLETION_BACKUP", &f.b.0)
            .env("LNGNB_PUBLIC_COMPLETION_POINT", format!("{stage:?}"))
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap()); let mut line = String::new();
        loop { line.clear(); assert!(stdout.read_line(&mut line).unwrap() > 0); if line.trim() == "READY" { break; } }
        child.kill().unwrap(); assert!(!child.wait().unwrap().success());
        f.reopen();
        let previous = snapshot(&f.a);
        f.intact(); assert_eq!(snapshot(&f.a), previous);
        assert_eq!(f.recover().unwrap(), f.intent.after);
        assert_eq!(snapshot(&f.a), f.new); independent(&f);
    }
}
