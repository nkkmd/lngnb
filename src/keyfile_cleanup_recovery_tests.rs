//! 公開試験鍵と隔離領域のみ。対象鍵unlink/完了の試験ではない。
use super::*;
use super::super::super::cleanup_start::recovery::CleanupRecoveryStage as R;

fn temp(intent: &KeyCleanupStart) -> String {
    format!(".lngnb-key-state-update-{}", data_encoding::HEXLOWER.encode(&intent.operation_id))
}
fn interrupt(source: &mut KeyDirectory, backup: &mut KeyDirectory, pass: &str,
    expected: &KeyCleanupExpected, stage: S) -> KeyCleanupStart {
    let p = prepare(source, backup, pass, expected).unwrap();
    let intent = p.intent();
    assert!(p.start_with(&mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }).is_err());
    intent
}
fn recover(source: &mut KeyDirectory, backup: &mut KeyDirectory, pass: &str,
    expected: &KeyCleanupExpected, intent: &KeyCleanupStart) -> Result<KeyStateDiagnostic> {
    source.recover_residue_cleanup_start(RESIDUE, pass, backup, "saved", expected, intent)
}
fn files(a: &Area) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut f: Vec<_> = stdfs::read_dir(&a.0).unwrap().map(|e| {
        let e = e.unwrap(); (e.file_name(), stdfs::read(e.path()).unwrap())
    }).collect();
    f.sort(); f
}
fn assert_stopped(source: &mut KeyDirectory, pass: &str, expected: &KeyCleanupExpected) {
    assert!(source.load("publisher", pass).is_ok());
    e(source.create("later", pass), KeyFileError::PendingRecovery);
    assert!(source.initialize_key_state(&expected.state.initial.area_id).is_err());
    assert!(source.initial_key_state(&expected.state.initial.area_id).is_err());
    assert!(source.recover_initial_key_state(&expected.state.initial).is_err());
}

#[test]
fn cleanup_recovery_three_layouts_all_start_boundaries_and_explicit_retries() {
    for stage in [S::Written, S::FileSynced, S::Prepared, S::BeforeExchange,
        S::Exchanged, S::StateSynced, S::BeforeCleanup, S::OldSnapshotRemoved, S::CleanupSynced] {
        let (a, b, mut source, mut backup, expected, key, pass) = setup();
        let old = snapshot(&a);
        let marker = stdfs::read(a.0.join(recovery_hold::MARKER)).unwrap();
        let guard = stdfs::read(a.0.join(recovery_hold::GUARD)).unwrap();
        let intent = interrupt(&mut source, &mut backup, &pass, &expected, stage);
        let complete_new = if snapshot(&a) == old { stdfs::read(a.0.join(temp(&intent))).unwrap() } else { snapshot(&a) };
        drop(source); drop(backup);
        let mut source = KeyDirectory::open(&a.0).unwrap();
        let mut backup = KeyDirectory::open(&b.0).unwrap();
        let before_open = files(&a);
        assert!(source.load("publisher", &pass).is_ok());
        assert_eq!(files(&a), before_open); // open/loadは自動採用しない。
        assert_eq!(recover(&mut source, &mut backup, &pass, &expected, &intent).unwrap(), intent.after);
        assert_eq!(snapshot(&a), complete_new);
        assert!(!a.0.join(temp(&intent)).exists());
        independent_start(&a, &b, &old, &snapshot(&a), &intent);
        assert_eq!(stdfs::read(a.0.join(recovery_hold::MARKER)).unwrap(), marker);
        assert_eq!(stdfs::read(a.0.join(recovery_hold::GUARD)).unwrap(), guard);
        preserved(&a, &b, &key);
        assert_stopped(&mut source, &pass, &expected);
        let stable = files(&a);
        // 過去の保存確認を推定せず、同じ明示値で今回fsyncをもう一度行える。
        assert_eq!(recover(&mut source, &mut backup, &pass, &expected, &intent).unwrap(), intent.after);
        assert_eq!(files(&a), stable);
    }
}

#[test]
fn cleanup_recovery_every_failure_boundary_preserves_keys_and_reopens_for_retry() {
    for layout in [S::Prepared, S::Exchanged, S::OldSnapshotRemoved] {
        for stage in [R::TargetSynced, R::PreservedSynced, R::DirectoriesSynced,
            R::ControlsSynced, R::SnapshotsSynced, R::Prepared, R::BeforeExchange,
            R::Exchanged, R::StateSynced, R::BeforeCleanup, R::OldSnapshotRemoved, R::CleanupSynced] {
            if layout != S::Prepared && matches!(stage, R::BeforeExchange | R::Exchanged) { continue; }
            if layout == S::OldSnapshotRemoved && stage == R::OldSnapshotRemoved { continue; }
            let (a, b, mut source, mut backup, expected, key, pass) = setup();
            let intent = interrupt(&mut source, &mut backup, &pass, &expected, layout);
            let durable = matches!(stage, R::StateSynced | R::BeforeCleanup | R::OldSnapshotRemoved | R::CleanupSynced);
            e(source.recover_residue_cleanup_start_with(RESIDUE, &pass, &mut backup, "saved", &expected, &intent,
                &mut |s| if s == stage { Err(KeyFileError::Io) } else { Ok(()) }),
                if durable { KeyFileError::RecoveryStateCleanupUncertain } else { KeyFileError::RecoveryStateUncertain });
            preserved(&a, &b, &key);
            drop(source); drop(backup);
            let mut source = KeyDirectory::open(&a.0).unwrap();
            let mut backup = KeyDirectory::open(&b.0).unwrap();
            assert_eq!(recover(&mut source, &mut backup, &pass, &expected, &intent).unwrap(), intent.after);
            preserved(&a, &b, &key);
            assert_stopped(&mut source, &pass, &expected);
        }
    }
}

#[test]
fn cleanup_recovery_rejects_wrong_selection_authentication_and_missing_or_incomplete_snapshots() {
    for layout in [S::Prepared, S::Exchanged, S::OldSnapshotRemoved] {
        let (a, b, mut source, mut backup, expected, key, pass) = setup();
        let intent = interrupt(&mut source, &mut backup, &pass, &expected, layout);
        let stable = files(&a);
        for n in 0..11 {
            let mut bad = intent;
            let mut exp = expected;
            match n {
                0 => bad.before.generation += 1,
                1 => { bad.before.snapshot_hash[0] ^= 1; exp.state = bad.before; },
                2 => bad.after.generation += 1,
                3 => bad.after.snapshot_hash[0] ^= 1,
                4 => bad.operation_id[0] ^= 1,
                5 => exp.target.ino ^= 1,
                6 => exp.preserved.ino ^= 1,
                7 => exp.preserved_directory.ino ^= 1,
                8 => exp.public_key[0] ^= 1,
                9 => { bad.before.initial.area_id[0] ^= 1; bad.after.initial = bad.before.initial; exp.state = bad.before; },
                _ => { bad.before.initial.snapshot_hash[0] ^= 1; bad.after.initial = bad.before.initial; exp.state = bad.before; },
            }
            assert!(recover(&mut source, &mut backup, &pass, &exp, &bad).is_err());
            assert_eq!(files(&a), stable);
        }
        assert!(recover(&mut source, &mut backup, "wrong public test password", &expected, &intent).is_err());
        preserved(&a, &b, &key);
        assert_eq!(files(&a), stable);
    }
    for n in 0..7 {
        let (a, b, mut source, mut backup, expected, key, pass) = setup();
        let intent = interrupt(&mut source, &mut backup, &pass, &expected, S::Prepared);
        let p = a.0.join(temp(&intent));
        match n {
            0 => stdfs::write(&p, b"").unwrap(),
            1 => stdfs::write(&p, b"incomplete").unwrap(),
            2 => stdfs::remove_file(&p).unwrap(),
            3 => stdfs::remove_file(a.0.join(initial_state::STATE)).unwrap(),
            4 => stdfs::write(&p, snapshot(&a)).unwrap(), // 旧＋旧。
            5 => { let new = stdfs::read(&p).unwrap(); stdfs::write(a.0.join(initial_state::STATE), &new).unwrap(); }, // 新＋新。
            _ => a.put(".lngnb-key-state-update-extra", b"unknown candidate"),
        }
        let stable = files(&a);
        assert!(recover(&mut source, &mut backup, &pass, &expected, &intent).is_err());
        assert_eq!(files(&a), stable);
        preserved(&a, &b, &key);
    }
}

#[test]
fn cleanup_recovery_rechecks_held_fds_bytes_and_absent_temp_before_each_mutation() {
    for layout in [S::Prepared, S::Exchanged, S::OldSnapshotRemoved] {
        for n in 0..8 {
            let (a, b, mut source, mut backup, expected, key, pass) = setup();
            let intent = interrupt(&mut source, &mut backup, &pass, &expected, layout);
            let boundary = if layout == S::Prepared { R::BeforeExchange } else { R::BeforeCleanup };
            assert!(source.recover_residue_cleanup_start_with(RESIDUE, &pass, &mut backup, "saved", &expected, &intent,
                &mut |s| {
                    if s == boundary {
                        let path = match n {
                            0 => a.0.join(RESIDUE), 1 => b.0.join("saved"),
                            2 => a.0.join(recovery_hold::MARKER), 3 => a.0.join(recovery_hold::GUARD),
                            4 => a.0.join(initial_state::STATE), _ => a.0.join(temp(&intent)),
                        };
                        match n {
                            0..=4 => { let bytes = stdfs::read(&path).unwrap(); stdfs::rename(&path, path.with_extension("held-original")).unwrap();
                                let dir = if n == 1 { &b } else { &a }; dir.put(path.file_name().unwrap().to_str().unwrap(), &bytes); },
                            5 if path.exists() => { stdfs::write(&path, b"changed snapshot").unwrap(); },
                            5 => a.put(&temp(&intent), b"unexpected late candidate"),
                            6 => a.put(".lngnb-key-state-update-other", b"extra"),
                            _ => { stdfs::set_permissions(a.0.join(RESIDUE), stdfs::Permissions::from_mode(0o400)).unwrap(); },
                        }
                    }
                    Ok(())
                }).is_err());
            // 交換/旧コピー削除に進まず、各変更と既存snapshotを残す。
            assert!(!snapshot(&a).is_empty());
            assert_eq!(stdfs::read(a.0.join("publisher")).unwrap(), key);
            assert!(a.0.join(recovery_hold::GUARD).exists());
            assert!(a.0.join(recovery_hold::MARKER).exists());
        }
    }
}

#[test]
fn cleanup_recovery_rejects_unsafe_controls_snapshots_and_current_ciphertexts() {
    for n in 0..17 {
        let (a, b, mut source, mut backup, mut expected, key, pass) = setup();
        let intent = interrupt(&mut source, &mut backup, &pass, &expected, S::Prepared);
        let path = match n {
            0..=3 => a.0.join(recovery_hold::MARKER),
            4..=5 => a.0.join(recovery_hold::GUARD),
            6..=7 => a.0.join(initial_state::STATE),
            8..=11 => a.0.join(temp(&intent)),
            12..=13 => a.0.join(RESIDUE),
            _ => b.0.join("saved"),
        };
        match n {
            0 | 4 | 6 | 8 | 12 | 14 => { stdfs::remove_file(&path).unwrap(); },
            1 => { let mut v = stdfs::read(&path).unwrap(); v[19] = b'1'; v.truncate(73); stdfs::write(&path, v).unwrap(); },
            2 => { let mut v = stdfs::read(&path).unwrap(); v[19] = b'9'; stdfs::write(&path, v).unwrap(); },
            3 | 5 | 7 => { stdfs::write(&path, b"incomplete control").unwrap(); },
            9 => { stdfs::write(&path, vec![0; initial_state::STATE_LIMIT + 1]).unwrap(); },
            10 => { stdfs::remove_file(&path).unwrap(); symlink(a.0.join(initial_state::STATE), &path).unwrap(); },
            11 => { stdfs::hard_link(&path, a.0.join("extra-hardlink")).unwrap(); },
            13 => { stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o644)).unwrap(); },
            15 => { stdfs::remove_file(&path).unwrap(); stdfs::create_dir(&path).unwrap(); },
            _ => { let unlocked = unlock(&key, &pass).unwrap();
                let different = super::super::super::super::encrypt_with(&unlocked, &pass, [0x42; 16], [0x24; 12]).unwrap();
                stdfs::write(&path, &different).unwrap();
                expected.preserved = KeyFileIdentity::from_metadata(&stdfs::metadata(&path).unwrap()); },
        }
        let state_before = stdfs::read(a.0.join(initial_state::STATE)).ok();
        assert!(recover(&mut source, &mut backup, &pass, &expected, &intent).is_err());
        assert_eq!(stdfs::read(a.0.join(initial_state::STATE)).ok(), state_before);
        assert_eq!(stdfs::read(a.0.join("publisher")).unwrap(), key);
        // 危険な対象は存在状態を修正しない。missing等を復元もしない。
        if matches!(n, 0 | 4 | 6 | 8 | 12 | 14) { assert!(!path.exists()); }
    }
}

#[test]
fn cleanup_recovery_rejects_different_prefix_even_with_a_valid_root_and_explicit_hash() {
    let (a, b, mut source, mut backup, mut expected, key, pass) = setup();
    // 過去に完了した履歴のprefixは試験側だけで合成する。
    prepare(&mut source, &mut backup, &pass, &expected).unwrap().start().unwrap();
    let mut v = cbor::decode(&snapshot(&a)).unwrap();
    let Value::Map(m) = &mut v else { panic!() };
    let Value::Array(events) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    let mut done = events[1].clone();
    let Value::Map(d) = &mut done else { panic!() };
    d.retain(|(k, _)| k != "target" && k != "preserved");
    set_field(&mut done, "kind", Value::Text("residue_cleanup_completed".into()));
    set_field(&mut done, "sequence", Value::Int(3));
    set_field(&mut done, "operation_id", Value::Bytes(vec![0x75; 32]));
    let Value::Map(d) = &mut done else { panic!() };
    d.push(("started_operation_id".into(), Value::Bytes(vec![0x73; 32])));
    d.push(("disposition".into(), Value::Text("removed_present".into())));
    events.push(done);
    stdfs::write(a.0.join(initial_state::STATE), cbor::encode(&v).unwrap()).unwrap();
    expected.state = source.key_state_history(&expected.state.initial.area_id).unwrap();
    let old = snapshot(&a);
    let p = source.prepare_residue_cleanup_with(RESIDUE, &pass, &mut backup, "saved", &expected, [0x76; 32], 42, &mut |_| Ok(())).unwrap();
    let intent = p.intent();
    assert!(p.start_with(&mut |s| if s == S::Prepared { Err(KeyFileError::Io) } else { Ok(()) }).is_err());
    // まず4件履歴でも完全prefixのまま正常復旧し、独立checkerを通す。
    assert_eq!(recover(&mut source, &mut backup, &pass, &expected, &intent).unwrap(), intent.after);
    independent_start(&a, &b, &old, &snapshot(&a), &intent);
    // 別の過去eventを改変した固定旧を置く。rootは同じでも明示旧hashと一致しない。
    let mut wrong = cbor::decode(&old).unwrap();
    let Value::Map(m) = &mut wrong else { panic!() };
    let Value::Array(evs) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    set_field(&mut evs[2], "recorded_unix_seconds", Value::Int(99));
    a.put(&temp(&intent), &cbor::encode(&wrong).unwrap());
    let stable = files(&a);
    assert!(recover(&mut source, &mut backup, &pass, &expected, &intent).is_err());
    assert_eq!(files(&a), stable);
    preserved(&a, &b, &key);
}

#[test]
fn cleanup_recovery_process_kill_reopens_and_requires_explicit_retry() {
    if let Some(path) = std::env::var_os("LNGNB_PUBLIC_CLEANUP_RECOVERY_AREA") {
        let backup_path = std::env::var_os("LNGNB_PUBLIC_CLEANUP_RECOVERY_BACKUP").unwrap();
        let mut source = KeyDirectory::open(Path::new(&path)).unwrap();
        let mut backup = KeyDirectory::open(Path::new(&backup_path)).unwrap();
        let marker = stdfs::read(Path::new(&path).join(recovery_hold::MARKER)).unwrap();
        let area_id = marker[21..53].try_into().unwrap();
        let expected = KeyCleanupExpected {
            state: source.key_state_history(&area_id).unwrap(),
            target: KeyFileIdentity::from_metadata(&stdfs::metadata(Path::new(&path).join(RESIDUE)).unwrap()),
            preserved_directory: KeyDirectoryIdentity::from_metadata(&stdfs::metadata(&backup_path).unwrap()),
            preserved: KeyFileIdentity::from_metadata(&stdfs::metadata(Path::new(&backup_path).join("saved")).unwrap()),
            public_key: intent_public_key(),
        };
        let (_, pass) = fixture();
        let intent = interrupt(&mut source, &mut backup, &pass, &expected, S::Prepared);
        let point = std::env::var("LNGNB_PUBLIC_CLEANUP_RECOVERY_POINT").unwrap();
        let _ = source.recover_residue_cleanup_start_with(RESIDUE, &pass, &mut backup, "saved", &expected, &intent,
            &mut |s| {
                if format!("{s:?}") == point {
                    // 初回root/旧新hashは公開試験用。親へ明示再試行値を渡す。
                    println!("READY {}", data_encoding::HEXLOWER.encode(&intent.after.snapshot_hash));
                    std::io::stdout().flush().unwrap();
                    loop { std::thread::park(); }
                }
                Ok(())
            });
        panic!("kill point not reached");
    }
    for stage in [R::Prepared, R::Exchanged, R::StateSynced, R::OldSnapshotRemoved, R::CleanupSynced] {
        let (a, b, source, backup, expected, key, pass) = setup();
        let old = snapshot(&a);
        drop(source); drop(backup);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "keyfile::files::tests::cleanup_start_tests::recovery_tests::cleanup_recovery_process_kill_reopens_and_requires_explicit_retry", "--nocapture"])
            .env("LNGNB_PUBLIC_CLEANUP_RECOVERY_AREA", &a.0)
            .env("LNGNB_PUBLIC_CLEANUP_RECOVERY_BACKUP", &b.0)
            .env("LNGNB_PUBLIC_CLEANUP_RECOVERY_POINT", format!("{stage:?}"))
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let new_hash = loop {
            line.clear(); assert!(stdout.read_line(&mut line).unwrap() > 0);
            if let Some(hex) = line.trim().strip_prefix("READY ") {
                break data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap().try_into().unwrap();
            }
        };
        child.kill().unwrap(); assert!(!child.wait().unwrap().success());
        let intent = KeyCleanupStart { before: expected.state, operation_id: [0x73; 32],
            after: KeyStateDiagnostic { initial: expected.state.initial, generation: 2,
                snapshot_hash: new_hash, state: KeyHistoryState::Active { started_operation_id: [0x73; 32] } } };
        let mut source = KeyDirectory::open(&a.0).unwrap();
        let mut backup = KeyDirectory::open(&b.0).unwrap();
        let before = files(&a);
        assert!(source.load("publisher", &pass).is_ok());
        e(source.create("later", &pass), KeyFileError::PendingRecovery);
        assert_eq!(files(&a), before);
        assert_eq!(recover(&mut source, &mut backup, &pass, &expected, &intent).unwrap(), intent.after);
        independent_start(&a, &b, &old, &snapshot(&a), &intent);
        assert_stopped(&mut source, &pass, &expected);
        preserved(&a, &b, &key);
    }
}

#[test]
fn cleanup_recovery_binds_both_directory_fds_and_needs_no_extra_entry_slot() {
    use std::os::unix::fs::OpenOptionsExt;
    let (a, b, mut source, mut backup, expected, key, pass) = setup();
    let intent = interrupt(&mut source, &mut backup, &pass, &expected, S::Prepared);
    let count = stdfs::read_dir(&a.0).unwrap().count();
    for i in count..SCAN_LIMIT {
        stdfs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(a.0.join(format!("entry-{i}"))).unwrap();
    }
    // 上限超過は無変更拒否。ちょうどなら新規entry不要で復旧できる。
    a.put("overflow", b"extra");
    e(recover(&mut source, &mut backup, &pass, &expected, &intent), KeyFileError::ScanLimit);
    stdfs::remove_file(a.0.join("overflow")).unwrap();
    let moved_a = a.0.with_extension("moved");
    let moved_b = b.0.with_extension("moved");
    stdfs::rename(&a.0, &moved_a).unwrap();
    stdfs::rename(&b.0, &moved_b).unwrap();
    stdfs::DirBuilder::new().mode(0o700).create(&a.0).unwrap();
    stdfs::DirBuilder::new().mode(0o700).create(&b.0).unwrap();
    a.put("unrelated", b"source replacement");
    b.put("unrelated", b"backup replacement");
    assert_eq!(recover(&mut source, &mut backup, &pass, &expected, &intent).unwrap(), intent.after);
    assert_eq!(stdfs::read(moved_a.join(RESIDUE)).unwrap(), key);
    assert_eq!(stdfs::read(moved_b.join("saved")).unwrap(), key);
    assert_eq!(stdfs::read(a.0.join("unrelated")).unwrap(), b"source replacement");
    assert_eq!(stdfs::read(b.0.join("unrelated")).unwrap(), b"backup replacement");
    drop(source); drop(backup);
    stdfs::remove_dir_all(moved_a).unwrap();
    stdfs::remove_dir_all(moved_b).unwrap();
}
