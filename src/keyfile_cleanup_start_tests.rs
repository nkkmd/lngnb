//! §5.100: 公開A14/隔離領域だけ。鍵の物理整理・追記復旧の試験ではない。
use super::super::cleanup_start::CleanupStartStage as S;
use super::*;
use crate::cbor::{self, Value};
const RESIDUE: &str = ".lngnb-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn setup() -> (
    Area,
    Area,
    KeyDirectory,
    KeyDirectory,
    KeyCleanupExpected,
    Vec<u8>,
    String,
) {
    let a = Area::new();
    let b = Area::new();
    let (key, pass) = fixture();
    a.put("publisher", &key);
    a.put(RESIDUE, &key);
    a.put(".lngnb-key-other", b"unknown preserved residue");
    b.put("saved", &key);
    let mut source = KeyDirectory::open(&a.0).unwrap();
    let backup = KeyDirectory::open(&b.0).unwrap();
    let KeyRecoveryHold::Held { area_id } = source.initialize_recovery_hold().unwrap() else {
        panic!()
    };
    source.initialize_key_state(&area_id).unwrap();
    let expected = KeyCleanupExpected {
        state: source.key_state_history(&area_id).unwrap(),
        target: KeyFileIdentity::from_metadata(&stdfs::metadata(a.0.join(RESIDUE)).unwrap()),
        preserved_directory: KeyDirectoryIdentity::from_metadata(&stdfs::metadata(&b.0).unwrap()),
        preserved: KeyFileIdentity::from_metadata(&stdfs::metadata(b.0.join("saved")).unwrap()),
        public_key: super::super::super::tests::unhex(
            super::super::super::tests::a13()["public_key_hex"]
                .as_str()
                .unwrap(),
        )
        .try_into()
        .unwrap(),
    };
    (a, b, source, backup, expected, key, pass)
}
fn prepare<'a>(
    source: &'a mut KeyDirectory,
    backup: &'a mut KeyDirectory,
    pass: &str,
    expected: &KeyCleanupExpected,
) -> Result<PreparedKeyCleanup<'a>> {
    source.prepare_residue_cleanup_with(
        RESIDUE,
        pass,
        backup,
        "saved",
        expected,
        [0x73; 32],
        42,
        &mut |_| Ok(()),
    )
}
fn snapshot(a: &Area) -> Vec<u8> {
    stdfs::read(a.0.join(initial_state::STATE)).unwrap()
}
fn preserved(a: &Area, b: &Area, key: &[u8]) {
    for name in ["publisher", RESIDUE] {
        assert_eq!(stdfs::read(a.0.join(name)).unwrap(), key);
    }
    assert_eq!(
        stdfs::read(a.0.join(".lngnb-key-other")).unwrap(),
        b"unknown preserved residue"
    );
    assert_eq!(stdfs::read(b.0.join("saved")).unwrap(), key);
}

#[test]
fn cleanup_start_retains_handles_records_exact_event_prefix_and_stops_after_reopen() {
    let (a, b, mut source, mut backup, expected, key, pass) = setup();
    let before = snapshot(&a);
    let marker = stdfs::read(a.0.join(recovery_hold::MARKER)).unwrap();
    let guard = stdfs::read(a.0.join(recovery_hold::GUARD)).unwrap();
    let prepared = prepare(&mut source, &mut backup, &pass, &expected).unwrap();
    let intent = prepared.intent();
    assert_eq!(intent.before, expected.state);
    assert_eq!(intent.operation_id, [0x73; 32]);
    assert_eq!(snapshot(&a), before); // 準備は履歴を作らない。
    e(KeyDirectory::open(&a.0), KeyFileError::Busy);
    e(KeyDirectory::open(&b.0), KeyFileError::Busy);
    assert_eq!(prepared.start().unwrap(), intent.after);
    let after = snapshot(&a);
    independent_start(&a, &b, &before, &after, &intent);
    assert_ne!(before, after);
    assert_eq!(
        source
            .key_state_history(&expected.state.initial.area_id)
            .unwrap(),
        intent.after
    );
    assert_eq!(
        stdfs::read(a.0.join(recovery_hold::MARKER)).unwrap(),
        marker
    );
    assert_eq!(stdfs::read(a.0.join(recovery_hold::GUARD)).unwrap(), guard);
    let Value::Map(old) = cbor::decode(&before).unwrap() else {
        panic!()
    };
    let Value::Map(new) = cbor::decode(&after).unwrap() else {
        panic!()
    };
    for (name, value) in old {
        let next = &new.iter().find(|(k, _)| *k == name).unwrap().1;
        if name == "events" {
            let Value::Array(events) = next else { panic!() };
            let Value::Array(previous) = value else {
                panic!()
            };
            assert_eq!(&events[..previous.len()], previous);
            assert_eq!(events.len(), previous.len() + 1);
        } else {
            assert_eq!(next, &value);
        }
    }
    assert!(!a.pending().iter().any(|p| {
        p.file_name()
            .unwrap()
            .as_encoded_bytes()
            .starts_with(b".lngnb-key-state-update-")
    }));
    preserved(&a, &b, &key);
    assert!(source.load("publisher", &pass).is_ok());
    e(source.create("later", &pass), KeyFileError::PendingRecovery);
    assert!(
        source
            .recover_initial_key_state(&expected.state.initial)
            .is_err()
    );
    drop(source);
    drop(backup);
    let mut source = KeyDirectory::open(&a.0).unwrap();
    let mut backup = KeyDirectory::open(&b.0).unwrap();
    let mut active_expected = expected;
    active_expected.state = source
        .key_state_history(&expected.state.initial.area_id)
        .unwrap();
    assert!(prepare(&mut source, &mut backup, &pass, &active_expected).is_err());
    assert_eq!(snapshot(&a), after);
    e(source.create("later", &pass), KeyFileError::PendingRecovery);
}

#[test]
fn cleanup_preparation_drop_and_all_qualification_failures_never_append_or_remove() {
    for stage in [
        S::TargetFileSynced,
        S::PreservedFileSynced,
        S::TargetDirectoriesSynced,
        S::StateFilesSynced,
        S::StateDirectorySynced,
    ] {
        let (a, b, mut source, mut backup, expected, key, pass) = setup();
        let old = snapshot(&a);
        assert!(
            source
                .prepare_residue_cleanup_with(
                    RESIDUE,
                    &pass,
                    &mut backup,
                    "saved",
                    &expected,
                    [0x73; 32],
                    42,
                    &mut |s| {
                        if s == stage {
                            Err(KeyFileError::Io)
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(snapshot(&a), old);
        preserved(&a, &b, &key);
        assert!(!a.pending().iter().any(|p| {
            p.file_name()
                .unwrap()
                .as_encoded_bytes()
                .starts_with(b".lngnb-key-state-update-")
        }));
        e(source.create("later", &pass), KeyFileError::PendingRecovery);
    }
    let (a, b, mut source, mut backup, expected, key, pass) = setup();
    let old = snapshot(&a);
    let prepared = prepare(&mut source, &mut backup, &pass, &expected).unwrap();
    drop(prepared);
    assert_eq!(snapshot(&a), old);
    preserved(&a, &b, &key);
    assert!(prepare(&mut source, &mut backup, &pass, &expected).is_ok());
}

#[test]
fn cleanup_start_rejects_wrong_expectations_authentication_names_and_different_ciphertext() {
    let (a, b, mut source, mut backup, expected, key, pass) = setup();
    let old = snapshot(&a);
    for n in 0..7 {
        let mut bad = expected;
        match n {
            0 => bad.target.ino ^= 1,
            1 => bad.preserved.ino ^= 1,
            2 => bad.preserved_directory.ino ^= 1,
            3 => bad.state.generation += 1,
            4 => bad.state.snapshot_hash[0] ^= 1,
            5 => bad.state.initial.area_id[0] ^= 1,
            _ => bad.public_key[0] ^= 1,
        }
        assert!(prepare(&mut source, &mut backup, &pass, &bad).is_err());
        assert_eq!(snapshot(&a), old);
        preserved(&a, &b, &key);
    }
    assert!(
        prepare(
            &mut source,
            &mut backup,
            "incorrect public test password",
            &expected
        )
        .is_err()
    );
    for (r, p) in [
        ("publisher", "saved"),
        (RESIDUE, "../saved"),
        (RESIDUE, ".lngnb-key-other"),
        (RESIDUE, "missing"),
    ] {
        assert!(
            source
                .prepare_residue_cleanup(r, &pass, &mut backup, p, &expected)
                .is_err()
        );
    }
    assert!(
        source
            .prepare_residue_cleanup_with(
                RESIDUE,
                &pass,
                &mut backup,
                "saved",
                &expected,
                expected.state.initial.operation_id,
                42,
                &mut |_| Ok(())
            )
            .is_err()
    );
    // 同じ鍵を再暗号化した完全bytes不一致は認証成功と区別する。
    drop(backup);
    stdfs::remove_file(b.0.join("saved")).unwrap();
    let unlocked = unlock(&key, &pass).unwrap();
    let other =
        super::super::super::encrypt_with(&unlocked, &pass, [0x42; 16], [0x24; 12]).unwrap();
    b.put("saved", &other);
    let mut new_backup = KeyDirectory::open(&b.0).unwrap();
    let mut different = expected;
    different.preserved =
        KeyFileIdentity::from_metadata(&stdfs::metadata(b.0.join("saved")).unwrap());
    e(
        prepare(&mut source, &mut new_backup, &pass, &different),
        KeyFileError::PreservationMismatch,
    );
    assert_eq!(snapshot(&a), old);
}

#[test]
fn cleanup_start_holds_same_inodes_and_rejects_postqualification_changes() {
    for which in ["target", "preserved", "state", "marker", "guard"] {
        let (a, b, mut source, mut backup, expected, key, pass) = setup();
        let old = snapshot(&a);
        let prepared = prepare(&mut source, &mut backup, &pass, &expected).unwrap();
        let path = match which {
            "target" => a.0.join(RESIDUE),
            "preserved" => b.0.join("saved"),
            "state" => a.0.join(initial_state::STATE),
            "marker" => a.0.join(recovery_hold::MARKER),
            _ => a.0.join(recovery_hold::GUARD),
        };
        let bytes = stdfs::read(&path).unwrap();
        let other = path.with_extension("replacement");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = stdfs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&other)
                .unwrap();
            f.write_all(&bytes).unwrap();
        }
        stdfs::rename(other, path).unwrap();
        assert!(prepared.start().is_err());
        assert_eq!(snapshot(&a), old);
        preserved(&a, &b, &key);
    }
}

#[test]
fn cleanup_start_write_exchange_and_cleanup_failures_preserve_both_snapshots_and_keys() {
    for stage in [
        S::Created,
        S::Written,
        S::FileSynced,
        S::Prepared,
        S::BeforeExchange,
        S::Exchanged,
        S::StateSynced,
        S::BeforeCleanup,
        S::OldSnapshotRemoved,
        S::CleanupSynced,
    ] {
        let (a, b, mut source, mut backup, expected, key, pass) = setup();
        let old = snapshot(&a);
        let prepared = prepare(&mut source, &mut backup, &pass, &expected).unwrap();
        let intent = prepared.intent();
        let durable = matches!(
            stage,
            S::StateSynced | S::BeforeCleanup | S::OldSnapshotRemoved | S::CleanupSynced
        );
        e(
            prepared.start_with(&mut |s| {
                if s == stage {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            }),
            if durable {
                KeyFileError::RecoveryStateCleanupUncertain
            } else {
                KeyFileError::RecoveryStateUncertain
            },
        );
        preserved(&a, &b, &key);
        let new_installed = matches!(
            stage,
            S::Exchanged
                | S::StateSynced
                | S::BeforeCleanup
                | S::OldSnapshotRemoved
                | S::CleanupSynced
        );
        assert_eq!(snapshot(&a) == old, !new_installed);
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        );
        if matches!(stage, S::OldSnapshotRemoved | S::CleanupSynced) {
            assert!(!a.0.join(temp).exists());
        } else {
            assert!(a.0.join(&temp).exists());
            if new_installed {
                assert_eq!(stdfs::read(a.0.join(temp)).unwrap(), old);
            }
        }
        drop(source);
        drop(backup);
        let mut reopened = KeyDirectory::open(&a.0).unwrap();
        e(
            reopened.create("later", &pass),
            KeyFileError::PendingRecovery,
        );
        assert!(reopened.load("publisher", &pass).is_ok());
        assert!(
            reopened
                .recover_initial_key_state(&expected.state.initial)
                .is_err()
        );
    }
}

#[test]
fn cleanup_start_directory_fd_binding_and_reserved_entry_capacity_are_checked_before_create() {
    let (a, b, mut source, mut backup, expected, key, pass) = setup();
    let old = snapshot(&a);
    // 既存一覧ちょうど上限では追加一枠がない。
    let count = stdfs::read_dir(&a.0).unwrap().count();
    for i in count..SCAN_LIMIT {
        a.put(&format!("entry-{i}"), b"");
    }
    e(
        prepare(&mut source, &mut backup, &pass, &expected),
        KeyFileError::ScanLimit,
    );
    assert_eq!(snapshot(&a), old);
    stdfs::remove_file(a.0.join(format!("entry-{}", SCAN_LIMIT - 1))).unwrap();
    let prepared = prepare(&mut source, &mut backup, &pass, &expected).unwrap();
    // rename後も両fdに束縛し、同名の別領域へ触れない。
    let moved_a = a.0.with_extension("moved");
    let moved_b = b.0.with_extension("moved");
    stdfs::rename(&a.0, &moved_a).unwrap();
    stdfs::rename(&b.0, &moved_b).unwrap();
    stdfs::DirBuilder::new().mode(0o700).create(&a.0).unwrap();
    stdfs::DirBuilder::new().mode(0o700).create(&b.0).unwrap();
    a.put("unrelated", b"source replacement");
    b.put("unrelated", b"backup replacement");
    assert!(prepared.start().is_ok());
    assert_eq!(stdfs::read(moved_a.join(RESIDUE)).unwrap(), key);
    assert_eq!(stdfs::read(moved_b.join("saved")).unwrap(), key);
    assert_eq!(
        stdfs::read(a.0.join("unrelated")).unwrap(),
        b"source replacement"
    );
    assert_eq!(
        stdfs::read(b.0.join("unrelated")).unwrap(),
        b"backup replacement"
    );
    drop(source);
    drop(backup);
    stdfs::remove_dir_all(moved_a).unwrap();
    stdfs::remove_dir_all(moved_b).unwrap();
}

fn independent_start(a: &Area, b: &Area, old: &[u8], new: &[u8], intent: &KeyCleanupStart) {
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    let input = serde_json::json!({
        "source": a.0, "backup": b.0, "target": RESIDUE, "preserved": "saved",
        "old": hex(old), "new": hex(new), "operation": hex(&intent.operation_id),
        "hash": hex(&intent.after.snapshot_hash), "public_key": hex(&intent_public_key()),
    });
    let mut child = Command::new(
        std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
    )
    .args(["tests/key_history_reference.py", "--started"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "independent start checker failed (details suppressed)"
    );
}
fn intent_public_key() -> [u8; 32] {
    super::super::super::tests::unhex(
        super::super::super::tests::a13()["public_key_hex"]
            .as_str()
            .unwrap(),
    )
    .try_into()
    .unwrap()
}

#[test]
fn cleanup_start_process_kill_keeps_old_or_active_history_and_never_adopts_updates() {
    if let Some(path) = std::env::var_os("LNGNB_PUBLIC_CLEANUP_START_AREA") {
        let backup_path = std::env::var_os("LNGNB_PUBLIC_CLEANUP_START_BACKUP").unwrap();
        let mut source = KeyDirectory::open(Path::new(&path)).unwrap();
        let mut backup = KeyDirectory::open(Path::new(&backup_path)).unwrap();
        let marker = stdfs::read(Path::new(&path).join(recovery_hold::MARKER)).unwrap();
        let area_id: [u8; 32] = marker[21..53].try_into().unwrap();
        let expected = KeyCleanupExpected {
            state: source.key_state_history(&area_id).unwrap(),
            target: KeyFileIdentity::from_metadata(
                &stdfs::metadata(Path::new(&path).join(RESIDUE)).unwrap(),
            ),
            preserved_directory: KeyDirectoryIdentity::from_metadata(
                &stdfs::metadata(&backup_path).unwrap(),
            ),
            preserved: KeyFileIdentity::from_metadata(
                &stdfs::metadata(Path::new(&backup_path).join("saved")).unwrap(),
            ),
            public_key: intent_public_key(),
        };
        let stage = std::env::var("LNGNB_PUBLIC_CLEANUP_START_POINT").unwrap();
        let (_, pass) = fixture();
        let mut hook = |s: S| {
            if format!("{s:?}") == stage {
                println!("READY");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        };
        let prepared = source
            .prepare_residue_cleanup_with(
                RESIDUE,
                &pass,
                &mut backup,
                "saved",
                &expected,
                [0x73; 32],
                42,
                &mut hook,
            )
            .unwrap();
        let _ = prepared.start_with(&mut hook);
        panic!("kill hook not reached");
    }
    for stage in [
        S::StateDirectorySynced,
        S::Prepared,
        S::Exchanged,
        S::StateSynced,
        S::OldSnapshotRemoved,
    ] {
        let (a, b, source, backup, expected, key, pass) = setup();
        let old = snapshot(&a);
        drop(source);
        drop(backup);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "keyfile::files::tests::cleanup_start_tests::cleanup_start_process_kill_keeps_old_or_active_history_and_never_adopts_updates", "--nocapture"])
            .env("LNGNB_PUBLIC_CLEANUP_START_AREA", &a.0)
            .env("LNGNB_PUBLIC_CLEANUP_START_BACKUP", &b.0)
            .env("LNGNB_PUBLIC_CLEANUP_START_POINT", format!("{stage:?}"))
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(stdout.read_line(&mut line).unwrap() > 0);
            if line.trim() == "READY" {
                break;
            }
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        preserved(&a, &b, &key);
        let mut source = KeyDirectory::open(&a.0).unwrap();
        e(source.create("later", &pass), KeyFileError::PendingRecovery);
        assert!(source.load("publisher", &pass).is_ok());
        assert_eq!(
            snapshot(&a) == old,
            matches!(stage, S::StateDirectorySynced | S::Prepared)
        );
        let temp =
            a.0.join(format!(".lngnb-key-state-update-{}", "73".repeat(32)));
        if matches!(stage, S::Prepared | S::Exchanged | S::StateSynced) {
            assert!(temp.exists());
            assert!(
                source
                    .key_state_history(&expected.state.initial.area_id)
                    .is_err()
            );
        }
        if stage != S::StateDirectorySynced {
            assert!(
                source
                    .recover_initial_key_state(&expected.state.initial)
                    .is_err()
            );
        }
    }
}

fn set_field(v: &mut Value, key: &str, value: Value) {
    let Value::Map(m) = v else { panic!() };
    m.iter_mut().find(|(k, _)| k == key).unwrap().1 = value;
}
fn event_id(n: u64) -> [u8; 32] {
    let mut id = [0xab; 32];
    id[24..].copy_from_slice(&n.to_be_bytes());
    id
}
#[test]
fn cleanup_start_keeps_completed_history_prefix_and_rejects_maximum_held() {
    let (a, b, mut source, mut backup, mut expected, key, pass) = setup();
    prepare(&mut source, &mut backup, &pass, &expected)
        .unwrap()
        .start()
        .unwrap();
    let mut state = cbor::decode(&snapshot(&a)).unwrap();
    let Value::Map(m) = &mut state else { panic!() };
    let Value::Array(events) = &mut m.iter_mut().find(|(k, _)| k == "events").unwrap().1 else {
        panic!()
    };
    let original_start = events[1].clone();
    // 完了処理は未実装。これは全prefix保持を検査する試験側の合成履歴。
    events.push(Value::Map(vec![
        ("sequence".into(), Value::Int(3)),
        ("operation_id".into(), Value::Bytes(event_id(3).to_vec())),
        (
            "kind".into(),
            Value::Text("residue_cleanup_completed".into()),
        ),
        (
            "actor_uid".into(),
            Value::Bytes(rustix::process::geteuid().as_raw().to_be_bytes().to_vec()),
        ),
        ("recorded_unix_seconds".into(), Value::Int(42)),
        ("rules".into(), Value::Text("lngnb-key-operations-1".into())),
        ("started_operation_id".into(), Value::Bytes(vec![0x73; 32])),
        ("disposition".into(), Value::Text("removed_present".into())),
    ]));
    let completed = events[2].clone();
    let first = events[0].clone();
    stdfs::write(
        a.0.join(initial_state::STATE),
        cbor::encode(&state).unwrap(),
    )
    .unwrap();
    expected.state = source
        .key_state_history(&expected.state.initial.area_id)
        .unwrap();
    let previous = snapshot(&a);
    let prepared = source
        .prepare_residue_cleanup_with(
            RESIDUE,
            &pass,
            &mut backup,
            "saved",
            &expected,
            [0x74; 32],
            41,
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(prepared.start().unwrap().generation, 4);
    let after = cbor::decode(&snapshot(&a)).unwrap();
    let old = cbor::decode(&previous).unwrap();
    let get_events = |value: Value| {
        let Value::Map(m) = value else { panic!() };
        let Value::Array(events) = m.into_iter().find(|(k, _)| k == "events").unwrap().1 else {
            panic!()
        };
        events
    };
    assert_eq!(&get_events(after)[..3], get_events(old));
    let mut all = vec![first];
    for n in 2..=1023 {
        let mut event = if n % 2 == 0 {
            original_start.clone()
        } else {
            completed.clone()
        };
        set_field(&mut event, "sequence", Value::Int(n as i64));
        set_field(
            &mut event,
            "operation_id",
            Value::Bytes(event_id(n).to_vec()),
        );
        if n % 2 != 0 {
            set_field(
                &mut event,
                "started_operation_id",
                Value::Bytes(event_id(n - 1).to_vec()),
            );
        }
        all.push(event);
    }
    set_field(&mut state, "events", Value::Array(all));
    let max = cbor::encode(&state).unwrap();
    stdfs::write(a.0.join(initial_state::STATE), &max).unwrap();
    expected.state = source
        .key_state_history(&expected.state.initial.area_id)
        .unwrap();
    assert_eq!(expected.state.generation, 1023);
    assert!(prepare(&mut source, &mut backup, &pass, &expected).is_err());
    assert_eq!(snapshot(&a), max);
    preserved(&a, &b, &key);
}

#[test]
fn cleanup_start_rejects_artifacts_links_modes_and_incomplete_ciphertext_before_append() {
    for case in 0..6 {
        let (a, b, mut source, mut backup, mut expected, key, pass) = setup();
        let old = snapshot(&a);
        match case {
            0 => a.put(".lngnb-key-state-update-existing", b"unadopted"),
            1 => {
                stdfs::remove_file(b.0.join("saved")).unwrap();
                symlink(a.0.join(RESIDUE), b.0.join("saved")).unwrap();
            }
            2 => {
                stdfs::hard_link(b.0.join("saved"), b.0.join("alias")).unwrap();
            }
            3 => {
                stdfs::set_permissions(b.0.join("saved"), stdfs::Permissions::from_mode(0o640))
                    .unwrap();
            }
            4 => {
                stdfs::write(b.0.join("saved"), b"incomplete").unwrap();
            }
            _ => {
                stdfs::remove_file(a.0.join(RESIDUE)).unwrap();
            }
        }
        // 更新した診断値を与えても、危険な現物を資格にしない。
        if let Ok(meta) = stdfs::symlink_metadata(b.0.join("saved")) {
            expected.preserved = KeyFileIdentity::from_metadata(&meta);
        }
        assert!(prepare(&mut source, &mut backup, &pass, &expected).is_err());
        assert_eq!(snapshot(&a), old);
        assert_eq!(stdfs::read(a.0.join("publisher")).unwrap(), key);
        e(source.create("later", &pass), KeyFileError::PendingRecovery);
    }
}

#[test]
fn cleanup_start_rechecks_changes_at_exchange_and_old_snapshot_cleanup_boundaries() {
    for stage in [S::BeforeCreate, S::BeforeExchange, S::BeforeCleanup] {
        for kind in [
            "target_mode",
            "preserved_bytes",
            "state_bytes",
            "missing",
            "extra_candidate",
            "old_snapshot",
        ] {
            if kind == "old_snapshot" && stage != S::BeforeCleanup {
                continue;
            }
            let (a, b, mut source, mut backup, expected, key, pass) = setup();
            let prepared = prepare(&mut source, &mut backup, &pass, &expected).unwrap();
            let temp =
                a.0.join(format!(".lngnb-key-state-update-{}", "73".repeat(32)));
            assert!(
                prepared
                    .start_with(&mut |s| {
                        if s == stage {
                            match kind {
                                "target_mode" => stdfs::set_permissions(
                                    a.0.join(RESIDUE),
                                    stdfs::Permissions::from_mode(0o640),
                                )
                                .unwrap(),
                                "preserved_bytes" => {
                                    stdfs::write(b.0.join("saved"), b"changed by test").unwrap()
                                }
                                "state_bytes" => {
                                    stdfs::write(a.0.join(initial_state::STATE), b"changed by test")
                                        .unwrap()
                                }
                                "missing" => stdfs::remove_file(b.0.join("saved")).unwrap(),
                                "extra_candidate" => {
                                    a.put(".lngnb-key-state-update-other", b"unadopted")
                                }
                                _ => stdfs::write(&temp, b"changed by test").unwrap(),
                            }
                        }
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(stdfs::read(a.0.join("publisher")).unwrap(), key);
            assert_eq!(stdfs::read(a.0.join(RESIDUE)).unwrap(), key);
            if stage == S::BeforeCleanup {
                assert!(temp.exists());
            }
            e(source.create("later", &pass), KeyFileError::PendingRecovery);
        }
    }
}
