//! 公開固定値/隔離領域だけ。Ready診断は解除・保存・認証の資格ではない。
use super::*;

fn file(dev: u64, ino: u64, length: u64, owner: [u8; 4]) -> Value {
    let mut v = file_identity();
    for (k, value) in [
        ("dev", b(dev.to_be_bytes())),
        ("ino", b(ino.to_be_bytes())),
        ("length", b(length.to_be_bytes())),
        ("uid", b(owner)),
    ] {
        set(&mut v, k, value);
    }
    v
}
fn resumed(n: usize, source: &[u8]) -> Value {
    let owner: [u8; 4] = source[69..73].try_into().unwrap();
    let dev = u64::from_be_bytes(source[53..61].try_into().unwrap());
    let mut fields = common(n, RESUMED);
    fields.extend([
        (
            "current",
            m(vec![
                ("name", t("publisher")),
                ("identity", file(dev, u64::MAX, 4096, owner)),
                ("ciphertext_sha256", b([0x33; 32])),
                ("public_key", b([0x44; 32])),
            ]),
        ),
        (
            "preserved",
            m(vec![
                ("name", t("saved")),
                ("identity", file(u64::MAX, 1 << 63, 4096, owner)),
                (
                    "directory",
                    m(vec![
                        ("dev", b(u64::MAX.to_be_bytes())),
                        ("ino", b((1u64 << 63).to_be_bytes())),
                        ("uid", b(owner)),
                    ]),
                ),
            ]),
        ),
        ("guard_identity", file(dev, u64::MAX - 1, 49, owner)),
        (
            "cleanup_operations",
            Value::Array((3..n).step_by(2).map(|i| b(id(i))).collect()),
        ),
        ("reason", t("reviewed_current_key_and_preservations")),
    ]);
    let mut v = m(fields);
    set(&mut v, "actor_uid", b(owner));
    v
}
fn ready(count: usize) -> Value {
    let mut v = history(count - 1);
    let Value::Array(mut events) = field(&v, "events").unwrap().clone() else {
        panic!()
    };
    events.push(resumed(count, &source()));
    set(&mut v, "events", Value::Array(events));
    v
}
fn edit(v: &mut Value, path: &[&str], key: &str, value: Value) {
    if path.is_empty() {
        set(v, key, value);
        return;
    }
    let mut child = field(v, path[0]).unwrap().clone();
    edit(&mut child, &path[1..], key, value);
    set(v, path[0], child);
}
fn reject_event(event: Value) {
    let mut v = ready(6);
    *event_mut(&mut v, 5) = event;
    assert!(decode(&v).is_err());
}

#[test]
fn resume_codec_derives_only_terminal_ready_and_retains_full_prefix_root() {
    for count in [2, 4, 6, 24, 256, 1024] {
        let v = ready(count);
        let raw = encoded(&v).unwrap();
        let d = decode(&v).unwrap();
        assert_eq!(
            d.state,
            KeyHistoryState::Ready {
                resumed_operation_id: id(count)
            }
        );
        assert_eq!(d.generation, count as u64);
        assert_eq!(d.initial.snapshot_hash, root());
        assert_eq!(d.snapshot_hash, <[u8; 32]>::from(Sha256::digest(&raw)));
        let Value::Array(events) = field(&v, "events").unwrap() else {
            panic!()
        };
        assert_eq!(
            events[..count - 1].to_vec(),
            match field(&history(count - 1), "events").unwrap() {
                Value::Array(e) => e.clone(),
                _ => panic!(),
            }
        );
        assert!(raw.len() < initial_state::STATE_LIMIT);
    }
    // 過去のactor_uid=u32::MAXを新kindの所有者条件で遡及拒否しない。
    assert!(decode(&ready(6)).is_ok());
    for (key, bad) in [("source_marker", b([0; 73])), ("area_id", b([0; 32]))] {
        let mut v = ready(4);
        set(&mut v, key, bad);
        assert!(decode(&v).is_err());
    }
    let mut v = ready(4);
    set(event_mut(&mut v, 0), "operation_id", b(id(77)));
    assert!(decode(&v).is_err());
}

#[test]
fn resume_codec_rejects_every_nested_missing_extra_null_and_raw_duplicate_key() {
    fn walk(event: &Value, child: &Value, path: &[&str]) {
        let Value::Map(items) = child else {
            return;
        };
        for (key, value) in items {
            let mut bad = event.clone();
            let mut sub = child.clone();
            remove(&mut sub, key);
            if path.is_empty() {
                reject_event(sub);
            } else {
                edit(&mut bad, &path[..path.len() - 1], path[path.len() - 1], sub);
                reject_event(bad);
            }
            let mut bad = event.clone();
            edit(&mut bad, path, key, Value::Null);
            reject_event(bad);
            let mut next = path.to_vec();
            next.push(key);
            walk(event, value, &next);
        }
        let mut bad_child = child.clone();
        let Value::Map(fields) = &mut bad_child else {
            unreachable!()
        };
        fields.push(("extra".into(), Value::Null));
        let mut bad = event.clone();
        if path.is_empty() {
            reject_event(bad_child);
        } else {
            edit(
                &mut bad,
                &path[..path.len() - 1],
                path[path.len() - 1],
                bad_child,
            );
            reject_event(bad);
        }
        // encoderを通さず各mapへ重複pairを挿入し、製品decoder経由で拒否を確認。
        let child_raw = encoded(child).unwrap();
        assert!(items.len() < 23);
        let mut duplicate = child_raw.clone();
        duplicate[0] += 1;
        duplicate.extend(encoded(&t(&items[0].0)).unwrap());
        duplicate.extend(encoded(&items[0].1).unwrap());
        let mut v = ready(6);
        *event_mut(&mut v, 5) = event.clone();
        let raw = encoded(&v).unwrap();
        let position = raw
            .windows(child_raw.len())
            .rposition(|w| w == child_raw)
            .unwrap();
        let mut corrupt = raw[..position].to_vec();
        corrupt.extend(duplicate);
        corrupt.extend_from_slice(&raw[position + child_raw.len()..]);
        assert!(decode_history(&corrupt, &source(), [0x42; 32], root()).is_err());
    }
    let e = resumed(6, &source());
    walk(&e, &e, &[]);
}

#[test]
fn resume_codec_rejects_identity_name_and_scalar_relations() {
    let good = resumed(6, &source());
    for (path, key, bad) in [
        (vec![], "kind", t("future")),
        (vec![], "rules", t("future")),
        (vec![], "reason", t("confirmed")),
        (vec![], "actor_uid", b(4u32.to_be_bytes())),
        (vec![], "actor_uid", b([0; 3])),
        (vec![], "operation_id", b([0; 31])),
        (vec![], "sequence", Value::Int(7)),
        (vec![], "recorded_unix_seconds", Value::Int(-1)),
        (vec!["current"], "ciphertext_sha256", b([0; 31])),
        (vec!["current"], "public_key", b([0; 33])),
        (vec!["current"], "name", t(".lngnb-key-x")),
        (vec!["preserved"], "name", t("../saved")),
        (vec!["current", "identity"], "dev", b(2u64.to_be_bytes())),
        (vec!["preserved", "identity"], "dev", b(1u64.to_be_bytes())),
        (
            vec!["preserved", "identity"],
            "length",
            b(1u64.to_be_bytes()),
        ),
        (vec!["preserved", "directory"], "uid", b(4u32.to_be_bytes())),
        (vec!["guard_identity"], "length", b(48u64.to_be_bytes())),
        (vec!["guard_identity"], "dev", b(2u64.to_be_bytes())),
    ] {
        let mut e = good.clone();
        edit(&mut e, &path, key, bad);
        reject_event(e);
    }
    for path in [
        &["current", "identity"][..],
        &["preserved", "identity"],
        &["guard_identity"],
    ] {
        for (key, bad) in [
            ("dev", Value::Int(i64::MAX)),
            ("ino", b([0; 7])),
            ("length", b(0u64.to_be_bytes())),
            ("length", b(4097u64.to_be_bytes())),
            ("nlink", b(2u64.to_be_bytes())),
            ("uid", b(4u32.to_be_bytes())),
            ("mode", b(0o100640u32.to_be_bytes())),
            ("mtime_seconds", Value::Bool(true)),
            ("ctime_seconds", b([0; 8])),
            ("mtime_nanoseconds", Value::Int(-1)),
            ("ctime_nanoseconds", Value::Int(1_000_000_000)),
        ] {
            let mut e = good.clone();
            edit(&mut e, path, key, bad);
            reject_event(e);
        }
    }
    for (a, bpath) in [
        (&["current", "identity"][..], &["guard_identity"][..]),
        (&["current", "identity"], &["preserved", "identity"]),
        (&["guard_identity"], &["preserved", "identity"]),
    ] {
        let mut e = good.clone();
        let mut id_value = &good;
        for k in a {
            id_value = field(id_value, k).unwrap();
        }
        for k in ["dev", "ino"] {
            edit(&mut e, bpath, k, field(id_value, k).unwrap().clone());
        }
        // 保全先devも合わせ、dev不整合の拒否だけに依存しない。
        if bpath[0] == "preserved" {
            edit(
                &mut e,
                &["preserved", "directory"],
                "dev",
                field(id_value, "dev").unwrap().clone(),
            );
        }
        reject_event(e);
    }
    for n in ["", ".", "..", "a/b", "é", &"a".repeat(129)] {
        let mut e = good.clone();
        edit(&mut e, &["current"], "name", t(n));
        reject_event(e);
    }
    let mut e = good;
    edit(&mut e, &["current"], "name", t(&"a".repeat(128)));
    let mut v = ready(6);
    *event_mut(&mut v, 5) = e;
    assert!(decode(&v).is_ok());
}

#[test]
fn resume_codec_rejects_reference_gaps_reordering_ids_and_all_following_events() {
    for refs in [
        vec![],
        vec![b(id(3))],
        vec![b(id(5)), b(id(3))],
        vec![b(id(3)), b(id(3))],
        vec![b(id(3)), b(id(2))],
        vec![b(id(3)), b(id(99))],
        vec![b(id(3)), b([0; 31])],
        vec![b(id(3)), b(id(5)), b(id(7))],
    ] {
        let mut e = resumed(6, &source());
        set(&mut e, "cleanup_operations", Value::Array(refs));
        reject_event(e);
    }
    for duplicate in [1, 2, 3, 4, 5] {
        let mut e = resumed(6, &source());
        set(&mut e, "operation_id", b(id(duplicate)));
        reject_event(e);
    }
    let mut active = history(2);
    let Value::Array(mut events) = field(&active, "events").unwrap().clone() else {
        panic!()
    };
    events.push(resumed(3, &source()));
    set(&mut active, "events", Value::Array(events));
    assert!(decode(&active).is_err());
    for next in [
        resumed(3, &source()),
        start(3),
        complete(3, ABSENT),
        field(&history(1), "events").unwrap().clone(),
    ] {
        let mut v = ready(2);
        let Value::Array(mut events) = field(&v, "events").unwrap().clone() else {
            panic!()
        };
        events.push(next);
        set(&mut v, "events", Value::Array(events));
        assert!(decode(&v).is_err());
    }
}

#[test]
fn resume_codec_checks_caps_canonical_bytes_and_past_start_reservation() {
    assert!(decode(&ready(1024)).is_ok());
    assert!(decode(&ready(1026)).is_err());
    let mut v = history(1024);
    let Value::Array(mut events) = field(&v, "events").unwrap().clone() else {
        panic!()
    };
    events.push(resumed(1025, &source()));
    set(&mut v, "events", Value::Array(events));
    assert!(decode(&v).is_err());
    let raw = encoded(&ready(4)).unwrap();
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(decode_history(&trailing, &source(), [0x42; 32], root()).is_err());
    for prefix in [&[0xbf][..], &[0xb8, 4], &[0xc0], &[0xf9, 0, 0]] {
        let mut bad = prefix.to_vec();
        bad.extend_from_slice(&raw[1..]);
        assert!(decode_history(&bad, &source(), [0x42; 32], root()).is_err());
    }
    // 正常なprofileの最大履歴は1 MiB未満。上限近傍のpaddingは不正CBORであり合格例とはしない。
    for len in [
        initial_state::STATE_LIMIT - 1,
        initial_state::STATE_LIMIT,
        initial_state::STATE_LIMIT + 1,
    ] {
        let mut bad = raw.clone();
        bad.resize(len, 0);
        assert!(decode_history(&bad, &source(), [0x42; 32], root()).is_err());
    }
}

#[test]
fn resume_codec_fixed_bytes_hashes_match_independent_python() {
    // 別の小さなCBOR実装で算出し、cbor2でも独立に検査する固定値。
    for (count, length, hash, event_hash) in [
        (
            2,
            1193,
            "84fe2145b9ad4e05544d158029fecb3c4db1ac80e742e3dcaf6537c7c0669101",
            "ba3fafdf78300e14e3f38b23798b8a75f99b572aa72bb7edbb8c27397cfaf8ed",
        ),
        (
            4,
            2370,
            "59d88fbe114ca4af87099134541b4811690baa53062fb4a1d2b0eb050ecbb799",
            "e91197917345ad6a7a9ed5520d18edcf7e7badee971885b669ba8ca0df7f68d5",
        ),
    ] {
        let v = ready(count);
        let raw = encoded(&v).unwrap();
        assert_eq!(raw.len(), length);
        assert_eq!(data_encoding::HEXLOWER.encode(&Sha256::digest(&raw)), hash);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(
                encoded(&resumed(count, &source())).unwrap()
            )),
            event_hash
        );
    }
    let cases: Vec<_> = [2, 4, 24, 256, 1024].into_iter().map(|count| {
        let v = ready(count); let d = decode(&v).unwrap();
        serde_json::json!({"count": count, "snapshot": data_encoding::HEXLOWER.encode(&encoded(&v).unwrap()),
            "hash": data_encoding::HEXLOWER.encode(&d.snapshot_hash), "root": data_encoding::HEXLOWER.encode(&root())})
    }).collect();
    let mut child = Command::new(
        std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
    )
    .arg("tests/key_resume_reference.py")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "independent resume checker failed (details suppressed)"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["checked"], 5);
}

#[test]
fn resume_diagnostic_keeps_guard_stop_and_initial_api_boundaries() {
    use std::fs as stdfs;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let path = std::env::temp_dir().join(format!("lngnb-resume-codec-{}", std::process::id()));
    stdfs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let mut dir = KeyDirectory::open(&path).unwrap();
    let public = dir
        .create("publisher", "public isolated test password")
        .unwrap();
    let key = stdfs::read(path.join("publisher")).unwrap();
    let KeyRecoveryHold::Held { area_id } = dir.initialize_recovery_hold().unwrap() else {
        panic!()
    };
    let initial = dir.initialize_key_state(&area_id).unwrap();
    let marker = stdfs::read(path.join(recovery_hold::MARKER)).unwrap();
    let guard_bytes = stdfs::read(path.join(recovery_hold::GUARD)).unwrap();
    let raw = stdfs::read(path.join(initial_state::STATE)).unwrap();
    let mut value = cbor::decode(&raw).unwrap();
    let Value::Bytes(source) = field(&value, "source_marker").unwrap() else {
        panic!()
    };
    let mut event = resumed(2, source);
    let operation = if initial.operation_id == id(2) {
        id(3)
    } else {
        id(2)
    };
    set(&mut event, "operation_id", b(operation));
    let meta =
        KeyFileIdentity::from_metadata(&stdfs::metadata(path.join(recovery_hold::GUARD)).unwrap());
    let guard = m(vec![
        ("dev", b(meta.dev.to_be_bytes())),
        ("ino", b(meta.ino.to_be_bytes())),
        ("length", b(meta.length.to_be_bytes())),
        ("nlink", b(meta.nlink.to_be_bytes())),
        ("uid", b(meta.uid.to_be_bytes())),
        ("mode", b(meta.mode.to_be_bytes())),
        ("mtime_seconds", Value::Int(meta.mtime_seconds)),
        ("ctime_seconds", Value::Int(meta.ctime_seconds)),
        ("mtime_nanoseconds", Value::Int(meta.mtime_nanoseconds)),
        ("ctime_nanoseconds", Value::Int(meta.ctime_nanoseconds)),
    ]);
    set(&mut event, "guard_identity", guard);
    let Value::Array(mut events) = field(&value, "events").unwrap().clone() else {
        panic!()
    };
    events.push(event);
    set(&mut value, "events", Value::Array(events));
    // 隔離fixtureへ合成履歴を配置。製品append/再開APIではない。
    let bytes = encoded(&value).unwrap();
    stdfs::write(path.join(initial_state::STATE), &bytes).unwrap();
    assert_eq!(
        dir.key_state_history(&area_id).unwrap().state,
        KeyHistoryState::Ready {
            resumed_operation_id: operation
        }
    );
    assert!(dir.initial_key_state(&area_id).is_err());
    assert!(dir.recover_initial_key_state(&initial).is_err());
    assert!(dir.initialize_key_state(&area_id).is_err());
    assert!(dir.initialize_recovery_hold().is_err());
    assert!(dir.recover_initial_hold(&area_id).is_err());
    assert_eq!(
        dir.create("later", "public isolated test password").err(),
        Some(KeyFileError::PendingRecovery)
    );
    assert_eq!(
        dir.change_passphrase(
            "publisher",
            "public isolated test password",
            "different public password"
        )
        .err(),
        Some(KeyFileError::PendingRecovery)
    );
    assert_eq!(
        dir.load("publisher", "public isolated test password")
            .unwrap()
            .public_key(),
        public
    );
    assert_eq!(stdfs::read(path.join("publisher")).unwrap(), key);
    assert_eq!(
        stdfs::read(path.join(recovery_hold::MARKER)).unwrap(),
        marker
    );
    assert_eq!(
        stdfs::read(path.join(recovery_hold::GUARD)).unwrap(),
        guard_bytes
    );
    assert_eq!(stdfs::read(path.join(initial_state::STATE)).unwrap(), bytes);
    let artifact = path.join(".lngnb-key-state-update-unknown");
    stdfs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&artifact)
        .unwrap();
    assert!(dir.key_state_history(&area_id).is_err());
    stdfs::remove_file(artifact).unwrap();
    stdfs::rename(path.join(recovery_hold::GUARD), path.join("retained-guard")).unwrap();
    stdfs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join(recovery_hold::GUARD))
        .unwrap()
        .write_all(&guard_bytes)
        .unwrap();
    assert!(dir.key_state_history(&area_id).is_err()); // 同bytes別inodeを拒否。
    stdfs::remove_file(path.join(recovery_hold::GUARD)).unwrap();
    drop(dir);
    let mut dir = KeyDirectory::open(&path).unwrap();
    assert!(dir.key_state_history(&area_id).is_err()); // 不在を解除成功へ昇格しない。
    assert_eq!(
        dir.create("later", "public isolated test password").err(),
        Some(KeyFileError::PendingRecovery)
    );
    assert_eq!(stdfs::read(path.join("publisher")).unwrap(), key);
    assert_eq!(stdfs::read(path.join(initial_state::STATE)).unwrap(), bytes);
    drop(dir);
    stdfs::remove_dir_all(path).unwrap();
}

#[path = "keyfile_passphrase_journal_tests.rs"]
mod passphrase_tests;
