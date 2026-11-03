//! §5.100/R27/R34: 公開固定値だけ。製品の追記/物理整理試験ではない。
use super::*;
use std::process::{Command, Stdio};

fn m(items: Vec<(&str, Value)>) -> Value {
    Value::Map(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn b<const N: usize>(a: [u8; N]) -> Value {
    Value::Bytes(a.to_vec())
}
fn t(s: &str) -> Value {
    Value::Text(s.into())
}
fn set(v: &mut Value, key: &str, replacement: Value) {
    let Value::Map(items) = v else { panic!() };
    *items.iter_mut().find(|(k, _)| k == key).unwrap() = (key.into(), replacement);
}
fn remove(v: &mut Value, key: &str) {
    let Value::Map(items) = v else { panic!() };
    items.retain(|(k, _)| k != key);
}
fn id(n: usize) -> [u8; 32] {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&(n as u64).to_be_bytes());
    out
}
fn source() -> Vec<u8> {
    let mut source = b"lngnb:key-recovery:1\0".to_vec();
    source.extend([0x42; 32]);
    source.extend(1u64.to_be_bytes());
    source.extend(2u64.to_be_bytes());
    source.extend(3u32.to_be_bytes());
    source
}
fn file_identity() -> Value {
    m(vec![
        ("dev", b(u64::MAX.to_be_bytes())),
        ("ino", b((1u64 << 63).to_be_bytes())),
        ("length", b(4096u64.to_be_bytes())),
        ("nlink", b(1u64.to_be_bytes())),
        ("uid", b(3u32.to_be_bytes())),
        ("mode", b(0o100600u32.to_be_bytes())),
        ("mtime_seconds", Value::Int(i64::MIN)),
        ("ctime_seconds", Value::Int(i64::MAX)),
        ("mtime_nanoseconds", Value::Int(0)),
        ("ctime_nanoseconds", Value::Int(999_999_999)),
    ])
}
fn common(n: usize, kind: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("sequence", Value::Int(n as i64)),
        ("operation_id", b(id(n))),
        ("kind", t(kind)),
        ("actor_uid", b(u32::MAX.to_be_bytes())),
        ("recorded_unix_seconds", Value::Int(if n % 2 == 0 { i64::MAX } else { 0 })),
        ("rules", t(RULES)),
    ]
}
fn start(n: usize) -> Value {
    let mut fields = common(n, STARTED);
    let mut preserved_identity = file_identity();
    set(&mut preserved_identity, "ino", b(((1u64 << 63) + 1).to_be_bytes()));
    fields.extend([
        ("target", m(vec![
            ("name", t(&format!(".lngnb-key-{}", "a".repeat(64)))),
            ("identity", file_identity()),
            ("ciphertext_sha256", b([0x11; 32])),
            ("public_key", b([0x22; 32])),
        ])),
        ("preserved", m(vec![
            ("name", t(&"b".repeat(128))),
            ("directory", m(vec![
                ("dev", b(u64::MAX.to_be_bytes())),
                ("ino", b((1u64 << 63).to_be_bytes())),
                ("uid", b(3u32.to_be_bytes())),
            ])),
            ("identity", preserved_identity),
        ])),
    ]);
    m(fields)
}
fn complete(n: usize, disposition: &str) -> Value {
    let mut fields = common(n, COMPLETED);
    fields.extend([
        ("started_operation_id", b(id(n - 1))),
        ("disposition", t(disposition)),
    ]);
    m(fields)
}
fn history(count: usize) -> Value {
    let mut v = initial_state::initial_value(&source(), [0x42; 32], id(1));
    let mut events = vec![field(&v, "events").unwrap().clone()];
    let Value::Array(mut items) = events.remove(0) else { panic!() };
    for n in 2..=count {
        items.push(if n % 2 == 0 { start(n) } else { complete(n, ABSENT) });
    }
    set(&mut v, "events", Value::Array(items));
    v
}
fn root() -> [u8; 32] {
    Sha256::digest(encoded(&history(1)).unwrap()).into()
}
fn decode(v: &Value) -> Result<KeyStateDiagnostic> {
    decode_history(&encoded(v).unwrap(), &source(), [0x42; 32], root())
}
fn event_mut(v: &mut Value, index: usize) -> &mut Value {
    let Value::Map(items) = v else { panic!() };
    let Value::Array(events) = &mut items.iter_mut().find(|(k, _)| k == "events").unwrap().1 else { panic!() };
    &mut events[index]
}

#[test]
fn history_derives_held_active_and_preserves_every_event_and_initial_root() {
    for count in [1, 2, 3, 4, 5, 23, 24, 255, 256, 1023] {
        let v = history(count);
        let original = encoded(&v).unwrap();
        let result = decode(&v).unwrap();
        assert_eq!(result.generation, count as u64);
        assert_eq!(result.initial.generation, 1);
        assert_eq!(result.initial.snapshot_hash, root());
        assert_eq!(result.snapshot_hash, <[u8; 32]>::from(Sha256::digest(&original)));
        assert_eq!(result.state, if count % 2 == 0 {
            KeyHistoryState::Active { started_operation_id: id(count) }
        } else { KeyHistoryState::Held });
        assert_eq!(encoded(&v).unwrap(), original);
    }
    for disposition in ["removed_present", ABSENT] {
        let mut v = history(3);
        set(event_mut(&mut v, 2), "disposition", t(disposition));
        assert_eq!(decode(&v).unwrap().state, KeyHistoryState::Held);
    }
    let mut altered = history(3);
    set(event_mut(&mut altered, 0), "operation_id", b(id(99)));
    assert!(decode(&altered).is_err());
    let bytes = encoded(&history(3)).unwrap();
    assert!(decode_history(&bytes, &source(), [0; 32], root()).is_err());
    assert!(decode_history(&bytes, &source(), [0x42; 32], [0; 32]).is_err());
    let mut other_source = source();
    other_source[72] ^= 1;
    assert!(decode_history(&bytes, &other_source, [0x42; 32], root()).is_err());
}

#[test]
fn history_rejects_all_missing_extra_duplicate_wrong_type_and_unknown_fields() {
    // 全階層の各必須fieldを独立に壊す。schemaを生成側のroundtripで判定しない。
    fn corrupt_maps(value: &mut Value, originals: &mut Vec<Value>) {
        let Value::Map(items) = value else { return };
        for (_, child) in items.iter_mut() {
            if let Value::Map(_) = child {
                originals.push(child.clone());
                corrupt_maps(child, originals);
            }
        }
    }
    let mut v = history(3);
    let mut maps = vec![v.clone(), event_mut(&mut v, 0).clone(), event_mut(&mut v, 1).clone(), event_mut(&mut v, 2).clone()];
    corrupt_maps(event_mut(&mut v, 1), &mut maps);
    for original in maps {
        let Value::Map(items) = &original else { panic!() };
        let expected: Vec<_> = items.iter().map(|(k, _)| k.as_str()).collect();
        for (key, _) in items {
            let mut missing = original.clone();
            remove(&mut missing, key);
            assert!(keys(&missing, &expected).is_err());
        }
        let mut extra = original.clone();
        let Value::Map(items) = &mut extra else { panic!() };
        items.push(("unknown".into(), Value::Null));
        assert!(keys(&extra, &expected).is_err());
        let mut duplicate = original.clone();
        let Value::Map(items) = &mut duplicate else { panic!() };
        items.push(items[0].clone());
        assert!(cbor::encode(&duplicate).is_err());
    }
    for (index, key, bad) in [
        (0, "kind", t("future")), (0, "sequence", Value::Bool(true)),
        (1, "kind", t("future")), (1, "sequence", Value::Int(3)),
        (1, "actor_uid", Value::Int(3)), (1, "actor_uid", b([0; 3])),
        (1, "operation_id", b([0; 31])), (1, "rules", t("lngnb-key-operations-2")),
        (1, "recorded_unix_seconds", Value::Int(-1)),
        (1, "recorded_unix_seconds", Value::Bool(true)),
        (1, "target", Value::Null), (1, "preserved", Value::Null),
        (2, "started_operation_id", b([0; 33])), (2, "disposition", t("future")),
    ] {
        let mut bad_history = history(3);
        set(event_mut(&mut bad_history, index), key, bad);
        assert!(decode(&bad_history).is_err(), "{index} {key}");
    }
    for key in ["format", "area_id", "source_marker", "events"] {
        let mut v = history(3);
        set(&mut v, key, Value::Null);
        assert!(decode(&v).is_err());
    }
}

#[test]
fn history_rejects_references_recompletion_duplicate_ids_and_impossible_transitions() {
    for reference in [id(1), id(3), id(4), id(0)] {
        let mut v = history(3);
        set(event_mut(&mut v, 2), "started_operation_id", b(reference));
        assert!(decode(&v).is_err());
    }
    for (index, duplicate) in [(1, 1), (2, 1), (2, 2), (4, 2)] {
        let mut v = history(5);
        set(event_mut(&mut v, index), "operation_id", b(id(duplicate)));
        assert!(decode(&v).is_err());
    }
    let mut v = history(3);
    *event_mut(&mut v, 2) = start(3);
    assert!(decode(&v).is_err());
    let mut v = history(2);
    *event_mut(&mut v, 1) = complete(2, ABSENT);
    assert!(decode(&v).is_err());
    let mut v = history(4);
    *event_mut(&mut v, 3) = complete(4, ABSENT);
    set(event_mut(&mut v, 3), "started_operation_id", b(id(2)));
    assert!(decode(&v).is_err());
    let mut v = history(5);
    set(event_mut(&mut v, 4), "started_operation_id", b(id(2)));
    assert!(decode(&v).is_err());
    for key in ["target", "actor_uid", "rules"] {
        let mut v = history(3);
        remove(event_mut(&mut v, 1), key);
        assert!(decode(&v).is_err());
    }
}

#[test]
fn history_validates_identity_name_types_lengths_and_full_unsigned_range() {
    let good = start(2);
    assert!(started(&good, &source()).is_ok());
    for (which, key, bad) in [
        ("target", "name", t("publisher")),
        ("target", "name", t(&format!(".lngnb-key-{}", "A".repeat(64)))),
        ("target", "ciphertext_sha256", b([0; 31])),
        ("target", "public_key", b([0; 33])),
        ("preserved", "name", t("../key")),
        ("preserved", "name", t(".lngnb-key-x")),
        ("preserved", "name", t(&"x".repeat(129))),
    ] {
        let mut event = good.clone();
        let mut sub = field(&event, which).unwrap().clone();
        set(&mut sub, key, bad);
        set(&mut event, which, sub);
        assert!(started(&event, &source()).is_err());
    }
    for (key, bad) in [
        ("dev", Value::Int(i64::MAX)), ("ino", b([0; 7])),
        ("length", b(4097u64.to_be_bytes())), ("length", b(0u64.to_be_bytes())),
        ("nlink", b(2u64.to_be_bytes())), ("uid", b(4u32.to_be_bytes())),
        ("mode", b(0o100640u32.to_be_bytes())), ("mode", b(0o104600u32.to_be_bytes())),
        ("mtime_seconds", Value::Bool(true)), ("ctime_seconds", b([0; 8])),
        ("mtime_nanoseconds", Value::Int(-1)), ("ctime_nanoseconds", Value::Int(1_000_000_000)),
    ] {
        let mut identity = file_identity();
        set(&mut identity, key, bad);
        assert!(super::identity(&identity, 3u32.to_be_bytes()).is_err());
    }
    let mut event = good;
    let mut preserved = field(&event, "preserved").unwrap().clone();
    set(&mut preserved, "directory", m(vec![
        ("dev", b(1u64.to_be_bytes())), ("ino", b(2u64.to_be_bytes())),
        ("uid", b(3u32.to_be_bytes())),
    ]));
    set(&mut event, "preserved", preserved);
    assert!(started(&event, &source()).is_err());
}

#[test]
fn history_checks_event_caps_and_every_start_prefix_completion_reservation() {
    assert!(decode(&history(1023)).is_ok());
    // 末尾が完了しても途中の1024件Active開始を救済しない。
    for count in [1024, 1025] {
        assert!(decode(&history(count)).is_err());
    }
    let mut v = history(1);
    set(&mut v, "events", Value::Array(vec![]));
    assert!(decode(&v).is_err());
    let completion = maximum_completion_bytes().unwrap();
    for count in [2, 23, 24, 255, 256, 1022] {
        let growth = array_head(count + 1) - array_head(count);
        let exact = 1000 + completion + growth;
        assert!(!completion_fits(count, 1000, completion, exact - 1));
        assert!(completion_fits(count, 1000, completion, exact));
        assert!(completion_fits(count, 1000, completion, exact + 1));
        assert!(!completion_fits(count, usize::MAX, completion, usize::MAX));
    }
    assert!(!completion_fits(1024, 1, completion, initial_state::STATE_LIMIT));
    let snapshot = vec![0; initial_state::STATE_LIMIT + 1];
    assert!(decode_history(&snapshot, &source(), [0x42; 32], root()).is_err());
}

#[test]
fn history_rejects_noncanonical_duplicate_trailing_and_unknown_version_bytes() {
    let good = encoded(&history(3)).unwrap();
    let mut extra = good.clone();
    extra.push(0);
    assert!(decode_history(&extra, &source(), [0x42; 32], root()).is_err());
    for prefix in [&[0xbf][..], &[0xc0][..], &[0xf9, 0, 0][..], &[0xa2, 0x61, b'x', 0, 0x61, b'x', 0][..], &[0xb8, 4][..]] {
        let mut bad = prefix.to_vec();
        bad.extend_from_slice(&good[1..]);
        assert!(decode_history(&bad, &source(), [0x42; 32], root()).is_err());
    }
    let mut v = history(3);
    set(&mut v, "format", t("lngnb-key-state-2"));
    assert!(decode(&v).is_err());
}

#[test]
fn history_fixed_examples_match_independent_python_cbor_hash_and_reservation() {
    let cases: Vec<_> = [1, 2, 3, 24, 256, 1023].into_iter().map(|count| {
        let bytes = encoded(&history(count)).unwrap();
        let result = decode(&history(count)).unwrap();
        serde_json::json!({
            "count": count, "snapshot": data_encoding::HEXLOWER.encode(&bytes),
            "hash": data_encoding::HEXLOWER.encode(&result.snapshot_hash),
            "root": data_encoding::HEXLOWER.encode(&root()),
            "completion_bytes": maximum_completion_bytes().unwrap(),
        })
    }).collect();
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required");
    let mut child = Command::new(python).arg("tests/key_history_reference.py")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(serde_json::to_string(&cases).unwrap().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "independent history checker failed (details suppressed)");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["checked"], 6);
}

#[test]
fn history_directory_diagnostic_preserves_stop_and_rejects_initial_api_bypass() {
    use std::fs as stdfs;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let path = std::env::temp_dir().join(format!("lngnb-history-{}", std::process::id()));
    stdfs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let mut dir = KeyDirectory::open(&path).unwrap();
    let hold = dir.initialize_recovery_hold().unwrap();
    let KeyRecoveryHold::Held { area_id } = hold else { panic!() };
    let initial = dir.initialize_key_state(&area_id).unwrap();
    let marker_before = stdfs::read(path.join(recovery_hold::MARKER)).unwrap();
    let guard_before = stdfs::read(path.join(recovery_hold::GUARD)).unwrap();
    let original = stdfs::read(path.join(initial_state::STATE)).unwrap();
    let mut snapshot = cbor::decode(&original).unwrap();
    let source = match field(&snapshot, "source_marker").unwrap() {
        Value::Bytes(b) => b.clone(), _ => panic!(),
    };
    let mut event = start(2);
    // この隔離fixtureだけに現在OSの所有者を適用。製品追記APIは存在しない。
    let owner = Value::Bytes(source[69..73].to_vec());
    for which in ["target", "preserved"] {
        let mut sub = field(&event, which).unwrap().clone();
        let mut identity = field(&sub, "identity").unwrap().clone();
        set(&mut identity, "uid", owner.clone());
        set(&mut sub, "identity", identity);
        if which == "preserved" {
            let mut directory = field(&sub, "directory").unwrap().clone();
            set(&mut directory, "uid", owner.clone());
            set(&mut sub, "directory", directory);
        }
        set(&mut event, which, sub);
    }
    // 初回IDとの重複を避け、固定の開始IDを選ぶ（実運用乱数とは別）。
    let start_id = if initial.operation_id == id(2) { id(3) } else { id(2) };
    set(&mut event, "operation_id", b(start_id));
    let Value::Array(mut events) = field(&snapshot, "events").unwrap().clone() else { panic!() };
    events.push(event);
    set(&mut snapshot, "events", Value::Array(events));
    let bytes = encoded(&snapshot).unwrap();
    stdfs::write(path.join(initial_state::STATE), &bytes).unwrap();
    let result = dir.key_state_history(&area_id).unwrap();
    assert_eq!(result.initial, initial);
    assert_eq!(result.state, KeyHistoryState::Active { started_operation_id: start_id });
    assert!(dir.initial_key_state(&area_id).is_err());
    assert!(dir.recover_initial_key_state(&initial).is_err());
    assert!(dir.initialize_key_state(&area_id).is_err());
    assert!(dir.initialize_recovery_hold().is_err());
    assert!(dir.recover_initial_hold(&area_id).is_err());
    assert_eq!(dir.create("later", "public test password").err(), Some(KeyFileError::PendingRecovery));
    assert!(dir.key_state_history(&[0; 32]).is_err());
    assert_eq!(stdfs::read(path.join(initial_state::STATE)).unwrap(), bytes);
    assert_eq!(stdfs::read(path.join(recovery_hold::MARKER)).unwrap(), marker_before);
    assert_eq!(stdfs::read(path.join(recovery_hold::GUARD)).unwrap(), guard_before);
    let extra = path.join(".lngnb-key-state-update-unknown");
    stdfs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(extra).unwrap();
    assert!(dir.key_state_history(&area_id).is_err());
    drop(dir);
    let mut dir = KeyDirectory::open(&path).unwrap();
    assert!(dir.key_state_history(&area_id).is_err());
    assert_eq!(dir.create("later", "public test password").err(), Some(KeyFileError::PendingRecovery));
    drop(dir);
    stdfs::remove_dir_all(path).unwrap();
}
