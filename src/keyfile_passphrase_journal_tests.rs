//! §5.113の公開固定値による履歴codec試験。
use super::*;
use std::io::Write;

const BEGIN: &str = "key_passphrase_change_started";
const PREPARE: &str = "key_passphrase_change_prepared";
const FINISH: &str = "key_passphrase_change_completed";
const REMOVED: &str = "removed_retained_old_ciphertext";
const ABSENT: &str = "confirmed_old_ciphertext_absent";

fn append(snapshot: &mut Value, kind: &str, additional: Vec<(&'static str, Value)>) {
    let hash: [u8; 32] = Sha256::digest(encoded(snapshot).unwrap()).into();
    let Value::Array(mut events) = field(snapshot, "events").unwrap().clone() else {
        panic!()
    };
    let mut fields = common(events.len() + 1, kind);
    fields.extend(additional);
    fields.push(("previous_snapshot_sha256", b(hash)));
    let mut event = m(fields);
    set(&mut event, "actor_uid", b(3u32.to_be_bytes()));
    events.push(event);
    set(snapshot, "events", Value::Array(events));
}

fn snapshots(ready_count: usize, disposition: &str) -> [Value; 3] {
    let mut snapshot = ready(ready_count);
    append(
        &mut snapshot,
        BEGIN,
        vec![
            ("name", t("publisher")),
            ("old_identity", file(1, u64::MAX, 4096, 3u32.to_be_bytes())),
            ("old_ciphertext_sha256", b([0x33; 32])),
            ("new_ciphertext_sha256", b([0x55; 32])),
            ("new_ciphertext_length", Value::Int(512)),
            ("public_key", b([0x44; 32])),
            (
                "guard_identity",
                file(1, u64::MAX - 3, 49, 3u32.to_be_bytes()),
            ),
        ],
    );
    let started = snapshot.clone();
    let mut new = file(1, u64::MAX - 4, 512, 3u32.to_be_bytes());
    append(
        &mut snapshot,
        PREPARE,
        vec![
            ("started_operation_id", b(id(ready_count + 1))),
            ("new_identity", new.clone()),
        ],
    );
    let prepared = snapshot.clone();
    set(&mut new, "ctime_seconds", Value::Int(i64::MIN));
    set(&mut new, "ctime_nanoseconds", Value::Int(1));
    append(
        &mut snapshot,
        FINISH,
        vec![
            ("started_operation_id", b(id(ready_count + 1))),
            ("prepared_operation_id", b(id(ready_count + 2))),
            ("installed_identity", new),
            ("disposition", t(disposition)),
        ],
    );
    [started, prepared, snapshot]
}

#[test]
fn passphrase_journal_fixed_prefixes_match_independent_python() {
    let mut cases = Vec::new();
    for (base, disposition) in [(2, REMOVED), (22, ABSENT), (254, REMOVED), (1020, ABSENT)] {
        let states = [
            KeyHistoryState::PassphraseChangeStarted {
                started_operation_id: id(base + 1),
            },
            KeyHistoryState::PassphraseChangePrepared {
                prepared_operation_id: id(base + 2),
            },
            KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id: id(base + 3),
            },
        ];
        let mut raw = Vec::new();
        for (snapshot, expected) in snapshots(base, disposition).into_iter().zip(states) {
            let diagnostic = decode(&snapshot).unwrap();
            assert_eq!(diagnostic.state, expected);
            assert_eq!(diagnostic.initial.snapshot_hash, root());
            raw.push(data_encoding::HEXLOWER.encode(&encoded(&snapshot).unwrap()));
        }
        cases.push(serde_json::json!({"base": base, "disposition": disposition, "snapshots": raw}));
    }
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("reference python");
    let mut child = Command::new(python)
        .args(["tests/key_resume_reference.py", "--passphrase-journal"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.as_mut().unwrap(), &cases).unwrap();
    child.stdin.take().unwrap().flush().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
}

#[test]
fn passphrase_journal_rejects_invalid_schema_and_transitions() {
    let [start, prepare, complete] = snapshots(2, REMOVED);
    for (valid, index, changes) in [
        (
            start,
            2,
            vec![
                ("name", t("other")),
                ("previous_snapshot_sha256", b([0; 32])),
                ("new_ciphertext_sha256", b([0x33; 32])),
                ("new_ciphertext_length", Value::Int(4097)),
                ("actor_uid", b(4u32.to_be_bytes())),
            ],
        ),
        (
            prepare,
            3,
            vec![
                ("new_identity", file(1, u64::MAX, 512, 3u32.to_be_bytes())),
                ("started_operation_id", b(id(1))),
                ("operation_id", b(id(3))),
            ],
        ),
        (
            complete,
            4,
            vec![
                ("prepared_operation_id", b(id(3))),
                (
                    "installed_identity",
                    file(1, u64::MAX - 5, 512, 3u32.to_be_bytes()),
                ),
                ("disposition", t("removed_present")),
                ("kind", t("unknown")),
            ],
        ),
    ] {
        for (key, value) in changes {
            let mut invalid = valid.clone();
            set(event_mut(&mut invalid, index), key, value);
            assert!(decode(&invalid).is_err(), "{key}");
        }
        let mut missing = valid.clone();
        remove(event_mut(&mut missing, index), "previous_snapshot_sha256");
        assert!(decode(&missing).is_err());
        let mut extra = valid;
        let Value::Map(fields) = event_mut(&mut extra, index) else {
            panic!()
        };
        fields.push(("unexpected".into(), Value::Int(0)));
        assert!(decode(&extra).is_err());
    }
    let mut ready = ready(2);
    append(
        &mut ready,
        PREPARE,
        vec![
            ("started_operation_id", b(id(1))),
            ("new_identity", file(1, 40, 512, 3u32.to_be_bytes())),
        ],
    );
    assert!(decode(&ready).is_err());
    let mut completed = snapshots(2, REMOVED)[2].clone();
    append(
        &mut completed,
        FINISH,
        vec![
            ("started_operation_id", b(id(3))),
            ("prepared_operation_id", b(id(4))),
            (
                "installed_identity",
                file(1, u64::MAX - 4, 512, 3u32.to_be_bytes()),
            ),
            ("disposition", t(REMOVED)),
        ],
    );
    assert!(decode(&completed).is_err());
}

#[test]
fn passphrase_journal_reserves_both_later_events() {
    let [start, _, _] = snapshots(1022, ABSENT);
    // 開始そのものは上限内でも、準備・完了を収容できない。
    assert!(encoded(&start).unwrap().len() < initial_state::STATE_LIMIT);
    assert!(decode(&start).is_err());
}

#[test]
fn passphrase_journal_reserves_exact_maximum_bytes_across_array_headers() {
    for base in [22, 254] {
        let [started, mut prepared, mut completed] = snapshots(base, REMOVED);
        for (snapshot, index, key) in [
            (&mut prepared, base + 1, "new_identity"),
            (&mut completed, base + 2, "installed_identity"),
        ] {
            let event = event_mut(snapshot, index);
            set(event, "recorded_unix_seconds", Value::Int(i64::MAX));
            let mut identity = field(event, key).unwrap().clone();
            for key in ["mtime_seconds", "ctime_seconds"] {
                set(&mut identity, key, Value::Int(i64::MAX));
            }
            for key in ["mtime_nanoseconds", "ctime_nanoseconds"] {
                set(&mut identity, key, Value::Int(999_999_999));
            }
            set(event, key, identity);
        }
        *event_mut(&mut completed, base + 1) = event_mut(&mut prepared, base + 1).clone();
        let final_size = encoded(&completed).unwrap().len();
        let mut started = started;
        for (snapshot, index, key, needs_prepare) in [
            (&mut started, base, "old_identity", true),
            (&mut prepared, base + 1, "new_identity", false),
        ] {
            let size = encoded(snapshot).unwrap().len();
            let identity = field(event_mut(snapshot, index), key).unwrap();
            assert!(
                !journal::reserved_fits(index + 1, size, identity, needs_prepare, final_size - 1)
                    .unwrap()
            );
            assert!(
                journal::reserved_fits(index + 1, size, identity, needs_prepare, final_size)
                    .unwrap()
            );
        }
    }
}

#[test]
fn passphrase_journal_rejects_raw_duplicate_event_keys() {
    for (index, mut snapshot) in snapshots(2, ABSENT).into_iter().enumerate() {
        let event = event_mut(&mut snapshot, index + 2);
        let raw = encoded(event).unwrap();
        assert!((0xa0..0xb7).contains(&raw[0]));
        let mut duplicate = raw.clone();
        duplicate[0] += 1;
        duplicate.extend(encoded(&t("sequence")).unwrap());
        duplicate.extend(encoded(&Value::Int((index + 3) as i64)).unwrap());
        let mut malformed = encoded(&snapshot).unwrap();
        let start = malformed.windows(raw.len()).position(|v| v == raw).unwrap();
        malformed.splice(start..start + raw.len(), duplicate);
        assert!(decode_history(&malformed, &source(), [0x42; 32], root()).is_err());
    }
}
