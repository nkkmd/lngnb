//! R07/R08/R10/R26/R27、A15 P01〜P09と追加境界。公開試験鍵のみ、実運用禁止。
use super::*;
use crate::{
    cbor::Value,
    id,
    storage::tests::{Temp, fixture, fixture_data, unhex},
};
use std::io::Cursor;

fn key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(
        &unhex(fixture_data()["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
}
fn revision() -> LocalRecord {
    LocalRecord::check(
        &unhex(
            fixture_data()["revision"]["envelope_cbor_hex"]
                .as_str()
                .unwrap(),
        ),
        None,
    )
    .unwrap()
}
fn set(body: &mut Value, name: &str, value: Value) {
    let Value::Map(fields) = body else {
        panic!("map");
    };
    fields.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
}
fn rev(parents: &[Id], length: u64, tag: &str) -> LocalRecord {
    let mut b = revision().body().clone();
    let mut parents: Vec<_> = parents.iter().map(|id| id.bytes).collect();
    parents.sort();
    set(
        &mut b,
        "parents",
        Value::Array(parents.iter().map(|p| Value::Bytes(p.to_vec())).collect()),
    );
    let Value::Map(fields) = &mut b else {
        panic!();
    };
    let payload = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1;
    set(payload, "byte_length", Value::Int(length as i64));
    let metadata = &mut fields.iter_mut().find(|(k, _)| k == "metadata").unwrap().1;
    set(
        metadata,
        "titles",
        Value::Map(vec![("en".into(), Value::Text(tag.into()))]),
    );
    LocalRecord::sign(b, &key()).unwrap()
}
fn bytes() -> Vec<u8> {
    unhex(fixture_data()["blob_hex"].as_str().unwrap())
}
fn result(s: &EvaluationSnapshot, id: Id) -> &Assessment {
    s.records.iter().find(|r| r.record_id == id).unwrap()
}
fn assert_state(
    s: &EvaluationSnapshot,
    r: &LocalRecord,
    state: Validation,
    reason: Option<Reason>,
) {
    let a = result(s, r.id());
    assert_eq!(a.validation, state);
    assert_eq!(a.reason, reason);
}
fn snapshot(w: &mut RecordWriter) -> EvaluationSnapshot {
    w.revalidate(EvaluationLimits::default()).unwrap()
}
fn dirty(w: &RecordWriter) -> i64 {
    w.store
        .conn
        .query_row("SELECT dirty FROM evaluation_state", [], |r| r.get(0))
        .unwrap()
}
fn blob_path(t: &Temp) -> std::path::PathBuf {
    let id = id::blob_id(&bytes());
    let hex = data_encoding::HEXLOWER.encode(&id.bytes);
    t.data().join("blobs").join(hex)
}

#[test]
fn missing_genesis_then_parent_arrival_and_metadata_only_history() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let parent = rev(&[], 14, "parent");
    let child = rev(&[parent.id()], 14, "child");
    w.insert(&child).unwrap();
    assert_state(
        &snapshot(&mut w),
        &child,
        Validation::Pending,
        Some(Reason::MissingGenesis),
    );
    w.insert(&fixture()).unwrap();
    assert_eq!(dirty(&w), 1);
    assert_state(
        &snapshot(&mut w),
        &child,
        Validation::Pending,
        Some(Reason::MissingParent),
    );
    w.insert(&parent).unwrap();
    let s = snapshot(&mut w);
    for r in [&parent, &child] {
        assert_state(&s, r, Validation::Valid, None);
        assert_eq!(
            result(&s, r.id()).payload_status,
            Some(PayloadStatus::Missing)
        );
    }
    assert!(s.committed);
    assert_eq!(dirty(&w), 0);
    assert!(
        !w.store
            .evaluate(EvaluationLimits::default())
            .unwrap()
            .committed
    );
    w.finish().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
}
#[test]
fn genesis_identity_wrong_publisher_and_parent_scope_are_separate() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let g = fixture();
    w.insert(&g).unwrap();
    let mut other_body = g.body().clone();
    set(&mut other_body, "knowledge_id", Value::Bytes(vec![9; 32]));
    let other = LocalRecord::sign(other_body, &key()).unwrap();
    w.insert(&other).unwrap();
    let mut b = revision().body().clone();
    set(
        &mut b,
        "genesis_record_id",
        Value::Bytes(other.id().bytes.to_vec()),
    );
    let mismatch = LocalRecord::sign(b, &key()).unwrap();
    w.insert(&mismatch).unwrap();
    let wrong = LocalRecord::sign(
        revision().body().clone(),
        &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    w.insert(&wrong).unwrap();
    let mut b = revision().body().clone();
    set(&mut b, "knowledge_id", Value::Bytes(vec![9; 32]));
    set(
        &mut b,
        "genesis_record_id",
        Value::Bytes(other.id().bytes.to_vec()),
    );
    let other_parent = LocalRecord::sign(b, &key()).unwrap();
    w.insert(&other_parent).unwrap();
    let child = rev(&[other_parent.id()], 14, "scope");
    w.insert(&child).unwrap();
    let genesis_parent = rev(&[g.id()], 14, "not revision");
    w.insert(&genesis_parent).unwrap();
    let wrong_child = rev(&[wrong.id()], 14, "bad parent");
    w.insert(&wrong_child).unwrap();
    let s = snapshot(&mut w);
    assert_state(
        &s,
        &mismatch,
        Validation::Invalid,
        Some(Reason::GenesisMismatch),
    );
    assert_state(
        &s,
        &wrong,
        Validation::Invalid,
        Some(Reason::WrongPublisher),
    );
    for r in [&child, &genesis_parent, &wrong_child] {
        assert_state(&s, r, Validation::Invalid, Some(Reason::InvalidParent));
    }
    w.finish().unwrap();
}
#[test]
fn genuine_blob_invalidates_only_bad_declaration_and_descendants() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let good = rev(&[], 14, "good");
    let bad = rev(&[good.id()], 15, "bad");
    let child = rev(&[bad.id()], 14, "child");
    let branch = rev(&[good.id()], 14, "branch");
    let merge = rev(&[child.id(), branch.id()], 14, "merge");
    for r in [&good, &bad, &child, &branch, &merge] {
        w.insert(r).unwrap();
    }
    let s = snapshot(&mut w);
    for r in [&good, &bad, &child, &branch, &merge] {
        assert_state(&s, r, Validation::Valid, None);
    }
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    assert_eq!(dirty(&w), 1);
    let s = snapshot(&mut w);
    assert_state(
        &s,
        &bad,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    for r in [&child, &merge] {
        assert_state(&s, r, Validation::Invalid, Some(Reason::InvalidParent));
    }
    for r in [&good, &branch] {
        assert_state(&s, r, Validation::Valid, None);
    }
    assert_eq!(
        result(&s, bad.id()).payload_reason,
        Some(PayloadReason::DeclaredLengthMismatch)
    );
    assert_eq!(
        result(&s, child.id()).payload_status,
        Some(PayloadStatus::Verified)
    );
    let count: i64 = w
        .store
        .conn
        .query_row("SELECT count(*) FROM known_invalid", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let edges: i64 = w
        .store
        .conn
        .query_row(
            "SELECT count(*) FROM parent_edges WHERE parent=?1",
            [&good.id().bytes],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(edges, 2);
    let original = bad.bytes().to_vec();
    assert_eq!(w.record(bad.id()).unwrap().unwrap().bytes(), original);
    let generation = s.generation;
    assert!(!w.insert(&bad).unwrap());
    assert_eq!(dirty(&w), 0);
    let again = snapshot(&mut w);
    assert_eq!(s.records, again.records);
    assert!(again.generation > generation);
    w.finish().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(
        s.records,
        store.evaluate(EvaluationLimits::default()).unwrap().records
    );
}
#[test]
fn existing_blob_is_checked_for_each_new_revision_and_empty_is_verified() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    let good = rev(&[], 14, "good");
    let bad = rev(&[], 15, "bad");
    for r in [&good, &bad] {
        w.insert(r).unwrap();
    }
    let mut b = revision().body().clone();
    let Value::Map(fields) = &mut b else {
        panic!();
    };
    let payload = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1;
    set(
        payload,
        "blob_id",
        Value::Bytes(id::blob_id(b"").bytes.to_vec()),
    );
    set(payload, "byte_length", Value::Int(0));
    let empty = LocalRecord::sign(b, &key()).unwrap();
    w.insert(&empty).unwrap();
    w.put_blob(id::blob_id(b""), Cursor::new([])).unwrap();
    let s = snapshot(&mut w);
    assert_state(&s, &good, Validation::Valid, None);
    assert_state(
        &s,
        &bad,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    assert_eq!(
        result(&s, empty.id()).payload_status,
        Some(PayloadStatus::Verified)
    );
    w.finish().unwrap();
}
#[test]
fn transfer_failure_and_policy_skip_do_not_prove_declared_conflict() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let bad = rev(&[], 15, "bad");
    w.insert(&bad).unwrap();
    assert!(matches!(
        w.put_blob(id::blob_id(&bytes()), Cursor::new(b"wrong")),
        Err(StorageError::BlobHashMismatch)
    ));
    let s = snapshot(&mut w);
    assert_state(&s, &bad, Validation::Valid, None);
    assert_eq!(
        result(&s, bad.id()).payload_status,
        Some(PayloadStatus::Unavailable)
    );
    // 大きな宣言長そのものも規範違反ではない。転送を始めない目録状態。
    let mut body = rev(&[], 20 * 1024 * 1024, "large declaration")
        .body()
        .clone();
    let Value::Map(fields) = &mut body else {
        panic!();
    };
    set(
        &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1,
        "blob_id",
        Value::Bytes(id::blob_id(b"not attempted").bytes.to_vec()),
    );
    let large = LocalRecord::sign(body, &key()).unwrap();
    w.insert(&large).unwrap();
    let s = snapshot(&mut w);
    assert_state(&s, &large, Validation::Valid, None);
    assert_eq!(
        result(&s, large.id()).payload_status,
        Some(PayloadStatus::Missing)
    );
    w.finish().unwrap();
}
#[test]
fn known_conflict_survives_missing_or_corrupt_evidence_and_reconstruction() {
    for corrupt in [false, true] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        w.insert(&fixture()).unwrap();
        let bad = rev(&[], 15, "bad");
        let child = rev(&[bad.id()], 14, "child");
        let good = rev(&[], 14, "branch");
        for r in [&bad, &child, &good] {
            w.insert(r).unwrap();
        }
        w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
            .unwrap();
        snapshot(&mut w);
        w.finish().unwrap();
        if corrupt {
            std::fs::write(blob_path(&t), b"corrupt bytes!").unwrap();
        } else {
            std::fs::remove_file(blob_path(&t)).unwrap();
        }
        let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        let s = store.evaluate(EvaluationLimits::default()).unwrap();
        for r in [&bad, &child] {
            assert_state(
                &s,
                r,
                Validation::Pending,
                Some(Reason::EvidenceUnavailable),
            );
        }
        assert_state(&s, &good, Validation::Valid, None);
        assert_eq!(
            result(&s, good.id()).payload_reason,
            Some(PayloadReason::StorageCorruption)
        );
        assert_eq!(
            result(&s, bad.id()).payload_reason,
            Some(PayloadReason::EvidenceUnavailable)
        );
        assert_eq!(
            result(&s, good.id()).payload_status,
            Some(PayloadStatus::Unavailable)
        );
        let count: i64 = store
            .conn
            .query_row("SELECT count(*) FROM known_invalid", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        // 再生成可能な評価/逆依存を失っても、別管理の根拠記録を消さない。
        store.conn.execute("DELETE FROM evaluations", []).unwrap();
        store.conn.execute("DELETE FROM parent_edges", []).unwrap();
        assert_eq!(
            s.records,
            store.evaluate(EvaluationLimits::default()).unwrap().records
        );
        drop(store);
        std::fs::write(blob_path(&t), bytes()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(blob_path(&t), std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_state(
            &store.evaluate(EvaluationLimits::default()).unwrap(),
            &bad,
            Validation::Invalid,
            Some(Reason::DeclaredLengthMismatch),
        );
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn physical_corruption_during_writer_is_not_clean_completion_or_record_forgery() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let good = rev(&[], 14, "good");
    w.insert(&good).unwrap();
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    std::fs::write(blob_path(&t), b"broken").unwrap();
    let s = w.store.evaluate(EvaluationLimits::default()).unwrap();
    assert_state(&s, &good, Validation::Valid, None);
    assert_eq!(
        result(&s, good.id()).payload_status,
        Some(PayloadStatus::Unavailable)
    );
    assert!(matches!(
        w.revalidate(EvaluationLimits::default()),
        Err(StorageError::Corrupt)
    ));
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
}
#[test]
fn failed_audit_or_evidence_transaction_rolls_back_and_forbids_clean_finish() {
    for table in ["history", "known_invalid", "evaluations", "parent_edges"] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        w.insert(&fixture()).unwrap();
        let parent = rev(&[], 14, "parent");
        let bad = rev(&[parent.id()], 15, "bad");
        for r in [&parent, &bad] {
            w.insert(r).unwrap();
        }
        snapshot(&mut w);
        w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
            .unwrap();
        let generation = w.store.generation().unwrap();
        w.store.conn.execute_batch(&format!("CREATE TRIGGER reject_evaluation BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'test_failure'); END;")).unwrap();
        assert!(w.revalidate(EvaluationLimits::default()).is_err());
        assert_eq!(w.store.generation().unwrap(), generation);
        assert_eq!(dirty(&w), 1);
        let conflicts: i64 = w
            .store
            .conn
            .query_row("SELECT count(*) FROM known_invalid", [], |r| r.get(0))
            .unwrap();
        assert_eq!(conflicts, 0);
        let state: String = w
            .store
            .conn
            .query_row(
                "SELECT validation FROM evaluations WHERE record_id=?1",
                [&bad.id().bytes],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "valid"); // 旧保存値はdirtyのため現在結果に使わない。
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
        assert_eq!(
            RecordStore::open(&t.data(), Limits::default())
                .unwrap()
                .startup_state()
                .unwrap(),
            StartupState::NeedsReview
        );
    }
}
#[test]
fn budgets_leave_no_partial_evaluation_and_can_be_retried_with_explicit_limits() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let a = rev(&[], 14, "a");
    let b = rev(&[a.id()], 14, "b");
    for r in [&a, &b] {
        w.insert(r).unwrap();
    }
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    let default = EvaluationLimits::default();
    for limits in [
        EvaluationLimits {
            records: 2,
            ..default
        },
        EvaluationLimits {
            record_bytes: 1,
            ..default
        },
        EvaluationLimits {
            edges: 0,
            ..default
        },
        EvaluationLimits {
            blob_bytes: 13,
            ..default
        },
        EvaluationLimits {
            elapsed: Duration::ZERO,
            ..default
        },
    ] {
        let generation = w.store.generation().unwrap();
        assert!(matches!(
            w.revalidate(limits),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(w.store.generation().unwrap(), generation);
        assert_eq!(w.reserved, 0);
        assert_eq!(dirty(&w), 1);
    }
    let total: u64 = [&fixture(), &a, &b]
        .iter()
        .map(|r| r.bytes().len() as u64)
        .sum();
    assert!(
        w.revalidate(EvaluationLimits {
            records: 3,
            record_bytes: total,
            edges: 1,
            blob_bytes: 14,
            ..default
        })
        .unwrap()
        .committed
    );
    w.finish().unwrap();
}
#[test]
fn input_arrival_orders_converge_with_branches_and_multiple_parents() {
    let a = rev(&[], 14, "a");
    let b = rev(&[a.id()], 15, "bad");
    let c = rev(&[a.id()], 14, "c");
    let d = rev(&[b.id(), c.id()], 14, "d");
    let records = [fixture(), a, b, c, d];
    let mut expected = None;
    for order in [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 0, 4, 1, 3],
        [3, 1, 4, 0, 2],
    ] {
        for blob_first in [true, false] {
            let t = Temp::new();
            let mut w = t.store().begin().unwrap();
            if blob_first {
                w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
                    .unwrap();
            }
            for i in order {
                w.insert(&records[i]).unwrap();
                snapshot(&mut w);
            }
            if !blob_first {
                w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
                    .unwrap();
            }
            let s = snapshot(&mut w);
            if let Some(expected) = &expected {
                assert_eq!(&s.records, expected);
            } else {
                expected = Some(s.records);
            }
            w.finish().unwrap();
        }
    }
}
#[test]
fn parent_reason_precedes_own_length_and_origins_are_not_dependencies() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let absent = record_id([0x22; 32]);
    let bad = rev(&[absent], 15, "missing parent and mismatch");
    w.insert(&bad).unwrap();
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    let mut body = rev(&[], 14, "origins").body().clone();
    let Value::Map(fields) = &mut body else {
        panic!();
    };
    fields.push((
        "origins".into(),
        Value::Array(vec![Value::Map(vec![(
            "knowledge_id".into(),
            Value::Bytes(vec![8; 32]),
        )])]),
    ));
    let origin = LocalRecord::sign(body, &key()).unwrap();
    w.insert(&origin).unwrap();
    let s = snapshot(&mut w);
    assert_state(&s, &bad, Validation::Pending, Some(Reason::MissingParent));
    assert_eq!(
        result(&s, bad.id()).payload_status,
        Some(PayloadStatus::Unavailable)
    );
    assert_state(&s, &origin, Validation::Valid, None);
    w.finish().unwrap();
}
#[test]
fn iterative_engine_checks_cycles_and_deep_history_without_protocol_fixtures() {
    // 循環は完成hashの固定点を必要とするため、局所検査済みノードの依存だけを
    // エンジン内で置換する防御試験。外部Recordの適合入力と混同しない。
    let sample = rev(&[], 14, "engine-only template");
    let genesis = fixture().id().bytes;
    let make = |_id, parents: Vec<Key>| {
        let record = sample.clone();
        Node {
            genesis,
            record,
            parents,
            payload: None,
        }
    };
    let g = fixture();
    let mut nodes = BTreeMap::new();
    nodes.insert(
        g.id().bytes,
        Node {
            genesis: g.id().bytes,
            record: g,
            parents: vec![],
            payload: None,
        },
    );
    let a = [1; 32];
    let b = [2; 32];
    let child = [3; 32];
    nodes.insert(a, make(1, vec![b]));
    nodes.insert(b, make(2, vec![a]));
    nodes.insert(child, make(3, vec![a]));
    let self_id = [4; 32];
    nodes.insert(self_id, make(4, vec![self_id]));
    let budget = Budget {
        start: Instant::now(),
        limits: EvaluationLimits::default(),
    };
    let results = evaluate_graph(&nodes, &BTreeMap::new(), &BTreeMap::new(), &budget).unwrap();
    for id in [a, b, child, self_id] {
        assert_eq!(
            results
                .iter()
                .find(|r| r.record_id.bytes == id)
                .unwrap()
                .validation,
            Validation::Invalid
        );
    }
    nodes.retain(|_, n| n.record.kind() == RecordKind::Genesis);
    let mut parent = None;
    for i in 0u32..1000 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        nodes.insert(id, make(i, parent.into_iter().collect()));
        parent = Some(id);
    }
    let results = evaluate_graph(&nodes, &BTreeMap::new(), &BTreeMap::new(), &budget).unwrap();
    assert_eq!(results.len(), 1001);
    assert!(results.iter().all(|r| r.validation == Validation::Valid));
}
#[test]
fn schema_two_is_rejected_without_modification() {
    let t = Temp::new();
    drop(t.store());
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
    drop(conn);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
}

#[test]
fn transfer_observation_persists_but_healthy_blob_wins_and_failed_audit_is_not_clean() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let good = rev(&[], 14, "good");
    w.insert(&good).unwrap();
    let id = id::blob_id(&bytes());
    assert!(matches!(
        w.put_blob(id, Cursor::new(b"bad")),
        Err(StorageError::BlobHashMismatch)
    ));
    let s = snapshot(&mut w);
    assert_state(&s, &good, Validation::Valid, None);
    assert_eq!(
        result(&s, good.id()).payload_reason,
        Some(PayloadReason::TransferHashMismatch)
    );
    assert_eq!(
        result(&s, good.id()).payload_status,
        Some(PayloadStatus::Unavailable)
    );
    w.finish().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(
        result(
            &store.evaluate(EvaluationLimits::default()).unwrap(),
            good.id()
        )
        .payload_status,
        Some(PayloadStatus::Unavailable)
    );
    let mut w = store.begin().unwrap();
    w.put_blob(id, Cursor::new(bytes())).unwrap();
    assert!(matches!(
        w.put_blob(id, Cursor::new(b"bad")),
        Err(StorageError::BlobHashMismatch)
    ));
    assert_eq!(
        result(&snapshot(&mut w), good.id()).payload_status,
        Some(PayloadStatus::Verified)
    );
    w.finish().unwrap();
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    w.store.conn.execute_batch("CREATE TRIGGER refuse_blob_failure BEFORE INSERT ON blob_failures BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(matches!(
        w.put_blob(id, Cursor::new(b"bad")),
        Err(StorageError::Sql(_))
    ));
    assert_eq!(w.reserved, 0);
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
}

#[test]
fn another_genesis_with_same_knowledge_cannot_supply_a_parent() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let g = fixture();
    w.insert(&g).unwrap();
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let mut b = g.body().clone();
    set(
        &mut b,
        "publisher_public_key",
        Value::Bytes(other_key.verifying_key().to_bytes().to_vec()),
    );
    let other = LocalRecord::sign(b, &other_key).unwrap();
    w.insert(&other).unwrap();
    let mut b = revision().body().clone();
    set(
        &mut b,
        "genesis_record_id",
        Value::Bytes(other.id().bytes.to_vec()),
    );
    let parent = LocalRecord::sign(b, &other_key).unwrap();
    w.insert(&parent).unwrap();
    let child = rev(&[parent.id()], 14, "other genesis parent");
    w.insert(&child).unwrap();
    let s = snapshot(&mut w);
    assert_state(&s, &parent, Validation::Valid, None);
    assert_state(&s, &child, Validation::Invalid, Some(Reason::InvalidParent));
    w.finish().unwrap();
}

#[test]
fn process_kill_before_evaluation_commit_keeps_old_snapshot_dirty_and_requires_review() {
    use std::{
        io::BufRead,
        process::{Command, Stdio},
    };
    if let Some(path) = std::env::var_os("LNGNB_EVAL_CHILD") {
        let store = RecordStore::open(Path::new(&path), Limits::default()).unwrap();
        let mut w = store.begin().unwrap();
        w.evaluation_pause = true;
        w.revalidate(EvaluationLimits::default()).unwrap();
        panic!("parent must kill before commit");
    }
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let bad = rev(&[], 15, "bad");
    w.insert(&bad).unwrap();
    snapshot(&mut w);
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    w.finish().unwrap();
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::tests::process_kill_before_evaluation_commit_keeps_old_snapshot_dirty_and_requires_review","--nocapture"]).env("LNGNB_EVAL_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "child ended before pause"
        );
        if line.contains("LNGNB_EVALUATION_BEFORE_COMMIT") {
            break;
        }
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    let (dirty, conflicts): (i64, i64) = store
        .conn
        .query_row(
            "SELECT dirty,(SELECT count(*) FROM known_invalid) FROM evaluation_state",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((dirty, conflicts), (1, 0));
    let old: String = store
        .conn
        .query_row(
            "SELECT validation FROM evaluations WHERE record_id=?1",
            [&bad.id().bytes],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old, "valid");
    let s = store.evaluate(EvaluationLimits::default()).unwrap();
    assert!(!s.committed);
    assert_state(
        &s,
        &bad,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
}
