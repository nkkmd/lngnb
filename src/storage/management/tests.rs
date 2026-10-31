//! A13公開fixtureのみ。試験鍵を実運用へ流用しない。
use super::*;
use crate::storage::{
    EvaluationLimits, StartupState, StorageError, Validation,
    tests::{Temp, fixture_data, logical_snapshot, unhex},
};

fn fixture(kind: &str) -> crate::record::LocalRecord {
    let f = fixture_data();
    crate::record::LocalRecord::check(&unhex(f[kind]["envelope_cbor_hex"].as_str().unwrap()), None)
        .unwrap()
}

#[test]
fn checked_requests_commit_idempotently_without_promoting_missing_dependencies() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    let record = fixture("revision");
    let receipt = RecordRequest::check(record.bytes())
        .unwrap()
        .submit(&mut writer)
        .unwrap();
    assert_eq!(receipt.record_id, record.id());
    assert!(receipt.inserted);
    assert_eq!(receipt.bytes()[..2], [1, 1]);
    assert_eq!(receipt.bytes()[2..], record.id().bytes);
    let before = logical_snapshot(&writer.store.conn);
    let duplicate = store_record(&mut writer, &record).unwrap();
    assert!(!duplicate.inserted);
    assert_eq!(logical_snapshot(&writer.store.conn), before);
    let diagnostic = writer.store.evaluate(EvaluationLimits::default()).unwrap();
    assert_eq!(diagnostic.records.len(), 1);
    assert_eq!(diagnostic.records[0].validation, Validation::Pending);
    // commit済みでもsessionを終了せずdropしたら手動確認待ちを残す。
    drop(writer);
    let store =
        crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(store.record(record.id()).unwrap().is_some());
    assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
}

#[test]
fn malformed_secret_shaped_and_tampered_inputs_never_reach_storage() {
    let temp = Temp::new();
    let writer = temp.store().begin().unwrap();
    let before = logical_snapshot(&writer.store.conn);
    let mut altered = fixture("genesis").bytes().to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    for bytes in [
        vec![],
        vec![0; 32],
        b"passphrase=private".to_vec(),
        vec![0xa0],
        altered,
        vec![0; crate::cbor::MAX_RECORD + 1],
    ] {
        assert!(RecordRequest::check(&bytes).is_err());
        assert_eq!(logical_snapshot(&writer.store.conn), before);
    }
    writer.finish().unwrap();
}

#[test]
fn sql_failure_retains_prior_commit_blocks_finish_and_cannot_be_cleared_by_retry() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    let genesis = fixture("genesis");
    store_record(&mut writer, &genesis).unwrap();
    writer.store.conn.execute_batch("CREATE TRIGGER deny_record BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(store_record(&mut writer, &fixture("revision")).is_err());
    assert!(writer.failed);
    assert!(matches!(
        store_record(&mut writer, &genesis),
        Err(StorageError::UnresolvedFailure)
    ));
    assert!(matches!(
        writer.finish(),
        Err(StorageError::UnresolvedFailure)
    ));
    let store =
        crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(store.record(genesis.id()).unwrap().is_some());
    assert!(store.record(fixture("revision").id()).unwrap().is_none());
}

#[test]
fn budget_refusal_does_not_insert_or_discard_confirmed_record() {
    let temp = Temp::new();
    let mut store = temp.store();
    store.limits.session_records = 1;
    let mut writer = store.begin().unwrap();
    store_record(&mut writer, &fixture("genesis")).unwrap();
    let before = logical_snapshot(&writer.store.conn);
    assert!(matches!(
        store_record(&mut writer, &fixture("revision")),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(logical_snapshot(&writer.store.conn), before);
    assert!(!writer.failed); // preflight拒否は保存syscall失敗と区別する。
    writer.finish().unwrap();
}

#[test]
fn failed_or_policy_rejected_writer_cannot_become_a_fresh_clean_listener() {
    use crate::storage::admin_transport::{Error, Listener};
    use std::time::Duration;
    for failed in [false, true] {
        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        if failed {
            writer.store.conn.execute_batch("CREATE TRIGGER deny_record BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
            assert!(store_record(&mut writer, &fixture("genesis")).is_err());
        }
        let result = Listener::bind_writer(writer, 0, Duration::from_secs(1));
        if failed {
            assert!(matches!(result, Err(Error::SessionFailed)));
        } else {
            assert!(matches!(result, Err(Error::Policy)));
        }
        assert!(!temp.data().join("admin.sock").exists());
        let store =
            crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default())
                .unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn common_diagnostic_rechecks_dependencies_without_committing_or_releasing_lock() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    store_record(&mut writer, &fixture("revision")).unwrap();
    let before = logical_snapshot(&writer.store.conn);
    let first = writer.store.diagnose(EvaluationLimits::default()).unwrap();
    assert_eq!(
        (first.records, first.valid, first.pending, first.invalid),
        (1, 0, 1, 0)
    );
    assert_eq!(
        (
            first.payload_verified,
            first.payload_missing,
            first.payload_unavailable
        ),
        (0, 1, 0)
    );
    assert_eq!(first.startup_state, StartupState::NeedsReview);
    assert_eq!(logical_snapshot(&writer.store.conn), before);
    assert!(
        crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default()).is_err()
    );
    store_record(&mut writer, &fixture("genesis")).unwrap();
    let before = logical_snapshot(&writer.store.conn);
    let second = writer.store.diagnose(EvaluationLimits::default()).unwrap();
    assert_eq!(
        (second.records, second.valid, second.pending, second.invalid),
        (2, 2, 0, 0)
    );
    assert_eq!(second.payload_missing, 1);
    assert!(second.generation > first.generation);
    assert_eq!(logical_snapshot(&writer.store.conn), before);
    drop(writer);
    let store =
        crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    let before = logical_snapshot(&store.conn);
    let diagnostic = store.diagnose(EvaluationLimits::default()).unwrap();
    assert_eq!(diagnostic.startup_state, StartupState::NeedsReview);
    assert_eq!(logical_snapshot(&store.conn), before);
    assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
}

#[test]
fn diagnostic_budget_returns_no_partial_result_and_cannot_clear_save_failure() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    store_record(&mut writer, &fixture("genesis")).unwrap();
    store_record(&mut writer, &fixture("revision")).unwrap();
    for limits in [
        EvaluationLimits {
            records: 1,
            ..EvaluationLimits::default()
        },
        EvaluationLimits {
            record_bytes: 1,
            ..EvaluationLimits::default()
        },
        EvaluationLimits {
            elapsed: std::time::Duration::ZERO,
            ..EvaluationLimits::default()
        },
    ] {
        let before = logical_snapshot(&writer.store.conn);
        assert!(matches!(
            writer.store.diagnose(limits),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(logical_snapshot(&writer.store.conn), before);
    }
    // 保存障害後の診断成功でもwriter.failedを解除せずfinishを拒否する。
    writer.store.conn.execute_batch("CREATE TRIGGER deny_blob BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    let bytes = b"public diagnostic failure fixture";
    assert!(
        writer
            .put_blob(crate::id::blob_id(bytes), std::io::Cursor::new(bytes))
            .is_err()
    );
    assert!(writer.failed);
    let before = logical_snapshot(&writer.store.conn);
    writer.store.diagnose(EvaluationLimits::default()).unwrap();
    assert_eq!(logical_snapshot(&writer.store.conn), before);
    assert!(writer.failed);
    assert!(matches!(
        writer.finish(),
        Err(StorageError::UnresolvedFailure)
    ));
}

#[test]
fn checked_config_save_is_shared_without_applying_session_values_or_clearing_manual_wait() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    let record = fixture("genesis");
    store_record(&mut writer, &record).unwrap();
    let config = crate::storage::AdminConfig {
        request_timeout_ms: 500,
        max_new_records: 2,
        max_diagnostic_records: 7,
        startup_records_per_step: 1,
    };
    let before = logical_snapshot(&writer.store.conn);
    for invalid in [
        crate::storage::AdminConfig {
            request_timeout_ms: 0,
            ..config
        },
        crate::storage::AdminConfig {
            max_new_records: 10_001,
            ..config
        },
        crate::storage::AdminConfig {
            max_diagnostic_records: 0,
            ..config
        },
        crate::storage::AdminConfig {
            startup_records_per_step: 10_001,
            ..config
        },
    ] {
        assert!(matches!(
            ConfigRequest::check(invalid),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(logical_snapshot(&writer.store.conn), before);
    }
    let counters = (writer.records, writer.bytes);
    assert_eq!(
        ConfigRequest::check(config)
            .unwrap()
            .save(&mut writer)
            .unwrap(),
        config
    );
    assert_eq!((writer.records, writer.bytes), counters);
    assert_eq!(writer.store.limits.session_records, 10_000);
    assert_eq!(writer.store.saved_admin_config().unwrap(), Some(config));
    assert!(
        crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default()).is_err()
    );
    drop(writer);
    let store =
        crate::storage::RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(
        store.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
}

fn stopped_config() -> crate::storage::AdminConfig {
    crate::storage::AdminConfig {
        request_timeout_ms: 500,
        max_new_records: 1,
        max_diagnostic_records: 1,
        startup_records_per_step: 1,
    }
}

#[test]
fn stopped_config_checks_all_records_before_saving_without_applying_new_limits() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    for kind in ["genesis", "revision"] {
        store_record(&mut writer, &fixture(kind)).unwrap();
    }
    writer.finish().unwrap();
    let config = stopped_config();
    assert_eq!(
        ConfigRequest::check(config)
            .unwrap()
            .save_stopped(&temp.data())
            .unwrap(),
        config
    );
    let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(store.saved_admin_config().unwrap(), Some(config));
    // 今回の全検査には、新しい件数1を適用しない。2件を検査・評価してから保存する。
    assert_eq!(
        store.diagnose(EvaluationLimits::default()).unwrap().records,
        2
    );
    let records: i64 = store.conn.query_row(
        "SELECT count(*) FROM history WHERE new_state='evaluation_input_complete' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=2:bytes=%'",
        [], |r| r.get(0)).unwrap();
    assert!(records > 0);
    for kind in ["genesis", "revision"] {
        let record = fixture(kind);
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    for name in [
        "admin.sock",
        "admin-status.sock",
        "admin-evaluate.sock",
        "admin-config.sock",
    ] {
        assert!(!temp.data().join(name).exists());
    }
}

#[test]
fn stopped_config_lock_and_manual_wait_never_fall_back_or_clear_state() {
    let temp = Temp::new();
    let store = temp.store();
    let before = logical_snapshot(&store.conn);
    assert!(
        ConfigRequest::check(stopped_config())
            .unwrap()
            .save_stopped(&temp.data())
            .is_err()
    );
    assert_eq!(logical_snapshot(&store.conn), before);
    let mut writer = store.begin().unwrap();
    let old = crate::storage::AdminConfig {
        max_new_records: 7,
        ..stopped_config()
    };
    writer.save_admin_config(old).unwrap();
    store_record(&mut writer, &fixture("genesis")).unwrap();
    drop(writer);
    assert!(matches!(
        ConfigRequest::check(stopped_config())
            .unwrap()
            .save_stopped(&temp.data()),
        Err(StorageError::NeedsReview)
    ));
    let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(store.saved_admin_config().unwrap(), Some(old));
    assert!(store.record(fixture("genesis").id()).unwrap().is_some());
    assert!(!temp.data().join("admin-config.sock").exists());
}

#[test]
fn stopped_config_save_and_finish_failures_preserve_old_or_committed_values() {
    for finish_failure in [false, true] {
        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        let old = crate::storage::AdminConfig {
            max_new_records: 7,
            ..stopped_config()
        };
        writer.save_admin_config(old).unwrap();
        store_record(&mut writer, &fixture("genesis")).unwrap();
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
        let trigger = if finish_failure {
            "CREATE TRIGGER deny_stopped_finish BEFORE UPDATE ON storage_state WHEN OLD.state='running' AND NEW.state='clean' BEGIN SELECT RAISE(ABORT,'test'); END;"
        } else {
            "CREATE TRIGGER deny_stopped_config BEFORE INSERT ON history WHEN NEW.new_state='admin_config_saved_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;"
        };
        store.conn.execute_batch(trigger).unwrap();
        drop(store);
        assert!(
            ConfigRequest::check(stopped_config())
                .unwrap()
                .save_stopped(&temp.data())
                .is_err()
        );
        let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
        let expected = if finish_failure {
            stopped_config()
        } else {
            old
        };
        assert_eq!(store.saved_admin_config().unwrap(), Some(expected));
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        let record = fixture("genesis");
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
        drop(store);
        assert!(matches!(
            ConfigRequest::check(stopped_config())
                .unwrap()
                .save_stopped(&temp.data()),
            Err(StorageError::NeedsReview)
        ));
    }
}

fn fixed_request(record: &LocalRecord) -> RevisionRequest {
    let refs = record.revision_references().unwrap();
    RevisionRequest::check(refs.knowledge_id, refs.genesis_record_id, record.id()).unwrap()
}
fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(
        &unhex(fixture_data()["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
}
fn with_references(
    parents: &[[u8; 32]],
    origins: Option<Vec<crate::cbor::Value>>,
    n: i64,
) -> LocalRecord {
    use crate::cbor::Value;
    let Value::Map(mut body) = fixture("revision").body().clone() else {
        unreachable!()
    };
    for (key, value) in &mut body {
        if key == "parents" {
            *value = Value::Array(parents.iter().map(|p| Value::Bytes(p.to_vec())).collect());
        }
        if key == "payload" {
            let Value::Map(payload) = value else {
                unreachable!()
            };
            *payload
                .iter_mut()
                .find(|(k, _)| k == "byte_length")
                .unwrap() = ("byte_length".into(), Value::Int(n));
        }
    }
    if let Some(origins) = origins {
        body.push(("origins".into(), Value::Array(origins)));
    }
    LocalRecord::sign(Value::Map(body), &signing_key()).unwrap()
}
fn origin_forms() -> Vec<crate::cbor::Value> {
    use crate::cbor::Value;
    let one = vec![("knowledge_id".into(), Value::Bytes(vec![7; 32]))];
    let mut two = one.clone();
    two.push(("genesis_record_id".into(), Value::Bytes(vec![8; 32])));
    let mut three = two.clone();
    three.push(("revision_record_id".into(), Value::Bytes(vec![9; 32])));
    vec![Value::Map(one), Value::Map(two), Value::Map(three)]
}

#[test]
fn fixed_revision_lookup_matches_all_three_ids_without_fallback_or_writes() {
    use crate::id::Kind;
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    let g = fixture("genesis");
    let r = fixture("revision");
    for record in [&g, &r] {
        store_record(&mut writer, record).unwrap();
    }
    writer.finish().unwrap();
    let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    let before = logical_snapshot(&store.conn);
    let request = fixed_request(&r);
    let saved = request.inspect(&store).unwrap().unwrap();
    assert_eq!(saved.record.bytes(), r.bytes());
    assert_eq!(saved.record.id(), r.id());
    assert_eq!(saved.references.knowledge_id.bytes, g.identity().knowledge);
    assert_eq!(saved.references.genesis_record_id, g.id());
    assert_eq!(
        saved.references.publisher_key_id,
        crate::id::key_id(&g.identity().public)
    );
    assert!(saved.references.parents.is_empty());
    assert_eq!(saved.references.origins, None);
    assert!(g.revision_references().is_err());
    for request in [
        RevisionRequest {
            knowledge: Id {
                kind: Kind::Knowledge,
                bytes: [4; 32],
            },
            ..request
        },
        RevisionRequest {
            genesis: Id {
                kind: Kind::Record,
                bytes: [4; 32],
            },
            ..request
        },
        RevisionRequest {
            revision: g.id(),
            ..request
        },
        RevisionRequest {
            revision: Id {
                kind: Kind::Record,
                bytes: [4; 32],
            },
            ..request
        },
    ] {
        assert!(request.inspect(&store).unwrap().is_none());
    }
    for (k, g, r) in [
        (g.id(), g.id(), r.id()),
        (request.knowledge, request.knowledge, r.id()),
        (request.knowledge, g.id(), request.knowledge),
    ] {
        assert!(matches!(
            RevisionRequest::check(k, g, r),
            Err(crate::Error::InvalidId)
        ));
    }
    assert_eq!(logical_snapshot(&store.conn), before);
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert!(RecordStore::open(&temp.data(), crate::storage::Limits::default()).is_err());
}

#[test]
fn stored_branches_merge_and_all_origin_forms_remain_distinct_declarations() {
    use crate::id::Kind;
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    let missing = fixture("revision").id().bytes;
    let a = with_references(&[missing], None, 101);
    let b = with_references(&[missing], Some(vec![]), 102);
    let mut parents = [a.id().bytes, b.id().bytes];
    parents.sort();
    let merge = with_references(&parents, Some(origin_forms()), 103);
    let other_initial = with_references(&[], None, 104);
    for record in [&a, &b, &merge, &other_initial] {
        store_record(&mut writer, record).unwrap();
    }
    writer.finish().unwrap();
    let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    let before = logical_snapshot(&store.conn);
    assert!(store.record(fixture("genesis").id()).unwrap().is_none());
    assert!(store.record(fixture("revision").id()).unwrap().is_none());
    for (record, expected) in [
        (&a, vec![missing]),
        (&b, vec![missing]),
        (&merge, parents.to_vec()),
        (&other_initial, vec![]),
    ] {
        let saved = fixed_request(record).inspect(&store).unwrap().unwrap();
        assert_eq!(saved.record.bytes(), record.bytes());
        assert_eq!(
            saved.references.parents,
            expected
                .into_iter()
                .map(|bytes| Id {
                    kind: Kind::Record,
                    bytes
                })
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(
        fixed_request(&b)
            .inspect(&store)
            .unwrap()
            .unwrap()
            .references
            .origins,
        Some(vec![])
    );
    let origins = fixed_request(&merge)
        .inspect(&store)
        .unwrap()
        .unwrap()
        .references
        .origins
        .unwrap();
    assert_eq!(origins.len(), 3);
    for (n, origin) in origins.iter().enumerate() {
        assert_eq!(
            origin.knowledge_id,
            Id {
                kind: Kind::Knowledge,
                bytes: [7; 32]
            }
        );
        assert_eq!(
            origin.genesis_record_id,
            (n >= 1).then_some(Id {
                kind: Kind::Record,
                bytes: [8; 32]
            })
        );
        assert_eq!(
            origin.revision_record_id,
            (n >= 2).then_some(Id {
                kind: Kind::Record,
                bytes: [9; 32]
            })
        );
    }
    assert_eq!(logical_snapshot(&store.conn), before);
}

#[test]
fn inspection_keeps_manual_wait_and_rejects_corrupt_or_oversized_saved_bytes() {
    let temp = Temp::new();
    let mut writer = temp.store().begin().unwrap();
    let r = fixture("revision");
    store_record(&mut writer, &r).unwrap();
    drop(writer);
    let store = RecordStore::open(&temp.data(), crate::storage::Limits::default()).unwrap();
    let request = fixed_request(&r);
    let before = logical_snapshot(&store.conn);
    assert_eq!(
        request.inspect(&store).unwrap().unwrap().record.bytes(),
        r.bytes()
    );
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(logical_snapshot(&store.conn), before);
    // 破損注入fixtureだけで不変triggerと制約を迂回し、製品読取りの確保前上限を確認する。
    store
        .conn
        .execute_batch("DROP TRIGGER records_no_update; PRAGMA ignore_check_constraints=ON")
        .unwrap();
    for bad in [
        fixture("genesis").bytes().to_vec(),
        b"invalid cbor".to_vec(),
        vec![0; crate::cbor::MAX_RECORD + 1],
    ] {
        store
            .conn
            .execute(
                "UPDATE records SET bytes=?1 WHERE id=?2",
                rusqlite::params![bad, r.id().bytes.as_slice()],
            )
            .unwrap();
        let before = logical_snapshot(&store.conn);
        assert!(matches!(
            request.inspect(&store),
            Err(StorageError::Corrupt)
        ));
        assert_eq!(logical_snapshot(&store.conn), before);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    }
    store
        .conn
        .execute_batch("ALTER TABLE records RENAME COLUMN bytes TO unreadable")
        .unwrap();
    let before = logical_snapshot(&store.conn);
    assert!(matches!(request.inspect(&store), Err(StorageError::Sql(_))));
    assert_eq!(logical_snapshot(&store.conn), before);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
}

#[test]
fn independent_python_checks_reference_views_including_absence_and_bounds() {
    use crate::cbor::{self, Value};
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut origins: Vec<_> = (0..128u8)
        .map(|n| Value::Map(vec![("knowledge_id".into(), Value::Bytes(vec![n; 32]))]))
        .collect();
    origins.sort_by_key(|v| cbor::encode(v).unwrap());
    let parents: Vec<_> = (0..256u32)
        .map(|n| {
            let mut id = [0; 32];
            id[28..].copy_from_slice(&n.to_be_bytes());
            id
        })
        .collect();
    let records = [
        fixture("revision"),
        with_references(&[], Some(vec![]), 1),
        with_references(&parents, Some(origins), 2),
        with_references(&[], Some(origin_forms()), 3),
    ];
    let hex = |bytes: &[u8]| {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(text, "{byte:02x}").unwrap();
        }
        text
    };
    let cases: Vec<_> = records.iter().map(|record| {
        let refs = record.revision_references().unwrap();
        serde_json::json!({"seed": fixture_data()["seed_hex"], "body": hex(&cbor::encode(record.body()).unwrap()), "envelope": hex(record.bytes()),
            "reference_view": {"knowledge_id": refs.knowledge_id.to_string(), "genesis_record_id": refs.genesis_record_id.to_string(), "publisher_key_id": refs.publisher_key_id.to_string(),
                "parents": refs.parents.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "origins": refs.origins.map(|origins| origins.iter().map(|origin| serde_json::json!({"knowledge_id": origin.knowledge_id.to_string(),
                    "genesis_record_id": origin.genesis_record_id.map(|v| v.to_string()), "revision_record_id": origin.revision_record_id.map(|v| v.to_string())})).collect::<Vec<_>>())}})
    }).collect();
    let mut child = Command::new(
        std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
    )
    .arg("tests/reference.py")
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
        "independent reference view check failed (details suppressed)"
    );
    let ids: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        ids,
        records
            .iter()
            .map(|r| r.id().to_string())
            .collect::<Vec<_>>()
    );
}
