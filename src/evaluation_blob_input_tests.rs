//! 親評価用本文入力の分割・根拠保全・障害点。公開試験鍵専用、実運用禁止。
use super::super::tests::{assert_oracle, bytes, key as signing_key, oracle_case, rev, set};
use super::*;
use crate::storage::tests::{Temp, fixture};
use std::{
    io::{BufRead, Cursor, Write},
    os::unix::fs::OpenOptionsExt,
    process::{Command, Stdio},
};

fn open(t: &Temp) -> RecordStore {
    RecordStore::open(&t.data(), Limits::default()).unwrap()
}
fn count(store: &RecordStore, table: &str) -> i64 {
    store
        .conn
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn revision(data: &[u8], length: u64, parents: &[Id], tag: &str) -> LocalRecord {
    let mut body = rev(parents, length, tag).body().clone();
    let Value::Map(fields) = &mut body else {
        panic!()
    };
    set(
        &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1,
        "blob_id",
        Value::Bytes(crate::id::blob_id(data).bytes.to_vec()),
    );
    LocalRecord::sign(body, &signing_key()).unwrap()
}
use crate::cbor::Value;
fn populate(t: &Temp, records: &[LocalRecord], payloads: &[Vec<u8>]) {
    let mut w = t.store().begin().unwrap();
    for r in records.iter().rev() {
        w.insert(r).unwrap();
    }
    for b in payloads {
        w.put_blob(crate::id::blob_id(b), Cursor::new(b)).unwrap();
    }
    w.finish().unwrap();
}
fn records(job: &mut EvaluationJob) {
    while !job
        .prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 1,
                ..EvaluationInputBudget::default()
            },
        )
        .unwrap()
        .complete
    {}
}
fn bodies(job: &mut EvaluationJob) -> EvaluationBlobProgress {
    loop {
        let p = job
            .prepare_blobs(
                EvaluationLimits::default(),
                EvaluationBlobBudget {
                    targets: 1,
                    ..EvaluationBlobBudget::default()
                },
            )
            .unwrap();
        if p.checks_complete {
            return p;
        }
    }
}
fn evaluated(job: &mut EvaluationJob) -> EvaluationSnapshot {
    loop {
        let p = job
            .step(
                EvaluationLimits::default(),
                EvaluationStepBudget { nodes: 1 },
            )
            .unwrap();
        if let Some(s) = p.snapshot {
            return s;
        }
    }
}
fn reference(
    records: &[LocalRecord],
    payloads: &[Vec<u8>],
    extra: serde_json::Value,
    snapshot: EvaluationSnapshot,
) {
    let mut case = oracle_case(records, false);
    case["retained"] = serde_json::json!(
        payloads
            .iter()
            .map(|b| data_encoding::HEXLOWER.encode(b))
            .collect::<Vec<_>>()
    );
    for (k, v) in extra.as_object().unwrap() {
        case[k] = v.clone();
    }
    assert_oracle(&[(case, snapshot)]);
}
fn path(t: &Temp, data: &[u8]) -> std::path::PathBuf {
    t.data()
        .join("blobs")
        .join(data_encoding::HEXLOWER.encode(&crate::id::blob_id(data).bytes))
}
fn restore(t: &Temp, data: &[u8]) {
    let p = path(t, data);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(p)
        .unwrap();
    f.write_all(data).unwrap();
    f.sync_all().unwrap();
}
fn later(n: u32) -> Vec<u8> {
    (n..n + 1000)
        .map(|i| format!("later blob {i}").into_bytes())
        .find(|b| crate::id::blob_id(b).bytes > crate::id::blob_id(&bytes()).bytes)
        .unwrap()
}

#[test]
fn multiple_targets_resume_under_a_smaller_byte_budget_and_parent_steps_do_not_rehash() {
    HASHES.with(|v| v.set(0));
    let t = Temp::new();
    let a = b"aaa".to_vec();
    let c = b"ccccc".to_vec();
    let d = b"missing".to_vec();
    let e = b"failed".to_vec();
    let parent = revision(&a, 3, &[], "parent");
    let bad = revision(&bytes(), 15, &[parent.id()], "bad");
    let good = revision(&bytes(), 14, &[parent.id()], "good");
    let nodes = [
        fixture(),
        parent,
        bad.clone(),
        good.clone(),
        revision(&c, 5, &[bad.id(), good.id()], "join"),
        revision(&d, 7, &[], "missing"),
        revision(&e, 6, &[], "failed"),
    ];
    let payloads = [a.clone(), bytes(), c.clone()];
    populate(&t, &nodes, &payloads);
    let mut w = open(&t).begin().unwrap();
    w.observe_blob_failure(crate::id::blob_id(&e), "transfer_failed")
        .unwrap();
    w.finish().unwrap();
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    job.pause().unwrap();
    for n in 1..=5 {
        let mut job = open(&t).evaluation_job().unwrap();
        let p = job
            .prepare_blobs(
                EvaluationLimits::default(),
                EvaluationBlobBudget {
                    targets: 1,
                    bytes: 14,
                    ..EvaluationBlobBudget::default()
                },
            )
            .unwrap();
        assert_eq!((p.checked_targets, p.total_targets), (n, 5));
        assert_eq!(p.checks_complete, n == 5);
        assert!(!p.storage_fault);
        if n == 1 {
            let before = crate::storage::tests::logical_snapshot(&job.writer.store.conn);
            let hashes = HASHES.with(|v| v.get());
            let limits = EvaluationLimits::default();
            let work = EvaluationBlobBudget::default();
            for (limits, work) in [
                (
                    limits,
                    EvaluationBlobBudget {
                        elapsed: Duration::ZERO,
                        ..work
                    },
                ),
                (
                    EvaluationLimits {
                        elapsed: Duration::ZERO,
                        ..limits
                    },
                    work,
                ),
            ] {
                assert!(matches!(
                    job.prepare_blobs(limits, work),
                    Err(StorageError::BudgetExceeded)
                ));
                assert_eq!(
                    crate::storage::tests::logical_snapshot(&job.writer.store.conn),
                    before
                );
                assert_eq!(HASHES.with(|v| v.get()), hashes);
            }
        }
        if !p.checks_complete {
            assert!(matches!(
                job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
                Err(StorageError::EvaluationInputPending)
            ));
        } else {
            assert_eq!(p.hashed_bytes, 22);
        }
        job.pause().unwrap();
    }
    assert_eq!(HASHES.with(|v| v.get()), 3);
    let mut job = open(&t).evaluation_job().unwrap();
    let generation = job.writer.store.generation().unwrap();
    assert!(bodies(&mut job).checks_complete);
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    let before = HASHES.with(|v| v.get());
    let s = evaluated(&mut job);
    assert_eq!(HASHES.with(|v| v.get()), before);
    reference(
        &nodes,
        &payloads,
        serde_json::json!({"failures":{data_encoding::HEXLOWER.encode(&crate::id::blob_id(&e).bytes):"transfer_failed"}}),
        s,
    );
    job.pause().unwrap();
}

#[test]
fn prerequisites_empty_and_missing_payloads_keep_completion_axes_separate() {
    let t = Temp::new();
    let nodes = [fixture(), rev(&[], 14, "missing")];
    populate(&t, &nodes, &[]);
    let mut job = open(&t).evaluation_job().unwrap();
    assert!(matches!(
        job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
        Err(StorageError::EvaluationInputPending)
    ));
    job.prepare(
        EvaluationLimits::default(),
        EvaluationInputBudget {
            records: 1,
            ..EvaluationInputBudget::default()
        },
    )
    .unwrap();
    assert!(matches!(
        job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
        Err(StorageError::EvaluationInputPending)
    ));
    records(&mut job);
    let p = job
        .prepare_blobs(
            EvaluationLimits::default(),
            EvaluationBlobBudget {
                bytes: 0,
                ..EvaluationBlobBudget::default()
            },
        )
        .unwrap();
    assert!(p.checks_complete);
    assert!(!p.storage_fault);
    assert_eq!(p.hashed_bytes, 0);
    reference(&nodes, &[], serde_json::json!({}), evaluated(&mut job));
    job.pause().unwrap();
    let t = Temp::new();
    let mut job = t.store().evaluation_job().unwrap();
    records(&mut job);
    let p = bodies(&mut job);
    assert_eq!(p.total_targets, 0);
    assert!(p.checks_complete);
    assert!(!p.storage_fault);
    assert!(evaluated(&mut job).records.is_empty());
    job.pause().unwrap();
}

#[test]
fn an_empty_blob_can_be_hashed_with_zero_byte_budget() {
    let t = Temp::new();
    let nodes = [fixture(), revision(b"", 0, &[], "empty")];
    let payloads = [vec![]];
    populate(&t, &nodes, &payloads);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    let p = job
        .prepare_blobs(
            EvaluationLimits {
                blob_bytes: 0,
                ..EvaluationLimits::default()
            },
            EvaluationBlobBudget {
                targets: 1,
                bytes: 0,
                ..EvaluationBlobBudget::default()
            },
        )
        .unwrap();
    assert_eq!((p.checked_targets, p.hashed_bytes), (1, 0));
    assert!(p.checks_complete);
    assert!(!p.storage_fault);
    reference(
        &nodes,
        &payloads,
        serde_json::json!({}),
        evaluated(&mut job),
    );
    job.pause().unwrap();
}

#[test]
fn byte_time_total_and_capacity_limits_keep_previous_progress() {
    let t = Temp::new();
    populate(&t, &[fixture(), rev(&[], 14, "one")], &[bytes()]);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    let generation = job.writer.store.generation().unwrap();
    let d = EvaluationBlobBudget::default();
    for work in [
        EvaluationBlobBudget { targets: 0, ..d },
        EvaluationBlobBudget { bytes: 13, ..d },
        EvaluationBlobBudget {
            elapsed: Duration::ZERO,
            ..d
        },
    ] {
        assert!(matches!(
            job.prepare_blobs(EvaluationLimits::default(), work),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert_eq!(count(&job.writer.store, "evaluation_blob_input"), 0);
    }
    assert!(matches!(
        job.prepare_blobs(
            EvaluationLimits {
                blob_bytes: 13,
                ..EvaluationLimits::default()
            },
            d
        ),
        Err(StorageError::BudgetExceeded)
    ));
    let p = job
        .prepare_blobs(
            EvaluationLimits::default(),
            EvaluationBlobBudget { bytes: 14, ..d },
        )
        .unwrap();
    assert!(p.checks_complete);
    let generation = job.writer.store.generation().unwrap();
    assert!(matches!(
        job.prepare_blobs(
            EvaluationLimits {
                blob_bytes: 13,
                ..EvaluationLimits::default()
            },
            d
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    job.pause().unwrap();
    let t = Temp::new();
    populate(&t, &[fixture(), rev(&[], 14, "capacity")], &[bytes()]);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    job.pause().unwrap();
    let store = RecordStore::open(
        &t.data(),
        Limits {
            reserve_percent: 100,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut job = store.evaluation_job().unwrap();
    let generation = job.writer.store.generation().unwrap();
    assert!(matches!(
        job.prepare_blobs(EvaluationLimits::default(), d),
        Err(StorageError::Capacity)
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    assert_eq!(count(&job.writer.store, "evaluation_blob_facts"), 0);
    job.pause().unwrap();
}

#[test]
fn record_blob_and_transfer_observations_invalidate_old_blob_inputs() {
    for change in ["record", "blob", "failure"] {
        let t = Temp::new();
        let a = rev(&[], 15, "bad");
        let mut nodes = vec![fixture(), a.clone(), rev(&[a.id()], 14, "child")];
        populate(&t, &nodes, &[]);
        let mut job = open(&t).evaluation_job().unwrap();
        records(&mut job);
        bodies(&mut job);
        reference(&nodes, &[], serde_json::json!({}), evaluated(&mut job));
        job.pause().unwrap();
        let mut w = open(&t).begin().unwrap();
        match change {
            "record" => {
                let r = rev(&[], 14, "new");
                w.insert(&r).unwrap();
                nodes.push(r);
            }
            "blob" => {
                w.put_blob(crate::id::blob_id(&bytes()), Cursor::new(bytes()))
                    .unwrap();
            }
            _ => w
                .observe_blob_failure(crate::id::blob_id(&bytes()), "transfer_hash_mismatch")
                .unwrap(),
        }
        w.finish().unwrap();
        let mut job = open(&t).evaluation_job().unwrap();
        assert!(matches!(
            job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
            Err(StorageError::EvaluationInputPending)
        ));
        if change == "record" {
            assert!(matches!(
                job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
                Err(StorageError::EvaluationInputPending)
            ));
            records(&mut job);
        }
        assert!(bodies(&mut job).checks_complete);
        let payloads = if change == "blob" {
            vec![bytes()]
        } else {
            vec![]
        };
        let extra = if change == "failure" {
            serde_json::json!({"failures":{data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes):"transfer_hash_mismatch"}})
        } else {
            serde_json::json!({})
        };
        reference(&nodes, &payloads, extra, evaluated(&mut job));
        job.pause().unwrap();
    }
}

#[test]
fn partial_blob_job_preserves_new_invalid_evidence_and_repair_never_clears_review() {
    let t = Temp::new();
    let other = later(0);
    let bad = rev(&[], 15, "bad");
    let child = rev(&[bad.id()], 14, "child");
    let nodes = [
        fixture(),
        bad.clone(),
        child.clone(),
        revision(&other, other.len() as u64, &[], "other"),
    ];
    let payloads = [bytes(), other.clone()];
    populate(&t, &nodes, &payloads);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    let p = job
        .prepare_blobs(
            EvaluationLimits::default(),
            EvaluationBlobBudget {
                targets: 1,
                ..EvaluationBlobBudget::default()
            },
        )
        .unwrap();
    assert_eq!(p.checked_targets, 1);
    assert!(!p.checks_complete);
    assert_eq!(count(&job.writer.store, "known_invalid"), 1);
    assert_eq!(count(&job.writer.store, "evaluations"), 0);
    job.pause().unwrap();
    std::fs::remove_file(path(&t, &bytes())).unwrap();
    let store = open(&t);
    let extra = serde_json::json!({"known":[data_encoding::HEXLOWER.encode(&bad.id().bytes)],"unavailable":[data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes)]});
    reference(
        &nodes,
        &payloads,
        extra,
        store.evaluate(EvaluationLimits::default()).unwrap(),
    );
    let mut job = store.evaluation_job().unwrap();
    assert!(matches!(
        job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
        Err(StorageError::Corrupt)
    ));
    drop(job);
    restore(&t, &bytes());
    let mut job = open(&t).evaluation_job().unwrap();
    assert!(!bodies(&mut job).storage_fault);
    reference(
        &nodes,
        &payloads,
        serde_json::json!({"known":[data_encoding::HEXLOWER.encode(&bad.id().bytes)]}),
        evaluated(&mut job),
    );
    assert_eq!(count(&job.writer.store, "known_invalid"), 1);
    job.pause().unwrap();
    assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
}

#[test]
fn missing_corrupt_and_wrong_length_retained_files_never_certify_record_forgery() {
    for fault in ["missing", "hash", "length"] {
        let t = Temp::new();
        let nodes = [fixture(), rev(&[], 15, "unproven declaration")];
        populate(&t, &nodes, &[bytes()]);
        let mut job = open(&t).evaluation_job().unwrap();
        records(&mut job);
        match fault {
            "missing" => std::fs::remove_file(path(&t, &bytes())).unwrap(),
            "hash" => std::fs::write(path(&t, &bytes()), vec![0; bytes().len()]).unwrap(),
            _ => std::fs::write(path(&t, &bytes()), b"longer than retained file").unwrap(),
        }
        let p = bodies(&mut job);
        assert!(p.checks_complete);
        assert!(p.storage_fault);
        assert_eq!(p.hashed_bytes, if fault == "hash" { 14 } else { 0 });
        assert_eq!(count(&job.writer.store, "known_invalid"), 0);
        assert!(matches!(
            job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
            Err(StorageError::Corrupt)
        ));
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        let store = open(&t);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        reference(
            &nodes,
            &[bytes()],
            serde_json::json!({"unavailable":[data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes)]}),
            store.evaluate(EvaluationLimits::default()).unwrap(),
        );
    }
}

#[test]
fn changed_verified_file_requires_rehash_and_keeps_manual_review_after_repair() {
    let t = Temp::new();
    let nodes = [fixture(), rev(&[], 14, "valid")];
    populate(&t, &nodes, &[bytes()]);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    bodies(&mut job);
    evaluated(&mut job);
    std::fs::write(path(&t, &bytes()), vec![0; bytes().len()]).unwrap();
    assert!(matches!(
        job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
        Err(StorageError::Corrupt)
    ));
    drop(job);
    let mut job = open(&t).evaluation_job().unwrap();
    assert!(bodies(&mut job).storage_fault);
    job.pause().unwrap();
    restore(&t, &bytes());
    let mut job = open(&t).evaluation_job().unwrap();
    let before = HASHES.with(|v| v.get());
    assert!(!bodies(&mut job).storage_fault);
    assert!(HASHES.with(|v| v.get()) > before);
    reference(
        &nodes,
        &[bytes()],
        serde_json::json!({}),
        evaluated(&mut job),
    );
    job.pause().unwrap();
    assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
}

#[test]
fn corrupted_manifest_is_not_hidden_by_new_observations_or_physical_repair() {
    for change in [
        "state",
        "bytes",
        "row",
        "header",
        "both",
        "digest",
        "directory",
        "total",
        "complete",
        "history",
        "length",
        "erase_fault",
    ] {
        let t = Temp::new();
        populate(&t, &[fixture(), rev(&[], 14, "one")], &[bytes()]);
        let mut job = open(&t).evaluation_job().unwrap();
        records(&mut job);
        if change == "erase_fault" {
            std::fs::write(path(&t, &bytes()), vec![0; bytes().len()]).unwrap();
        }
        bodies(&mut job);
        job.pause().unwrap();
        let conn = Connection::open(t.data().join(DB)).unwrap();
        match change {
            "state" => {
                conn.execute("UPDATE evaluation_blob_facts SET state='unavailable'", [])
                    .unwrap();
            }
            "erase_fault" => {
                conn.execute("UPDATE evaluation_blob_facts SET state='verified'", [])
                    .unwrap();
                restore(&t, &bytes());
            }
            "bytes" => {
                conn.execute("UPDATE evaluation_blob_facts SET examined_bytes=0", [])
                    .unwrap();
            }
            "row" => {
                conn.execute("DELETE FROM evaluation_blob_facts", [])
                    .unwrap();
            }
            "header" | "both" => {
                conn.execute("DELETE FROM evaluation_blob_input", [])
                    .unwrap();
                if change == "both" {
                    conn.execute("DELETE FROM evaluation_blob_facts", [])
                        .unwrap();
                }
            }
            "digest" => {
                conn.execute("UPDATE evaluation_blob_input SET digest=zeroblob(32)", [])
                    .unwrap();
            }
            "directory" => {
                conn.execute("UPDATE evaluation_blob_input SET directory='changed'", [])
                    .unwrap();
            }
            "total" => {
                conn.execute("UPDATE evaluation_blob_input SET total=total+1", [])
                    .unwrap();
            }
            "complete" => {
                conn.execute("UPDATE evaluation_blob_input SET complete=0", [])
                    .unwrap();
            }
            "history" => {
                conn.execute("UPDATE history SET reason='wrong' WHERE generation=(SELECT checkpoint_generation FROM evaluation_blob_input)",[]).unwrap();
            }
            _ => {
                conn.execute(
                    "UPDATE evaluation_blob_facts SET byte_length=byte_length+1",
                    [],
                )
                .unwrap();
            }
        }
        conn.execute("INSERT INTO blob_failures SELECT ?1,'transfer_failed',generation,'test' FROM storage_state WHERE singleton=1",[crate::id::blob_id(&bytes()).bytes]).unwrap();
        drop(conn);
        let mut job = open(&t).evaluation_job().unwrap();
        let generation = job.writer.store.generation().unwrap();
        assert!(
            matches!(
                job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
                Err(StorageError::Corrupt)
            ),
            "{change}"
        );
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
    }
}

#[test]
fn checkpoint_and_evidence_sql_refusals_roll_back_the_whole_blob_job() {
    for (table, op) in [
        ("evaluation_blob_facts", "INSERT"),
        ("evaluation_blob_facts", "UPDATE"),
        ("evaluation_blob_facts", "DELETE"),
        ("evaluation_blob_input", "INSERT"),
        ("evaluation_blob_input", "UPDATE"),
        ("known_invalid", "INSERT"),
        ("history", "INSERT"),
        ("evaluation_state", "UPDATE"),
    ] {
        let t = Temp::new();
        let other = later(0);
        let nodes = [
            fixture(),
            rev(&[], 15, "bad"),
            revision(&other, other.len() as u64, &[], "other"),
        ];
        populate(&t, &nodes, &[bytes(), other]);
        let mut job = open(&t).evaluation_job().unwrap();
        records(&mut job);
        if op != "INSERT" && table != "evaluation_state" {
            job.prepare_blobs(
                EvaluationLimits::default(),
                EvaluationBlobBudget {
                    targets: 1,
                    ..EvaluationBlobBudget::default()
                },
            )
            .unwrap();
        }
        if op == "DELETE" {
            job.writer
                .observe_blob_failure(crate::id::blob_id(&bytes()), "transfer_failed")
                .unwrap();
        }
        let generation = job.writer.store.generation().unwrap();
        let before = [
            count(&job.writer.store, "evaluation_blob_facts"),
            count(&job.writer.store, "evaluation_blob_input"),
            count(&job.writer.store, "known_invalid"),
        ];
        job.writer.store.conn.execute_batch(&format!("CREATE TRIGGER refuse_blob_input BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(
            matches!(
                job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
                Err(StorageError::Sql(_))
            ),
            "{table}/{op}"
        );
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert_eq!(
            [
                count(&job.writer.store, "evaluation_blob_facts"),
                count(&job.writer.store, "evaluation_blob_input"),
                count(&job.writer.store, "known_invalid")
            ],
            before
        );
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn blob_checkpoint_kill_resumes_only_committed_hashes_and_preserves_roots() {
    if let Some(path) = std::env::var_os("LNGNB_BLOB_INPUT_KILL") {
        let mut job = RecordStore::open(Path::new(&path), Limits::default())
            .unwrap()
            .evaluation_job()
            .unwrap();
        job.pause_at = Some(
            if std::env::var("LNGNB_BLOB_INPUT_PHASE").unwrap() == "before" {
                "blob_before"
            } else {
                "blob_after"
            },
        );
        job.prepare_blobs(
            EvaluationLimits::default(),
            EvaluationBlobBudget {
                targets: 1,
                ..EvaluationBlobBudget::default()
            },
        )
        .unwrap();
        panic!("kill待ち");
    }
    for phase in ["before", "after"] {
        let t = Temp::new();
        let a = later(0);
        let b = later(1000);
        let bad = rev(&[], 15, "bad");
        let nodes = [
            fixture(),
            bad.clone(),
            rev(&[bad.id()], 14, "child"),
            revision(&a, a.len() as u64, &[], "a"),
            revision(&b, b.len() as u64, &[], "b"),
        ];
        let payloads = [bytes(), a, b];
        populate(&t, &nodes, &payloads);
        let mut job = open(&t).evaluation_job().unwrap();
        records(&mut job);
        job.prepare_blobs(
            EvaluationLimits::default(),
            EvaluationBlobBudget {
                targets: 1,
                ..EvaluationBlobBudget::default()
            },
        )
        .unwrap();
        job.pause().unwrap();
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::blob_preparation::tests::blob_checkpoint_kill_resumes_only_committed_hashes_and_preserves_roots","--nocapture"]).env("LNGNB_BLOB_INPUT_KILL",t.data()).env("LNGNB_BLOB_INPUT_PHASE",phase).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains(&format!("LNGNB_EVALUATION_CHECKPOINT_blob_{phase}")) {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let mut job = open(&t).evaluation_job().unwrap();
        let saved = load(
            &job.writer.store,
            &Budget {
                start: Instant::now(),
                limits: EvaluationLimits::default(),
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            saved.progress().checked_targets,
            if phase == "before" { 1 } else { 2 }
        );
        assert_eq!(count(&job.writer.store, "known_invalid"), 1);
        bodies(&mut job);
        reference(
            &nodes,
            &payloads,
            serde_json::json!({}),
            evaluated(&mut job),
        );
        job.pause().unwrap();
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn file_or_source_change_after_hashing_prevents_checkpoint_commit() {
    if let Some(path) = std::env::var_os("LNGNB_BLOB_INPUT_CHANGE") {
        let mut job = RecordStore::open(Path::new(&path), Limits::default())
            .unwrap()
            .evaluation_job()
            .unwrap();
        job.pause_at = Some(
            if std::env::var("LNGNB_BLOB_CHANGE_KIND").unwrap() == "file" {
                "blob_before"
            } else {
                "blob_scanned"
            },
        );
        assert!(matches!(
            job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
            Err(StorageError::Corrupt)
        ));
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        return;
    }
    for kind in ["file", "payload", "record"] {
        let t = Temp::new();
        populate(&t, &[fixture(), rev(&[], 15, "bad")], &[bytes()]);
        let mut job = open(&t).evaluation_job().unwrap();
        records(&mut job);
        job.pause().unwrap();
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::blob_preparation::tests::file_or_source_change_after_hashing_prevents_checkpoint_commit","--nocapture"]).env("LNGNB_BLOB_INPUT_CHANGE",t.data()).env("LNGNB_BLOB_CHANGE_KIND",kind).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains(if kind == "file" {
                "LNGNB_EVALUATION_CHECKPOINT_blob_before"
            } else {
                "LNGNB_EVALUATION_CHECKPOINT_blob_scanned"
            }) {
                break;
            }
        }
        if kind == "file" {
            std::fs::write(path(&t, &bytes()), vec![0; 14]).unwrap();
        } else {
            let conn = Connection::open(t.data().join(DB)).unwrap();
            if kind == "payload" {
                conn.execute("INSERT INTO blob_failures SELECT ?1,'transfer_failed',generation,'test' FROM storage_state WHERE singleton=1",[crate::id::blob_id(&bytes()).bytes]).unwrap();
            } else {
                let r = rev(&[], 14, "after hash");
                conn.execute(
                    "INSERT INTO records VALUES(?1,?2)",
                    params![r.id().bytes, r.bytes()],
                )
                .unwrap();
            }
        }
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
        assert!(child.wait().unwrap().success());
        let store = open(&t);
        for table in [
            "evaluation_blob_input",
            "evaluation_blob_facts",
            "known_invalid",
        ] {
            assert_eq!(count(&store, table), 0);
        }
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn orphaned_bytes_are_not_adopted_and_healthy_retained_bytes_win_over_transfer_failure() {
    let t = Temp::new();
    let nodes = [fixture(), rev(&[], 14, "orphan")];
    populate(&t, &nodes, &[]);
    restore(&t, &bytes());
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    assert!(!bodies(&mut job).storage_fault);
    assert_eq!(count(&job.writer.store, "blobs"), 0);
    assert!(path(&t, &bytes()).exists());
    reference(&nodes, &[], serde_json::json!({}), evaluated(&mut job));
    job.pause().unwrap();
    assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    let t = Temp::new();
    populate(&t, &nodes, &[bytes()]);
    let mut w = open(&t).begin().unwrap();
    w.observe_blob_failure(crate::id::blob_id(&bytes()), "transfer_failed")
        .unwrap();
    w.finish().unwrap();
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    assert!(!bodies(&mut job).storage_fault);
    reference(
        &nodes,
        &[bytes()],
        serde_json::json!({"failures":{data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes):"transfer_failed"}}),
        evaluated(&mut job),
    );
    job.pause().unwrap();
}

#[test]
fn completed_manifest_does_not_hide_inconsistent_existing_evidence() {
    let t = Temp::new();
    populate(&t, &[fixture(), rev(&[], 15, "bad")], &[bytes()]);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    bodies(&mut job);
    assert_eq!(count(&job.writer.store, "known_invalid"), 1);
    job.writer
        .store
        .conn
        .execute_batch(
            "DROP TRIGGER evidence_no_update; UPDATE known_invalid SET actual_length=13;",
        )
        .unwrap();
    assert!(matches!(
        job.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default()),
        Err(StorageError::Corrupt)
    ));
    assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
}

#[test]
fn schema_seven_is_rejected_read_only_without_automatic_migration() {
    let t = Temp::new();
    drop(t.store());
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.pragma_update(None, "user_version", 7).unwrap();
    drop(conn);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
}

#[test]
fn payload_observation_after_cached_input_loading_blocks_stale_parent_publication() {
    if let Some(path) = std::env::var_os("LNGNB_BLOB_EVAL_CHANGE") {
        let mut job = RecordStore::open(Path::new(&path), Limits::default())
            .unwrap()
            .evaluation_job()
            .unwrap();
        job.pause_at = Some("eval_input_ready");
        assert!(matches!(
            job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
            Err(StorageError::Corrupt)
        ));
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        return;
    }
    let t = Temp::new();
    let nodes = [fixture(), rev(&[], 15, "unproven")];
    populate(&t, &nodes, &[]);
    let mut job = open(&t).evaluation_job().unwrap();
    records(&mut job);
    bodies(&mut job);
    job.pause().unwrap();
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::blob_preparation::tests::payload_observation_after_cached_input_loading_blocks_stale_parent_publication","--nocapture"]).env("LNGNB_BLOB_EVAL_CHANGE",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line.contains("LNGNB_EVALUATION_CHECKPOINT_eval_input_ready") {
            break;
        }
    }
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.execute("INSERT INTO blob_failures SELECT ?1,'transfer_failed',generation,'test' FROM storage_state WHERE singleton=1",[crate::id::blob_id(&bytes()).bytes]).unwrap();
    drop(conn);
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    assert!(child.wait().unwrap().success());
    let store = open(&t);
    assert_eq!(count(&store, "evaluations"), 0);
    assert_eq!(count(&store, "evaluation_work"), 0);
    let dirty: i64 = store
        .conn
        .query_row("SELECT dirty FROM evaluation_state", [], |r| r.get(0))
        .unwrap();
    assert_eq!(dirty, 1);
    let mut job = store.evaluation_job().unwrap();
    bodies(&mut job);
    reference(
        &nodes,
        &[],
        serde_json::json!({"failures":{data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes):"transfer_failed"}}),
        evaluated(&mut job),
    );
    job.pause().unwrap();
    assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
}
