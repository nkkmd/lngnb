//! R07/R08/R20/R24/R26/R27/R30。公開済み試験鍵専用、実運用へ流用禁止。
use super::super::tests::{assert_oracle, assert_state, bytes, oracle_case, result, rev};
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
fn populated(t: &Temp, records: &[LocalRecord], blob: bool) {
    let mut w = t.store().begin().unwrap();
    for r in records.iter().rev() {
        w.insert(r).unwrap();
    }
    if blob {
        w.put_blob(crate::id::blob_id(&bytes()), Cursor::new(bytes()))
            .unwrap();
    }
    w.finish().unwrap();
}
fn all(job: &mut EvaluationJob, nodes: u64) -> EvaluationSnapshot {
    loop {
        let p = job
            .step(EvaluationLimits::default(), EvaluationStepBudget { nodes })
            .unwrap();
        if let Some(s) = p.snapshot {
            assert!(p.processed_complete);
            return s;
        }
        assert!(!p.processed_complete);
        assert!(!p.validation_complete);
    }
}
#[test]
fn signed_long_history_resumes_in_32_record_jobs_and_matches_independent_reference() {
    let t = Temp::new();
    let mut records = vec![fixture()];
    let mut parent = None;
    for depth in 0..65 {
        let r = rev(
            &parent.into_iter().collect::<Vec<_>>(),
            14,
            &format!("queue depth {depth}"),
        );
        parent = Some(r.id());
        records.push(r);
    }
    let bad = rev(&[parent.unwrap()], 15, "bad branch");
    let good = rev(&[parent.unwrap()], 14, "good branch");
    let join = rev(&[bad.id(), good.id()], 14, "join");
    records.extend([bad.clone(), good.clone(), join.clone()]);
    populated(&t, &records, true);
    let baseline = open(&t).evaluate(EvaluationLimits::default()).unwrap();
    for expected in [32, 64, 69] {
        let mut job = open(&t).evaluation_job().unwrap();
        let p = job
            .step(EvaluationLimits::default(), EvaluationStepBudget::default())
            .unwrap();
        assert_eq!((p.processed, p.total), (expected, 69));
        assert_eq!(count(&job.writer.store, "known_invalid"), 1);
        let dirty: i64 = job
            .writer
            .store
            .conn
            .query_row("SELECT dirty FROM evaluation_state", [], |r| r.get(0))
            .unwrap();
        if expected < 69 {
            assert!(p.snapshot.is_none());
            assert!(!p.processed_complete);
            assert!(!p.validation_complete);
            assert_eq!(dirty, 1);
            assert_eq!(count(&job.writer.store, "evaluations"), 0);
        } else {
            assert!(p.validation_complete);
            assert_eq!(dirty, 0);
            let s = p.snapshot.unwrap();
            assert!(s.committed);
            assert_eq!(s.records, baseline.records);
            assert_state(
                &s,
                &bad,
                Validation::Invalid,
                Some(Reason::DeclaredLengthMismatch),
            );
            assert_state(&s, &join, Validation::Invalid, Some(Reason::InvalidParent));
            assert_state(&s, &good, Validation::Valid, None);
            assert_oracle(&[(oracle_case(&records, true), s)]);
        }
        job.pause().unwrap();
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::Clean);
    }
}
#[test]
fn processed_completion_is_separate_from_pending_dependencies_and_empty_is_complete() {
    let t = Temp::new();
    let missing = record_id([0x22; 32]);
    let r = rev(&[missing], 14, "missing");
    let records = [fixture(), r.clone()];
    populated(&t, &records, false);
    let mut job = open(&t).evaluation_job().unwrap();
    let p = job
        .step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
    assert_eq!(p.processed, 1);
    assert!(!p.processed_complete);
    assert!(p.snapshot.is_none());
    let p = job
        .step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
    assert!(p.processed_complete);
    assert!(!p.validation_complete);
    let s = p.snapshot.unwrap();
    assert_state(&s, &r, Validation::Pending, Some(Reason::MissingParent));
    assert_eq!(
        result(&s, r.id()).payload_status,
        Some(PayloadStatus::Missing)
    );
    assert_oracle(&[(oracle_case(&records, false), s)]);
    job.pause().unwrap();
    let empty = Temp::new();
    let mut job = empty.store().evaluation_job().unwrap();
    let p = job
        .step(EvaluationLimits::default(), EvaluationStepBudget::default())
        .unwrap();
    assert_eq!(p.processed, 0);
    assert!(p.processed_complete);
    assert!(p.validation_complete);
    assert!(p.snapshot.unwrap().records.is_empty());
    job.pause().unwrap();
}
#[test]
fn new_record_blob_or_failure_observation_invalidates_the_old_prefix() {
    for change in ["record", "blob", "failure"] {
        let t = Temp::new();
        let a = rev(&[], 15, "a");
        let b = rev(&[a.id()], 14, "b");
        let mut records = vec![fixture(), a.clone(), b];
        populated(&t, &records, false);
        let mut job = open(&t).evaluation_job().unwrap();
        assert_eq!(
            job.step(
                EvaluationLimits::default(),
                EvaluationStepBudget { nodes: 2 }
            )
            .unwrap()
            .processed,
            2
        );
        job.pause().unwrap();
        let mut w = open(&t).begin().unwrap();
        match change {
            "record" => {
                let c = rev(&[], 14, "new");
                w.insert(&c).unwrap();
                records.push(c);
            }
            "blob" => {
                w.put_blob(crate::id::blob_id(&bytes()), Cursor::new(bytes()))
                    .unwrap();
            }
            _ => w
                .observe_blob_failure(crate::id::blob_id(&bytes()), "transfer_failed")
                .unwrap(),
        }
        w.finish().unwrap();
        let mut job = open(&t).evaluation_job().unwrap();
        assert_eq!(
            job.step(
                EvaluationLimits::default(),
                EvaluationStepBudget { nodes: 1 }
            )
            .unwrap()
            .processed,
            1
        );
        let s = all(&mut job, 1);
        assert_eq!(
            s.records,
            job.writer
                .store
                .evaluate(EvaluationLimits::default())
                .unwrap()
                .records
        );
        let mut case = oracle_case(&records, change == "blob");
        if change == "failure" {
            case["failures"] = serde_json::json!({data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes):"transfer_failed"});
        }
        assert_oracle(&[(case, s)]);
        job.pause().unwrap();
    }
}
#[test]
fn corrupted_checkpoint_is_rejected_before_input_change_can_reset_it() {
    for change in [
        "row", "delete", "input", "digest", "total", "complete", "history", "header", "both",
    ] {
        let t = Temp::new();
        let records = [fixture(), rev(&[], 14, "one"), rev(&[], 14, "two")];
        populated(&t, &records, false);
        let mut job = open(&t).evaluation_job().unwrap();
        job.step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
        job.pause().unwrap();
        let mut w = open(&t).begin().unwrap();
        match change {
            "row" => {
                let (id, raw): (Vec<u8>, Vec<u8>) = w
                    .store
                    .conn
                    .query_row("SELECT record_id,result FROM evaluation_work", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .unwrap();
                let mut a = decoded(&raw, id.clone().try_into().unwrap()).unwrap();
                a.validation = Validation::Invalid;
                a.reason = Some(Reason::WrongPublisher);
                a.related = Some(fixture().id());
                w.store
                    .conn
                    .execute(
                        "UPDATE evaluation_work SET result=?1 WHERE record_id=?2",
                        params![encoded(&a).unwrap(), id],
                    )
                    .unwrap();
            }
            "delete" => {
                w.store
                    .conn
                    .execute("DELETE FROM evaluation_work", [])
                    .unwrap();
            }
            "input" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_job SET input=zeroblob(32)", [])
                    .unwrap();
            }
            "digest" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_job SET digest=zeroblob(32)", [])
                    .unwrap();
            }
            "total" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_job SET total=total+1", [])
                    .unwrap();
            }
            "complete" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_job SET complete=1", [])
                    .unwrap();
            }
            "header" | "both" => {
                w.store
                    .conn
                    .execute("DELETE FROM evaluation_job", [])
                    .unwrap();
                if change == "both" {
                    w.store
                        .conn
                        .execute("DELETE FROM evaluation_work", [])
                        .unwrap();
                }
            }
            _ => {
                w.store.conn.execute("UPDATE history SET reason='wrong' WHERE generation=(SELECT checkpoint_generation FROM evaluation_job)",[]).unwrap();
            }
        }
        w.insert(&rev(&[], 14, "input changed too")).unwrap();
        w.finish().unwrap();
        let mut job = open(&t).evaluation_job().unwrap();
        let generation = job.writer.store.generation().unwrap();
        assert!(
            matches!(
                job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
                Err(StorageError::Corrupt)
            ),
            "{change}"
        );
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn sql_failure_rolls_back_results_roots_publication_and_checkpoint_as_one_unit() {
    for table in [
        "evaluation_work",
        "evaluation_job",
        "history",
        "known_invalid",
        "evaluations",
        "parent_edges",
        "evaluation_state",
    ] {
        let t = Temp::new();
        let a = rev(&[], 15, "bad");
        let records = [fixture(), a.clone(), rev(&[a.id()], 14, "child")];
        populated(&t, &records, true);
        let mut job = open(&t).evaluation_job().unwrap();
        let generation = job.writer.store.generation().unwrap();
        let op = if table == "evaluation_state" {
            "UPDATE"
        } else {
            "INSERT"
        };
        job.writer.store.conn.execute_batch(&format!("CREATE TRIGGER refuse_queue BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(
            matches!(
                job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
                Err(StorageError::Sql(_))
            ),
            "{table}"
        );
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        for table in [
            "evaluation_job",
            "evaluation_work",
            "evaluations",
            "parent_edges",
            "known_invalid",
        ] {
            assert_eq!(count(&job.writer.store, table), 0);
        }
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn failed_checkpoint_update_keeps_only_previous_committed_progress() {
    let t = Temp::new();
    populated(
        &t,
        &[fixture(), rev(&[], 14, "a"), rev(&[], 14, "b")],
        false,
    );
    let mut job = open(&t).evaluation_job().unwrap();
    job.step(
        EvaluationLimits::default(),
        EvaluationStepBudget { nodes: 1 },
    )
    .unwrap();
    let generation = job.writer.store.generation().unwrap();
    job.writer.store.conn.execute_batch("CREATE TRIGGER refuse_checkpoint BEFORE UPDATE ON evaluation_job BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(matches!(
        job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
        Err(StorageError::Sql(_))
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    assert_eq!(count(&job.writer.store, "evaluation_work"), 1);
    assert_eq!(count(&job.writer.store, "evaluations"), 0);
    assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
}
#[test]
fn partial_job_preserves_new_invalid_evidence_and_repair_does_not_clear_review() {
    let t = Temp::new();
    let a = rev(&[], 15, "bad");
    let child = rev(&[a.id()], 14, "child");
    populated(
        &t,
        &[fixture(), a.clone(), child.clone(), rev(&[], 14, "branch")],
        true,
    );
    let mut job = open(&t).evaluation_job().unwrap();
    job.step(
        EvaluationLimits::default(),
        EvaluationStepBudget { nodes: 1 },
    )
    .unwrap();
    assert_eq!(count(&job.writer.store, "known_invalid"), 1);
    job.pause().unwrap();
    let path = t
        .data()
        .join("blobs")
        .join(data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes));
    std::fs::remove_file(&path).unwrap();
    let store = open(&t);
    let s = store.evaluate(EvaluationLimits::default()).unwrap();
    for r in [&a, &child] {
        assert_state(
            &s,
            r,
            Validation::Pending,
            Some(Reason::EvidenceUnavailable),
        );
    }
    let mut job = store.evaluation_job().unwrap();
    assert!(matches!(
        job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
        Err(StorageError::Corrupt)
    ));
    assert_eq!(count(&job.writer.store, "evaluation_work"), 1);
    assert_eq!(count(&job.writer.store, "known_invalid"), 1);
    drop(job);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(&bytes()).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let mut job = open(&t).evaluation_job().unwrap();
    assert_eq!(
        job.step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 }
        )
        .unwrap()
        .processed,
        2
    );
    let s = all(&mut job, 1);
    assert_state(
        &s,
        &a,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    assert_state(&s, &child, Validation::Invalid, Some(Reason::InvalidParent));
    job.pause().unwrap();
    let store = open(&t);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
}
#[test]
fn preparation_budgets_capacity_and_zero_work_never_claim_progress() {
    let t = Temp::new();
    let a = rev(&[], 14, "a");
    populated(&t, &[fixture(), a.clone(), rev(&[a.id()], 14, "b")], true);
    let mut job = open(&t).evaluation_job().unwrap();
    let generation = job.writer.store.generation().unwrap();
    let d = EvaluationLimits::default();
    for limits in [
        EvaluationLimits { records: 2, ..d },
        EvaluationLimits {
            record_bytes: 1,
            ..d
        },
        EvaluationLimits { edges: 0, ..d },
        EvaluationLimits {
            blob_bytes: 13,
            ..d
        },
        EvaluationLimits {
            elapsed: Duration::ZERO,
            ..d
        },
    ] {
        assert!(matches!(
            job.step(limits, EvaluationStepBudget::default()),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert_eq!(count(&job.writer.store, "evaluation_work"), 0);
    }
    assert!(matches!(
        job.step(d, EvaluationStepBudget { nodes: 0 }),
        Err(StorageError::BudgetExceeded)
    ));
    job.step(d, EvaluationStepBudget { nodes: 1 }).unwrap();
    let generation = job.writer.store.generation().unwrap();
    assert!(matches!(
        job.step(
            EvaluationLimits { records: 2, ..d },
            EvaluationStepBudget::default()
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    assert_eq!(count(&job.writer.store, "evaluation_work"), 1);
    all(&mut job, 1);
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
        job.step(d, EvaluationStepBudget::default()),
        Err(StorageError::Capacity)
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    job.pause().unwrap();
}
#[test]
fn checkpoint_kill_resumes_only_committed_rows_and_never_clears_review() {
    if let Some(path) = std::env::var_os("LNGNB_QUEUE_KILL_CHILD") {
        let store = RecordStore::open(Path::new(&path), Limits::default()).unwrap();
        let mut job = store.evaluation_job().unwrap();
        job.pause_at = Some(
            if std::env::var("LNGNB_QUEUE_KILL_PHASE").unwrap() == "before" {
                "before"
            } else {
                "after"
            },
        );
        job.step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
        panic!("killされる必要がある");
    }
    for phase in ["before", "after"] {
        let t = Temp::new();
        populated(
            &t,
            &[
                fixture(),
                rev(&[], 14, "a"),
                rev(&[], 14, "b"),
                rev(&[], 14, "c"),
            ],
            false,
        );
        let mut job = open(&t).evaluation_job().unwrap();
        job.step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
        job.pause().unwrap();
        let mut child=Command::new(std::env::current_exe().unwrap())
            .args(["--exact","storage::evaluation::queue::tests::checkpoint_kill_resumes_only_committed_rows_and_never_clears_review","--nocapture"])
            .env("LNGNB_QUEUE_KILL_CHILD",t.data()).env("LNGNB_QUEUE_KILL_PHASE",phase).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "子プロセスがcheckpointへ到達しない"
            );
            if line.contains(&format!("LNGNB_EVALUATION_CHECKPOINT_{phase}")) {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let store = open(&t);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(
            count(&store, "evaluation_work"),
            if phase == "before" { 1 } else { 2 }
        );
        let mut job = store.evaluation_job().unwrap();
        let p = job
            .step(
                EvaluationLimits::default(),
                EvaluationStepBudget { nodes: 1 },
            )
            .unwrap();
        assert_eq!(p.processed, if phase == "before" { 2 } else { 3 });
        job.pause().unwrap();
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn unfinished_startup_inspection_cannot_be_bypassed_by_evaluation_job() {
    let t = Temp::new();
    populated(&t, &[fixture(), rev(&[], 14, "a")], false);
    let mut inspection = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    inspection
        .step(InspectionBudget {
            records: 1,
            ..InspectionBudget::default()
        })
        .unwrap();
    inspection.pause().unwrap();
    assert!(matches!(
        open(&t).evaluation_job(),
        Err(StorageError::InspectionPending)
    ));
}
#[test]
fn schema_five_is_preserved_without_automatic_migration() {
    let t = Temp::new();
    drop(t.store());
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.pragma_update(None, "user_version", 5).unwrap();
    drop(conn);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
}

#[test]
fn historical_rows_stay_dirty_until_complete_publication_and_replay_does_not_duplicate_changes() {
    let t = Temp::new();
    let a = rev(&[], 15, "bad");
    let child = rev(&[a.id()], 14, "child");
    let records = [fixture(), a.clone(), child.clone()];
    populated(&t, &records, false);
    let mut w = open(&t).begin().unwrap();
    w.revalidate(EvaluationLimits::default()).unwrap();
    w.put_blob(crate::id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    w.finish().unwrap();
    let mut job = open(&t).evaluation_job().unwrap();
    let p = job
        .step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
    assert!(p.snapshot.is_none());
    let (dirty,state):(i64,String)=job.writer.store.conn.query_row("SELECT dirty,(SELECT validation FROM evaluations WHERE record_id=?1) FROM evaluation_state",[a.id().bytes],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!((dirty, state), (1, "valid".into()));
    let s = all(&mut job, 1);
    assert_state(
        &s,
        &a,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    assert_oracle(&[(oracle_case(&records, true), s)]);
    let changed_before: i64 = job
        .writer
        .store
        .conn
        .query_row(
            "SELECT count(*) FROM history WHERE reason='record_dependency_evaluation'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let p = job
        .step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 1 },
        )
        .unwrap();
    assert!(p.processed_complete);
    assert!(p.validation_complete);
    let changed_after: i64 = job
        .writer
        .store
        .conn
        .query_row(
            "SELECT count(*) FROM history WHERE reason='record_dependency_evaluation'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(changed_before, changed_after);
    job.pause().unwrap();
}

#[test]
fn blob_change_after_hash_before_checkpoint_is_not_committed() {
    if let Some(path) = std::env::var_os("LNGNB_QUEUE_MUTATION_CHILD") {
        let store = RecordStore::open(Path::new(&path), Limits::default()).unwrap();
        let mut job = store.evaluation_job().unwrap();
        job.pause_at = Some("before");
        assert!(matches!(
            job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
            Err(StorageError::Corrupt)
        ));
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        return;
    }
    let t = Temp::new();
    populated(&t, &[fixture(), rev(&[], 15, "bad")], true);
    let mut child=Command::new(std::env::current_exe().unwrap())
        .args(["--exact","storage::evaluation::queue::tests::blob_change_after_hash_before_checkpoint_is_not_committed","--nocapture"])
        .env("LNGNB_QUEUE_MUTATION_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line.contains("LNGNB_EVALUATION_CHECKPOINT_before") {
            break;
        }
    }
    let path = t
        .data()
        .join("blobs")
        .join(data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes));
    std::fs::write(path, b"changed after verification").unwrap();
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    assert!(child.wait().unwrap().success());
    let store = open(&t);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    for table in [
        "evaluation_work",
        "evaluation_job",
        "evaluations",
        "known_invalid",
    ] {
        assert_eq!(count(&store, table), 0);
    }
}
