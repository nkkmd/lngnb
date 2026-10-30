//! Record入力収集の境界・再開・独立照合。公開済み試験鍵専用、実運用禁止。
use super::super::tests::{assert_oracle, bytes, oracle_case, rev};
use super::*;
use crate::storage::tests::{Temp, fixture};
use std::{
    io::{BufRead, Cursor, Write},
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
fn collected(job: &mut EvaluationJob, records: u64) -> EvaluationInputProgress {
    loop {
        let p = job
            .prepare(
                EvaluationLimits::default(),
                EvaluationInputBudget {
                    records,
                    ..EvaluationInputBudget::default()
                },
            )
            .unwrap();
        if p.complete {
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
#[test]
fn collection_crosses_job_byte_limit_and_compact_inputs_feed_independent_evaluation() {
    let t = Temp::new();
    let a = rev(&[], 14, &"a".repeat(4000));
    let b = rev(&[a.id()], 15, &"b".repeat(4000));
    let records = [
        fixture(),
        a.clone(),
        b.clone(),
        rev(&[a.id(), b.id()], 14, "join"),
    ];
    populated(&t, &records, true);
    let max = records
        .iter()
        .map(|r| r.bytes().len() as u64)
        .max()
        .unwrap();
    let total = records.iter().map(|r| r.bytes().len() as u64).sum::<u64>();
    assert!(total > max);
    let mut ordered = records.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|r| r.id().bytes);
    for n in 1..=4 {
        let mut job = open(&t).evaluation_job().unwrap();
        let p = job
            .prepare(
                EvaluationLimits::default(),
                EvaluationInputBudget {
                    records: 1,
                    bytes: max,
                    ..EvaluationInputBudget::default()
                },
            )
            .unwrap();
        assert_eq!(p.collected_records, n);
        assert_eq!(
            p.collected_bytes,
            ordered[..n as usize]
                .iter()
                .map(|r| r.bytes().len() as u64)
                .sum::<u64>()
        );
        assert_eq!(p.complete, n == 4);
        if !p.complete {
            assert!(matches!(
                job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
                Err(StorageError::EvaluationInputPending)
            ));
        }
        job.pause().unwrap();
    }
    let mut job = open(&t).evaluation_job().unwrap();
    let stored: i64 = job
        .writer
        .store
        .conn
        .query_row(
            "SELECT sum(length(summary)) FROM evaluation_nodes",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!((stored as u64) < total / 8);
    assert!(matches!(
        job.step(
            EvaluationLimits {
                blob_bytes: 13,
                ..EvaluationLimits::default()
            },
            EvaluationStepBudget::default()
        ),
        Err(StorageError::BudgetExceeded)
    ));
    let s = evaluated(&mut job);
    assert!(s.committed);
    assert_oracle(&[(oracle_case(&records, true), s)]);
    job.pause().unwrap();
}
#[test]
fn only_record_arrivals_restart_collection_and_other_observations_reuse_inputs() {
    for change in ["record", "blob", "failure"] {
        let t = Temp::new();
        let a = rev(&[], 15, "a");
        let mut records = vec![fixture(), a.clone(), rev(&[a.id()], 14, "b")];
        populated(&t, &records, false);
        let mut job = open(&t).evaluation_job().unwrap();
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 2,
                ..EvaluationInputBudget::default()
            },
        )
        .unwrap();
        job.pause().unwrap();
        let mut w = open(&t).begin().unwrap();
        match change {
            "record" => {
                let r = rev(&[], 14, "new");
                w.insert(&r).unwrap();
                records.push(r);
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
        assert!(matches!(
            job.step(EvaluationLimits::default(), EvaluationStepBudget::default()),
            Err(StorageError::EvaluationInputPending)
        ));
        let p = job
            .prepare(
                EvaluationLimits::default(),
                EvaluationInputBudget {
                    records: 1,
                    ..EvaluationInputBudget::default()
                },
            )
            .unwrap();
        assert_eq!(p.collected_records, if change == "record" { 1 } else { 3 });
        collected(&mut job, 1);
        let s = evaluated(&mut job);
        let mut case = oracle_case(&records, change == "blob");
        if change == "failure" {
            case["failures"] = serde_json::json!({data_encoding::HEXLOWER.encode(&crate::id::blob_id(&bytes()).bytes):"transfer_failed"});
        }
        assert_oracle(&[(case, s)]);
        job.pause().unwrap();
    }
}
#[test]
fn new_record_before_the_old_cursor_is_not_skipped() {
    let t = Temp::new();
    let records = [fixture(), rev(&[], 14, "one"), rev(&[], 14, "two")];
    populated(&t, &records, false);
    let mut job = open(&t).evaluation_job().unwrap();
    job.prepare(
        EvaluationLimits::default(),
        EvaluationInputBudget {
            records: 2,
            ..EvaluationInputBudget::default()
        },
    )
    .unwrap();
    let cursor: Vec<u8> = job
        .writer
        .store
        .conn
        .query_row("SELECT cursor FROM evaluation_input", [], |r| r.get(0))
        .unwrap();
    job.pause().unwrap();
    let earlier = (0..1000)
        .map(|n| rev(&[], 14, &format!("earlier {n}")))
        .find(|r| r.id().bytes.as_slice() < cursor.as_slice())
        .unwrap();
    let mut w = open(&t).begin().unwrap();
    w.insert(&earlier).unwrap();
    w.finish().unwrap();
    let mut job = open(&t).evaluation_job().unwrap();
    assert_eq!(
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 1,
                ..EvaluationInputBudget::default()
            }
        )
        .unwrap()
        .collected_records,
        1
    );
    assert_eq!(collected(&mut job, 1).collected_records, 4);
    let s = evaluated(&mut job);
    assert!(s.records.iter().any(|r| r.record_id == earlier.id()));
    job.pause().unwrap();
}
#[test]
fn corrupted_summary_checkpoint_or_history_is_not_reset_by_new_input() {
    for change in [
        "summary", "row", "header", "both", "bytes", "edges", "cursor", "digest", "complete",
        "history", "length",
    ] {
        let t = Temp::new();
        populated(
            &t,
            &[fixture(), rev(&[], 14, "a"), rev(&[], 14, "b")],
            false,
        );
        let mut job = open(&t).evaluation_job().unwrap();
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 1,
                ..EvaluationInputBudget::default()
            },
        )
        .unwrap();
        job.pause().unwrap();
        let mut w = open(&t).begin().unwrap();
        match change {
            "summary" => {
                let (id, raw): (Vec<u8>, Vec<u8>) = w
                    .store
                    .conn
                    .query_row("SELECT record_id,summary FROM evaluation_nodes", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .unwrap();
                let mut node = decode(&raw, id.clone().try_into().unwrap()).unwrap();
                node.identity.knowledge = [0x99; 32];
                w.store
                    .conn
                    .execute(
                        "UPDATE evaluation_nodes SET summary=?1 WHERE record_id=?2",
                        params![encode(&node).unwrap(), id],
                    )
                    .unwrap();
            }
            "row" => {
                w.store
                    .conn
                    .execute("DELETE FROM evaluation_nodes", [])
                    .unwrap();
            }
            "header" | "both" => {
                w.store
                    .conn
                    .execute("DELETE FROM evaluation_input", [])
                    .unwrap();
                if change == "both" {
                    w.store
                        .conn
                        .execute("DELETE FROM evaluation_nodes", [])
                        .unwrap();
                }
            }
            "bytes" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_input SET bytes=bytes+1", [])
                    .unwrap();
            }
            "edges" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_input SET edges=edges+1", [])
                    .unwrap();
            }
            "cursor" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_input SET cursor=zeroblob(32)", [])
                    .unwrap();
            }
            "digest" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_input SET digest=zeroblob(32)", [])
                    .unwrap();
            }
            "complete" => {
                w.store
                    .conn
                    .execute("UPDATE evaluation_input SET complete=1", [])
                    .unwrap();
            }
            "length" => {
                w.store
                    .conn
                    .execute(
                        "UPDATE evaluation_nodes SET source_length=source_length+1",
                        [],
                    )
                    .unwrap();
            }
            _ => {
                w.store.conn.execute("UPDATE history SET reason='wrong' WHERE generation=(SELECT checkpoint_generation FROM evaluation_input)",[]).unwrap();
            }
        }
        w.insert(&rev(&[], 14, "input also changed")).unwrap();
        w.finish().unwrap();
        let mut job = open(&t).evaluation_job().unwrap();
        let generation = job.writer.store.generation().unwrap();
        assert!(
            matches!(
                job.prepare(
                    EvaluationLimits::default(),
                    EvaluationInputBudget::default()
                ),
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
fn corrupted_uncollected_primary_record_never_gets_a_summary() {
    let t = Temp::new();
    populated(
        &t,
        &[fixture(), rev(&[], 14, "a"), rev(&[], 14, "b")],
        false,
    );
    let mut job = open(&t).evaluation_job().unwrap();
    job.prepare(
        EvaluationLimits::default(),
        EvaluationInputBudget {
            records: 1,
            ..EvaluationInputBudget::default()
        },
    )
    .unwrap();
    let generation = job.writer.store.generation().unwrap();
    job.writer.store.conn.execute_batch("DROP TRIGGER records_no_update; UPDATE records SET bytes=zeroblob(length(bytes)) WHERE id=(SELECT id FROM records WHERE id>(SELECT cursor FROM evaluation_input) ORDER BY id LIMIT 1);").unwrap();
    assert!(matches!(
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget::default()
        ),
        Err(StorageError::Corrupt)
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    assert_eq!(count(&job.writer.store, "evaluation_nodes"), 1);
    assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
}
#[test]
fn sql_refusal_rolls_back_summaries_flags_checkpoint_and_generation() {
    for (table, op) in [
        ("evaluation_nodes", "INSERT"),
        ("evaluation_input", "INSERT"),
        ("evaluation_input", "UPDATE"),
        ("history", "INSERT"),
        ("evaluation_state", "UPDATE"),
        ("evaluation_nodes", "DELETE"),
    ] {
        let t = Temp::new();
        populated(
            &t,
            &[fixture(), rev(&[], 14, "a"), rev(&[], 14, "b")],
            false,
        );
        let mut job = open(&t).evaluation_job().unwrap();
        let previous = if op == "UPDATE" && table == "evaluation_input" || op == "DELETE" {
            job.prepare(
                EvaluationLimits::default(),
                EvaluationInputBudget {
                    records: 1,
                    ..EvaluationInputBudget::default()
                },
            )
            .unwrap();
            1
        } else {
            0
        };
        if op == "DELETE" {
            job.pause().unwrap();
            let mut w = open(&t).begin().unwrap();
            w.insert(&rev(&[], 14, "new")).unwrap();
            w.finish().unwrap();
            job = open(&t).evaluation_job().unwrap();
        }
        let generation = job.writer.store.generation().unwrap();
        job.writer.store.conn.execute_batch(&format!("CREATE TRIGGER refuse_input BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(
            matches!(
                job.prepare(
                    EvaluationLimits::default(),
                    EvaluationInputBudget::default()
                ),
                Err(StorageError::Sql(_))
            ),
            "{table}/{op}"
        );
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert_eq!(count(&job.writer.store, "evaluation_nodes"), previous);
        assert_eq!(
            count(&job.writer.store, "evaluation_input"),
            i64::from(previous > 0)
        );
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn per_job_and_total_limits_do_not_erase_committed_input_progress() {
    let t = Temp::new();
    let a = rev(&[], 14, "a");
    populated(&t, &[fixture(), a.clone(), rev(&[a.id()], 14, "b")], false);
    let mut job = open(&t).evaluation_job().unwrap();
    let d = EvaluationInputBudget::default();
    let generation = job.writer.store.generation().unwrap();
    for work in [
        EvaluationInputBudget { records: 0, ..d },
        EvaluationInputBudget { bytes: 0, ..d },
        EvaluationInputBudget { bytes: 1, ..d },
        EvaluationInputBudget {
            elapsed: Duration::ZERO,
            ..d
        },
    ] {
        assert!(matches!(
            job.prepare(EvaluationLimits::default(), work),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert_eq!(count(&job.writer.store, "evaluation_nodes"), 0);
    }
    let l = EvaluationLimits::default();
    for limits in [
        EvaluationLimits { records: 1, ..l },
        EvaluationLimits {
            record_bytes: 1,
            ..l
        },
        EvaluationLimits { edges: 0, ..l },
    ] {
        assert!(matches!(
            job.prepare(limits, d),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(count(&job.writer.store, "evaluation_nodes"), 0);
    }
    job.prepare(l, EvaluationInputBudget { records: 1, ..d })
        .unwrap();
    let generation = job.writer.store.generation().unwrap();
    assert!(matches!(
        job.prepare(
            EvaluationLimits {
                record_bytes: 1,
                ..l
            },
            d
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    assert_eq!(count(&job.writer.store, "evaluation_nodes"), 1);
    let before: String = job.writer.store.conn.query_row(
        "SELECT quote(cursor)||':'||records||':'||bytes||':'||edges||':'||complete||':'||quote(digest)||':'||checkpoint_generation FROM evaluation_input",
        [], |r| r.get(0),
    ).unwrap();
    for (limits, work) in [
        (l, EvaluationInputBudget { elapsed: Duration::ZERO, ..d }),
        (EvaluationLimits { elapsed: Duration::ZERO, ..l }, d),
    ] {
        assert!(matches!(job.prepare(limits, work), Err(StorageError::BudgetExceeded)));
        let after: String = job.writer.store.conn.query_row(
            "SELECT quote(cursor)||':'||records||':'||bytes||':'||edges||':'||complete||':'||quote(digest)||':'||checkpoint_generation FROM evaluation_input",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(before, after);
        assert_eq!(job.writer.store.generation().unwrap(), generation);
        assert_eq!(count(&job.writer.store, "evaluation_nodes"), 1);
    }
    collected(&mut job, 1);
    let generation = job.writer.store.generation().unwrap();
    assert!(job.prepare(l, d).unwrap().complete);
    assert_eq!(job.writer.store.generation().unwrap(), generation);
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
    // 新しい入力でcacheを作り直す場合の容量不足は別の新規領域で確認する。
    assert!(job.prepare(l, d).unwrap().complete);
    job.pause().unwrap();
    let second = Temp::new();
    populated(&second, &[fixture()], false);
    let store = RecordStore::open(
        &second.data(),
        Limits {
            reserve_percent: 100,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut job = store.evaluation_job().unwrap();
    assert!(matches!(job.prepare(l, d), Err(StorageError::Capacity)));
    assert_eq!(count(&job.writer.store, "evaluation_input"), 0);
    job.pause().unwrap();
}
#[test]
fn checkpoint_kill_keeps_only_committed_record_inputs_and_review() {
    if let Some(path) = std::env::var_os("LNGNB_INPUT_KILL_CHILD") {
        let mut job = RecordStore::open(Path::new(&path), Limits::default())
            .unwrap()
            .evaluation_job()
            .unwrap();
        job.pause_at = Some(
            if std::env::var("LNGNB_INPUT_KILL_PHASE").unwrap() == "before" {
                "input_before"
            } else {
                "input_after"
            },
        );
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 1,
                ..EvaluationInputBudget::default()
            },
        )
        .unwrap();
        panic!("kill待ち");
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
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 1,
                ..EvaluationInputBudget::default()
            },
        )
        .unwrap();
        job.pause().unwrap();
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::preparation::tests::checkpoint_kill_keeps_only_committed_record_inputs_and_review","--nocapture"])
            .env("LNGNB_INPUT_KILL_CHILD",t.data()).env("LNGNB_INPUT_KILL_PHASE",phase).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains(&format!("LNGNB_EVALUATION_CHECKPOINT_input_{phase}")) {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let store = open(&t);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(
            count(&store, "evaluation_nodes"),
            if phase == "before" { 1 } else { 2 }
        );
        let mut job = store.evaluation_job().unwrap();
        assert_eq!(
            job.prepare(
                EvaluationLimits::default(),
                EvaluationInputBudget {
                    records: 1,
                    ..EvaluationInputBudget::default()
                }
            )
            .unwrap()
            .collected_records,
            if phase == "before" { 2 } else { 3 }
        );
        collected(&mut job, 1);
        evaluated(&mut job);
        job.pause().unwrap();
        assert_eq!(open(&t).startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn empty_input_and_maximum_parent_summary_preserve_completion_axes() {
    let t = Temp::new();
    let mut job = t.store().evaluation_job().unwrap();
    let p = collected(&mut job, 1);
    assert_eq!(p.collected_records, 0);
    assert!(p.complete);
    assert!(evaluated(&mut job).records.is_empty());
    job.pause().unwrap();
    let t = Temp::new();
    let parents = (0u16..256)
        .map(|i| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&i.to_be_bytes());
            record_id(id)
        })
        .collect::<Vec<_>>();
    let records = [
        fixture(),
        rev(&parents, i64::MAX as u64, "256 missing parents"),
        rev(&[], 0, "zero declaration"),
    ];
    populated(&t, &records, true);
    let mut job = open(&t).evaluation_job().unwrap();
    let p = collected(&mut job, 1);
    assert_eq!(p.collected_edges, 256);
    let result = job
        .step(
            EvaluationLimits::default(),
            EvaluationStepBudget { nodes: 100 },
        )
        .unwrap();
    assert!(result.processed_complete);
    assert!(!result.validation_complete);
    assert_oracle(&[(oracle_case(&records, true), result.snapshot.unwrap())]);
    job.pause().unwrap();
}
#[test]
fn schema_six_is_rejected_read_only_without_migration() {
    let t = Temp::new();
    drop(t.store());
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.pragma_update(None, "user_version", 6).unwrap();
    drop(conn);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
}

#[test]
fn source_epoch_change_after_scanning_refuses_the_checkpoint() {
    if let Some(path) = std::env::var_os("LNGNB_INPUT_SOURCE_CHILD") {
        let mut job = RecordStore::open(Path::new(&path), Limits::default())
            .unwrap()
            .evaluation_job()
            .unwrap();
        job.pause_at = Some("input_scanned");
        assert!(matches!(
            job.prepare(
                EvaluationLimits::default(),
                EvaluationInputBudget::default()
            ),
            Err(StorageError::Corrupt)
        ));
        assert!(matches!(job.pause(), Err(StorageError::UnresolvedFailure)));
        return;
    }
    let t = Temp::new();
    populated(&t, &[fixture(), rev(&[], 14, "a")], false);
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::preparation::tests::source_epoch_change_after_scanning_refuses_the_checkpoint","--nocapture"])
        .env("LNGNB_INPUT_SOURCE_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line.contains("LNGNB_EVALUATION_CHECKPOINT_input_scanned") {
            break;
        }
    }
    // 正規writerはflockで競合できない。ここでは排他を無視する外部SQLを故意に注入する。
    let new = rev(&[], 14, "arrived after scan");
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.execute(
        "INSERT INTO records VALUES(?1,?2)",
        params![new.id().bytes, new.bytes()],
    )
    .unwrap();
    drop(conn);
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    assert!(child.wait().unwrap().success());
    let store = open(&t);
    assert_eq!(count(&store, "records"), 3);
    assert_eq!(count(&store, "evaluation_nodes"), 0);
    assert_eq!(count(&store, "evaluation_input"), 0);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
}

#[test]
fn prepared_genesis_publisher_and_parent_scopes_match_independent_reference() {
    use super::super::tests::{key as signing_key, set};
    let sample = rev(&[], 14, "sample");
    // A15 S04の公開試験seedのみ。実運用への流用禁止。
    let wrong_key = LocalRecord::sign(
        sample.body().clone(),
        &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    let mut body = sample.body().clone();
    set(&mut body, "knowledge_id", Value::Bytes(vec![0x72; 32]));
    let foreign = LocalRecord::sign(body, &signing_key()).unwrap();
    let mut body = sample.body().clone();
    set(
        &mut body,
        "genesis_record_id",
        Value::Bytes(sample.id().bytes.to_vec()),
    );
    let bad_genesis = LocalRecord::sign(body, &signing_key()).unwrap();
    let records = [
        fixture(),
        sample,
        wrong_key,
        foreign.clone(),
        bad_genesis.clone(),
        rev(&[foreign.id(), bad_genesis.id()], 15, "bad scopes"),
    ];
    let t = Temp::new();
    populated(&t, &records, true);
    let mut job = open(&t).evaluation_job().unwrap();
    collected(&mut job, 1);
    assert_oracle(&[(oracle_case(&records, true), evaluated(&mut job))]);
    job.pause().unwrap();
}

#[test]
fn one_record_byte_and_parent_boundaries_are_policy_limits_with_adjustable_resume() {
    let t = Temp::new();
    let a = rev(&[], 14, "root");
    // 最初のbyte境界で子を処理済みにしない。親辺を持つRecordを後方へ固定する。
    let first = a.id().bytes.min(fixture().id().bytes);
    let b = (0..1000)
        .map(|n| rev(&[a.id()], 14, &format!("child {n}")))
        .find(|r| r.id().bytes > first)
        .unwrap();
    let records = [fixture(), a, b];
    populated(&t, &records, false);
    let store = open(&t);
    let first_id: Vec<u8> = store
        .conn
        .query_row("SELECT id FROM records ORDER BY id LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let first = records
        .iter()
        .find(|r| r.id().bytes.as_slice() == first_id)
        .unwrap();
    let mut job = store.evaluation_job().unwrap();
    let d = EvaluationInputBudget::default();
    assert!(matches!(
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                bytes: first.bytes().len() as u64 - 1,
                ..d
            }
        ),
        Err(StorageError::BudgetExceeded)
    ));
    let p = job
        .prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget {
                records: 1,
                bytes: first.bytes().len() as u64,
                ..d
            },
        )
        .unwrap();
    assert_eq!(p.collected_records, 1);
    loop {
        match job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget { edges: 0, ..d },
        ) {
            Ok(p) => {
                assert!(!p.complete);
            }
            Err(StorageError::BudgetExceeded) => break,
            other => panic!("{other:?}"),
        }
    }
    assert!(collected(&mut job, 1).complete);
    assert_oracle(&[(oracle_case(&records, false), evaluated(&mut job))]);
    job.pause().unwrap();
}

#[test]
fn prepared_metadata_is_reused_but_later_blob_arrival_replaces_old_parent_verdicts() {
    let t = Temp::new();
    let a = rev(&[], 15, "bad length");
    let child = rev(&[a.id()], 14, "child");
    let records = [fixture(), a.clone(), child.clone()];
    populated(&t, &records, false);
    let mut job = open(&t).evaluation_job().unwrap();
    collected(&mut job, 1);
    let first = evaluated(&mut job);
    job.pause().unwrap();
    let mut w = open(&t).begin().unwrap();
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
    assert_eq!(p.processed, 1);
    assert!(p.snapshot.is_none());
    assert_eq!(count(&job.writer.store, "evaluation_nodes"), 3);
    let (dirty,old):(i64,String)=job.writer.store.conn.query_row("SELECT dirty,(SELECT validation FROM evaluations WHERE record_id=?1) FROM evaluation_state",[a.id().bytes],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!((dirty, old), (1, "valid".into()));
    let generation = job.writer.store.generation().unwrap();
    assert!(
        job.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget::default()
        )
        .unwrap()
        .complete
    );
    assert_eq!(job.writer.store.generation().unwrap(), generation);
    let second = evaluated(&mut job);
    assert_oracle(&[
        (oracle_case(&records, false), first),
        (oracle_case(&records, true), second),
    ]);
    job.pause().unwrap();
}

#[test]
fn record_arrival_after_prepared_input_loading_prevents_stale_parent_publication() {
    if let Some(path) = std::env::var_os("LNGNB_INPUT_EVAL_CHILD") {
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
    populated(&t, &[fixture(), rev(&[], 14, "a")], false);
    let mut job = open(&t).evaluation_job().unwrap();
    collected(&mut job, 1);
    job.pause().unwrap();
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::preparation::tests::record_arrival_after_prepared_input_loading_prevents_stale_parent_publication","--nocapture"])
        .env("LNGNB_INPUT_EVAL_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line.contains("LNGNB_EVALUATION_CHECKPOINT_eval_input_ready") {
            break;
        }
    }
    let new = rev(&[], 14, "new after ready");
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.execute(
        "INSERT INTO records VALUES(?1,?2)",
        params![new.id().bytes, new.bytes()],
    )
    .unwrap();
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
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
}
