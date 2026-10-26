//! R20/R24/R27/R28/R30。公開A13試験鍵のみ。実運用へ流用しない。
use super::*;
use crate::{
    cbor::Value,
    id,
    storage::tests::{Temp, fixture, fixture_data, unhex},
};
use std::{
    io::{BufRead, Cursor, Write},
    process::{Command, Stdio},
};
fn generated(n: u8) -> LocalRecord {
    let mut body = fixture().body().clone();
    let Value::Map(fields) = &mut body else {
        panic!();
    };
    fields
        .iter_mut()
        .find(|(k, _)| k == "knowledge_id")
        .unwrap()
        .1 = Value::Bytes(vec![n; 32]);
    let seed = unhex(fixture_data()["seed_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    LocalRecord::sign(body, &ed25519_dalek::SigningKey::from_bytes(&seed)).unwrap()
}
fn populate(t: &Temp, n: u8) -> Vec<LocalRecord> {
    let mut w = t.store().begin().unwrap();
    let mut records: Vec<_> = (0..n).map(generated).collect();
    records.sort_by_key(|r| r.id().bytes);
    for r in &records {
        w.insert(r).unwrap();
    }
    w.finish().unwrap();
    records
}
fn one() -> InspectionBudget {
    InspectionBudget {
        records: 1,
        ..InspectionBudget::default()
    }
}
fn complete(check: &mut RecordInspection) {
    for _ in 0..100 {
        if check.step(one()).unwrap().checks_complete {
            return;
        }
    }
    panic!("inspection did not make progress");
}
fn raw(t: &Temp) -> Connection {
    Connection::open(t.data().join(DB)).unwrap()
}

#[test]
fn record_count_budget_resumes_across_clean_job_boundaries_and_preserves_bytes() {
    let t = Temp::new();
    let records = populate(&t, 5);
    let mut bytes = 0;
    for n in 1..=5 {
        let mut check = RecordInspection::open(
            &t.data(),
            Limits {
                scan_records: 1,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(check.progress().unwrap().checked_records, n - 1);
        let progress = check.step(one()).unwrap();
        bytes += records[n as usize - 1].bytes().len() as u64;
        assert_eq!(progress.checked_records, n);
        assert_eq!(progress.checked_bytes, bytes);
        assert!(!progress.checks_complete);
        assert_eq!(progress.records_complete, n == 5);
        check.pause().unwrap();
    }
    let mut check = RecordInspection::open(
        &t.data(),
        Limits {
            scan_records: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let progress = check.step(one()).unwrap();
    assert!(progress.checks_complete);
    let store = check.into_store().unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    for record in records {
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    store.begin().unwrap().finish().unwrap();
}
#[test]
fn partial_inspection_cannot_be_extracted_or_bypassed_by_ordinary_open() {
    let t = Temp::new();
    populate(&t, 2);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    check.step(one()).unwrap();
    check.pause().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        StartupState::InspectionPending
    );
    assert!(matches!(
        store.begin(),
        Err(StorageError::InspectionPending)
    ));
    let check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert!(matches!(
        check.into_store(),
        Err(StorageError::InspectionPending)
    ));
    // 未完了ハンドルを正常停止せずに消費したため、ここからは手動待ちを維持する。
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    let store = check.into_store().unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
}
#[test]
fn invalid_job_budgets_do_not_move_cursor_and_exact_byte_budget_works() {
    let t = Temp::new();
    let records = populate(&t, 2);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    let old = check.progress().unwrap();
    let first = records[0].bytes().len() as u64;
    for budget in [
        InspectionBudget {
            records: 0,
            ..one()
        },
        InspectionBudget {
            bytes: first - 1,
            ..one()
        },
        InspectionBudget {
            elapsed: Duration::ZERO,
            ..one()
        },
    ] {
        let generation = check.store.generation().unwrap();
        assert!(matches!(
            check.step(budget),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(check.progress().unwrap(), old);
        assert_eq!(check.store.generation().unwrap(), generation);
    }
    let p = check
        .step(InspectionBudget {
            records: 2,
            bytes: first,
            ..InspectionBudget::default()
        })
        .unwrap();
    assert_eq!(p.checked_records, 1);
    assert_eq!(p.checked_bytes, first);
    check.pause().unwrap();
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    assert_eq!(
        check.into_store().unwrap().startup_state().unwrap(),
        StartupState::Clean
    );
}
#[test]
fn inspection_started_after_abnormal_stop_never_clears_review() {
    let t = Temp::new();
    populate(&t, 3);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    check.step(one()).unwrap();
    drop(check);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(check.progress().unwrap().checked_records, 1);
    check.step(one()).unwrap();
    check.pause().unwrap();
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    let store = check.into_store().unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn checkpoint_and_history_failures_roll_back_progress_and_forbid_clean_pause() {
    for table in ["record_inspection", "history"] {
        let t = Temp::new();
        populate(&t, 3);
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        check.step(one()).unwrap();
        let before = check.progress().unwrap();
        let generation = check.store.generation().unwrap();
        let operation = if table == "history" {
            "INSERT"
        } else {
            "UPDATE"
        };
        check.store.conn.execute_batch(&format!("CREATE TRIGGER reject_checkpoint BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        assert!(check.step(one()).is_err());
        assert_eq!(check.progress().unwrap(), before);
        assert_eq!(check.store.generation().unwrap(), generation);
        assert!(matches!(
            check.pause(),
            Err(StorageError::UnresolvedFailure)
        ));
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
fn running_mark_is_committed_before_first_checkpoint() {
    let t = Temp::new();
    populate(&t, 1);
    let conn = raw(&t);
    conn.execute_batch("CREATE TRIGGER reject_start BEFORE UPDATE OF state ON storage_state WHEN NEW.state='running' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    drop(conn);
    assert!(RecordInspection::open(&t.data(), Limits::default()).is_err());
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(checkpoint(&store.conn).unwrap().phase, "idle");
    drop(store);
    let conn = raw(&t);
    conn.execute_batch("DROP TRIGGER reject_start; CREATE TRIGGER reject_first_checkpoint BEFORE UPDATE ON record_inspection BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    drop(conn);
    assert!(RecordInspection::open(&t.data(), Limits::default()).is_err());
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn altered_checkpoint_metadata_or_audit_is_rejected_without_reinitializing() {
    for sql in [
        "UPDATE record_inspection SET checked_records=checked_records+1",
        "UPDATE record_inspection SET cursor=zeroblob(32)",
        "UPDATE record_inspection SET phase='complete'",
        "UPDATE record_inspection SET checkpoint_generation=0",
        "UPDATE record_inspection SET source_epoch=-1",
        "UPDATE record_inspection SET source_epoch=source_epoch+1",
    ] {
        let t = Temp::new();
        populate(&t, 3);
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        check.step(one()).unwrap();
        check.pause().unwrap();
        let conn = raw(&t);
        // CHECK制約そのものが拒否する不正値も、無断修復せず保持する。
        let changed = conn.execute(sql, []);
        drop(conn);
        if sql == "UPDATE record_inspection SET source_epoch=-1" {
            assert!(changed.is_err());
        } else {
            changed.unwrap();
            let before = std::fs::read(t.data().join(DB)).unwrap();
            assert!(RecordInspection::open(&t.data(), Limits::default()).is_err());
            assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
        }
    }
}
#[test]
fn source_change_invalidates_cursor_even_for_an_id_before_it() {
    let t = Temp::new();
    let records = populate(&t, 2);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    check.step(one()).unwrap();
    let lower = (3u8..=200)
        .map(generated)
        .find(|r| r.id().bytes < records[0].id().bytes)
        .unwrap();
    // 排他に従わない試験用の直接書込み。製品経路は未完了検査中にwriterを得られない。
    check
        .store
        .conn
        .execute(
            "INSERT INTO records VALUES(?1,?2)",
            params![&lower.id().bytes, lower.bytes()],
        )
        .unwrap();
    assert!(matches!(check.step(one()), Err(StorageError::Corrupt)));
    assert!(check.pause().is_err());
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(check.progress().unwrap().checked_records, 0);
    complete(&mut check);
    assert_eq!(check.progress().unwrap().checked_records, 3);
    assert_eq!(
        check.into_store().unwrap().startup_state().unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn blob_budget_does_not_erase_record_progress_or_claim_completion() {
    let t = Temp::new();
    populate(&t, 2);
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    w.put_blob(id::blob_id(b"abcdef"), Cursor::new(b"abcdef"))
        .unwrap();
    w.finish().unwrap();
    let limits = Limits {
        scan_blob_bytes: 5,
        ..Limits::default()
    };
    let mut check = RecordInspection::open(&t.data(), limits).unwrap();
    check.step(InspectionBudget::default()).unwrap();
    assert!(check.progress().unwrap().records_complete);
    assert!(matches!(
        check.step(one()),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(!check.progress().unwrap().checks_complete);
    check.pause().unwrap();
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(check.progress().unwrap().checked_records, 2);
    assert!(check.step(one()).unwrap().checks_complete);
    assert_eq!(
        check.into_store().unwrap().startup_state().unwrap(),
        StartupState::Clean
    );
}
#[test]
fn missing_retained_blob_requires_review_even_after_record_check_finishes() {
    let t = Temp::new();
    populate(&t, 1);
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    let id = id::blob_id(b"body");
    w.put_blob(id, Cursor::new(b"body")).unwrap();
    w.finish().unwrap();
    std::fs::remove_file(
        t.data()
            .join("blobs")
            .join(data_encoding::HEXLOWER.encode(&id.bytes)),
    )
    .unwrap();
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    let store = check.into_store().unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(store.blob_recovery().missing, vec![id]);
    drop(store);
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn completed_record_check_is_restarted_on_a_new_inspection_not_reused_as_current() {
    let t = Temp::new();
    populate(&t, 3);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    drop(check.into_store().unwrap());
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(check.progress().unwrap().checked_records, 0);
    assert!(!check.progress().unwrap().records_complete);
    complete(&mut check);
    drop(check.into_store().unwrap());
}
#[test]
fn corruption_in_unchecked_record_never_advances_checkpoint_or_marks_clean() {
    let t = Temp::new();
    let records = populate(&t, 3);
    let conn = raw(&t);
    conn.execute_batch("DROP TRIGGER records_no_update;")
        .unwrap();
    let mut corrupt = records[1].bytes().to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    conn.execute(
        "UPDATE records SET bytes=?1 WHERE id=?2",
        params![corrupt, &records[1].id().bytes],
    )
    .unwrap();
    drop(conn);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    let generation = check.store.generation().unwrap();
    assert!(matches!(
        check.step(InspectionBudget::default()),
        Err(StorageError::Corrupt)
    ));
    assert_eq!(check.progress().unwrap().checked_records, 0);
    assert_eq!(check.store.generation().unwrap(), generation);
    assert!(check.pause().is_err());
}
#[test]
fn empty_store_and_unheld_revision_payload_are_normal() {
    for with_revision in [false, true] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        if with_revision {
            let f = fixture_data();
            let revision = LocalRecord::check(
                &unhex(f["revision"]["envelope_cbor_hex"].as_str().unwrap()),
                None,
            )
            .unwrap();
            w.insert(&fixture()).unwrap();
            w.insert(&revision).unwrap();
        }
        w.finish().unwrap();
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        complete(&mut check);
        let store = check.into_store().unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
        assert!(!store.blob_recovery().needs_review());
    }
}
#[test]
fn schema_three_remains_unchanged_and_unsupported() {
    let t = Temp::new();
    drop(t.store());
    let conn = raw(&t);
    conn.pragma_update(None, "user_version", 3).unwrap();
    drop(conn);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordInspection::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
}
#[test]
fn kill_before_or_after_checkpoint_resumes_only_committed_progress_and_keeps_review() {
    if let Some(path) = std::env::var_os("LNGNB_RECORD_CHECK_CHILD") {
        let mut check = RecordInspection::open(Path::new(&path), Limits::default()).unwrap();
        let before = std::env::var_os("LNGNB_RECORD_CHECK_BEFORE").is_some();
        check.pause_before_checkpoint = before;
        check.step(one()).unwrap();
        println!("LNGNB_RECORD_CHECK_AFTER_CHECKPOINT");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must kill child");
    }
    for before in [true, false] {
        let t = Temp::new();
        populate(&t, 4);
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        check.step(one()).unwrap();
        check.pause().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact","storage::inspection::tests::kill_before_or_after_checkpoint_resumes_only_committed_progress_and_keeps_review","--nocapture"]).env("LNGNB_RECORD_CHECK_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped());
        if before {
            command.env("LNGNB_RECORD_CHECK_BEFORE", "1");
        }
        let mut child = command.spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let marker = if before {
            "LNGNB_RECORD_CHECK_BEFORE_CHECKPOINT"
        } else {
            "LNGNB_RECORD_CHECK_AFTER_CHECKPOINT"
        };
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line.contains(marker) {
                break;
            }
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(
            check.progress().unwrap().checked_records,
            if before { 1 } else { 2 }
        );
        complete(&mut check);
        assert_eq!(
            check.into_store().unwrap().startup_state().unwrap(),
            StartupState::NeedsReview
        );
    }
}

#[test]
fn split_blob_quick_check_budget_preserves_checkpoint_and_can_be_adjusted() {
    use crate::storage::evaluation::tests::rev;
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    for i in 0..128 {
        w.insert(&rev(&[], 14, &format!("quick check {i}")))
            .unwrap();
    }
    w.finish().unwrap();
    let mut inspection = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    let p = inspection
        .step(InspectionBudget {
            records: 128,
            ..InspectionBudget::default()
        })
        .unwrap();
    assert!(p.records_complete);
    let before = inspection.progress().unwrap();
    inspection.store.limits.sql_inspection = SqlInspectionBudget {
        callbacks: 1,
        ..SqlInspectionBudget::default()
    };
    assert!(matches!(
        inspection.step(InspectionBudget::default()),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(inspection.progress().unwrap(), before);
    inspection.store.limits.sql_inspection = SqlInspectionBudget::default();
    assert!(
        inspection
            .step(InspectionBudget::default())
            .unwrap()
            .checks_complete
    );
    let s = inspection.into_store().unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
}
