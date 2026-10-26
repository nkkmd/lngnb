//! R24/R28/R30: SQL予算は破損・保存成功・手動解除とは別。公開試験値のみ。
use super::*;
use crate::{id, storage::tests::Temp};
use std::io::Cursor;
const LONG: &str = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n";
fn tiny() -> SqlInspectionBudget {
    SqlInspectionBudget {
        callbacks: 1,
        ..SqlInspectionBudget::default()
    }
}
fn query(c: &Connection) -> Result<i64> {
    Ok(c.query_row(LONG, [], |r| r.get(0))?)
}
#[test]
fn progress_interrupt_is_policy_limit_and_handler_does_not_leak() {
    let c = Connection::open_in_memory().unwrap();
    assert!(matches!(
        run(&c, tiny(), || query(&c)),
        Err(StorageError::BudgetExceeded)
    ));
    // 同じ接続で、制限handlerが残っていないことと予算調整後の成功を別々に確認。
    assert_eq!(query(&c).unwrap(), 50_005_000);
    assert_eq!(
        run(&c, SqlInspectionBudget::default(), || query(&c)).unwrap(),
        50_005_000
    );
    assert_eq!(query(&c).unwrap(), 50_005_000);
    // 最後に未完了行がある大きな台帳を、中断時に「未完了なし」と答えない。
    c.execute_batch("CREATE TABLE blob_cleanup_runs(finished_generation INTEGER); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000) INSERT INTO blob_cleanup_runs SELECT CASE WHEN x=5000 THEN NULL ELSE 1 END FROM n").unwrap();
    assert!(matches!(
        cleanup::pending(&c, tiny()),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(cleanup::pending(&c, SqlInspectionBudget::default()).unwrap());
    c.execute(
        "UPDATE blob_cleanup_runs SET finished_generation=1 WHERE finished_generation IS NULL",
        [],
    )
    .unwrap();
    assert!(!cleanup::pending(&c, SqlInspectionBudget::default()).unwrap());
}
#[test]
fn zero_budget_does_not_run_the_inspection() {
    let c = Connection::open_in_memory().unwrap();
    for budget in [
        SqlInspectionBudget {
            callbacks: 0,
            ..tiny()
        },
        SqlInspectionBudget {
            elapsed: Duration::ZERO,
            ..tiny()
        },
    ] {
        assert!(matches!(
            run::<()>(&c, budget, || panic!("must not run")),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(query(&c).unwrap(), 50_005_000);
    }
}
#[test]
fn elapsed_budget_is_checked_during_sql_and_after_short_sql() {
    let c = Connection::open_in_memory().unwrap();
    let budget = SqlInspectionBudget {
        elapsed: Duration::from_millis(1),
        ..SqlInspectionBudget::default()
    };
    let expired = budget.within(Instant::now(), Duration::ZERO);
    assert!(matches!(
        run::<()>(&c, expired, || panic!("expired parent budget")),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(
        budget
            .within(Instant::now(), Duration::from_secs(1))
            .elapsed,
        budget.elapsed
    );
    for short in [false, true] {
        assert!(matches!(
            run(&c, budget, || {
                std::thread::sleep(Duration::from_millis(3));
                if short {
                    Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?)
                } else {
                    query(&c)
                }
            }),
            Err(StorageError::BudgetExceeded)
        ));
    }
    assert_eq!(query(&c).unwrap(), 50_005_000);
}
#[test]
fn sql_error_and_panic_keep_their_meaning_and_remove_the_handler() {
    let c = Connection::open_in_memory().unwrap();
    assert!(matches!(
        run::<()>(&c, tiny(), || {
            c.execute_batch("SELECT absent_column")?;
            Ok(())
        }),
        Err(StorageError::Sql(_))
    ));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = run::<()>(&c, tiny(), || panic!("test unwind"));
    }));
    assert!(panic.is_err());
    assert_eq!(query(&c).unwrap(), 50_005_000);
}
#[test]
fn external_interrupt_is_not_reported_as_our_budget() {
    let c = Connection::open_in_memory().unwrap();
    let handle = c.get_interrupt_handle();
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(3));
        handle.interrupt();
    });
    let result = run(&c, SqlInspectionBudget::default(), || {
        Ok(c.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT sum(x) FROM n", [], |r| r.get::<_, i64>(0))?)
    });
    worker.join().unwrap();
    assert!(
        matches!(result, Err(StorageError::Sql(rusqlite::Error::SqliteFailure(e, _))) if e.code == rusqlite::ErrorCode::OperationInterrupted)
    );
    assert_eq!(query(&c).unwrap(), 50_005_000);
}
fn promises(t: &Temp) {
    let mut w = t.store().begin().unwrap();
    for _ in 0..48 {
        w.stage_blob(
            id::blob_id(b"bounded ledger"),
            Cursor::new(b"bounded ledger"),
            1,
            TemporaryLimits::default(),
        )
        .unwrap();
    }
    w.finish().unwrap();
}
#[test]
fn read_only_format_inspection_budget_preserves_database_and_can_be_adjusted() {
    let t = Temp::new();
    promises(&t);
    let path = t.data().join(DB);
    let before = std::fs::read(&path).unwrap();
    let limits = Limits {
        sql_inspection: tiny(),
        ..Limits::default()
    };
    assert!(matches!(
        RecordStore::open(&t.data(), limits),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
#[test]
fn stage_preflight_budget_consumes_no_input_and_allows_safe_retry() {
    let t = Temp::new();
    promises(&t);
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    let before = w.store.generation().unwrap();
    w.store.limits.sql_inspection = tiny();
    struct NeverRead;
    impl std::io::Read for NeverRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("input must not be read")
        }
    }
    assert!(matches!(
        w.stage_blob(
            id::blob_id(b"new"),
            NeverRead,
            1,
            TemporaryLimits::default()
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(w.store.generation().unwrap(), before);
    assert!(!w.failed);
    w.store.limits.sql_inspection = SqlInspectionBudget::default();
    w.stage_blob(
        id::blob_id(b"new"),
        Cursor::new(b"new"),
        1,
        TemporaryLimits::default(),
    )
    .unwrap();
    w.finish().unwrap();
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::Clean
    );
}
#[test]
fn quick_check_is_budgeted_in_record_inspection() {
    use crate::storage::evaluation::tests::rev;
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    for i in 0..128 {
        w.insert(&rev(&[], 14, &format!("quick check {i}")))
            .unwrap();
    }
    w.finish().unwrap();
    let mut s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    let before = s.generation().unwrap();
    s.limits.sql_inspection = tiny();
    assert!(matches!(
        s.check_records(),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(s.generation().unwrap(), before);
    drop(s);
}
