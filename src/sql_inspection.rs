//! R24/R28/R30: 台帳照合SQLの進捗予算。行数や実時間の厳密な上限ではない。
use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// 一回の台帳照合群に適用するローカル予算。一次データの形式上限ではない。
#[derive(Debug, Clone, Copy)]
pub struct SqlInspectionBudget {
    /// SQLiteが概ね1,000 VM命令ごとに呼ぶ進捗callbackの上限。
    /// 命令数・行数の正確な計数ではなく、短いSQLではcallbackが来ない場合もある。
    pub callbacks: u64,
    /// SQLの進捗通知時と、検査群の前後で確認する。OSのI/O待ちを強制中断しない。
    pub elapsed: Duration,
}
impl Default for SqlInspectionBudget {
    fn default() -> Self {
        Self {
            callbacks: 100_000,
            elapsed: Duration::from_secs(60),
        }
    }
}
impl SqlInspectionBudget {
    // SQL予算を呼出し元の残り時間より延長しない。
    pub(super) fn within(self, start: Instant, elapsed: Duration) -> Self {
        Self {
            elapsed: self.elapsed.min(elapsed.saturating_sub(start.elapsed())),
            ..self
        }
    }
}
struct Handler<'a>(&'a Connection);
impl Drop for Handler<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}
/// privateな直列化接続の読取り照合だけを囲む。ネストせず、transactionのcommit/
/// rollback・書込み・呼出し元のhandler登録をこのclosureに含めない。
/// エラー/巻戻し/panicでもhandlerを外し、後の保存や復旧をinterruptしない。
pub(super) fn run<T>(
    conn: &Connection,
    budget: SqlInspectionBudget,
    inspect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if budget.callbacks == 0 || budget.elapsed.is_zero() {
        return Err(StorageError::BudgetExceeded);
    }
    let start = Instant::now();
    let exhausted = Arc::new(AtomicBool::new(false));
    let mark = Arc::clone(&exhausted);
    let mut callbacks = 0u64;
    conn.progress_handler(
        1000,
        Some(move || {
            callbacks = callbacks.saturating_add(1);
            let stop = callbacks >= budget.callbacks || start.elapsed() >= budget.elapsed;
            if stop {
                mark.store(true, Ordering::Relaxed);
            }
            stop
        }),
    );
    let handler = Handler(conn);
    let result = inspect();
    // SQLite自身のSQLITE_INTERRUPTすべてを予算超過へ読み替えない。
    let limited =
        exhausted.load(Ordering::Relaxed) || result.is_ok() && start.elapsed() >= budget.elapsed;
    drop(handler);
    if limited {
        Err(StorageError::BudgetExceeded)
    } else {
        result
    }
}

#[cfg(test)]
#[path = "sql_inspection_tests.rs"]
mod tests;
