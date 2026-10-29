//! R24/R27/R28/R30: 管理受理側の設定保存。適用・公開・復旧解除は別操作。
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminConfig {
    pub request_timeout_ms: u64,
    pub max_new_records: u64,
    pub max_diagnostic_records: u64,
    pub startup_records_per_step: u64,
}
impl AdminConfig {
    pub fn is_valid(self) -> bool {
        (1..=30_000).contains(&self.request_timeout_ms)
            && (1..=10_000).contains(&self.max_new_records)
            && (1..=10_000).contains(&self.max_diagnostic_records)
            && (1..=10_000).contains(&self.startup_records_per_step)
    }
    fn description(self) -> String {
        format!(
            "admin_config_v1:{},{},{},{}",
            self.request_timeout_ms,
            self.max_new_records,
            self.max_diagnostic_records,
            self.startup_records_per_step
        )
    }
}

type StoredConfig = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<i64>,
);

pub(super) fn load(conn: &Connection) -> Result<Option<AdminConfig>> {
    let (timeout, records, diagnostic, startup, generation):
        StoredConfig = conn.query_row(
        "SELECT request_timeout_ms,max_new_records,max_diagnostic_records,startup_records_per_step,generation FROM admin_config WHERE singleton=1",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    let latest: Option<i64> = conn.query_row(
        "SELECT generation FROM history WHERE new_state='admin_config_saved_local_only' ORDER BY generation DESC LIMIT 1",
        [], |r| r.get(0)).optional()?;
    if generation != latest {
        return Err(StorageError::Corrupt);
    }
    let Some(generation) = generation else {
        if timeout.is_some() || records.is_some() || diagnostic.is_some() || startup.is_some() {
            return Err(StorageError::Corrupt);
        }
        return Ok(None);
    };
    let config = AdminConfig {
        request_timeout_ms: timeout.ok_or(StorageError::Corrupt)?,
        max_new_records: records.ok_or(StorageError::Corrupt)?,
        max_diagnostic_records: diagnostic.ok_or(StorageError::Corrupt)?,
        startup_records_per_step: startup.ok_or(StorageError::Corrupt)?,
    };
    if !config.is_valid() || generation < 0 {
        return Err(StorageError::Corrupt);
    }
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM history h,storage_state s WHERE h.generation=?1 AND s.singleton=1 AND h.namespace=s.namespace AND h.generation<=s.generation AND h.target IS NULL AND h.new_state='admin_config_saved_local_only' AND h.reason=?2 AND h.rules='lngnb-validation-1')",
        params![generation,config.description()], |r| r.get(0))?;
    if !valid {
        return Err(StorageError::Corrupt);
    }
    Ok(Some(config))
}
impl RecordStore {
    /// 停止中の保存値だけをread-only接続・同一排他・同一snapshotで照合する。
    /// 起動検査、設定補完、履歴/cursor/起動印の更新、正常停止/手動解除をしない。
    /// SQLiteのWAL/SHM補助I/Oまで全ファイル不変とは保証しない。
    pub fn read_saved_admin_config(path: &Path) -> Result<Option<AdminConfig>> {
        let dir = directory(path)?;
        check_area(&dir)?;
        check_files(&dir)?;
        let _lock = lock(&dir, false)?;
        let mut conn = connection(&dir, true)?;
        conn.execute_batch("PRAGMA query_only=ON;")?;
        configure_local(&conn)?;
        let query_only: i64 = conn.pragma_query_value(None, "query_only", |r| r.get(0))?;
        if query_only != 1 {
            return Err(StorageError::UnsupportedFormat);
        }
        let tx = conn.transaction()?;
        check_format(&tx, SqlInspectionBudget::default())?;
        let config = load(&tx)?;
        tx.commit()?;
        conn.close().map_err(|(_, e)| StorageError::Sql(e))?;
        Ok(config)
    }
    /// 保存値だけを返す。未保存はNone。起動への適用や既定値補完をしない。
    pub fn saved_admin_config(&self) -> Result<Option<AdminConfig>> {
        load(&self.conn)
    }
}
impl RecordWriter {
    /// 明示した全4項目を同じ排他・FULL transactionで保存する内部操作。
    /// 保存成功は起動への適用や正常停止を意味しない。
    pub fn save_admin_config(&mut self, config: AdminConfig) -> Result<()> {
        self.save_admin_config_with(config, |_| {})
    }
    fn save_admin_config_with(
        &mut self,
        config: AdminConfig,
        mut checkpoint: impl FnMut(bool),
    ) -> Result<()> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if !config.is_valid() {
            return Err(StorageError::BudgetExceeded);
        }
        let result = (|| {
            let old = load(&self.store.conn)?;
            let capacity = self.store.capacity()?;
            if capacity.available <= capacity.reserved_floor.saturating_add(65536) {
                return Err(StorageError::Capacity);
            }
            let tx = self.store.conn.transaction()?;
            advance(&tx)?;
            if tx.execute("UPDATE admin_config SET request_timeout_ms=?1,max_new_records=?2,max_diagnostic_records=?3,startup_records_per_step=?4,generation=(SELECT generation FROM storage_state WHERE singleton=1) WHERE singleton=1",
                params![config.request_timeout_ms,config.max_new_records,config.max_diagnostic_records,config.startup_records_per_step])? != 1 {
                return Err(StorageError::Corrupt);
            }
            audit(
                &tx,
                None,
                &old.map_or_else(|| "unsaved".into(), AdminConfig::description),
                "admin_config_saved_local_only",
                &config.description(),
            )?;
            checkpoint(true);
            tx.commit()?;
            checkpoint(false);
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::{Temp, logical_snapshot};

    fn config() -> AdminConfig {
        AdminConfig {
            request_timeout_ms: 5000,
            max_new_records: 100,
            max_diagnostic_records: 500,
            startup_records_per_step: 1,
        }
    }
    #[test]
    fn readonly_config_preserves_all_logical_state_and_manual_wait() {
        let temp = Temp::new();
        drop(temp.store());
        let conn = Connection::open(temp.data().join(DB)).unwrap();
        let before = super::super::tests::logical_snapshot(&conn);
        assert_eq!(
            RecordStore::read_saved_admin_config(&temp.data()).unwrap(),
            None
        );
        assert_eq!(super::super::tests::logical_snapshot(&conn), before);
        drop(conn);
        let mut writer = RecordStore::open(&temp.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        writer.save_admin_config(config()).unwrap();
        drop(writer);
        let conn = Connection::open(temp.data().join(DB)).unwrap();
        let before = super::super::tests::logical_snapshot(&conn);
        assert_eq!(
            RecordStore::read_saved_admin_config(&temp.data()).unwrap(),
            Some(config())
        );
        assert_eq!(super::super::tests::logical_snapshot(&conn), before);
        assert_eq!(state(&conn).unwrap(), StartupState::NeedsReview);
        assert!(
            LocalStartup::open(&temp.data(), Limits::default())
                .unwrap()
                .needs_review()
        );
    }
    #[test]
    fn readonly_config_rejects_lock_conflict_and_does_not_scan_records() {
        let temp = Temp::new();
        let store = temp.store();
        assert!(matches!(
            RecordStore::read_saved_admin_config(&temp.data()),
            Err(StorageError::Busy)
        ));
        drop(store);
        let conn = Connection::open(temp.data().join(DB)).unwrap();
        conn.execute(
            "INSERT INTO records(id,bytes) VALUES(?1,?2)",
            params![&[255u8; 32][..], b"invalid".as_slice()],
        )
        .unwrap();
        let before = super::super::tests::logical_snapshot(&conn);
        assert_eq!(
            RecordStore::read_saved_admin_config(&temp.data()).unwrap(),
            None
        );
        assert_eq!(super::super::tests::logical_snapshot(&conn), before);
    }
    #[test]
    fn explicit_save_survives_reopen_without_becoming_runtime_configuration() {
        let temp = Temp::new();
        let store = temp.store();
        assert_eq!(store.saved_admin_config().unwrap(), None);
        let mut writer = store.begin().unwrap();
        writer.save_admin_config(config()).unwrap();
        assert_eq!(writer.store.saved_admin_config().unwrap(), Some(config()));
        // 保存設定で現sessionの予算を変更しない。
        assert_eq!(
            writer.store.limits.session_records,
            Limits::default().session_records
        );
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.saved_admin_config().unwrap(), Some(config()));
        assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    }
    #[test]
    fn invalid_values_never_change_existing_settings_or_history() {
        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        writer.save_admin_config(config()).unwrap();
        let before = logical_snapshot(&writer.store.conn);
        for field in 0..4 {
            for value in [0, 30_001, u64::MAX] {
                let mut bad = config();
                match field {
                    0 => bad.request_timeout_ms = value,
                    1 => bad.max_new_records = value,
                    2 => bad.max_diagnostic_records = value,
                    _ => bad.startup_records_per_step = value,
                }
                assert!(matches!(
                    writer.save_admin_config(bad),
                    Err(StorageError::BudgetExceeded)
                ));
                assert_eq!(logical_snapshot(&writer.store.conn), before);
            }
        }
        writer.finish().unwrap();
    }
    #[test]
    fn boundaries_and_capacity_rejection_preserve_existing_settings() {
        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        for n in [1, 10_000] {
            let value = AdminConfig {
                request_timeout_ms: 30_000,
                max_new_records: n,
                max_diagnostic_records: n,
                startup_records_per_step: n,
            };
            writer.save_admin_config(value).unwrap();
            assert_eq!(writer.store.saved_admin_config().unwrap(), Some(value));
        }
        let before = logical_snapshot(&writer.store.conn);
        writer.store.limits.reserve_min_bytes = u64::MAX;
        assert!(matches!(
            writer.save_admin_config(config()),
            Err(StorageError::Capacity)
        ));
        assert_eq!(logical_snapshot(&writer.store.conn), before);
        assert!(matches!(
            writer.finish(),
            Err(StorageError::UnresolvedFailure)
        ));
    }
    #[test]
    fn old_schema_is_rejected_without_modification_or_reinitialization() {
        let temp = Temp::new();
        drop(temp.store());
        let conn = Connection::open(temp.data().join(DB)).unwrap();
        conn.pragma_update(None, "user_version", 11).unwrap();
        conn.execute_batch("DROP TABLE admin_config; DROP INDEX history_admin_config;")
            .unwrap();
        let before = logical_snapshot(&conn);
        assert!(matches!(
            RecordStore::open(&temp.data(), Limits::default()),
            Err(StorageError::UnsupportedFormat)
        ));
        assert_eq!(logical_snapshot(&conn), before);
    }
    #[test]
    fn process_kill_before_and_after_commit_retains_only_confirmed_settings() {
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};
        if let Some(path) = std::env::var_os("LNGNB_CONFIG_KILL_CHILD") {
            let store = RecordStore::open(Path::new(&path), Limits::default()).unwrap();
            let mut writer = store.begin().unwrap();
            let before = std::env::var("LNGNB_CONFIG_KILL_BEFORE").unwrap() == "true";
            let mut next = config();
            next.max_new_records = 2;
            writer
                .save_admin_config_with(next, |point| {
                    if point == before {
                        println!("LNGNB_CONFIG_KILL_READY");
                        std::io::stdout().flush().unwrap();
                        let mut line = String::new();
                        std::io::stdin().read_line(&mut line).unwrap();
                    }
                })
                .unwrap();
            panic!("parent must kill the child");
        }
        for before in [true, false] {
            let temp = Temp::new();
            let mut writer = temp.store().begin().unwrap();
            writer.save_admin_config(config()).unwrap();
            writer.finish().unwrap();
            let mut child=Command::new(std::env::current_exe().unwrap())
                .args(["--exact","storage::admin_config::tests::process_kill_before_and_after_commit_retains_only_confirmed_settings","--nocapture"])
                .env("LNGNB_CONFIG_KILL_CHILD",temp.data())
                .env("LNGNB_CONFIG_KILL_BEFORE",before.to_string())
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
            let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut ready = false;
            for _ in 0..20 {
                let mut line = String::new();
                if output.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.contains("LNGNB_CONFIG_KILL_READY") {
                    ready = true;
                    break;
                }
            }
            if !ready {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not reach commit boundary");
            }
            assert!(matches!(
                RecordStore::open(&temp.data(), Limits::default()),
                Err(StorageError::Busy)
            ));
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            let mut expected = config();
            if !before {
                expected.max_new_records = 2;
            }
            assert_eq!(store.saved_admin_config().unwrap(), Some(expected));
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
            assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
        }
    }
    #[test]
    fn setting_or_history_failure_rolls_back_and_blocks_normal_finish() {
        for table in ["admin_config", "history", "storage_state"] {
            let temp = Temp::new();
            let mut writer = temp.store().begin().unwrap();
            writer.save_admin_config(config()).unwrap();
            let operation = if table == "history" {
                "INSERT"
            } else {
                "UPDATE"
            };
            writer.store.conn.execute_batch(&format!("CREATE TRIGGER deny_config BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
            let before = logical_snapshot(&writer.store.conn);
            let mut next = config();
            next.max_new_records = 2;
            assert!(writer.save_admin_config(next).is_err());
            assert_eq!(logical_snapshot(&writer.store.conn), before);
            assert_eq!(writer.store.saved_admin_config().unwrap(), Some(config()));
            assert!(matches!(
                writer.save_admin_config(config()),
                Err(StorageError::UnresolvedFailure)
            ));
            assert!(matches!(
                writer.finish(),
                Err(StorageError::UnresolvedFailure)
            ));
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
            assert_eq!(store.saved_admin_config().unwrap(), Some(config()));
        }
    }
    #[test]
    fn interrupted_writer_and_successful_read_do_not_clear_manual_review() {
        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        writer.save_admin_config(config()).unwrap();
        drop(writer);
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.saved_admin_config().unwrap(), Some(config()));
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
    }
    #[test]
    fn missing_changed_or_detached_configuration_is_not_defaulted() {
        for sql in [
            "DELETE FROM admin_config",
            "UPDATE admin_config SET max_new_records=2",
            "UPDATE admin_config SET generation=NULL,request_timeout_ms=NULL,max_new_records=NULL,max_diagnostic_records=NULL,startup_records_per_step=NULL",
            "UPDATE history SET reason='changed' WHERE new_state='admin_config_saved_local_only'",
        ] {
            let temp = Temp::new();
            let mut writer = temp.store().begin().unwrap();
            writer.save_admin_config(config()).unwrap();
            writer.finish().unwrap();
            let conn = Connection::open(temp.data().join(DB)).unwrap();
            conn.execute_batch(sql).unwrap();
            let before = logical_snapshot(&conn);
            assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
            assert_eq!(logical_snapshot(&conn), before);
        }
    }
}
