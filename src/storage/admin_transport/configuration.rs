//! R24/R27/R28/R30: 同じwriter中で設定を保存し、成功後だけ次操作へ適用する内部基盤。
//! IPC要求・CLI接続は未提供。呼出し元が所有者/rootの認証を終えていることが前提。
use super::*;
use crate::storage::{AdminConfig, management::ConfigRequest};

impl Listener {
    /// 全4項目を保存し、通信期限・新規Record上限・診断件数を次操作へ適用する。
    /// startup_records_per_stepは次回起動用。今の起動検査をやり直したとは扱わない。
    /// &mut借用により進行中Connectionと並行できず、保存失敗では適用せずfinishを禁止する。
    pub fn change_admin_config(&mut self, request: ConfigRequest) -> Result<AdminConfig> {
        let result = self.change_admin_config_inner(request);
        if result.is_err() {
            if let Access::Write(writer) = &mut self.access {
                writer.failed = true;
            }
        }
        result
    }
    fn change_admin_config_inner(&mut self, request: ConfigRequest) -> Result<AdminConfig> {
        self.check_endpoint()?;
        for endpoint in [&self.status, &self.evaluation] {
            endpoint
                .as_ref()
                .ok_or(Error::WrongMode)?
                .check(self.access.store(), self.owner)?;
        }
        let Access::Write(writer) = &mut self.access else {
            return Err(Error::WrongMode);
        };
        if writer.failed {
            return Err(Error::SessionFailed);
        }
        let config = request.values();
        // session全体の上限。既に保存した件数を超過扱いにせず、counterもresetしない。
        if config.max_new_records < writer.records {
            return Err(Error::Policy);
        }
        let saved = request.save(writer).map_err(|_| Error::SessionFailed)?;
        // ここからは検査済み値の代入だけ。commit前の値を実行時へ先行適用しない。
        writer.store.limits.session_records = saved.max_new_records;
        self.timeout = Duration::from_millis(saved.request_timeout_ms);
        self.evaluation_records = saved.max_diagnostic_records;
        Ok(saved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        EvaluationLimits, Limits, LocalStartup, LocalStartupBudget, StartupState,
        management::store_record,
        tests::{Temp, fixture, logical_snapshot},
    };
    use std::thread;

    fn values() -> AdminConfig {
        AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 2,
            max_diagnostic_records: 7,
            startup_records_per_step: 1,
        }
    }
    fn listener(temp: &Temp, records: bool) -> Listener {
        drop(temp.store());
        let mut startup = LocalStartup::open(&temp.data(), Limits::default()).unwrap();
        while !startup
            .step(EvaluationLimits::default(), LocalStartupBudget::default())
            .unwrap()
            .checks_complete()
        {}
        let mut writer = startup.into_writer().unwrap();
        if records {
            store_record(&mut writer, &fixture()).unwrap();
            let revision = crate::storage::evaluation::tests::rev(&[], 14, "config-test");
            store_record(&mut writer, &revision).unwrap();
        }
        let mut listener =
            Listener::bind_writer(writer, MAX_FRAME, Duration::from_millis(100)).unwrap();
        listener.enable_status().unwrap();
        listener.enable_evaluation().unwrap();
        listener
    }
    fn status(temp: &Temp, listener: &mut Listener) -> RuntimeStatus {
        let path = temp.data();
        let worker = thread::spawn(move || client::status(&path, Duration::from_secs(5)).unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !listener.serve_status_if_pending().unwrap() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        worker.join().unwrap()
    }
    #[test]
    fn runtime_config_commits_before_applying_and_preserves_session_counters() {
        let temp = Temp::new();
        let mut listener = listener(&temp, true);
        let before = status(&temp, &mut listener);
        let saved = listener
            .change_admin_config(ConfigRequest::check(values()).unwrap())
            .unwrap();
        assert_eq!(saved, values());
        assert_eq!(listener.evaluation_records, 7);
        let after = status(&temp, &mut listener);
        assert!(after.generation > before.generation);
        assert_eq!(after.new_records, before.new_records);
        assert_eq!(after.stored_bytes, before.stored_bytes);
        assert_eq!(after.max_new_records, 2);
        assert_eq!(after.max_stored_bytes, before.max_stored_bytes);
        assert_eq!(after.request_timeout_ms, 500);
        assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
        let Access::Write(writer) = &mut listener.access else {
            unreachable!()
        };
        assert_eq!(writer.store.saved_admin_config().unwrap(), Some(values()));
        assert!(!store_record(writer, &fixture()).unwrap().inserted);
        let extra = crate::storage::evaluation::tests::rev(&[], 14, "extra");
        assert!(matches!(
            store_record(writer, &extra),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(writer.records, 2);
        listener.close_writer().unwrap().finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
        assert_eq!(store.saved_admin_config().unwrap(), Some(values()));
        assert_eq!(
            store.record(fixture().id()).unwrap().unwrap().bytes(),
            fixture().bytes()
        );
        assert!(store.record(extra.id()).unwrap().is_none());
    }
    #[test]
    fn runtime_config_sql_failure_does_not_apply_or_clear_failed_session() {
        let temp = Temp::new();
        let mut listener = listener(&temp, true);
        let Access::Write(writer) = &mut listener.access else {
            unreachable!()
        };
        writer.store.conn.execute_batch("CREATE TRIGGER reject_config BEFORE INSERT ON history WHEN NEW.new_state='admin_config_saved_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        let before = logical_snapshot(&writer.store.conn);
        assert_eq!(
            listener.change_admin_config(ConfigRequest::check(values()).unwrap()),
            Err(Error::SessionFailed)
        );
        assert_eq!(listener.timeout, Duration::from_millis(100));
        assert_eq!(listener.evaluation_records, 10_000);
        let Access::Write(writer) = &mut listener.access else {
            unreachable!()
        };
        assert_eq!(writer.store.limits.session_records, 10_000);
        assert_eq!(logical_snapshot(&writer.store.conn), before);
        assert!(writer.failed);
        writer.store.conn.execute_batch("DROP TRIGGER reject_config").unwrap();
        assert_eq!(
            listener.change_admin_config(ConfigRequest::check(values()).unwrap()),
            Err(Error::SessionFailed)
        );
        assert!(listener.close_writer().unwrap().finish().is_err());
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(store.saved_admin_config().unwrap(), None);
        assert_eq!(
            store.record(fixture().id()).unwrap().unwrap().bytes(),
            fixture().bytes()
        );
    }
    #[test]
    fn runtime_config_rejects_below_consumed_budget_and_incomplete_endpoints() {
        for incomplete in [false, true] {
            let temp = Temp::new();
            let mut listener = listener(&temp, true);
            if incomplete {
                let endpoint = listener.evaluation.take().unwrap();
                endpoint
                    .close(listener.access.store(), listener.owner)
                    .unwrap();
            }
            let before = logical_snapshot(&listener.access.store().conn);
            let request = ConfigRequest::check(AdminConfig {
                max_new_records: 1,
                ..values()
            })
            .unwrap();
            assert_eq!(
                listener.change_admin_config(request),
                Err(if incomplete {
                    Error::WrongMode
                } else {
                    Error::Policy
                })
            );
            assert_eq!(logical_snapshot(&listener.access.store().conn), before);
            assert_eq!(listener.timeout, Duration::from_millis(100));
            assert!(listener.close_writer().unwrap().finish().is_err());
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        }
    }
}
