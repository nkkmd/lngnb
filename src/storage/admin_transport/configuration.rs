//! R24/R27/R28/R30: 同じwriter中で設定を保存し、成功後だけ次操作へ適用する内部基盤。
//! 専用IPCとclientを提供し、前面受理側と明示的な稼働中変更CLIから使用する。
use super::*;
use crate::storage::{AdminConfig, management::ConfigRequest};

pub(super) const NAME: &str = "admin-config.sock";
pub(super) const MAGIC: [u8; 4] = *b"LNC\x01";
pub(super) const SIZE: usize = 32;

pub(super) fn bytes(config: AdminConfig) -> [u8; SIZE] {
    let mut bytes = [0; SIZE];
    for (i, value) in [
        config.request_timeout_ms,
        config.max_new_records,
        config.max_diagnostic_records,
        config.startup_records_per_step,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}
fn request(bytes: &[u8; SIZE]) -> Result<ConfigRequest> {
    let n = |i: usize| u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    ConfigRequest::check(AdminConfig {
        request_timeout_ms: n(0),
        max_new_records: n(1),
        max_diagnostic_records: n(2),
        startup_records_per_step: n(3),
    })
    .map_err(|_| Error::Policy)
}

/// ResponseLostだけは全4項目の保存と次操作への適用まで確認済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    Transport(Error),
    ResponseLost(AdminConfig),
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport(_) => "admin_config_unconfirmed",
            Self::ResponseLost(_) => "admin_config_saved_applied_response_failed",
        })
    }
}
impl std::error::Error for ConfigError {}

impl Listener {
    /// 全診断endpointを用意済みのwriterへ、設定専用名を新規bindする。
    pub fn enable_configuration(&mut self) -> Result<()> {
        self.check_endpoint()?;
        match &self.access {
            Access::Write(writer) if !writer.failed => (),
            Access::Write(_) => return Err(Error::SessionFailed),
            _ => return Err(Error::WrongMode),
        }
        for endpoint in [&self.status, &self.evaluation] {
            endpoint
                .as_ref()
                .ok_or(Error::WrongMode)?
                .check(self.access.store(), self.owner)?;
        }
        if self.configuration.is_some() {
            return Err(Error::EndpointExists);
        }
        self.configuration = Some(status::Endpoint::bind(
            self.access.store(),
            self.owner,
            NAME,
        )?);
        Ok(())
    }
    /// 一接続一要求。認証・固定長検査後だけ共通保存へ進む。失敗はfinish不可。
    pub fn serve_configuration_if_pending(&mut self) -> std::result::Result<bool, ConfigError> {
        let result = self.configuration_if_pending();
        if result.is_err() {
            if let Access::Write(writer) = &mut self.access {
                writer.failed = true;
            }
        }
        result
    }
    fn configuration_if_pending(&mut self) -> std::result::Result<bool, ConfigError> {
        let receive = || -> Result<Option<UnixStream>> {
            self.check_endpoint()?;
            let endpoint = self.configuration.as_ref().ok_or(Error::WrongMode)?;
            endpoint.check(self.access.store(), self.owner)?;
            let Some(stream) = endpoint.accept()? else {
                return Ok(None);
            };
            authenticate(&stream, self.owner)?;
            self.check_endpoint()?;
            endpoint.check(self.access.store(), self.owner)?;
            stream.set_nonblocking(true).map_err(|_| Error::Io)?;
            Ok(Some(stream))
        };
        let Some(mut stream) = receive().map_err(ConfigError::Transport)? else {
            return Ok(false);
        };
        // この要求の期限は旧値で固定する。変更値は次の管理操作から有効。
        let deadline = Instant::now() + self.timeout;
        let saved = (|| -> Result<AdminConfig> {
            let mut header = [0; 8];
            transfer(&mut stream, &mut header, deadline)?;
            if header[..4] != MAGIC || header[4..] != (SIZE as u32).to_be_bytes() {
                return Err(Error::InvalidFrame);
            }
            let mut body = [0; SIZE];
            transfer(&mut stream, &mut body, deadline)?;
            let request = request(&body)?;
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            self.change_admin_config(request)
        })()
        .map_err(ConfigError::Transport)?;
        // commit以降の失敗は、保存済みの値を保全して応答喪失として返す。
        let mut reply = vec![3]; // saved + applied; startup分割件数は次回起動用
        reply.extend_from_slice(&bytes(saved));
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&(reply.len() as u32).to_be_bytes());
        send_all(&mut stream, &header, deadline)
            .and_then(|_| send_all(&mut stream, &reply, deadline))
            .map_err(|_| ConfigError::ResponseLost(saved))?;
        Ok(true)
    }
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
        if let Some(endpoint) = &self.configuration {
            endpoint.check(self.access.store(), self.owner)?;
        }
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
        writer
            .store
            .conn
            .execute_batch("DROP TRIGGER reject_config")
            .unwrap();
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
    fn poll_config(listener: &mut Listener) -> std::result::Result<bool, ConfigError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.serve_configuration_if_pending() {
                Ok(false) => {
                    assert!(Instant::now() < deadline);
                    thread::yield_now();
                }
                result => return result,
            }
        }
    }
    #[test]
    fn config_wire_has_independent_fixed_bytes_and_rejects_all_invalid_fields() {
        let expected = "00000000000001f4000000000000000200000000000000070000000000000001";
        let fixed: Vec<u8> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(bytes(values()).as_slice(), fixed);
        assert_eq!(request(&bytes(values())).unwrap().values(), values());
        for index in 0..4 {
            for invalid in [0u64, u64::MAX] {
                let mut bad = bytes(values());
                bad[index * 8..index * 8 + 8].copy_from_slice(&invalid.to_be_bytes());
                assert_eq!(request(&bad), Err(Error::Policy));
            }
        }
    }
    #[test]
    fn config_ipc_authenticates_saves_applies_and_closes_four_sockets() {
        let temp = Temp::new();
        let mut listener = listener(&temp, true);
        listener.enable_configuration().unwrap();
        listener.timeout = Duration::from_secs(5);
        assert!(!listener.serve_configuration_if_pending().unwrap());
        let before = status(&temp, &mut listener);
        let path = temp.data();
        let worker = thread::spawn(move || {
            client::change_config(
                &path,
                ConfigRequest::check(values()).unwrap(),
                Duration::from_secs(5),
            )
        });
        assert_eq!(poll_config(&mut listener), Ok(true));
        assert_eq!(worker.join().unwrap(), Ok(values()));
        let after = status(&temp, &mut listener);
        assert!(after.generation > before.generation);
        assert_eq!(after.new_records, before.new_records);
        assert_eq!(after.stored_bytes, before.stored_bytes);
        assert_eq!(after.max_new_records, 2);
        assert_eq!(after.request_timeout_ms, 500);
        assert_eq!(listener.evaluation_records, 7);
        assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
        listener.close_writer().unwrap().finish().unwrap();
        for name in [super::super::NAME, status::NAME, evaluation::NAME, NAME] {
            assert!(!temp.data().join(name).exists());
        }
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.saved_admin_config().unwrap(), Some(values()));
        assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    }
    fn raw_request(temp: &Temp, body: &[u8], header: [u8; 8]) -> UnixStream {
        let dir = crate::storage::directory(&temp.data()).unwrap();
        let mut stream = UnixStream::connect(anchored(&dir, NAME)).unwrap();
        stream.write_all(&header).unwrap();
        stream.write_all(body).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        stream
    }
    #[test]
    fn invalid_config_frames_preserve_data_and_require_review() {
        for variant in 0..5 {
            let temp = Temp::new();
            let mut listener = listener(&temp, true);
            listener.enable_configuration().unwrap();
            listener.timeout = Duration::from_secs(5);
            let before = logical_snapshot(&listener.access.store().conn);
            let mut header = [b'L', b'N', b'C', 1, 0, 0, 0, 32];
            let mut body = bytes(values()).to_vec();
            match variant {
                0 => header[3] = 2,
                1 => header[4..].fill(255),
                2 => body.truncate(10),
                3 => body[..8].fill(0),
                _ => body[8..16].copy_from_slice(&1u64.to_be_bytes()),
            }
            let _stream = raw_request(&temp, &body, header);
            assert!(matches!(
                poll_config(&mut listener),
                Err(ConfigError::Transport(_))
            ));
            assert_eq!(logical_snapshot(&listener.access.store().conn), before);
            assert_eq!(listener.timeout, Duration::from_secs(5));
            drop(listener); // 保全停止ではsocketも残す。
            assert!(temp.data().join(NAME).exists());
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
            assert_eq!(
                store.record(fixture().id()).unwrap().unwrap().bytes(),
                fixture().bytes()
            );
            assert!(matches!(store.begin(), Err(StorageError::NeedsReview)));
        }
    }
    #[test]
    fn config_ipc_sql_rejection_and_response_loss_have_distinct_saved_state() {
        for reject_sql in [true, false] {
            let temp = Temp::new();
            let mut listener = listener(&temp, true);
            listener.enable_configuration().unwrap();
            listener.timeout = Duration::from_secs(5);
            if reject_sql {
                listener.access.store().conn.execute_batch("CREATE TRIGGER reject_config BEFORE INSERT ON history WHEN NEW.new_state='admin_config_saved_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
            }
            let stream = raw_request(&temp, &bytes(values()), [b'L', b'N', b'C', 1, 0, 0, 0, 32]);
            // 書込み済み要求は残すが応答を受取れない状態にし、速度に依存させない。
            stream.shutdown(std::net::Shutdown::Read).unwrap();
            assert_eq!(
                poll_config(&mut listener),
                Err(if reject_sql {
                    ConfigError::Transport(Error::SessionFailed)
                } else {
                    ConfigError::ResponseLost(values())
                })
            );
            assert_eq!(
                listener.timeout,
                Duration::from_millis(if reject_sql { 5000 } else { 500 })
            );
            assert_eq!(
                listener.access.store().saved_admin_config().unwrap(),
                if reject_sql { None } else { Some(values()) }
            );
            assert!(listener.close_writer().unwrap().finish().is_err());
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
            assert_eq!(
                store.record(fixture().id()).unwrap().unwrap().bytes(),
                fixture().bytes()
            );
        }
    }
    #[test]
    fn configuration_endpoint_residue_and_replacement_are_not_adopted() {
        for replace in [false, true] {
            let temp = Temp::new();
            let mut listener = listener(&temp, false);
            let path = anchored(&listener.access.store().dir, NAME);
            if replace {
                listener.enable_configuration().unwrap();
                listener.timeout = Duration::from_secs(5);
                std::fs::remove_file(&path).unwrap();
            }
            std::fs::write(&path, b"preserve").unwrap();
            if replace {
                assert_eq!(
                    listener.serve_configuration_if_pending(),
                    Err(ConfigError::Transport(Error::UnsafeEndpoint))
                );
                assert!(listener.close_writer().is_err());
            } else {
                assert_eq!(listener.enable_configuration(), Err(Error::EndpointExists));
                drop(listener);
            }
            assert_eq!(std::fs::read(temp.data().join(NAME)).unwrap(), b"preserve");
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        }
    }
}
