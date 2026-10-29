//! 前面の管理受理側。公開HTTP・秘密鍵・自動復旧を扱わない。
use lngnb::storage::{
    EvaluationLimits, Limits, LocalStartup, LocalStartupBudget,
    admin_transport::{Error as TransportError, Listener},
};
use std::{
    fmt,
    io::Write,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// この起動だけに適用する受理側予算。既定上限を超える設定は受けない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    timeout_ms: u64,
    max_new_records: u64,
    max_diagnostic_records: u64,
    startup_records_per_step: u64,
    startup_record_bytes_per_step: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_new_records: 10_000,
            max_diagnostic_records: 10_000,
            startup_records_per_step: 10_000,
            startup_record_bytes_per_step: 64 * 1024 * 1024,
        }
    }
}
impl Config {
    pub fn saved_values(self) -> lngnb::storage::AdminConfig {
        lngnb::storage::AdminConfig {
            request_timeout_ms: self.timeout_ms,
            max_new_records: self.max_new_records,
            max_diagnostic_records: self.max_diagnostic_records,
            startup_records_per_step: self.startup_records_per_step,
        }
    }
    pub fn checked(timeout_ms: Option<u64>, max_new_records: Option<u64>) -> Option<Self> {
        let defaults = Self::default();
        let timeout_ms = timeout_ms.unwrap_or(defaults.timeout_ms);
        let max_new_records = max_new_records.unwrap_or(defaults.max_new_records);
        if timeout_ms == 0
            || timeout_ms > defaults.timeout_ms
            || max_new_records == 0
            || max_new_records > defaults.max_new_records
        {
            return None;
        }
        Some(Self {
            timeout_ms,
            max_new_records,
            max_diagnostic_records: defaults.max_diagnostic_records,
            startup_records_per_step: defaults.startup_records_per_step,
            startup_record_bytes_per_step: defaults.startup_record_bytes_per_step,
        })
    }
    pub fn with_diagnostic_records(mut self, value: Option<u64>) -> Option<Self> {
        let value = value.unwrap_or(self.max_diagnostic_records);
        if value == 0 || value > 10_000 {
            return None;
        }
        self.max_diagnostic_records = value;
        Some(self)
    }
    pub fn with_startup_records(mut self, value: Option<u64>) -> Option<Self> {
        let value = value.unwrap_or(self.startup_records_per_step);
        if value == 0 || value > 10_000 {
            return None;
        }
        self.startup_records_per_step = value;
        Some(self)
    }
    pub fn with_startup_record_bytes(mut self, value: Option<u64>) -> Option<Self> {
        let value = value.unwrap_or(self.startup_record_bytes_per_step);
        if value == 0 || value > 64 * 1024 * 1024 {
            return None;
        }
        self.startup_record_bytes_per_step = value;
        Some(self)
    }
    fn startup_budget(self) -> LocalStartupBudget {
        let mut budget = LocalStartupBudget::default();
        budget.inspection.records = self.startup_records_per_step;
        budget.records.records = self.startup_records_per_step;
        budget.inspection.bytes = self.startup_record_bytes_per_step;
        budget.records.bytes = self.startup_record_bytes_per_step;
        budget
    }
}

/// 省略と明示的な既定値指定を区別し、自動保存しない。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    pub timeout_ms: Option<u64>,
    pub max_new_records: Option<u64>,
    pub max_diagnostic_records: Option<u64>,
    pub startup_records_per_step: Option<u64>,
    pub startup_record_bytes_per_step: Option<u64>,
}
impl Overrides {
    pub fn resolve(self, saved: Option<lngnb::storage::AdminConfig>) -> Option<Config> {
        if saved.is_some_and(|c| !c.is_valid()) {
            return None;
        }
        Config::checked(
            self.timeout_ms.or(saved.map(|c| c.request_timeout_ms)),
            self.max_new_records.or(saved.map(|c| c.max_new_records)),
        )?
        .with_diagnostic_records(
            self.max_diagnostic_records
                .or(saved.map(|c| c.max_diagnostic_records)),
        )?
        .with_startup_records(
            self.startup_records_per_step
                .or(saved.map(|c| c.startup_records_per_step)),
        )?
        .with_startup_record_bytes(self.startup_record_bytes_per_step)
    }
}

#[derive(Debug)]
pub enum Error {
    Signal,
    Unconfirmed,
    StoppedOutput,
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        if matches!(self, Self::Unconfirmed) {
            3
        } else {
            1
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Signal => "終了signalの設定に失敗しました。受理側を起動していません。",
            Self::Unconfirmed => "管理受理側の正常終了を確認できません。保存済み・未確定の可能性があります。領域と残っているsocketを保全し、再送・再初期化・socket削除を繰り返さず確認してください。正常停止・復旧完了とは扱いません。",
            Self::StoppedOutput => "管理受理側の受付停止・ローカル保存sessionの正常終了後、結果出力に失敗しました。公開・復旧完了の判定ではありません。",
        })
    }
}
impl std::error::Error for Error {}
struct Signals {
    stop: Arc<AtomicBool>,
    ids: Vec<signal_hook::SigId>,
}
impl Signals {
    fn install() -> Result<Self, Error> {
        let mut signals = Self {
            stop: Arc::new(AtomicBool::new(false)),
            ids: Vec::new(),
        };
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let id = signal_hook::flag::register(signal, Arc::clone(&signals.stop))
                .map_err(|_| Error::Signal)?;
            signals.ids.push(id);
        }
        Ok(signals)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.ids.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
pub fn run(path: &Path, config: Overrides, output: &mut impl Write) -> Result<(), Error> {
    let signals = Signals::install()?;
    serve(path, config, &signals.stop, output)
}
fn serve(
    path: &Path,
    overrides: Overrides,
    stop: &AtomicBool,
    output: &mut impl Write,
) -> Result<(), Error> {
    let (mut startup, saved) =
        LocalStartup::open_with_admin_config(path, Limits::default(), overrides.max_new_records)
            .map_err(|_| Error::Unconfirmed)?;
    let config = overrides.resolve(saved).ok_or(Error::Unconfirmed)?;
    if startup.needs_review() {
        return Err(Error::Unconfirmed);
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(Error::Unconfirmed);
        }
        if startup
            .step(EvaluationLimits::default(), config.startup_budget())
            .map_err(|_| Error::Unconfirmed)?
            .checks_complete()
        {
            break;
        }
    }
    let writer = startup.into_writer().map_err(|_| Error::Unconfirmed)?;
    let mut listener = Listener::bind_writer(
        writer,
        lngnb::cbor::MAX_RECORD,
        Duration::from_millis(config.timeout_ms),
    )
    .map_err(|_| Error::Unconfirmed)?;
    listener.enable_status().map_err(|_| Error::Unconfirmed)?;
    listener
        .enable_evaluation_with_record_limit(config.max_diagnostic_records)
        .map_err(|_| Error::Unconfirmed)?;
    let ready = format!(
        "管理受理側のローカル起動検査を完了し、管理socketを開きました。公開・復旧完了の判定ではありません。\nrequest_timeout_ms: {}\nmax_new_records: {}\nmax_diagnostic_records: {}\nstartup_records_per_step: {}\nstartup_record_bytes_per_step: {}\n起動引数・保存値・既定値の順で選んだ設定を適用しました。起動引数は保存していません。Record byte予算はこの起動だけの指定で、保存対象外です。\n",
        config.timeout_ms,
        config.max_new_records,
        config.max_diagnostic_records,
        config.startup_records_per_step,
        config.startup_record_bytes_per_step
    );
    output
        .write_all(ready.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Unconfirmed)?;
    while !stop.load(Ordering::SeqCst) {
        listener
            .serve_status_if_pending()
            .map_err(|_| Error::Unconfirmed)?;
        if stop.load(Ordering::SeqCst) {
            break;
        }
        listener
            .serve_evaluation_if_pending()
            .map_err(|_| Error::Unconfirmed)?;
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut connection = match listener.accept_for(Duration::from_millis(100)) {
            Ok(connection) => connection,
            Err(TransportError::Timeout) => continue,
            Err(_) => return Err(Error::Unconfirmed),
        };
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // 途中frame・不正Record・保存失敗・応答喪失のどれでもfinishへ進めない。
        connection
            .store_record_or_probe()
            .map_err(|_| Error::Unconfirmed)?;
    }
    // Connectionは全て終結済み。socket整理の失敗でもfinishしない。
    let writer = listener.close_writer().map_err(|_| Error::Unconfirmed)?;
    writer.finish().map_err(|_| Error::Unconfirmed)?;
    output
        .write_all("管理受理側の受付を停止し、ローカル保存sessionを正常終了しました。全資料保存・公開・復旧完了の判定ではありません。\n".as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::StoppedOutput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_record_byte_budget_is_bounded_and_separate_from_saved_values() {
        let defaults = LocalStartupBudget::default();
        for value in [1, 64 * 1024 * 1024] {
            let config = Config::default()
                .with_startup_record_bytes(Some(value))
                .unwrap();
            let budget = config.startup_budget();
            assert_eq!(budget.inspection.bytes, value);
            assert_eq!(budget.records.bytes, value);
            assert_eq!(budget.inspection.records, defaults.inspection.records);
            assert_eq!(budget.records.edges, defaults.records.edges);
            assert_eq!(budget.inspection.blob_bytes, defaults.inspection.blob_bytes);
            assert_eq!(budget.blobs.bytes, defaults.blobs.bytes);
            assert_eq!(budget.inspection.elapsed, defaults.inspection.elapsed);
            assert_eq!(config.saved_values(), Config::default().saved_values());
        }
        for value in [0, 64 * 1024 * 1024 + 1, u64::MAX] {
            assert!(
                Config::default()
                    .with_startup_record_bytes(Some(value))
                    .is_none()
            );
        }
        let saved = Config::default().saved_values();
        assert_eq!(
            Overrides::default()
                .resolve(Some(saved))
                .unwrap()
                .startup_record_bytes_per_step,
            64 * 1024 * 1024
        );
        assert_eq!(
            Overrides {
                startup_record_bytes_per_step: Some(1024),
                ..Overrides::default()
            }
            .resolve(Some(saved))
            .unwrap()
            .startup_record_bytes_per_step,
            1024
        );
    }

    #[test]
    fn overrides_resolve_per_field_without_hiding_invalid_saved_values() {
        let saved = lngnb::storage::AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 7,
            max_diagnostic_records: 8,
            startup_records_per_step: 1,
        };
        assert_eq!(Overrides::default().resolve(None), Some(Config::default()));
        assert_eq!(
            Overrides::default()
                .resolve(Some(saved))
                .unwrap()
                .saved_values(),
            saved
        );
        let explicit = Overrides {
            timeout_ms: Some(30_000),
            max_new_records: Some(10_000),
            ..Overrides::default()
        };
        let resolved = explicit.resolve(Some(saved)).unwrap().saved_values();
        assert_eq!(resolved.request_timeout_ms, 30_000);
        assert_eq!(resolved.max_new_records, 10_000);
        assert_eq!(resolved.max_diagnostic_records, 8);
        assert_eq!(resolved.startup_records_per_step, 1);
        let invalid = lngnb::storage::AdminConfig {
            request_timeout_ms: 0,
            ..saved
        };
        assert!(explicit.resolve(Some(invalid)).is_none());
    }

    #[test]
    fn failure_boundaries_do_not_disclose_sources_or_claim_recovery() {
        for (error, code) in [
            (Error::Signal, 1),
            (Error::Unconfirmed, 3),
            (Error::StoppedOutput, 1),
        ] {
            assert_eq!(error.exit_code(), code);
            assert!(std::error::Error::source(&error).is_none());
        }
        assert!(
            Error::Unconfirmed
                .to_string()
                .contains("正常停止・復旧完了とは扱いません")
        );
        assert!(Error::StoppedOutput.to_string().contains("正常終了後"));
    }

    #[test]
    fn runtime_config_only_tightens_existing_defaults() {
        assert_eq!(Config::checked(None, None), Some(Config::default()));
        assert_eq!(
            Config::default().max_new_records,
            Limits::default().session_records
        );
        assert_eq!(Config::default().timeout_ms, 30_000);
        assert_eq!(Config::default().max_diagnostic_records, 10_000);
        assert_eq!(
            Config::default().with_diagnostic_records(None),
            Some(Config::default())
        );
        for value in [1, 10_000] {
            assert_eq!(
                Config::default()
                    .with_diagnostic_records(Some(value))
                    .unwrap()
                    .max_diagnostic_records,
                value
            );
        }
        for value in [0, 10_001, u64::MAX] {
            assert!(
                Config::default()
                    .with_diagnostic_records(Some(value))
                    .is_none()
            );
        }

        let defaults = LocalStartupBudget::default();
        assert_eq!(
            Config::default().startup_records_per_step,
            defaults.inspection.records
        );
        assert_eq!(
            Config::default().startup_records_per_step,
            defaults.records.records
        );
        assert_eq!(
            Config::default().with_startup_records(None),
            Some(Config::default())
        );
        for n in [1, 10_000] {
            let config = Config::default().with_startup_records(Some(n)).unwrap();
            let budget = config.startup_budget();
            assert_eq!(budget.inspection.records, n);
            assert_eq!(budget.records.records, n);
            assert_eq!(budget.inspection.bytes, defaults.inspection.bytes);
            assert_eq!(budget.records.edges, defaults.records.edges);
            assert_eq!(config.max_diagnostic_records, 10_000);
        }
        for n in [0, 10_001, u64::MAX] {
            assert!(Config::default().with_startup_records(Some(n)).is_none());
        }
        assert!(Config::checked(Some(1), Some(1)).is_some());
        assert!(Config::checked(Some(30_000), Some(10_000)).is_some());
        for (timeout, records) in [
            (0, 1),
            (30_001, 1),
            (1, 0),
            (1, 10_001),
            (u64::MAX, u64::MAX),
        ] {
            assert!(Config::checked(Some(timeout), Some(records)).is_none());
        }
    }
}
