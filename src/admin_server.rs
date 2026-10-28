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
}
impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_new_records: 10_000,
        }
    }
}
impl Config {
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
        })
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
pub fn run(path: &Path, config: Config, output: &mut impl Write) -> Result<(), Error> {
    let signals = Signals::install()?;
    serve(path, config, &signals.stop, output)
}
fn serve(
    path: &Path,
    config: Config,
    stop: &AtomicBool,
    output: &mut impl Write,
) -> Result<(), Error> {
    let limits = Limits {
        session_records: config.max_new_records,
        ..Limits::default()
    };
    let mut startup = LocalStartup::open(path, limits).map_err(|_| Error::Unconfirmed)?;
    if startup.needs_review() {
        return Err(Error::Unconfirmed);
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(Error::Unconfirmed);
        }
        if startup
            .step(EvaluationLimits::default(), LocalStartupBudget::default())
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
    let ready = format!(
        "管理受理側のローカル起動検査を完了し、管理socketを開きました。公開・復旧完了の判定ではありません。\nrequest_timeout_ms: {}\nmax_new_records: {}\n設定はこの起動だけに適用し、保存していません。\n",
        config.timeout_ms, config.max_new_records
    );
    output
        .write_all(ready.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Unconfirmed)?;
    while !stop.load(Ordering::SeqCst) {
        listener.serve_status_if_pending().map_err(|_| Error::Unconfirmed)?;
        if stop.load(Ordering::SeqCst) { break; }
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
