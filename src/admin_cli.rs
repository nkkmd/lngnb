//! 管理socketの接続診断と前面の管理受理側。公開リレーではない。
use super::{AppError, admin_server::Config};
use lngnb::storage::admin_transport::client;
use std::{ffi::OsString, fmt, io::Write, path::PathBuf, time::Duration};

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    data: PathBuf,
    action: Action,
}
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Probe,
    Status,
    Evaluate,
    Serve(Config),
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage(
            "admin probe/status/evaluate/serve の操作・明示領域・設定値を確認してください",
        )
    };
    let [action, rest @ ..] = args else {
        return Err(usage());
    };
    if action != "probe" && action != "status" && action != "evaluate" && action != "serve" {
        return Err(usage());
    }
    let mut data = None;
    let mut timeout = None;
    let mut records = None;
    let mut diagnostic_records = None;
    let mut startup_records = None;
    for pair in rest.chunks(2) {
        let [option, value] = pair else {
            return Err(usage());
        };
        if value.is_empty() {
            return Err(usage());
        }
        match option.to_str() {
            Some("--data-dir") if data.is_none() => data = Some(PathBuf::from(value)),
            Some("--request-timeout-ms") if action == "serve" && timeout.is_none() => {
                timeout = Some(number(value).ok_or_else(usage)?);
            }
            Some("--max-new-records") if action == "serve" && records.is_none() => {
                records = Some(number(value).ok_or_else(usage)?);
            }
            Some("--max-diagnostic-records")
                if action == "serve" && diagnostic_records.is_none() =>
            {
                diagnostic_records = Some(number(value).ok_or_else(usage)?);
            }
            Some("--startup-records-per-step") if action == "serve" && startup_records.is_none() => {
                startup_records = Some(number(value).ok_or_else(usage)?);
            }
            _ => return Err(usage()),
        }
    }
    let action = if action == "probe" {
        Action::Probe
    } else if action == "evaluate" {
        Action::Evaluate
    } else if action == "status" {
        Action::Status
    } else {
        Action::Serve(
            Config::checked(timeout, records)
                .and_then(|c| c.with_diagnostic_records(diagnostic_records))
                .and_then(|c| c.with_startup_records(startup_records))
                .ok_or_else(usage)?,
        )
    };
    Ok(Command {
        data: data.ok_or_else(usage)?,
        action,
    })
}
fn number(value: &OsString) -> Option<u64> {
    let s = value.to_str()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}
#[derive(Debug)]
pub enum Error {
    Connection,
    Output,
    Status,
    StatusOutput,
    Evaluation,
    EvaluationOutput,
    Server(super::admin_server::Error),
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Server(e) => e.exit_code(),
            _ => 1,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Server(e) = self {
            return e.fmt(f);
        }
        f.write_str(match self {
            Self::Evaluation => "保存・評価診断を取得・照合できません。部分件数・健全性は不明です。受理側が保全停止した可能性があるため領域とsocketを保持して確認してください。自動再送・直接DB読込み・残存物整理・再開は行いません。",
            Self::EvaluationOutput => "保存・評価診断の照合後、結果出力に失敗しました。診断は評価確定・公開・正常停止・復旧完了ではありません。",
            Self::Status => "管理受理側の実行時診断を取得・照合できません。保存要求・再送・直接DB読込み・socket削除は行っていません。診断endpointがない旧受理側へは保存経路で再接続しません。",
            Self::StatusOutput => "管理受理側の実行時診断を照合後、結果出力に失敗しました。保存要求は送っていません。公開・正常停止・復旧完了の判定ではありません。",
            Self::Connection => "管理socketへの認証付き接続を確認できません。初期化・削除・再送・直接保存は行っていません。",
            Self::Server(_) => unreachable!(),
            Self::Output => "接続先の権限・UID照合後、診断出力に失敗しました。保存要求は送っていません。",
        })
    }
}
impl std::error::Error for Error {}
pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    if let Action::Serve(config) = command.action {
        return super::admin_server::run(&command.data, config, output).map_err(Error::Server);
    }
    if command.action == Action::Evaluate {
        let diagnostic = client::evaluate(&command.data, Duration::from_secs(30))
            .map_err(|_| Error::Evaluation)?;
        return evaluation_report(diagnostic, output);
    }
    if command.action == Action::Status {
        let status =
            client::status(&command.data, Duration::from_secs(30)).map_err(|_| Error::Status)?;
        return status_report(status, output);
    }
    client::probe(&command.data, Duration::from_secs(30)).map_err(|_| Error::Connection)?;
    report(output)
}
fn report(output: &mut impl Write) -> Result<(), Error> {
    output
        .write_all("管理socketへの接続と接続先の権限・UIDを照合しました。\n保存要求は送っていません。相手の受理準備・プロトコル対応・保存状態・公開可否・正常停止・復旧完了の判定ではありません。\n".as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output)
}

fn status_report(
    status: lngnb::storage::admin_transport::RuntimeStatus,
    output: &mut impl Write,
) -> Result<(), Error> {
    let text = format!(
        "管理受理側の実行時診断（全資料の健全性・公開・正常停止・復旧完了の判定ではありません）。\ngeneration: {}\nsession_new_records: {}\nsession_stored_bytes: {}\nmax_new_records: {}\nmax_stored_bytes: {}\nrequest_timeout_ms: {}\navailable_bytes: {}\nreserved_floor_bytes: {}\ncapacity_warning: {}\n保存要求は送っていません。件数はこの保存sessionの新規挿入だけで、保存済み総件数ではありません。手動確認待ちは解除しません。\n",
        status.generation,
        status.new_records,
        status.stored_bytes,
        status.max_new_records,
        status.max_stored_bytes,
        status.request_timeout_ms,
        status.available_bytes,
        status.reserved_floor_bytes,
        status.capacity_warning
    );
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::StatusOutput)
}

fn evaluation_report(
    status: lngnb::storage::admin_transport::EvaluationStatus,
    output: &mut impl Write,
) -> Result<(), Error> {
    let text = format!(
        "管理受理側の保存・評価診断（公開・正常停止・復旧完了の判定ではありません）。\ndiagnostic_generation: {}\nrecords: {}\ndiagnostic_valid: {}\ndiagnostic_pending: {}\ndiagnostic_invalid: {}\npayload_verified: {}\npayload_missing: {}\npayload_unavailable: {}\n診断は保存済み評価へ反映していません。保存要求は送らず、手動確認待ちは解除しません。pin・公開・同期・重要履歴全体の診断は未実装です。\n",
        status.generation,
        status.records,
        status.valid,
        status.pending,
        status.invalid,
        status.payload_verified,
        status.payload_missing,
        status.payload_unavailable
    );
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::EvaluationOutput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_requires_one_explicit_path_without_echoing_arguments() {
        assert_eq!(
            parse(&["probe".into(), "--data-dir".into(), "資料 space".into()])
                .unwrap()
                .data,
            PathBuf::from("資料 space")
        );
        assert_eq!(
            parse(&["serve".into(), "--data-dir".into(), "data".into()])
                .unwrap()
                .action,
            Action::Serve(Config::default())
        );
        for args in [
            vec!["serve", "--data-dir", "a", "--data-dir", "b"],
            vec![],
            vec!["probe"],
            vec!["probe", "--data-dir", ""],
            vec!["private", "--data-dir", "a"],
            vec!["probe", "--data-dir", "a", "--data-dir", "b"],
            vec!["probe", "--token", "private"],
        ] {
            let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            let e = parse(&args).unwrap_err();
            assert_eq!(e.exit_code(), 2);
            assert!(!e.to_string().contains("private"));
        }
    }

    #[test]
    fn probe_report_limits_claims_and_rejects_write_and_flush_failure() {
        let mut output = Vec::new();
        report(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("保存要求は送っていません"));
        assert!(text.contains("受理準備・プロトコル対応・保存状態"));
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(b.len())
                } else {
                    Err(std::io::Error::other("private"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("private"))
            }
        }
        for flush in [false, true] {
            let e = report(&mut Sink(flush)).unwrap_err();
            assert!(matches!(e, Error::Output));
            assert_eq!(e.exit_code(), 1);
            assert!(!e.to_string().contains("private"));
        }
    }

    #[test]
    fn runtime_options_are_canonical_bounded_unique_and_serve_only() {
        let good: Vec<OsString> = [
            "serve",
            "--max-new-records",
            "1",
            "--data-dir",
            "資料 space",
            "--request-timeout-ms",
            "500",
            "--max-diagnostic-records",
            "7",
            "--startup-records-per-step",
            "3",
        ]
        .map(Into::into)
        .to_vec();
        let command = parse(&good).unwrap();
        assert_eq!(command.data, PathBuf::from("資料 space"));
        assert_eq!(
            command.action,
            Action::Serve(
                Config::checked(Some(500), Some(1))
                    .unwrap()
                    .with_diagnostic_records(Some(7))
                    .unwrap()
                    .with_startup_records(Some(3))
                    .unwrap()
            )
        );
        for (option, max) in [
            ("--request-timeout-ms", "30001"),
            ("--max-new-records", "10001"),
            ("--max-diagnostic-records", "10001"),
            ("--startup-records-per-step", "10001"),
        ] {
            for bad in [
                "0",
                max,
                "01",
                "+1",
                "-1",
                "1.0",
                " 1",
                "１",
                "18446744073709551616",
                "private",
            ] {
                let args: Vec<OsString> = ["serve", "--data-dir", "data", option, bad]
                    .map(Into::into)
                    .to_vec();
                let error = parse(&args).unwrap_err();
                assert_eq!(error.exit_code(), 2);
                assert!(!error.to_string().contains("private"));
            }
            for args in [
                vec!["serve", "--data-dir", "data", option],
                vec!["serve", "--data-dir", "data", option, "1", option, "2"],
                vec!["probe", "--data-dir", "data", option, "1"],
            ] {
                let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
                assert_eq!(parse(&args).unwrap_err().exit_code(), 2);
            }
        }
    }
    #[test]
    fn status_is_explicit_and_output_failure_is_not_storage_uncertainty() {
        assert_eq!(
            parse(&["status".into(), "--data-dir".into(), "data".into()])
                .unwrap()
                .action,
            Action::Status
        );
        for option in [
            "--request-timeout-ms",
            "--max-new-records",
            "--max-diagnostic-records",
            "--startup-records-per-step",
        ] {
            let args: Vec<OsString> = ["status", "--data-dir", "data", option, "1"]
                .map(Into::into)
                .to_vec();
            assert_eq!(parse(&args).unwrap_err().exit_code(), 2);
        }
        let status = lngnb::storage::admin_transport::RuntimeStatus {
            generation: 1,
            new_records: 0,
            stored_bytes: 0,
            max_new_records: 1,
            max_stored_bytes: 1,
            available_bytes: 1,
            reserved_floor_bytes: 1,
            request_timeout_ms: 1,
            capacity_warning: false,
        };
        let mut out = Vec::new();
        status_report(status, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("保存済み総件数ではありません")
        );
        let mut closed = std::io::Cursor::new(&mut [0u8; 0][..]);
        let error = status_report(status, &mut closed).unwrap_err();
        assert!(matches!(error, Error::StatusOutput));
        assert_eq!(error.exit_code(), 1);
        assert_eq!(Error::Status.exit_code(), 1);
    }
}

#[cfg(test)]
mod evaluation_tests {
    use super::*;
    #[test]
    fn evaluation_is_explicit_and_output_failure_does_not_claim_storage_uncertainty() {
        assert_eq!(
            parse(&["evaluate".into(), "--data-dir".into(), "data".into()])
                .unwrap()
                .action,
            Action::Evaluate
        );
        for args in [
            vec!["evaluate"],
            vec!["evaluate", "--data-dir", ""],
            vec![
                "evaluate",
                "--data-dir",
                "data",
                "--request-timeout-ms",
                "1",
            ],
            vec!["evaluate", "--data-dir", "data", "--max-new-records", "1"],
            vec![
                "evaluate",
                "--data-dir",
                "data",
                "--max-diagnostic-records",
                "1",
            ],
            vec!["evaluate", "--data-dir", "data", "--startup-records-per-step", "1"],
        ] {
            let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            assert_eq!(parse(&args).unwrap_err().exit_code(), 2);
        }
        let snapshot = lngnb::storage::admin_transport::EvaluationStatus {
            generation: 1,
            records: 1,
            valid: 0,
            pending: 1,
            invalid: 0,
            payload_verified: 0,
            payload_missing: 1,
            payload_unavailable: 0,
        };
        let mut output = Vec::new();
        evaluation_report(snapshot, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("保存済み評価へ反映していません")
        );
        let mut closed = std::io::Cursor::new(&mut [0u8; 0][..]);
        assert_eq!(
            evaluation_report(snapshot, &mut closed)
                .unwrap_err()
                .exit_code(),
            1
        );
        assert_eq!(Error::Evaluation.exit_code(), 1);
    }
}
