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
    Serve(Config),
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || AppError::Usage("admin probe/serve の操作・明示領域・設定値を確認してください");
    let [action, rest @ ..] = args else {
        return Err(usage());
    };
    if action != "probe" && action != "serve" {
        return Err(usage());
    }
    let mut data = None;
    let mut timeout = None;
    let mut records = None;
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
            _ => return Err(usage()),
        }
    }
    let action = if action == "probe" {
        Action::Probe
    } else {
        Action::Serve(Config::checked(timeout, records).ok_or_else(usage)?)
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
    client::probe(&command.data, Duration::from_secs(30)).map_err(|_| Error::Connection)?;
    report(output)
}
fn report(output: &mut impl Write) -> Result<(), Error> {
    output
        .write_all("管理socketへの接続と接続先の権限・UIDを照合しました。\n保存要求は送っていません。相手の受理準備・プロトコル対応・保存状態・公開可否・正常停止・復旧完了の判定ではありません。\n".as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output)
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
        ]
        .map(Into::into)
        .to_vec();
        let command = parse(&good).unwrap();
        assert_eq!(command.data, PathBuf::from("資料 space"));
        assert_eq!(
            command.action,
            Action::Serve(Config::checked(Some(500), Some(1)).unwrap())
        );
        for (option, max) in [
            ("--request-timeout-ms", "30001"),
            ("--max-new-records", "10001"),
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
}
