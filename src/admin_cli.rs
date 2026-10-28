//! 管理socketの接続診断と前面の管理受理側。公開リレーではない。
use super::AppError;
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
    Serve,
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    match args {
        [action, option, path]
            if (action == "probe" || action == "serve")
                && option == "--data-dir"
                && !path.is_empty() =>
        {
            Ok(Command {
                data: PathBuf::from(path),
                action: if action == "probe" {
                    Action::Probe
                } else {
                    Action::Serve
                },
            })
        }
        _ => Err(AppError::Usage(
            "admin probe/serve --data-dir PATH を指定してください",
        )),
    }
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
    if command.action == Action::Serve {
        return super::admin_server::run(&command.data, output).map_err(Error::Server);
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
            parse(&["serve".into(), "--data-dir".into(), "data".into()]).unwrap().action,
            Action::Serve
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
}
