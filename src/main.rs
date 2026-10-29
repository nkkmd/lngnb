use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod admin_cli;
#[cfg(target_os = "linux")]
mod admin_server;
#[cfg(target_os = "linux")]
mod data_cli;
#[cfg(target_os = "linux")]
mod document_cli;
#[cfg(target_os = "linux")]
mod key_cli;
#[cfg(target_os = "linux")]
mod record_cli;

const HELP: &str = "lngnb — 分散図書館・知識基盤（開発初期段階）

使い方:
  lngnb --help
  lngnb --version
  lngnb config show [--data-dir PATH]
  lngnb data init --data-dir PATH
  lngnb data status --data-dir PATH
  lngnb admin probe --data-dir PATH
  lngnb admin status --data-dir PATH
  lngnb admin evaluate --data-dir PATH
  lngnb admin config-show --data-dir PATH
  lngnb admin config-save --data-dir PATH --request-timeout-ms N --max-new-records N --max-diagnostic-records N --startup-records-per-step N
  lngnb admin serve --data-dir PATH [--request-timeout-ms N] [--max-new-records N] [--max-diagnostic-records N] [--startup-records-per-step N] [--startup-record-bytes-per-step N]
  lngnb record submit --data-dir PATH --record PATH
  lngnb document create --data-dir PATH --key-dir PATH --name NAME --expect-key-id KEY_ID --payload PATH --metadata PATH [--media-type TYPE] [--max-payload-bytes N]
  lngnb key create --key-dir PATH --name NAME
  lngnb key check --key-dir PATH --name NAME
  lngnb key change-passphrase --key-dir PATH --name NAME
  lngnb key recovery-status --key-dir PATH
  lngnb key check-residue --key-dir PATH --residue NAME
  lngnb key preserve-residue --key-dir PATH --residue NAME --backup-dir PATH --backup-name NAME
  lngnb key restore-residue --key-dir PATH --residue NAME --restore-name NAME --expect-key-id KEY_ID

key は既存の所有者専用0700ディレクトリを使います（自動作成・権限変更なし）。
NAMEは1〜128 bytesのASCII英数字/._-（dot/dotdot・予約prefixを除く）。
パスフレーズは前面の制御端末から非表示入力します。
暗号化鍵とパスフレーズを別々に保全してください。紛失は管理トークンで回復できません。
鍵共用時は漏洩の影響が複数資料に及びます。同一Knowledgeの鍵交代は未対応です。
recovery-status は残存名と上限付き読取りだけを診断します（端末不要）。
check-residue は一覧中の生成形式名を明示し、端末入力で認証復号します。
どちらも書換え・採用・削除、元の対象名・新旧・過去の更新結果の確定は行いません。
preserve-residue は認証した暗号文を別の既存0700領域へ非上書きで保存します。
保全元・残存物は残し、過去の更新確定や残存物の削除許可にはしません。
restore-residue は期待鍵IDと照合し、同じ領域の空いている通常名へ非上書き復元します。
復元先名と期待鍵IDを自動選択せず、全残存物と変更停止を維持します。

config show は設定候補の表示だけを行います。
データ領域の初期化・設定の保存・既存設定の読込み・接続は行いません。
document create は初期化済みの正常なデータ領域へ新規資料を保存します。
metadataは決定的CBOR map。本文予算は既定16 MiB、指定上限は64 MiB未満です。
保存失敗時は一部保存の可能性があるため、再作成せず領域を保全してください。
data init は既存の親ディレクトリの下に新しい保存領域だけを作成します。
既存領域は空でも上書きせず、待受先・投稿モード等の保存は未実装です。
data status は排他中の保存状態・管理用再検査・容量を表示します（公開可否ではありません）。
保持本文の欠損等を新たに検出した場合は停止印と履歴を記録し、自動修復・削除・再開をしません。
record submit は検査済みの完成署名Record一件だけを、認証したローカル管理socketへ送ります。
入力は2 MiB以下の通常file。保存応答不明は終了3で保全し、自動再送・直接保存へ切り替えません。
admin probe は保存要求なしでsocket接続先の権限・UIDだけを照合します。受理準備や保存状態は判定しません。
admin serve は前面で管理受理側だけを起動します。SIGINT/SIGTERMで受付停止と進行処理の終結を要求します。
受信/応答の各期限は1〜30000 ms、新規Record上限は1〜10000件で、既定は各上限です。
評価診断のRecord数予算は --max-diagnostic-records で1〜10000件（既定10000）を指定できます。
起動時のRecord局所検査と依存入力収集は --startup-records-per-step で一段階の1〜10000件（既定10000）へ分割できます。
--startup-record-bytes-per-step は両Record段階の一stepのbyte予算（1〜67108864、既定67108864）です。
このbyte予算は保存対象外で、省略時は既定へ戻ります。一件も収まらなければ受付前に保全停止します。
保存対象4項目は項目ごとに起動引数→検査済み保存値→既定値を選び、適用値を起動時に表示します。引数は自動保存しません。
不正保存値を明示引数で補わず、全検査の完了前にはsocketを開きません。
不正通信・保存障害・応答喪失では正常停止にせず、領域とsocketを保持します。
admin status は診断専用socketから実行時の世代・新規保存件数/予算・空き容量だけを取得します。
診断endpointがない旧受理側へは保存経路で再接続せず、保存要求・直接DB読込み・復旧解除をしません。
admin config-show は停止中の保存値だけを照合・表示します。未保存を既定値で補わず、適用値とは区別します。
設定・履歴・起動検査cursor・手動待ちは変更せず、稼働中の排他競合では拒否します。
admin config-save は停止中の正常領域へ4項目すべてを明示保存します。保存値は次のadmin serveで読み込みます。
保存失敗・正常停止未確認は終了3、保存/正常停止後の出力失敗は1です。
稼働中は排他競合で拒否し、IPCへ切り替えません。手動待ち・既存不正設定を自動解除・補完しません。
全管理状態・製品リレー起動は未実装です。
改訂・派生・pin・公開・リレー起動・復旧確認CLIは未実装です。
";

// 工程②は候補表示だけ。永続設定やリレー起動は対応工程で実装する。
#[derive(Debug, PartialEq, Eq)]
struct Config {
    data_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./lngnb-data"),
        }
    }
}

impl Config {
    fn describe(&self) -> String {
        format!(
            "設定候補（未保存・未適用）\ndata_dir: {:?}\n待受方針: loopback\n投稿モード: Restricted\n初期化・設定読込み・保存・接続は行っていません。\n",
            self.data_dir
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Config(Config),
    #[cfg(target_os = "linux")]
    Key(key_cli::Command),
    #[cfg(target_os = "linux")]
    Document(document_cli::Command),
    #[cfg(target_os = "linux")]
    Data(data_cli::Command),
    #[cfg(target_os = "linux")]
    Record(record_cli::Command),
    #[cfg(target_os = "linux")]
    Admin(admin_cli::Command),
}

#[derive(Debug)]
enum AppError {
    Usage(&'static str),
    Output(io::Error),
    #[cfg(target_os = "linux")]
    Key(key_cli::Error),
    #[cfg(target_os = "linux")]
    Document(document_cli::Error),
    #[cfg(target_os = "linux")]
    Data(data_cli::Error),
    #[cfg(target_os = "linux")]
    Record(record_cli::Error),
    #[cfg(target_os = "linux")]
    Admin(admin_cli::Error),
}

impl AppError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Output(_) => 1,
            #[cfg(target_os = "linux")]
            Self::Key(e) => e.exit_code(),
            #[cfg(target_os = "linux")]
            Self::Document(e) => e.exit_code(),
            #[cfg(target_os = "linux")]
            Self::Data(e) => e.exit_code(),
            #[cfg(target_os = "linux")]
            Self::Record(e) => e.exit_code(),
            #[cfg(target_os = "linux")]
            Self::Admin(e) => e.exit_code(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(f, "{message}（使い方: lngnb --help）"),
            Self::Output(_) => f.write_str("標準出力への書込みに失敗しました"),
            #[cfg(target_os = "linux")]
            Self::Key(e) => e.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Document(e) => e.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Data(e) => e.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Record(e) => e.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Admin(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Output(error) => Some(error),
            Self::Usage(_) => None,
            #[cfg(target_os = "linux")]
            Self::Key(_) => None,
            #[cfg(target_os = "linux")]
            Self::Document(_) => None,
            #[cfg(target_os = "linux")]
            Self::Data(_) => None,
            #[cfg(target_os = "linux")]
            Self::Record(_) => None,
            #[cfg(target_os = "linux")]
            Self::Admin(_) => None,
        }
    }
}

fn parse(args: &[OsString]) -> Result<Command, AppError> {
    match args {
        [] => Err(AppError::Usage("操作を指定してください")),
        [arg] if arg == "--help" || arg == "-h" => Ok(Command::Help),
        [arg] if arg == "--version" || arg == "-V" => Ok(Command::Version),
        #[cfg(target_os = "linux")]
        [group, rest @ ..] if group == "key" => key_cli::parse(rest).map(Command::Key),
        #[cfg(target_os = "linux")]
        [group, rest @ ..] if group == "document" => {
            document_cli::parse(rest).map(Command::Document)
        }
        #[cfg(target_os = "linux")]
        [group, rest @ ..] if group == "data" => data_cli::parse(rest).map(Command::Data),
        #[cfg(target_os = "linux")]
        [group, rest @ ..] if group == "record" => record_cli::parse(rest).map(Command::Record),
        #[cfg(target_os = "linux")]
        [group, rest @ ..] if group == "admin" => admin_cli::parse(rest).map(Command::Admin),
        [group, action, rest @ ..] if group == "config" && action == "show" => {
            let config = match rest {
                [] => Config::default(),
                [option, path] if option == "--data-dir" && !path.is_empty() => Config {
                    data_dir: PathBuf::from(path),
                },
                _ => return Err(AppError::Usage("config show の引数が不正です")),
            };
            Ok(Command::Config(config))
        }
        // 未知の引数には秘密値が含まれる可能性があるため、値を再出力しない。
        _ => Err(AppError::Usage(
            "未対応のコマンドまたは引数です。製品操作は未実装です",
        )),
    }
}

fn run(args: &[OsString], output: &mut impl Write) -> Result<(), AppError> {
    let text = match parse(args)? {
        Command::Help => HELP.to_owned(),
        Command::Version => format!(
            "lngnb {}（開発版・製品適合試験未完了）\n",
            env!("CARGO_PKG_VERSION")
        ),
        Command::Config(config) => config.describe(),
        #[cfg(target_os = "linux")]
        Command::Key(command) => return key_cli::run(command, output).map_err(AppError::Key),
        #[cfg(target_os = "linux")]
        Command::Document(command) => {
            return document_cli::run(command, output).map_err(AppError::Document);
        }
        #[cfg(target_os = "linux")]
        Command::Data(command) => return data_cli::run(command, output).map_err(AppError::Data),
        #[cfg(target_os = "linux")]
        Command::Admin(command) => return admin_cli::run(command, output).map_err(AppError::Admin),
        #[cfg(target_os = "linux")]
        Command::Record(command) => {
            return record_cli::run(command, output).map_err(AppError::Record);
        }
    };
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(AppError::Output)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&args, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // 診断先も閉じられている場合は、終了コードで失敗を伝える。
            let _ = writeln!(io::stderr().lock(), "エラー: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // R01/R34（工程②の基礎のみ）: 保存設定の読込みや製品試験ではない。
    #[test]
    fn config_is_only_a_candidate() {
        let command = parse(&["config".into(), "show".into()]).unwrap();
        assert_eq!(command, Command::Config(Config::default()));
        let text = Config::default().describe();
        assert!(text.contains("未保存・未適用"));
        assert!(text.contains("loopback"));
        assert!(text.contains("Restricted"));
    }

    #[test]
    fn explicit_path_is_preserved() {
        let path = OsString::from("資料/space and 日本語");
        assert_eq!(
            parse(&[
                "config".into(),
                "show".into(),
                "--data-dir".into(),
                path.clone()
            ])
            .unwrap(),
            Command::Config(Config {
                data_dir: path.into()
            })
        );
    }

    #[test]
    fn invalid_input_does_not_disclose_arguments_or_write_success() {
        for args in [
            vec![],
            vec!["serve"],
            vec!["--help", "secret-value"],
            vec!["config", "show", "--data-dir"],
            vec!["config", "show", "--data-dir", ""],
            vec!["config", "show", "--token", "secret-value"],
            vec!["config", "show", "--data-dir", "a", "--data-dir", "b"],
        ] {
            let args: Vec<_> = args.into_iter().map(OsString::from).collect();
            let mut output = Vec::new();
            let error = run(&args, &mut output).unwrap_err();
            assert_eq!(error.exit_code(), 2);
            assert!(!error.to_string().contains("secret-value"));
            assert!(output.is_empty());
        }
    }

    #[test]
    fn output_failure_is_not_success() {
        let mut closed = io::Cursor::new(&mut [0u8; 0][..]);
        let error = run(&["--help".into()], &mut closed).unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn flush_failure_is_not_success() {
        struct FailFlush;
        impl Write for FailFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("test"))
            }
        }
        assert_eq!(
            run(&["--version".into()], &mut FailFlush)
                .unwrap_err()
                .exit_code(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_is_preserved_and_unknown_argument_is_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let bytes = OsString::from_vec(vec![b'/', 0xff]);
        assert_eq!(
            parse(&[
                "config".into(),
                "show".into(),
                "--data-dir".into(),
                bytes.clone()
            ])
            .unwrap(),
            Command::Config(Config {
                data_dir: bytes.clone().into()
            })
        );
        assert!(parse(&[bytes]).is_err());
    }
}
