//! R34/A11: 実行ファイル専用の鍵操作。DB/HTTP/IPCには接続しない。
use super::AppError;
use lngnb::{
    id::key_id,
    keyfile::{KeyDirectory, KeyFileError, KeyRecoveryInventory},
    secret_terminal::{SecretInputError, SecretTerminal, TerminalSignals},
};
use std::{ffi::OsString, fmt, io::Write, path::PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Check,
    Change,
    RecoveryStatus,
    CheckResidue,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    action: Action,
    directory: PathBuf,
    name: Option<String>,
}

pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || AppError::Usage("key の操作と引数を確認してください");
    let [action, rest @ ..] = args else {
        return Err(usage());
    };
    let action = match action.to_str() {
        Some("create") => Action::Create,
        Some("check") => Action::Check,
        Some("change-passphrase") => Action::Change,
        Some("recovery-status") => Action::RecoveryStatus,
        Some("check-residue") => Action::CheckResidue,
        _ => return Err(usage()),
    };
    let mut directory = None;
    let mut name = None;
    for pair in rest.chunks(2) {
        let [option, value] = pair else {
            return Err(usage());
        };
        if option == "--key-dir" && directory.is_none() && !value.is_empty() {
            directory = Some(PathBuf::from(value));
        } else if ((option == "--name"
            && action != Action::CheckResidue
            && action != Action::RecoveryStatus)
            || (option == "--residue" && action == Action::CheckResidue))
            && name.is_none()
        {
            let s = value.to_str().ok_or_else(usage)?;
            let valid_residue = s.strip_prefix(".lngnb-key-").is_some_and(|suffix| {
                suffix.len() == 64
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
            if action == Action::CheckResidue {
                if !valid_residue {
                    return Err(usage());
                }
            } else if s.is_empty()
                || s.len() > 128
                || s == "."
                || s == ".."
                || s.starts_with(".lngnb-key-")
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(usage());
            }
            name = Some(s.to_owned());
        } else {
            return Err(usage());
        }
    }
    Ok(Command {
        directory: directory.ok_or_else(usage)?,
        name: if action == Action::RecoveryStatus {
            None
        } else {
            Some(name.ok_or_else(usage)?)
        },
        action,
    })
}

#[derive(Debug)]
pub enum Error {
    Input(SecretInputError),
    File(KeyFileError),
    Output { changed: bool },
}
impl From<SecretInputError> for Error {
    fn from(e: SecretInputError) -> Self {
        Self::Input(e)
    }
}
impl From<KeyFileError> for Error {
    fn from(e: KeyFileError) -> Self {
        Self::File(e)
    }
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Input(SecretInputError::Cancelled) => 130,
            Self::File(KeyFileError::CommitUncertain) => 3,
            Self::File(KeyFileError::CleanupUncertain) => 4,
            _ => 1,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(e) => {
                write!(f, "{e}。鍵ファイルの作成・更新は実行していません。")?;
                if *e == SecretInputError::RestoreFailed {
                    f.write_str("端末復元を確認できません。入力を続けず、別の正常な端末を使ってください。元端末の復旧には stty sane を使用できますが、元設定の完全復元を意味しません。")?;
                }
                Ok(())
            }
            Self::File(e) => {
                write!(f, "{e}。")?;
                f.write_str(match e {
                    KeyFileError::CommitUncertain => "保存結果は未確定です。現在名と残存ファイルを保全し、再作成・再更新・削除をせず確認してください。成功や元鍵への復帰を断定できません。",
                    KeyFileError::CleanupUncertain => "新しい鍵ファイルの永続化は確認済みですが、旧暗号文の整理は未完了または不確実です。残存ファイルを保全し、旧パスフレーズが使えると仮定しないでください。",
                    KeyFileError::PendingRecovery => "残存する回復用ファイルがあるため変更を停止しました。自動採用・削除はしません。現在名は key check で読込み確認できますが、過去の更新完了や残存ファイルの安全性は確認しません。明示復旧CLIは未実装です。",
                    KeyFileError::RecoveryChanged => "診断中の入力変化を検出しました。結果は確定せず、全ファイルを保全したまま再診断してください。",
                    KeyFileError::Exists => "既存ファイルを上書きしていません。対象を確認してください。",
                    KeyFileError::UnsafePath => "所有者専用0700ディレクトリ・0600通常ファイルと安全な経路を確認してください。自動で権限変更しません。",
                    _ => "成功は確認できません。現在名と残存ファイルを保全し、変更を繰り返さず確認してください。",
                })
            }
            Self::Output { changed: true } => f.write_str("鍵ファイル操作は完了しましたが、結果の出力に失敗しました。再実行せず key check で現在名を確認してください。"),
            Self::Output { changed: false } => f.write_str("案内または確認結果の出力に失敗しました。"),
        }
    }
}

pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    // この実行ファイルではworkerや他handlerをまだ導入していない。
    // parse以外の操作より先に明示導入。ライブラリAPIへ暗黙導入しない。
    let signals = TerminalSignals::install()?;
    let mut directory = KeyDirectory::open(&command.directory)?;
    if command.action == Action::RecoveryStatus {
        return report_inventory(&directory.recovery_inventory()?, output);
    }
    let name = command.name.as_deref().unwrap_or("");
    let mut terminal = SecretTerminal::open_interruptible(signals)?;
    let public = match command.action {
        Action::Create => {
            let p = terminal.new_passphrase()?;
            signals.check_cancelled()?;
            directory.create(name, p.as_str())?
        }
        Action::Check => {
            let p = terminal.current_passphrase()?;
            let key = directory.load(name, p.as_str())?;
            key.public_key()
        }
        Action::Change => {
            let old = terminal.current_passphrase()?;
            // 認証に失敗した旧鍵で新パスフレーズを求めない。
            drop(directory.load(name, old.as_str())?);
            let new = terminal.new_passphrase()?;
            signals.check_cancelled()?;
            directory.change_passphrase(name, old.as_str(), new.as_str())?
        }
        Action::CheckResidue => {
            let p = terminal.recovery_passphrase()?;
            signals.check_cancelled()?;
            directory.check_recovery_file(name, p.as_str())?
        }
        Action::RecoveryStatus => unreachable!("inventory returns before terminal input"),
    };
    drop(terminal);
    drop(directory);
    report(&command.action, &public, output)
}

fn report(action: &Action, public: &[u8; 32], output: &mut impl Write) -> Result<(), Error> {
    let status = match action {
        Action::Create => "暗号化鍵を作成しました",
        Action::Check => {
            "現在名の鍵ファイルを復号し公開鍵の一致を確認しました（残存ファイルの復旧確認ではありません）"
        }
        Action::Change => "同じ発行鍵のパスフレーズを更新しました",
        Action::CheckResidue => {
            "指定した残存暗号文を認証復号し公開鍵の一致を確認しました。元の対象名・新旧・更新確定・削除可否は未確認です。書換え・採用・削除は行っていません"
        }
        Action::RecoveryStatus => unreachable!("inventory has a separate report"),
    };
    let text = format!(
        "{status}\nkey_id: {}\n暗号化鍵ファイルとパスフレーズを別々に保全してください。パスフレーズ紛失は管理トークンで回復できません。\n鍵紛失・漏洩時の同一Knowledgeの鍵交代は未対応です。新鍵・新Knowledgeへ由来を付けて移行します。他リレーでの起点採用は別操作です。\n",
        key_id(public)
    );
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output {
            changed: matches!(action, Action::Create | Action::Change),
        })
}

fn report_inventory(
    inventory: &KeyRecoveryInventory,
    output: &mut impl Write,
) -> Result<(), Error> {
    let mut text = format!(
        "残存名の一覧走査を完了しました（各ファイルは個別読取り時点の観測）。\npending_recovery: {}\nunrecognized_entries: {}\n",
        inventory.has_residues(),
        inventory.unrecognized_entries
    );
    for entry in &inventory.entries {
        let status = entry
            .read_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "bounded_read_complete_unauthenticated".into());
        text.push_str(&format!("residue: {} status: {status}\n", entry.name));
    }
    text.push_str("上限付き読取りの完了は形式・認証・保存確定の確認ではありません。生成名と異なる予約prefixのentryは件数だけを示します。\n書換え・採用・削除は行っていません。元の対象名・新旧・過去の更新結果・削除可否は推測しません。終了0は診断処理の終了だけで、復旧完了ではありません。残存物があれば変更停止を維持します。\n");
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output { changed: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parsing_requires_explicit_paths_and_never_echoes_unknown_secret_arguments() {
        for args in [
            vec!["create"],
            vec!["create", "--key-dir", "/tmp/test", "--name", "../publisher"],
            vec![
                "create",
                "--key-dir",
                "/tmp/test",
                "--name",
                ".lngnb-key-residue",
            ],
            vec![
                "check",
                "--key-dir",
                "/tmp/test",
                "--name",
                "publisher",
                "--passphrase",
                "public-secret-argument",
            ],
            vec![
                "check",
                "--key-dir",
                "/tmp/test",
                "--key-dir",
                "/tmp/test",
                "--name",
                "publisher",
            ],
        ] {
            let args: Vec<_> = args.into_iter().map(OsString::from).collect();
            let error = parse(&args).unwrap_err();
            assert_eq!(error.exit_code(), 2);
            assert!(!error.to_string().contains("public-secret-argument"));
        }
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(vec![b'/', 0xff]);
        let parsed = parse(&[
            "check".into(),
            "--name".into(),
            "publisher".into(),
            "--key-dir".into(),
            path.clone(),
        ])
        .unwrap();
        assert_eq!(parsed.directory, PathBuf::from(path));
    }
    #[test]
    fn diagnostic_commands_require_explicit_residue_selection_and_hide_untrusted_names() {
        assert!(
            parse(&[
                "recovery-status".into(),
                "--key-dir".into(),
                "/tmp/test".into()
            ])
            .unwrap()
            .name
            .is_none()
        );
        let residue = format!(".lngnb-key-{}", "a".repeat(64));
        assert_eq!(
            parse(&[
                "check-residue".into(),
                "--key-dir".into(),
                "/tmp/test".into(),
                "--residue".into(),
                residue.clone().into()
            ])
            .unwrap()
            .name,
            Some(residue)
        );
        for args in [
            vec!["recovery-status", "--key-dir", "/tmp/test", "--name", "key"],
            vec![
                "check-residue",
                "--key-dir",
                "/tmp/test",
                "--residue",
                ".lngnb-key-user",
            ],
            vec!["check-residue", "--key-dir", "/tmp/test", "--name", "key"],
            vec!["check", "--key-dir", "/tmp/test", "--residue", "key"],
        ] {
            assert!(parse(&args.into_iter().map(OsString::from).collect::<Vec<_>>()).is_err());
        }
        let mut output = Vec::new();
        report_inventory(
            &KeyRecoveryInventory {
                entries: vec![],
                unrecognized_entries: 2,
            },
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains("pending_recovery: true") && text.contains("unrecognized_entries: 2")
        );
        assert!(text.contains("復旧完了ではありません"));
        assert!(!text.contains("key_id:"));
    }
    #[test]
    fn uncertain_results_have_distinct_non_success_codes_and_guidance() {
        for (e, code, marker) in [
            (KeyFileError::CommitUncertain, 3, "保存結果は未確定"),
            (KeyFileError::CleanupUncertain, 4, "永続化は確認済み"),
            (KeyFileError::PendingRecovery, 1, "自動採用・削除はしません"),
        ] {
            let error = Error::File(e);
            assert_eq!(error.exit_code(), code);
            assert!(error.to_string().contains(marker));
        }
        let error = Error::Input(SecretInputError::RestoreFailed);
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains("stty sane"));
        assert_eq!(Error::Input(SecretInputError::Cancelled).exit_code(), 130);
    }
    #[test]
    fn output_failure_after_commit_is_distinguished_and_does_not_undo_key() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("public test"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for action in [
            Action::Create,
            Action::Check,
            Action::Change,
            Action::CheckResidue,
        ] {
            let error = report(&action, &[0; 32], &mut Closed).unwrap_err();
            assert_eq!(error.exit_code(), 1);
            assert_eq!(
                error.to_string().contains("鍵ファイル操作は完了"),
                matches!(action, Action::Create | Action::Change)
            );
        }
        struct FailFlush;
        impl Write for FailFlush {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("public flush failure"))
            }
        }
        let error = report(&Action::Change, &[0; 32], &mut FailFlush).unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains("再実行せず"));
        assert_eq!(
            report_inventory(
                &KeyRecoveryInventory {
                    entries: vec![],
                    unrecognized_entries: 0
                },
                &mut FailFlush
            )
            .unwrap_err()
            .exit_code(),
            1
        );
    }
}
