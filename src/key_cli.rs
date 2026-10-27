//! R34/A11: 実行ファイル専用の鍵操作。DB/HTTP/IPCには接続しない。
use super::AppError;
use lngnb::{
    id::{Id, Kind, key_id},
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
    PreserveResidue,
    RestoreResidue,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    action: Action,
    directory: PathBuf,
    name: Option<String>,
    backup: Option<(PathBuf, String)>,
    restoration: Option<(String, Id)>,
}

fn regular_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && !s.starts_with(".lngnb-key-")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
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
        Some("preserve-residue") => Action::PreserveResidue,
        Some("restore-residue") => Action::RestoreResidue,
        _ => return Err(usage()),
    };
    let mut directory = None;
    let mut name = None;
    let mut backup_dir = None;
    let mut backup_name = None;
    let mut restore_name = None;
    let mut expected_id = None;
    for pair in rest.chunks(2) {
        let [option, value] = pair else {
            return Err(usage());
        };
        if option == "--key-dir" && directory.is_none() && !value.is_empty() {
            directory = Some(PathBuf::from(value));
        } else if option == "--restore-name"
            && action == Action::RestoreResidue
            && restore_name.is_none()
        {
            let s = value.to_str().ok_or_else(usage)?;
            if !regular_name(s) {
                return Err(usage());
            }
            restore_name = Some(s.to_owned());
        } else if option == "--expect-key-id"
            && action == Action::RestoreResidue
            && expected_id.is_none()
        {
            expected_id =
                Some(Id::parse(Kind::Key, value.to_str().ok_or_else(usage)?).map_err(|_| usage())?);
        } else if option == "--backup-dir"
            && action == Action::PreserveResidue
            && backup_dir.is_none()
            && !value.is_empty()
        {
            backup_dir = Some(PathBuf::from(value));
        } else if option == "--backup-name"
            && action == Action::PreserveResidue
            && backup_name.is_none()
        {
            let s = value.to_str().ok_or_else(usage)?;
            if !regular_name(s) {
                return Err(usage());
            }
            backup_name = Some(s.to_owned());
        } else if ((option == "--name"
            && !matches!(
                action,
                Action::CheckResidue | Action::PreserveResidue | Action::RestoreResidue
            )
            && action != Action::RecoveryStatus)
            || (option == "--residue"
                && matches!(
                    action,
                    Action::CheckResidue | Action::PreserveResidue | Action::RestoreResidue
                )))
            && name.is_none()
        {
            let s = value.to_str().ok_or_else(usage)?;
            let valid_residue = s.strip_prefix(".lngnb-key-").is_some_and(|suffix| {
                suffix.len() == 64
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
            if matches!(
                action,
                Action::CheckResidue | Action::PreserveResidue | Action::RestoreResidue
            ) {
                if !valid_residue {
                    return Err(usage());
                }
            } else if !regular_name(s) {
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
        backup: if action == Action::PreserveResidue {
            Some((
                backup_dir.ok_or_else(usage)?,
                backup_name.ok_or_else(usage)?,
            ))
        } else {
            None
        },
        restoration: if action == Action::RestoreResidue {
            Some((
                restore_name.ok_or_else(usage)?,
                expected_id.ok_or_else(usage)?,
            ))
        } else {
            None
        },
        action,
    })
}

#[derive(Debug)]
pub enum Error {
    Input(SecretInputError),
    File(KeyFileError),
    Preserve(KeyFileError),
    PreservationOutput,
    Restore(KeyFileError),
    RestorationOutput,
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
            Self::File(KeyFileError::CommitUncertain)
            | Self::Preserve(KeyFileError::CommitUncertain)
            | Self::Restore(KeyFileError::CommitUncertain) => 3,
            Self::File(KeyFileError::CleanupUncertain)
            | Self::Preserve(KeyFileError::CleanupUncertain) => 4,
            Self::File(KeyFileError::PreservationReviewRequired)
            | Self::Preserve(KeyFileError::PreservationReviewRequired) => 5,
            Self::File(KeyFileError::RestorationReviewRequired)
            | Self::Restore(KeyFileError::RestorationReviewRequired) => 6,
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
                    KeyFileError::PendingRecovery => "残存する回復用ファイルがあるため変更を停止しました。自動採用・削除はしません。現在名は key check で読込み確認できますが、過去の更新完了や残存ファイルの安全性は確認しません。指定残存物の非上書き復元は key restore-residue を使えますが、既存鍵の置換・残存物の整理は未実装です。",
                    KeyFileError::RecoveryChanged => "診断中の入力変化を検出しました。結果は確定せず、全ファイルを保全したまま再診断してください。",
                    KeyFileError::PreservationReviewRequired => "保全先の永続化は確認済みですが、保全元の最終照合等は未完了または不一致です。両領域の全ファイルを保持し、再実行・削除をせず確認してください。",
                    KeyFileError::RestorationReviewRequired => "復元先の永続化は確認済みですが、残存元の最終照合等は未完了または不一致です。全残存物と復元先を保持し、再実行・削除をせず確認してください。",
                    KeyFileError::UnexpectedPublicKey => "期待する鍵IDと一致しないため復元していません。残存物の選択と期待する鍵IDを確認してください。",
                    KeyFileError::Exists => "既存ファイルを上書きしていません。対象を確認してください。",
                    KeyFileError::UnsafePath => "所有者専用0700ディレクトリ・0600通常ファイルと安全な経路を確認してください。自動で権限変更しません。",
                    _ => "成功は確認できません。現在名と残存ファイルを保全し、変更を繰り返さず確認してください。",
                })
            }
            Self::Preserve(e) => {
                f.write_str("残存鍵の保全処理: ")?;
                Self::File(*e).fmt(f)?;
                f.write_str(" 保全元への書換え・削除は行っていません。保全先の未確定ファイルも保持し、元の更新結果や削除可否を推測しないでください。")
            }
            Self::Restore(e) => {
                f.write_str("残存鍵の復元処理: ")?;
                Self::File(*e).fmt(f)?;
                f.write_str(" 残存元への書換え・削除は行っていません。全残存物と復元先の未確定ファイルも保持してください。過去の更新結果・新旧・整理可否は確定せず、変更停止も解除しません。")
            }
            Self::RestorationOutput => f.write_str("復元先への暗号文保存は完了しましたが、結果出力に失敗しました。全残存物と復元先を保持し、再実行せず復元先を key check で確認してください。過去の更新確定・残存物の整理許可ではなく、変更停止も解除しません。"),
            Self::PreservationOutput => f.write_str("保全先への暗号文保存は完了しましたが、結果出力に失敗しました。保全元・保全先を保持し、再実行せず保全先を key check で確認してください。過去の更新確定や残存物の削除許可ではありません。"),
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
    if command.action == Action::PreserveResidue {
        let (path, backup_name) = command
            .backup
            .as_ref()
            .ok_or(Error::File(KeyFileError::UnsafePath))?;
        // どちらも非待機lock。同じinode/逆順の競合でも待ち合わせない。
        let mut backup = KeyDirectory::open(path).map_err(Error::Preserve)?;
        let mut terminal = SecretTerminal::open_interruptible(signals)?;
        let p = terminal.recovery_passphrase()?;
        signals.check_cancelled()?;
        let public = directory
            .preserve_recovery_file(name, p.as_str(), &mut backup, backup_name)
            .map_err(Error::Preserve)?;
        drop(p);
        drop(terminal);
        drop(backup);
        drop(directory);
        return report(&command.action, &public, output);
    }
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
        Action::RestoreResidue => {
            let (target, expected) = command
                .restoration
                .as_ref()
                .ok_or(Error::Restore(KeyFileError::UnsafePath))?;
            let p = terminal.recovery_passphrase()?;
            signals.check_cancelled()?;
            let public = directory
                .check_recovery_file(name, p.as_str())
                .map_err(Error::Restore)?;
            if key_id(&public) != *expected {
                return Err(Error::Restore(KeyFileError::UnexpectedPublicKey));
            }
            // 認証照合中の取消しも保存開始前に確認。APIが再認証/配置前照合を担う。
            signals.check_cancelled()?;
            directory
                .restore_recovery_file(name, p.as_str(), target, &public)
                .map_err(Error::Restore)?
        }
        Action::RecoveryStatus => unreachable!("inventory returns before terminal input"),
        Action::PreserveResidue => unreachable!("preservation uses both directory locks above"),
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
        Action::RestoreResidue => {
            "指定した残存暗号文を期待する鍵IDと照合し、明示した空いている復元先名へ同じbytesを保存しました。全残存物を保持し、変更停止も解除していません。過去の更新確定・元名の推測・新旧判定・残存物の整理許可ではありません"
        }
        Action::RecoveryStatus => unreachable!("inventory has a separate report"),
        Action::PreserveResidue => {
            "指定した残存暗号文を認証し、明示した保全先の新しい名前へ同じbytesを保存しました。保全元の現在名・残存物は書換え・削除していません。過去の更新確定・新旧判定・残存物の整理許可ではありません"
        }
    };
    let text = format!(
        "{status}\nkey_id: {}\n暗号化鍵ファイルとパスフレーズを別々に保全してください。パスフレーズ紛失は管理トークンで回復できません。\n鍵紛失・漏洩時の同一Knowledgeの鍵交代は未対応です。新鍵・新Knowledgeへ由来を付けて移行します。他リレーでの起点採用は別操作です。\n",
        key_id(public)
    );
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| {
            if *action == Action::RestoreResidue {
                Error::RestorationOutput
            } else if *action == Action::PreserveResidue {
                Error::PreservationOutput
            } else {
                Error::Output {
                    changed: matches!(action, Action::Create | Action::Change),
                }
            }
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
    fn restoration_requires_explicit_selection_target_and_canonical_key_id() {
        let residue = format!(".lngnb-key-{}", "a".repeat(64));
        let ident = key_id(&[0; 32]).to_string();
        let args = [
            "restore-residue",
            "--key-dir",
            "/keys",
            "--residue",
            &residue,
            "--restore-name",
            "restored",
            "--expect-key-id",
            &ident,
        ];
        let valid: Vec<OsString> = args.iter().map(OsString::from).collect();
        let parsed = parse(&valid).unwrap();
        assert_eq!(parsed.name, Some(residue.clone()));
        assert_eq!(
            parsed.restoration,
            Some(("restored".into(), key_id(&[0; 32])))
        );
        for start in [1, 3, 5, 7] {
            let mut bad = valid.clone();
            bad.drain(start..start + 2);
            assert!(parse(&bad).is_err());
        }
        for (index, value) in [
            (4, "publisher"),
            (6, "../escape"),
            (6, ".lngnb-key-reserved"),
            (8, "ky1_invalid"),
            (8, "public-secret-argument"),
        ] {
            let mut bad = valid.clone();
            bad[index] = value.into();
            let error = parse(&bad).unwrap_err();
            assert_eq!(error.exit_code(), 2);
            assert!(!error.to_string().contains(value));
        }
        for invalid_id in [
            ident.to_uppercase(),
            ident.replacen("ky1_", "rc1_", 1),
            format!(" {ident}"),
        ] {
            let mut bad = valid.clone();
            bad[8] = invalid_id.into();
            assert!(parse(&bad).is_err());
        }
        for option in [
            "--restore-name",
            "--expect-key-id",
            "--residue",
            "--key-dir",
        ] {
            let mut bad = valid.clone();
            bad.extend([option.into(), "duplicate".into()]);
            assert!(parse(&bad).is_err());
        }
        for other in [
            "create",
            "check",
            "change-passphrase",
            "preserve-residue",
            "check-residue",
            "recovery-status",
        ] {
            let mut bad = valid.clone();
            bad[0] = other.into();
            assert!(parse(&bad).is_err());
        }
        let mut bad = valid;
        bad.extend(["--backup-dir".into(), "/backup".into()]);
        assert!(parse(&bad).is_err());
    }
    #[test]
    fn restoration_errors_and_output_failures_never_report_overall_recovery_success() {
        for (error, code, marker) in [
            (
                KeyFileError::UnexpectedPublicKey,
                1,
                "期待する鍵IDと一致しない",
            ),
            (
                KeyFileError::Key(lngnb::keyfile::KeyError::AuthenticationFailed),
                1,
                "key_authentication_failed",
            ),
            (KeyFileError::Exists, 1, "上書きしていません"),
            (KeyFileError::Io, 1, "成功は確認できません"),
            (KeyFileError::RecoveryChanged, 1, "入力変化"),
            (KeyFileError::CommitUncertain, 3, "保存結果は未確定"),
            (
                KeyFileError::RestorationReviewRequired,
                6,
                "復元先の永続化は確認済み",
            ),
        ] {
            let e = Error::Restore(error);
            assert_eq!(e.exit_code(), code);
            let text = e.to_string();
            assert!(text.contains(marker) && text.contains("変更停止も解除しません"));
            assert!(text.contains("全残存物") && text.contains("書換え・削除は行っていません"));
        }
        struct Broken {
            flush: bool,
        }
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.flush {
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("public write failure"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("public flush failure"))
            }
        }
        for flush in [false, true] {
            let e = report(&Action::RestoreResidue, &[0; 32], &mut Broken { flush }).unwrap_err();
            assert!(matches!(e, Error::RestorationOutput));
            assert_eq!(e.exit_code(), 1);
            assert!(e.to_string().contains("保存は完了") && e.to_string().contains("再実行せず"));
        }
        let mut output = Vec::new();
        report(&Action::RestoreResidue, &[0; 32], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains("変更停止も解除していません") && text.contains("整理許可ではありません")
        );
        assert!(text.contains(&key_id(&[0; 32]).to_string()));
    }
    #[test]
    fn preservation_requires_both_explicit_targets_and_distinguishes_committed_review() {
        let residue = format!(".lngnb-key-{}", "a".repeat(64));
        let args = [
            "preserve-residue",
            "--key-dir",
            "/source",
            "--residue",
            &residue,
            "--backup-dir",
            "/backup",
            "--backup-name",
            "saved",
        ];
        let parsed = parse(&args.iter().map(OsString::from).collect::<Vec<_>>()).unwrap();
        assert_eq!(
            parsed.backup,
            Some((PathBuf::from("/backup"), "saved".into()))
        );
        assert!(parse(&args[..7].iter().map(OsString::from).collect::<Vec<_>>()).is_err());
        for name in ["../escape", ".lngnb-key-reserved", ""] {
            let mut bad = args.iter().map(OsString::from).collect::<Vec<_>>();
            bad[8] = name.into();
            assert!(parse(&bad).is_err());
        }
        for (e, code) in [
            (KeyFileError::Io, 1),
            (KeyFileError::CommitUncertain, 3),
            (KeyFileError::PreservationReviewRequired, 5),
        ] {
            let error = Error::Preserve(e);
            assert_eq!(error.exit_code(), code);
            assert!(
                error
                    .to_string()
                    .contains("保全元への書換え・削除は行っていません")
            );
        }
        assert!(
            Error::Preserve(KeyFileError::PreservationReviewRequired)
                .to_string()
                .contains("保全先の永続化は確認済み")
        );
        assert_eq!(Error::PreservationOutput.exit_code(), 1);
        assert!(Error::PreservationOutput.to_string().contains("再実行せず"));
    }
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
        assert!(matches!(
            report(&Action::PreserveResidue, &[0; 32], &mut FailFlush),
            Err(Error::PreservationOutput)
        ));
    }
}
