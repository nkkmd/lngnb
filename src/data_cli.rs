//! R01/R24/R28/R30: 保存領域の明示初期化とローカル診断。公開/復旧/IPCではない。
use super::AppError;
use lngnb::storage::{EvaluationLimits, Limits, RecordStore, StartupState, StorageError};
use std::{ffi::OsString, fmt, io::Write, path::PathBuf};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Action {
    Init,
    Status,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    action: Action,
    path: PathBuf,
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || AppError::Usage("data init/status --data-dir PATH を指定してください");
    let [action, option, path] = args else {
        return Err(usage());
    };
    let action = match action.to_str() {
        Some("init") => Action::Init,
        Some("status") => Action::Status,
        _ => return Err(usage()),
    };
    if option != "--data-dir" || path.is_empty() {
        return Err(usage());
    }
    Ok(Command {
        action,
        path: PathBuf::from(path),
    })
}
#[derive(Debug)]
pub enum Error {
    Exists,
    Init(StorageError),
    Status(StorageError),
    Output(Action),
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        if matches!(self, Self::Init(_)) { 3 } else { 1 }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists=>f.write_str("保存先が既に存在するため初期化を拒否しました。既存領域は上書きしていません。"),
            Self::Init(e)=>write!(f,"{e}。保存領域の初期化完了を確認できません。作成済み・途中の領域が存在する可能性があります。保全し、削除・再初期化せず確認してください。"),
            Self::Status(e)=>write!(f,"{e}。状態診断を完了できません。未検査の件数・健全性は不明です。停止印・データを保全し、自動修復・再開は行いません。"),
            Self::Output(Action::Init)=>f.write_str("保存領域の初期化は完了しましたが、結果出力に失敗しました。再初期化せず data status で確認してください。"),
            Self::Output(Action::Status)=>f.write_str("保存領域の診断は終了しましたが、結果出力に失敗しました。診断中に記録した停止印があれば維持します。"),
        }
    }
}
impl std::error::Error for Error {}

pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    let text = match command.action {
        Action::Init => {
            let store = RecordStore::initialize(&command.path, Limits::default()).map_err(|e| {
                if matches!(&e,StorageError::Io(io) if io.kind()==std::io::ErrorKind::AlreadyExists)
                {
                    Error::Exists
                } else {
                    Error::Init(e)
                }
            })?;
            drop(store);
            "保存領域を初期化しました（正常停止）。待受・投稿設定の保存、リレー起動・公開は未実装です。\n".to_owned()
        }
        Action::Status => status(&command.path).map_err(Error::Status)?,
    };
    report(command.action, &text, output)
}
fn status(path: &std::path::Path) -> Result<String, StorageError> {
    // 同じ排他を最後の照合まで保持。起動検査cursorの進行・writer取得・正常停止は行わない。
    let store = RecordStore::open(path, Limits::default())?;
    let diagnostic = store.diagnose(EvaluationLimits::default())?;
    let state = diagnostic.startup_state;
    let capacity = diagnostic.capacity;
    let valid = diagnostic.valid;
    let pending = diagnostic.pending;
    let invalid = diagnostic.invalid;
    let verified = diagnostic.payload_verified;
    let missing = diagnostic.payload_missing;
    let unavailable = diagnostic.payload_unavailable;
    let state = match state {
        StartupState::Clean => "clean",
        StartupState::NeedsReview => "manual_review_required",
        StartupState::InspectionPending => "inspection_pending",
    };
    Ok(format!(
        "保存領域の管理用診断（公開可否・復旧完了の判定ではありません）。\nstartup_state: {state}\ndiagnostic_generation: {}\nrecords: {}\ndiagnostic_valid: {valid}\ndiagnostic_pending: {pending}\ndiagnostic_invalid: {invalid}\npayload_verified: {verified}\npayload_missing: {missing}\npayload_unavailable: {unavailable}\nincomplete_staging: {}\norphaned_blobs: {}\nmissing_retained_blobs: {}\ncorrupt_retained_blobs: {}\navailable_bytes: {}\nreserved_floor_bytes: {}\ncapacity_warning: {}\nこの診断結果は保存済み評価へ反映していません。手動確認待ちは解除しません。pin・公開・同期の状態表示は未実装です。\n",
        diagnostic.generation,
        diagnostic.records,
        diagnostic.incomplete_staging,
        diagnostic.orphaned_blobs,
        diagnostic.missing_retained_blobs,
        diagnostic.corrupt_retained_blobs,
        capacity.available,
        capacity.reserved_floor,
        capacity.warning
    ))
}
fn report(action: Action, text: &str, output: &mut impl Write) -> Result<(), Error> {
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output(action))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_path_only_and_no_unknown_or_duplicate_options() {
        for action in ["init", "status"] {
            let a: Vec<OsString> = vec![action.into(), "--data-dir".into(), "space 日本語".into()];
            assert_eq!(parse(&a).unwrap().path, PathBuf::from("space 日本語"));
            for bad in [
                vec![],
                vec![action.into()],
                vec![action.into(), "--data-dir".into(), "".into()],
                vec![
                    action.into(),
                    "--data-dir".into(),
                    "data".into(),
                    "extra".into(),
                ],
            ] {
                assert!(parse(&bad).is_err());
            }
        }
        let e = parse(&["private input".into(), "--data-dir".into(), "value".into()]).unwrap_err();
        assert!(!e.to_string().contains("private input"));
    }
    #[test]
    fn initialization_uncertainty_and_diagnostic_failure_are_not_output_failures() {
        let e = Error::Init(StorageError::Io(std::io::Error::other("private detail")));
        assert_eq!(e.exit_code(), 3);
        assert!(!e.to_string().contains("private detail"));
        assert!(std::error::Error::source(&e).is_none());
        assert_eq!(Error::Exists.exit_code(), 1);
        assert_eq!(Error::Status(StorageError::Corrupt).exit_code(), 1);
        assert!(
            Error::Output(Action::Init)
                .to_string()
                .contains("初期化は完了")
        );
    }
    #[test]
    fn write_and_flush_failures_return_no_success() {
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(b.len())
                } else {
                    Err(std::io::Error::other("test"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("test"))
            }
        }
        for action in [Action::Init, Action::Status] {
            for flush in [false, true] {
                assert!(
                    matches!(report(action,"ok",&mut Sink(flush)),Err(Error::Output(a)) if a==action)
                );
            }
        }
    }
}
