//! R26/R27/R30: 根拠復旧の確認記録。明示再開・手動待ち解除へ接続しない。
use super::AppError;
use lngnb::storage::{StorageError, management::RecoveryReviewRequest};
use std::{ffi::OsString, fmt, io::Write, path::PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    path: PathBuf,
    request: RecoveryReviewRequest,
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage(
            "data recovery-confirm に保存領域・期待世代・復旧内容・未確認事項を明示してください",
        )
    };
    let (mut path, mut generation, mut restored, mut unconfirmed) = (None, None, None, None);
    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args.next().ok_or_else(usage)?;
        if value.is_empty() {
            return Err(usage());
        }
        match option.to_str() {
            Some("--data-dir") if path.is_none() => path = Some(PathBuf::from(value)),
            Some("--expect-generation") if generation.is_none() => {
                let text = value.to_str().ok_or_else(usage)?;
                if text.len() > 19 {
                    return Err(usage());
                }
                let g = text.parse::<i64>().map_err(|_| usage())?;
                if g < 0 || g.to_string() != text {
                    return Err(usage());
                }
                generation = Some(g);
            }
            Some("--restored") if restored.is_none() => {
                restored = Some(value.to_str().ok_or_else(usage)?)
            }
            Some("--unconfirmed") if unconfirmed.is_none() => {
                unconfirmed = Some(value.to_str().ok_or_else(usage)?)
            }
            _ => return Err(usage()),
        }
    }
    Ok(Command {
        path: path.ok_or_else(usage)?,
        request: RecoveryReviewRequest::check(
            generation.ok_or_else(usage)?,
            restored.ok_or_else(usage)?,
            unconfirmed.ok_or_else(usage)?,
        )
        .map_err(|_| usage())?,
    })
}
#[derive(Debug)]
pub enum Error {
    Confirm(StorageError),
    Output,
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        1
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirm(error)=>write!(f,"{error}。根拠復旧確認の記録完了を確認できません。開始履歴や確認が保存済みの可能性があります。領域・停止印を保全し、自動再試行・再開は行いません。"),
            Self::Output=>f.write_str("根拠復旧確認は記録しましたが、結果出力に失敗しました。手動確認待ちは維持し、明示再開・正常停止・公開は行っていません。再実行前に現在世代を確認してください。"),
        }
    }
}
impl std::error::Error for Error {}
pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    let receipt = command
        .request
        .confirm_stopped(&command.path)
        .map_err(Error::Confirm)?;
    // 既存APIはcommit後に排他を解放する。この受領値を出力時の現在世代とは呼ばない。
    let text = format!(
        "根拠復旧の管理確認を記録しました（手動確認待ちを維持）。\nsource_generation: {}\nrecorded_generation: {}\nchecked_evidence: {}\nmanual_review_required: true\n確認件数は既知不正の根拠起点だけです。親評価完了・起動完了・復旧完了・明示再開・正常停止・公開資格を保証しません。未確認事項を解消済みとは扱いません。\n",
        receipt.source_generation, receipt.recorded_generation, receipt.checked_evidence
    );
    report(&text, output)
}
fn report(text: &str, output: &mut impl Write) -> Result<(), Error> {
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmation_requires_all_explicit_fields_and_rejects_unsafe_generation_or_notes() {
        let args: Vec<OsString> = [
            "--data-dir",
            "data",
            "--expect-generation",
            "0",
            "--restored",
            "復旧内容",
            "--unconfirmed",
            "未確認事項",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert!(parse(&args).is_ok());
        for i in (0..args.len()).step_by(2) {
            let mut missing = args.clone();
            drop(missing.drain(i..i + 2));
            assert!(parse(&missing).is_err());
            let mut duplicate = args.clone();
            duplicate.extend_from_slice(&args[i..i + 2]);
            assert!(parse(&duplicate).is_err());
        }
        for g in [
            "-1",
            "+1",
            "01",
            " 1",
            "1 ",
            "9223372036854775808",
            "PRIVATE INPUT",
        ] {
            let mut wrong = args.clone();
            wrong[3] = g.into();
            let e = parse(&wrong).unwrap_err();
            assert!(!e.to_string().contains("PRIVATE INPUT"));
        }
        for note in [
            "".to_owned(),
            " \n".into(),
            "x".repeat(4097),
            "bad\0note".into(),
        ] {
            for index in [5, 7] {
                let mut wrong = args.clone();
                wrong[index] = note.clone().into();
                assert!(parse(&wrong).is_err());
            }
        }
        let mut extra = args;
        extra.extend(["--resume".into(), "PRIVATE INPUT".into()]);
        assert!(parse(&extra).is_err());
    }
    #[test]
    fn confirmation_uncertainty_is_distinct_from_committed_output_failure() {
        let error = Error::Confirm(StorageError::Io(std::io::Error::other("PRIVATE INPUT")));
        assert_eq!(error.exit_code(), 1);
        assert!(!error.to_string().contains("PRIVATE INPUT"));
        assert!(std::error::Error::source(&error).is_none());
        assert!(Error::Output.to_string().contains("確認は記録"));
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
        for flush in [false, true] {
            assert!(matches!(report("ok", &mut Sink(flush)), Err(Error::Output)));
        }
    }
}
