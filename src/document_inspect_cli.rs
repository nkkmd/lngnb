//! R04/R07/R24/R30/R34: 完全固定指定によるローカル保存版の参照宣言確認。
use super::AppError;
use lngnb::{
    id::{Id, Kind},
    storage::{
        Limits, RecordStore, StartupState, StorageError,
        management::{RevisionRequest, SavedRevision},
    },
};
use std::{ffi::OsString, fmt, io::Write, path::PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    path: PathBuf,
    request: RevisionRequest,
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage(
            "document inspect に保存領域とKnowledge/Genesis/Revisionの三IDを指定してください",
        )
    };
    let mut path = None;
    let mut knowledge = None;
    let mut genesis = None;
    let mut revision = None;
    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args.next().ok_or_else(usage)?;
        if value.is_empty() {
            return Err(usage());
        }
        let id = |kind| Id::parse(kind, value.to_str().ok_or_else(usage)?).map_err(|_| usage());
        match option.to_str() {
            Some("--data-dir") if path.is_none() => path = Some(PathBuf::from(value)),
            Some("--knowledge-id") if knowledge.is_none() => knowledge = Some(id(Kind::Knowledge)?),
            Some("--genesis-id") if genesis.is_none() => genesis = Some(id(Kind::Record)?),
            Some("--revision-id") if revision.is_none() => revision = Some(id(Kind::Record)?),
            _ => return Err(usage()),
        }
    }
    let request = RevisionRequest::check(
        knowledge.ok_or_else(usage)?,
        genesis.ok_or_else(usage)?,
        revision.ok_or_else(usage)?,
    )
    .map_err(|_| usage())?;
    Ok(Command {
        path: path.ok_or_else(usage)?,
        request,
    })
}

#[derive(Debug)]
pub enum Error {
    Storage(StorageError),
    Missing,
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
            Self::Storage(error) => write!(f, "{error}。保存版の読取り確認を完了できません。領域と停止印を保全してください。自動修復・再開は行いません。"),
            Self::Missing => f.write_str("指定した三IDに一致する保存版を確認できません。別版への切替・参照先の取得・手動確認待ちの解除は行っていません。"),
            Self::Output => f.write_str("保存版の読取り確認は終了しましたが、結果出力に失敗しました。手動確認待ちは解除していません。"),
        }
    }
}
impl std::error::Error for Error {}

pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    // 同じ排他を出力まで保持。openの既存照合・予算を省略せず、起動cursorを進めない。
    let store = RecordStore::open(&command.path, Limits::default()).map_err(Error::Storage)?;
    let saved = command
        .request
        .inspect(&store)
        .map_err(Error::Storage)?
        .ok_or(Error::Missing)?;
    let state = store.startup_state().map_err(Error::Storage)?;
    let text = describe(&saved, state);
    report(&text, output)
}
fn describe(saved: &SavedRevision, state: StartupState) -> String {
    use std::fmt::Write as _;
    let refs = &saved.references;
    let state = match state {
        StartupState::Clean => "clean",
        StartupState::NeedsReview => "manual_review_required",
        StartupState::InspectionPending => "inspection_pending",
    };
    let mut text = format!(
        "ローカル保存版の署名内参照（依存評価・公開可否の判定ではありません）。\nstartup_state: {state}\nknowledge_id: {}\ngenesis_id: {}\nrevision_id: {}\npublisher_key_id: {}\nparents: {}\n",
        refs.knowledge_id,
        refs.genesis_record_id,
        saved.record.id(),
        refs.publisher_key_id,
        refs.parents.len()
    );
    for (n, parent) in refs.parents.iter().enumerate() {
        writeln!(text, "parent[{n}]: {parent}").expect("String write");
    }
    if let Some(origins) = &refs.origins {
        writeln!(text, "origins: {}", origins.len()).expect("String write");
        for (n, origin) in origins.iter().enumerate() {
            writeln!(text, "origin[{n}].knowledge_id: {}", origin.knowledge_id)
                .expect("String write");
            for (name, value) in [
                ("genesis_id", origin.genesis_record_id),
                ("revision_id", origin.revision_record_id),
            ] {
                let value = value
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unspecified".to_owned());
                writeln!(text, "origin[{n}].{name}: {value}").expect("String write");
            }
        }
    } else {
        text.push_str("origins: unspecified\n");
    }
    text.push_str("表示は署名された宣言です。Genesis・親・由来の外部照合、全祖先評価、本文保持、pin・公開・復旧完了は判定していません。手動確認待ちは解除しません。\n");
    text
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
    fn args() -> Vec<OsString> {
        vec![
            "--data-dir".into(),
            "data".into(),
            "--knowledge-id".into(),
            Id {
                kind: Kind::Knowledge,
                bytes: [0; 32],
            }
            .to_string()
            .into(),
            "--genesis-id".into(),
            Id {
                kind: Kind::Record,
                bytes: [1; 32],
            }
            .to_string()
            .into(),
            "--revision-id".into(),
            Id {
                kind: Kind::Record,
                bytes: [2; 32],
            }
            .to_string()
            .into(),
        ]
    }
    #[test]
    fn fixed_selection_requires_each_canonical_id_and_only_read_arguments() {
        let a = args();
        assert!(parse(&a).is_ok());
        let reversed: Vec<_> = a.chunks_exact(2).rev().flatten().cloned().collect();
        assert_eq!(parse(&a).unwrap(), parse(&reversed).unwrap());
        for i in (0..a.len()).step_by(2) {
            let mut missing = a.clone();
            drop(missing.drain(i..i + 2));
            assert!(parse(&missing).is_err());
            let mut duplicate = a.clone();
            duplicate.extend_from_slice(&a[i..i + 2]);
            assert!(parse(&duplicate).is_err());
            let mut empty = a.clone();
            empty[i + 1] = "".into();
            assert!(parse(&empty).is_err());
        }
        for (i, value) in [
            (3, a[5].clone()),
            (5, a[3].clone()),
            (7, a[3].clone()),
            (7, "PRIVATE INPUT".into()),
            (7, a[7].to_str().unwrap().to_uppercase().into()),
        ] {
            let mut wrong = a.clone();
            wrong[i] = value;
            let error = parse(&wrong).unwrap_err();
            assert!(!error.to_string().contains("PRIVATE INPUT"));
        }
        for option in [
            "--key-dir",
            "--payload",
            "--metadata",
            "--parent",
            "--origin-genesis",
            "--no-parents",
            "--max-payload-bytes",
        ] {
            let mut extra = a.clone();
            extra.extend([option.into(), "PRIVATE INPUT".into()]);
            assert!(parse(&extra).is_err());
        }
        let mut trailing = a;
        trailing.push("PRIVATE INPUT".into());
        assert!(parse(&trailing).is_err());
    }
    #[test]
    fn read_failures_and_output_failures_are_distinct_and_never_echo_sources() {
        let error = Error::Storage(StorageError::Io(std::io::Error::other("PRIVATE INPUT")));
        assert_eq!(error.exit_code(), 1);
        assert!(!error.to_string().contains("PRIVATE INPUT"));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(Error::Missing.exit_code(), 1);
        assert_eq!(Error::Output.exit_code(), 1);
        assert!(Error::Output.to_string().contains("読取り確認は終了"));
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("test"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("test"))
            }
        }
        for flush in [false, true] {
            assert!(matches!(
                report("result", &mut Sink(flush)),
                Err(Error::Output)
            ));
        }
    }
}
