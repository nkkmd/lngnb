//! R04/R07/R24/R30/R34: 明示scopeの保存履歴と非永続管理用診断。
use super::AppError;
use lngnb::{
    id::{Id, Kind},
    storage::{
        EvaluationLimits, Limits, PayloadStatus, RecordStore, StartupState, StorageError,
        Validation,
        management::{
            DiagnosedRevisionHistory, RevisionInventoryBudget, RevisionInventoryRequest,
            SavedParentTarget,
        },
    },
};
use std::{
    ffi::OsString,
    fmt,
    fmt::Write as _,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    path: PathBuf,
    request: RevisionInventoryRequest,
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage("document history に保存領域とKnowledge/Genesisの二IDを指定してください")
    };
    let (mut path, mut knowledge, mut genesis) = (None, None, None);
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
            _ => return Err(usage()),
        }
    }
    Ok(Command {
        path: path.ok_or_else(usage)?,
        request: RevisionInventoryRequest::check(
            knowledge.ok_or_else(usage)?,
            genesis.ok_or_else(usage)?,
        )
        .map_err(|_| usage())?,
    })
}

#[derive(Debug)]
pub enum Error {
    Storage(StorageError),
    Budget,
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
            Self::Storage(error) => write!(f, "{error}。保存履歴の読取り診断を完了できません。領域と停止印を保全してください。自動修復・再開は行いません。"),
            Self::Budget => f.write_str("保存履歴の出力準備予算が不足しました。部分結果は出力せず、手動確認待ちは解除していません。"),
            Self::Output => f.write_str("保存履歴の読取り診断は終了しましたが、結果出力に失敗しました。手動確認待ちは解除していません。"),
        }
    }
}
impl std::error::Error for Error {}

pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    // 既存open検査を省略せず、出力まで同じ排他を保持。writer/finish/IPCへ切り替えない。
    let store = RecordStore::open(&command.path, Limits::default()).map_err(Error::Storage)?;
    let history = command
        .request
        .inspect_diagnosed(
            &store,
            RevisionInventoryBudget::default(),
            EvaluationLimits::default(),
        )
        .map_err(Error::Storage)?;
    let state = store.startup_state().map_err(Error::Storage)?;
    let text = describe(&history, state, 32 * 1024 * 1024, Duration::from_secs(60))?;
    report(&text, output)
}

struct Text {
    text: String,
    bytes: usize,
    start: Instant,
    elapsed: Duration,
}
impl fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.start.elapsed() >= self.elapsed || s.len() > self.bytes {
            return Err(fmt::Error);
        }
        self.bytes -= s.len();
        self.text.push_str(s);
        Ok(())
    }
}
fn describe(
    h: &DiagnosedRevisionHistory,
    state: StartupState,
    bytes: usize,
    elapsed: Duration,
) -> Result<String, Error> {
    let inventory = &h.history.inventory;
    let assessment = &h.assessment;
    if inventory.generation != assessment.generation
        || assessment.committed
        || inventory.revisions.len() != h.history.relations.len()
        || inventory.revisions.len() != assessment.revisions.len()
        || inventory
            .revisions
            .iter()
            .zip(&h.history.relations)
            .zip(&assessment.revisions)
            .any(|((s, r), a)| s.record.id() != r.revision_id || s.record.id() != a.record_id)
    {
        return Err(Error::Storage(StorageError::Corrupt));
    }
    let mut text = Text {
        text: String::new(),
        bytes,
        start: Instant::now(),
        elapsed,
    };
    let state = match state {
        StartupState::Clean => "clean",
        StartupState::NeedsReview => "manual_review_required",
        StartupState::InspectionPending => "inspection_pending",
    };
    let formatted = (|| -> fmt::Result {
        writeln!(
            text,
            "ローカル保存範囲の親子宣言と管理用診断（世界の完全履歴・現在候補・公開資格ではありません）。"
        )?;
        writeln!(
            text,
            "startup_state: {state}\nknowledge_id: {}\ngenesis_id: {}\ngeneration: {}\nassessment_committed: {}\nassessment_storage_fault: {}\nrevisions: {}",
            inventory.knowledge_id,
            inventory.genesis_record_id,
            inventory.generation,
            assessment.committed,
            assessment.storage_fault,
            inventory.revisions.len()
        )?;
        for (n, ((saved, relations), a)) in inventory
            .revisions
            .iter()
            .zip(&h.history.relations)
            .zip(&assessment.revisions)
            .enumerate()
        {
            let p = format!("revision[{n}]");
            let validation = match a.validation {
                Validation::Valid => "valid",
                Validation::Pending => "pending",
                Validation::Invalid => "invalid",
            };
            let payload = match a.payload_status {
                Some(PayloadStatus::Verified) => "verified",
                Some(PayloadStatus::Missing) => "missing",
                Some(PayloadStatus::Unavailable) => "unavailable",
                None => "unspecified",
            };
            writeln!(
                text,
                "{p}.id: {}\n{p}.publisher_key_id: {}\n{p}.record_validation: {validation}\n{p}.validation_reason: {}\n{p}.related_id: {}\n{p}.payload_status: {payload}\n{p}.payload_reason: {}",
                saved.record.id(),
                saved.references.publisher_key_id,
                a.reason.map_or("none", |r| r.code()),
                a.related
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unspecified".into()),
                a.payload_reason.map_or("none", |r| r.code())
            )?;
            writeln!(
                text,
                "{p}.declared_root: {}\n{p}.declared_merge: {}\n{p}.declared_branch: {}\n{p}.declared_tip: {}\n{p}.parents: {}",
                relations.parents.is_empty(),
                relations.parents.len() > 1,
                relations.declared_children.len() > 1,
                relations.declared_children.is_empty(),
                relations.parents.len()
            )?;
            for (j, parent) in relations.parents.iter().enumerate() {
                let target = match parent.target {
                    SavedParentTarget::Missing => "missing",
                    SavedParentTarget::NotRevision => "not_revision",
                    SavedParentTarget::DifferentKnowledge => "different_knowledge",
                    SavedParentTarget::DifferentGenesis => "different_genesis",
                    SavedParentTarget::DifferentPublisher => "different_publisher",
                    SavedParentTarget::DirectMatch => "direct_match",
                };
                writeln!(
                    text,
                    "{p}.parent[{j}].id: {}\n{p}.parent[{j}].target: {target}",
                    parent.parent_id
                )?;
            }
            writeln!(
                text,
                "{p}.declared_children: {}",
                relations.declared_children.len()
            )?;
            for (j, child) in relations.declared_children.iter().enumerate() {
                writeln!(text, "{p}.declared_child[{j}]: {child}")?;
            }
            if let Some(origins) = &saved.references.origins {
                writeln!(text, "{p}.origins: {}", origins.len())?;
                for (j, origin) in origins.iter().enumerate() {
                    writeln!(
                        text,
                        "{p}.origin[{j}].knowledge_id: {}",
                        origin.knowledge_id
                    )?;
                    for (name, id) in [
                        ("genesis_id", origin.genesis_record_id),
                        ("revision_id", origin.revision_record_id),
                    ] {
                        writeln!(
                            text,
                            "{p}.origin[{j}].{name}: {}",
                            id.map(|id| id.to_string())
                                .unwrap_or_else(|| "unspecified".into())
                        )?;
                    }
                }
            } else {
                writeln!(text, "{p}.origins: unspecified")?;
            }
        }
        writeln!(
            text,
            "親子と先端は保存範囲内の宣言です。直接対応と依存評価は別です。validも本文保持・pin・公開資格・復旧完了を保証しません。由来は親履歴・承認・必須依存ではありません。評価は非永続で、手動確認待ちは解除しません。"
        )?;
        text.write_str("")
    })();
    formatted.map_err(|_| Error::Budget)?;
    Ok(text.text)
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
    fn scope_requires_explicit_canonical_ids_and_rejects_selection_or_secret_options() {
        let args: Vec<OsString> = vec![
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
        ];
        assert!(parse(&args).is_ok());
        for i in (0..args.len()).step_by(2) {
            let mut missing = args.clone();
            drop(missing.drain(i..i + 2));
            assert!(parse(&missing).is_err());
            let mut duplicate = args.clone();
            duplicate.extend_from_slice(&args[i..i + 2]);
            assert!(parse(&duplicate).is_err());
            let mut empty = args.clone();
            empty[i + 1] = "".into();
            assert!(parse(&empty).is_err());
        }
        for option in [
            "--revision-id",
            "--key-dir",
            "--parent",
            "--current",
            "--resume",
        ] {
            let mut extra = args.clone();
            extra.extend([option.into(), "PRIVATE INPUT".into()]);
            let error = parse(&extra).unwrap_err();
            assert!(!error.to_string().contains("PRIVATE INPUT"));
        }
        for (i, value) in [
            (3, args[5].clone()),
            (5, args[3].clone()),
            (5, args[5].to_str().unwrap().to_uppercase().into()),
        ] {
            let mut wrong = args.clone();
            wrong[i] = value;
            assert!(parse(&wrong).is_err());
        }
    }
    #[test]
    fn output_preparation_is_bounded_and_write_or_flush_failures_are_distinct() {
        use lngnb::storage::management::{
            RevisionInventory, SavedHistoryAssessment, SavedRevisionHistory,
        };
        let h = DiagnosedRevisionHistory {
            history: SavedRevisionHistory {
                inventory: RevisionInventory {
                    knowledge_id: Id {
                        kind: Kind::Knowledge,
                        bytes: [0; 32],
                    },
                    genesis_record_id: Id {
                        kind: Kind::Record,
                        bytes: [1; 32],
                    },
                    generation: 1,
                    revisions: vec![],
                },
                relations: vec![],
            },
            assessment: SavedHistoryAssessment {
                generation: 1,
                committed: false,
                storage_fault: false,
                revisions: vec![],
            },
        };
        assert!(matches!(
            describe(&h, StartupState::NeedsReview, 0, Duration::from_secs(60)),
            Err(Error::Budget)
        ));
        assert!(matches!(
            describe(&h, StartupState::NeedsReview, usize::MAX, Duration::ZERO),
            Err(Error::Budget)
        ));
        let text = describe(&h, StartupState::NeedsReview, 4096, Duration::from_secs(60)).unwrap();
        assert!(text.contains("revisions: 0") && text.contains("manual_review_required"));
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(b.len())
                } else {
                    Err(std::io::Error::other("PRIVATE INPUT"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("PRIVATE INPUT"))
            }
        }
        for flush in [false, true] {
            let error = report(&text, &mut Sink(flush)).unwrap_err();
            assert!(matches!(error, Error::Output));
            assert!(!error.to_string().contains("PRIVATE INPUT"));
        }
    }
}
