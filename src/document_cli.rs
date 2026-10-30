//! R01/R05/R24/R30/R34: 明示鍵で新規資料を署名し、既存の正常な領域へ保存するCLI。
use super::AppError;
use lngnb::{
    authoring::{self, CreationBudget, CreationError},
    authoring_input::{self, InputError},
    id::{self, Id, Kind},
    keyfile::{KeyDirectory, KeyFileError},
    record::{LocalRecord, RecordKind},
    secret_terminal::{SecretInputError, SecretTerminal, TerminalSignals},
    storage::{
        EvaluationLimits, Limits, LocalStartup, LocalStartupBudget, StorageError, management,
    },
};
use std::{
    ffi::OsString,
    fmt,
    io::{Cursor, Write},
    path::PathBuf,
};

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Create,
    Revise {
        genesis: PathBuf,
        parents: Vec<PathBuf>,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    action: Action,
    data: PathBuf,
    keys: PathBuf,
    name: String,
    expected: Id,
    payload: PathBuf,
    metadata: PathBuf,
    media: Option<String>,
    max_payload: usize,
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || AppError::Usage("document create/revise の操作と引数を確認してください");
    let [action, rest @ ..] = args else {
        return Err(usage());
    };
    if action != "create" && action != "revise" {
        return Err(usage());
    }
    let mut data = None;
    let mut keys = None;
    let mut name = None;
    let mut expected = None;
    let mut payload = None;
    let mut metadata = None;
    let mut media = None;
    let mut max_payload = None;
    let mut genesis = None;
    let mut parents = Vec::new();
    let mut no_parents = false;
    let mut rest = rest.iter();
    while let Some(option) = rest.next() {
        if option == "--no-parents" {
            if action != "revise" || no_parents {
                return Err(usage());
            }
            no_parents = true;
            continue;
        }
        let value = rest.next().ok_or_else(usage)?;
        if value.is_empty() {
            return Err(usage());
        }
        match option.to_str() {
            Some("--genesis") if action == "revise" && genesis.is_none() => {
                genesis = Some(PathBuf::from(value))
            }
            Some("--parent") if action == "revise" && parents.len() < 256 => {
                parents.push(PathBuf::from(value))
            }
            Some("--data-dir") if data.is_none() => data = Some(PathBuf::from(value)),
            Some("--key-dir") if keys.is_none() => keys = Some(PathBuf::from(value)),
            Some("--payload") if payload.is_none() => payload = Some(PathBuf::from(value)),
            Some("--metadata") if metadata.is_none() => metadata = Some(PathBuf::from(value)),
            Some("--name") if name.is_none() => {
                let s = value.to_str().ok_or_else(usage)?;
                if s.len() > 128
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
            }
            Some("--expect-key-id") if expected.is_none() => {
                expected = Some(
                    Id::parse(Kind::Key, value.to_str().ok_or_else(usage)?).map_err(|_| usage())?,
                )
            }
            Some("--media-type") if media.is_none() => {
                let s = value.to_str().ok_or_else(usage)?;
                if s.len() > 255 {
                    return Err(usage());
                }
                media = Some(s.to_owned());
            }
            Some("--max-payload-bytes") if max_payload.is_none() => {
                let s = value.to_str().ok_or_else(usage)?;
                if !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
                    return Err(usage());
                }
                let n = s.parse::<usize>().map_err(|_| usage())?;
                if n >= Limits::default().session_bytes as usize {
                    return Err(usage());
                }
                max_payload = Some(n);
            }
            _ => return Err(usage()),
        }
    }
    let action = if action == "revise" {
        if no_parents != parents.is_empty() {
            return Err(usage());
        }
        Action::Revise {
            genesis: genesis.ok_or_else(usage)?,
            parents,
        }
    } else {
        Action::Create
    };
    Ok(Command {
        action,
        data: data.ok_or_else(usage)?,
        keys: keys.ok_or_else(usage)?,
        name: name.ok_or_else(usage)?,
        expected: expected.ok_or_else(usage)?,
        payload: payload.ok_or_else(usage)?,
        metadata: metadata.ok_or_else(usage)?,
        media,
        max_payload: max_payload.unwrap_or(CreationBudget::default().max_payload_bytes),
    })
}

// 下位I/O/SQLのsourceや入力値を診断へ展開しない。
#[derive(Debug)]
pub enum Error {
    Input(SecretInputError),
    File(InputError),
    Key(KeyFileError),
    Creation(CreationError),
    Storage(StorageError),
    Output,
    SelectionMissing,
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Input(SecretInputError::Cancelled) | Self::File(InputError::Cancelled) => 130,
            Self::Storage(_) | Self::SelectionMissing => 3,
            _ => 1,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
        Self::Input(e)=> {write!(f,"{e}。資料の保存は開始していません。")?;
            if *e==SecretInputError::RestoreFailed {f.write_str("端末復元を確認できません。別の正常な端末を使ってください。stty sane は元設定の完全復元ではありません。")?;} Ok(())},
        Self::File(e)=>write!(f,"{e}。資料の保存は開始していません。"),
        Self::Key(e)=>write!(f,"{e}。資料の保存は開始していません。"),
        Self::Creation(e)=>write!(f,"{e}。資料の保存は開始していません。"),
        Self::Storage(e)=>write!(f,"{e}。保存処理を完了できませんでした。一部または全部が保存済みの可能性があります。領域を保全し、再作成せず確認してください。手動確認待ちは解除していません。"),
        Self::SelectionMissing=>f.write_str("明示したGenesisまたは親が保存先にありません。新しい本文・Recordの保存は開始していません。領域を保全して確認してください。手動確認待ちは解除していません。"),
        Self::Output=>f.write_str("資料のローカル保存と正常終了は完了しましたが、結果出力に失敗しました。再作成せず保存領域を確認してください。"),
    }
    }
}
impl std::error::Error for Error {}
impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    let signals = TerminalSignals::install().map_err(Error::Input)?;
    let budget = CreationBudget {
        max_payload_bytes: command.max_payload,
    };
    let input =
        authoring_input::read_initial_files(&command.payload, &command.metadata, budget, || {
            signals.check_cancelled().is_err()
        })
        .map_err(Error::File)?;
    let selected = match &command.action {
        Action::Create => None,
        Action::Revise { genesis, parents } => {
            Some(read_revision_selection(genesis, parents, &signals)?)
        }
    };
    let mut directory = KeyDirectory::open(&command.keys).map_err(Error::Key)?;
    if directory
        .recovery_inventory()
        .map_err(Error::Key)?
        .has_residues()
    {
        return Err(Error::Key(KeyFileError::PendingRecovery));
    }
    let mut terminal = SecretTerminal::open_interruptible(signals).map_err(Error::Input)?;
    let pass = terminal.current_passphrase().map_err(Error::Input)?;
    signals.check_cancelled().map_err(Error::Input)?;
    let key = directory
        .load(&command.name, pass.as_str())
        .map_err(Error::Key)?;
    drop(pass);
    if id::key_id(&key.public_key()) != command.expected {
        return Err(Error::Key(KeyFileError::UnexpectedPublicKey));
    }
    signals.check_cancelled().map_err(Error::Input)?;
    let (payload, metadata) = input.into_parts();
    let (genesis, revision, is_initial) = if let Some((genesis, parents)) = selected {
        let refs: Vec<_> = parents.iter().collect();
        let revision = authoring::create_revision(
            &key,
            &genesis,
            &refs,
            &payload,
            metadata,
            command.media.as_deref(),
            budget,
        )
        .map_err(Error::Creation)?;
        (genesis, revision, false)
    } else {
        let pair =
            authoring::create_initial(&key, &payload, metadata, command.media.as_deref(), budget)
                .map_err(Error::Creation)?;
        let (genesis, revision) = pair.into_parts();
        (genesis, revision, true)
    };
    drop(key);
    drop(terminal);
    drop(directory);
    signals.check_cancelled().map_err(Error::Input)?;
    let text = summary(&genesis, &revision, is_initial)?;
    // 保存側へ渡すのは完成Recordと同じ所有本文だけ。秘密鍵/端末はここより前に破棄する。
    save(
        &command.data,
        &genesis,
        &revision,
        &payload,
        command.max_payload,
        is_initial,
    )?;
    report(&text, output)
}

// 元Record集合は合計16 MiBまで。次fileも残予算で確保前に制限する。
fn read_revision_selection(
    genesis: &std::path::Path,
    parents: &[PathBuf],
    signals: &TerminalSignals,
) -> Result<(LocalRecord, Vec<LocalRecord>), Error> {
    let mut remaining = 16 * 1024 * 1024;
    let mut read = |path: &std::path::Path| {
        let bytes = authoring_input::read_record_file_limited(path, remaining, || {
            signals.check_cancelled().is_err()
        })
        .map_err(Error::File)?;
        remaining -= bytes.len();
        LocalRecord::check(&bytes, None).map_err(|_| Error::Creation(CreationError::InvalidInput))
    };
    let genesis = read(genesis)?;
    if genesis.kind() != RecordKind::Genesis {
        return Err(Error::Creation(CreationError::InvalidInput));
    }
    let mut records = Vec::with_capacity(parents.len());
    for path in parents {
        let parent = read(path)?;
        parent
            .check_genesis(&genesis)
            .map_err(|_| Error::Creation(CreationError::InvalidInput))?;
        if records.iter().any(|r: &LocalRecord| r.id() == parent.id()) {
            return Err(Error::Creation(CreationError::InvalidInput));
        }
        records.push(parent);
    }
    Ok((genesis, records))
}

fn save(
    path: &std::path::Path,
    genesis: &LocalRecord,
    revision: &LocalRecord,
    payload: &[u8],
    max_payload: usize,
    is_initial: bool,
) -> Result<(), Error> {
    let limits = Limits {
        max_blob_bytes: max_payload as u64,
        ..Limits::default()
    };
    let total = (payload.len() as u64)
        .checked_add(genesis.bytes().len() as u64)
        .and_then(|n| n.checked_add(revision.bytes().len() as u64))
        .and_then(|n| n.checked_add(1))
        .ok_or(StorageError::BudgetExceeded)?;
    if total > limits.session_bytes {
        return Err(Error::Storage(StorageError::BudgetExceeded));
    }
    let mut startup = LocalStartup::open(path, limits)?;
    if startup.needs_review() {
        return Err(Error::Storage(StorageError::NeedsReview));
    }
    loop {
        if startup
            .step(EvaluationLimits::default(), LocalStartupBudget::default())?
            .checks_complete()
        {
            break;
        }
    }
    let mut writer = startup.into_writer()?;
    if !is_initial {
        for id in std::iter::once(genesis.id()).chain(
            revision
                .parents()
                .map_err(|_| StorageError::Corrupt)?
                .into_iter()
                .map(|bytes| Id {
                    kind: Kind::Record,
                    bytes,
                }),
        ) {
            if writer.record(id)?.is_none() {
                return Err(Error::SelectionMissing);
            }
        }
    }
    // 各段階は独立確定。後段失敗で先に保存した本文/Recordを消さない。
    let blob = writer.put_blob(id::blob_id(payload), Cursor::new(payload))?;
    if blob.byte_length != payload.len() as u64 {
        return Err(Error::Storage(StorageError::Corrupt));
    }
    if is_initial {
        management::store_record(&mut writer, genesis)?;
    }
    management::store_record(&mut writer, revision)?;
    writer.finish().map_err(Error::Storage)
}
fn summary(
    genesis: &LocalRecord,
    revision: &LocalRecord,
    is_initial: bool,
) -> Result<String, Error> {
    let knowledge = match genesis.body() {
        lngnb::cbor::Value::Map(m) => {
            m.iter()
                .find(|(k, _)| k == "knowledge_id")
                .and_then(|(_, v)| {
                    if let lngnb::cbor::Value::Bytes(b) = v {
                        b.as_slice().try_into().ok()
                    } else {
                        None
                    }
                })
        }
        _ => None,
    }
    .ok_or(Error::Creation(CreationError::InvalidInput))?;
    Ok(format!(
        "{}の本文と署名Recordをローカル保存しました（pin・公開は未実装）。\nknowledge_id: {}\ngenesis_id: {}\nrevision_id: {}\n",
        if is_initial {
            "新規資料"
        } else {
            "改訂版"
        },
        Id {
            kind: Kind::Knowledge,
            bytes: knowledge
        },
        genesis.id(),
        revision.id()
    ))
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
            "create",
            "--data-dir",
            "data",
            "--key-dir",
            "keys",
            "--name",
            "publisher",
            "--expect-key-id",
            "ky1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--payload",
            "body",
            "--metadata",
            "meta",
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }
    #[test]
    fn revision_requires_explicit_genesis_and_parent_choice_with_bounded_count() {
        let mut a = args();
        a[0] = "revise".into();
        assert!(parse(&a).is_err());
        a.extend(["--genesis".into(), "genesis.cbor".into()]);
        assert!(parse(&a).is_err());
        let mut empty = a.clone();
        empty.push("--no-parents".into());
        assert!(
            matches!(parse(&empty).unwrap().action, Action::Revise { parents, .. } if parents.is_empty())
        );
        empty.push("--no-parents".into());
        assert!(parse(&empty).is_err());
        a.extend(["--parent".into(), "parent.cbor".into()]);
        assert!(parse(&a).is_ok());
        let mut conflict = a.clone();
        conflict.push("--no-parents".into());
        assert!(parse(&conflict).is_err());
        for _ in 1..256 {
            a.extend(["--parent".into(), "parent.cbor".into()]);
        }
        assert!(parse(&a).is_ok());
        a.extend(["--parent".into(), "parent.cbor".into()]);
        assert!(parse(&a).is_err());
        let mut create = args();
        create.extend(["--genesis".into(), "private path".into()]);
        assert!(parse(&create).is_err());
    }
    #[test]
    fn explicit_selection_and_optional_budget_are_parsed_without_correction() {
        let mut a = args();
        let c = parse(&a).unwrap();
        assert_eq!(c.max_payload, 16 * 1024 * 1024);
        a.extend([
            "--max-payload-bytes".into(),
            "0".into(),
            "--media-type".into(),
            "text/plain".into(),
        ]);
        assert_eq!(parse(&a).unwrap().max_payload, 0);
    }
    #[test]
    fn malformed_duplicate_and_missing_arguments_never_echo_values() {
        for at in [0, 2, 4, 6, 8, 10, 12] {
            let mut a = args();
            a.remove(at);
            assert!(parse(&a).is_err());
        }
        for pair in [
            ["--name", "other"],
            ["--unknown", "private marker"],
            ["--max-payload-bytes", "01"],
            ["--max-payload-bytes", "67108864"],
            ["--max-payload-bytes", "-1"],
        ] {
            let mut a = args();
            a.extend(pair.map(Into::into));
            let e = parse(&a).unwrap_err();
            assert!(!e.to_string().contains("private marker"));
        }
        let mut a = args();
        a[8] = "rc1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(parse(&a).is_err());
    }
    #[test]
    fn cancellation_storage_and_output_failures_are_distinct() {
        assert_eq!(Error::Input(SecretInputError::Cancelled).exit_code(), 130);
        assert_eq!(Error::Storage(StorageError::NeedsReview).exit_code(), 3);
        assert!(
            Error::Storage(StorageError::NeedsReview)
                .to_string()
                .contains("一部または全部")
        );
        assert_eq!(Error::Output.exit_code(), 1);
        assert!(Error::Output.to_string().contains("保存と正常終了は完了"));
        let e = Error::Storage(StorageError::Io(std::io::Error::other("private marker")));
        assert!(!e.to_string().contains("private marker"));
        assert!(std::error::Error::source(&e).is_none());
    }
    #[test]
    fn result_write_and_flush_failures_never_return_success() {
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(b.len())
                } else {
                    Err(std::io::Error::other("private output"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("private output"))
            }
        }
        for flush in [false, true] {
            assert!(matches!(
                report("stored", &mut Sink(flush)),
                Err(Error::Output)
            ));
        }
    }
}
