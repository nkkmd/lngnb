//! R01/R05/R24/R30/R34: 明示鍵で新規資料を署名し、既存の正常な領域へ保存するCLI。
use super::AppError;
use lngnb::{
    authoring::{self, CreationBudget, CreationError, InitialRecords},
    authoring_input::{self, InputError},
    id::{self, Id, Kind},
    keyfile::{KeyDirectory, KeyFileError},
    secret_terminal::{SecretInputError, SecretTerminal, TerminalSignals},
    storage::{EvaluationLimits, Limits, LocalStartup, LocalStartupBudget, StorageError},
};
use std::{
    ffi::OsString,
    fmt,
    io::{Cursor, Write},
    path::PathBuf,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
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
    let usage = || AppError::Usage("document create の操作と引数を確認してください");
    let [action, rest @ ..] = args else {
        return Err(usage());
    };
    if action != "create" {
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
    for pair in rest.chunks(2) {
        let [option, value] = pair else {
            return Err(usage());
        };
        if value.is_empty() {
            return Err(usage());
        }
        match option.to_str() {
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
    Ok(Command {
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
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Input(SecretInputError::Cancelled) | Self::File(InputError::Cancelled) => 130,
            Self::Storage(_) => 3,
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
        Self::Output=>f.write_str("資料のローカル保存と正常終了は完了しましたが、結果出力に失敗しました。再作成せず保存領域を確認してください。"),
    }
    }
}
impl std::error::Error for Error {}

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
    let pair =
        authoring::create_initial(&key, &payload, metadata, command.media.as_deref(), budget)
            .map_err(Error::Creation)?;
    drop(key);
    drop(terminal);
    drop(directory);
    signals.check_cancelled().map_err(Error::Input)?;
    let text = summary(&pair)?;
    // 保存側へ渡すのは完成Recordと同じ所有本文だけ。秘密鍵/端末はここより前に破棄する。
    save(&command.data, &pair, &payload, command.max_payload).map_err(Error::Storage)?;
    report(&text, output)
}

fn save(
    path: &std::path::Path,
    pair: &InitialRecords,
    payload: &[u8],
    max_payload: usize,
) -> Result<(), StorageError> {
    let limits = Limits {
        max_blob_bytes: max_payload as u64,
        ..Limits::default()
    };
    let total = (payload.len() as u64)
        .checked_add(pair.genesis().bytes().len() as u64)
        .and_then(|n| n.checked_add(pair.revision().bytes().len() as u64))
        .and_then(|n| n.checked_add(1))
        .ok_or(StorageError::BudgetExceeded)?;
    if total > limits.session_bytes {
        return Err(StorageError::BudgetExceeded);
    }
    let mut startup = LocalStartup::open(path, limits)?;
    if startup.needs_review() {
        return Err(StorageError::NeedsReview);
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
    // 各段階は独立確定。後段失敗で先に保存した本文/Recordを消さない。
    let blob = writer.put_blob(id::blob_id(payload), Cursor::new(payload))?;
    if blob.byte_length != payload.len() as u64 {
        return Err(StorageError::Corrupt);
    }
    writer.insert(pair.genesis())?;
    writer.insert(pair.revision())?;
    writer.finish()
}
fn summary(pair: &InitialRecords) -> Result<String, Error> {
    let knowledge = match pair.genesis().body() {
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
        "新規資料の本文と署名Recordをローカル保存しました（pin・公開は未実装）。\nknowledge_id: {}\ngenesis_id: {}\nrevision_id: {}\n",
        Id {
            kind: Kind::Knowledge,
            bytes: knowledge
        },
        pair.genesis().id(),
        pair.revision().id()
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
