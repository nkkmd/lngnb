//! 残存暗号文の整理開始を記録するCLI。
use super::*;
use data_encoding::HEXLOWER;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Request {
    residue: String,
    backup_dir: PathBuf,
    backup_name: String,
    area_id: [u8; 32],
    snapshot_hash: [u8; 32],
    expected_key: Id,
}

pub(super) fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage = || AppError::Usage("key cleanup-start の引数を確認してください");
    let mut values = std::collections::BTreeMap::new();
    for pair in args.chunks(2) {
        let [flag, value] = pair else {
            return Err(usage());
        };
        if value.is_empty()
            || values
                .insert(flag.to_str().ok_or_else(usage)?, value)
                .is_some()
        {
            return Err(usage());
        }
    }
    let mut take = |key| values.remove(key).ok_or_else(usage);
    let directory = PathBuf::from(take("--key-dir")?);
    let backup_dir = PathBuf::from(take("--backup-dir")?);
    let mut string = |key| take(key)?.to_str().ok_or_else(usage);
    let residue = string("--residue")?;
    let backup_name = string("--backup-name")?;
    let expected_key = Id::parse(Kind::Key, string("--expect-key-id")?).map_err(|_| usage())?;
    let decode = |value: &str| {
        let mut id = [0; 32];
        if value.len() != 64 || HEXLOWER.decode_mut(value.as_bytes(), &mut id).is_err() {
            return Err(usage());
        }
        Ok(id)
    };
    let area_id = decode(string("--expect-area-id")?)?;
    let snapshot_hash = decode(string("--snapshot-hash")?)?;
    let valid_residue = residue
        .strip_prefix(".lngnb-key-")
        .is_some_and(|id| decode(id).is_ok());
    if !valid_residue || !regular_name(backup_name) || !values.is_empty() {
        return Err(usage());
    }
    Ok(Command {
        action: Action::CleanupStart(Box::new(Request {
            residue: residue.into(),
            backup_dir,
            backup_name: backup_name.into(),
            area_id,
            snapshot_hash,
            expected_key,
        })),
        directory,
        name: None,
        backup: None,
        restoration: None,
    })
}

impl Request {
    pub(super) fn run(
        self,
        source: &mut KeyDirectory,
        signals: TerminalSignals,
        output: &mut impl Write,
    ) -> Result<(), Error> {
        let fail = Error::HistoryPassphrase;
        let mut backup = KeyDirectory::open(&self.backup_dir).map_err(fail)?;
        let mut terminal = SecretTerminal::open_interruptible(signals)?;
        let password = terminal.recovery_passphrase()?;
        signals.check_cancelled()?;
        drop(terminal);
        let public = source
            .check_recovery_file(&self.residue, password.as_str())
            .map_err(fail)?;
        if key_id(&public) != self.expected_key {
            return Err(fail(KeyFileError::UnexpectedPublicKey));
        }
        let expected = source
            .residue_cleanup_selection(
                &self.residue,
                &backup,
                &self.backup_name,
                &self.area_id,
                &self.snapshot_hash,
                public,
            )
            .map_err(fail)?;
        let prepared = source
            .prepare_residue_cleanup(
                &self.residue,
                password.as_str(),
                &mut backup,
                &self.backup_name,
                &expected,
            )
            .map_err(fail)?;
        let intent = prepared.intent();
        signals.check_cancelled()?;
        writeln!(output, "key_cleanup_start_intent area_id={} generation={} before_hash={} after_hash={} operation_id={}",
            HEXLOWER.encode(&self.area_id), intent.before.generation,
            HEXLOWER.encode(&intent.before.snapshot_hash), HEXLOWER.encode(&intent.after.snapshot_hash),
            HEXLOWER.encode(&intent.operation_id),
        ).and_then(|()| output.flush()).map_err(|_| Error::HistoryOutput)?;
        prepared.start().map_err(fail)?;
        writeln!(output, "key_cleanup_start_saved")
            .and_then(|()| output.flush())
            .map_err(|_| Error::HistoryOutput)
    }
}
