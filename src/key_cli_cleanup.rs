//! 残存暗号文の整理開始を記録するCLI。
use super::*;
use data_encoding::HEXLOWER;
use lngnb::keyfile::KeyCleanupDisposition;
use std::ffi::OsStr;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Request {
    residue: String,
    backup_dir: PathBuf,
    backup_name: String,
    area_id: [u8; 32],
    snapshot_hash: [u8; 32],
    recovery: Option<Recovery>,
    complete_absent: bool,
    completion_start: Option<([u8; 32], KeyCleanupDisposition)>,
    remove: bool,
    expected_key: Id,
}

#[derive(Debug, PartialEq, Eq)]
struct Recovery {
    generation: u64,
    after_hash: [u8; 32],
    operation_id: [u8; 32],
}

fn decode(value: &str) -> Option<[u8; 32]> {
    let mut id = [0; 32];
    if value.len() != 64 {
        return None;
    }
    HEXLOWER.decode_mut(value.as_bytes(), &mut id).ok()?;
    Some(id)
}

fn receipt(value: &str) -> Option<StartReceipt> {
    let mut fields = value.split(' ');
    if fields.next()? != "key_cleanup_start_intent" {
        return None;
    }
    let area_id = decode(fields.next()?.strip_prefix("area_id=")?)?;
    let generation_text = fields.next()?.strip_prefix("generation=")?;
    let generation: u64 = generation_text.parse().ok()?;
    if generation.to_string() != generation_text || generation.checked_add(1).is_none() {
        return None;
    }
    let before = decode(fields.next()?.strip_prefix("before_hash=")?)?;
    let after_hash = decode(fields.next()?.strip_prefix("after_hash=")?)?;
    let operation_id = decode(fields.next()?.strip_prefix("operation_id=")?)?;
    if fields.next().is_some() {
        return None;
    }
    Some((
        area_id,
        before,
        Recovery {
            generation,
            after_hash,
            operation_id,
        },
    ))
}

type StartReceipt = ([u8; 32], [u8; 32], Recovery);

type CompletionReference = ([u8; 32], KeyCleanupDisposition);

fn completion_receipt(value: &str) -> Option<(StartReceipt, CompletionReference)> {
    let mut fields = value.split(' ');
    if fields.next()? != "key_cleanup_completion_intent" {
        return None;
    }
    let area = fields.next()?;
    let generation = fields.next()?;
    let before = fields.next()?;
    let after = fields.next()?;
    let started = decode(fields.next()?.strip_prefix("started_operation_id=")?)?;
    let operation = fields.next()?;
    let disposition = match fields.next()? {
        "disposition=confirmed_absent_on_recovery" => {
            KeyCleanupDisposition::ConfirmedAbsentOnRecovery
        }
        "disposition=removed_present" => KeyCleanupDisposition::RemovedPresent,
        _ => return None,
    };
    if fields.next().is_some() {
        return None;
    }
    let (area, before, recovery) = receipt(&format!(
        "key_cleanup_start_intent {area} {generation} {before} {after} {operation}"
    ))?;
    Some(((area, before, recovery), (started, disposition)))
}

pub(super) fn parse(args: &[OsString], action: &OsStr) -> Result<Command, AppError> {
    let usage = || AppError::Usage("key の整理操作の引数を確認してください");
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
    let (area_id, snapshot_hash, recovery, completion_start) = if action
        == "recover-cleanup-completion"
    {
        let ((area, before, recovery), started) =
            completion_receipt(string("--completion")?).ok_or_else(usage)?;
        (area, before, Some(recovery), Some(started))
    } else if action != "cleanup-start" {
        let (area_id, snapshot_hash, recovery) = receipt(string("--start")?).ok_or_else(usage)?;
        (area_id, snapshot_hash, Some(recovery), None)
    } else {
        (
            decode(string("--expect-area-id")?).ok_or_else(usage)?,
            decode(string("--snapshot-hash")?).ok_or_else(usage)?,
            None,
            None,
        )
    };
    let valid_residue = residue
        .strip_prefix(".lngnb-key-")
        .is_some_and(|id| decode(id).is_some());
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
            recovery,
            completion_start,
            remove: action == "cleanup-remove",
            complete_absent: action == "cleanup-complete-absent",
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
        if self.remove || self.complete_absent || self.completion_start.is_some() {
            let start = self.recovery.expect("completion requires a start receipt");
            let public = backup
                .load(&self.backup_name, password.as_str())
                .map_err(fail)?
                .public_key();
            if key_id(&public) != self.expected_key {
                return Err(fail(KeyFileError::UnexpectedPublicKey));
            }
            if let Some((started_operation_id, disposition)) = self.completion_start {
                signals.check_cancelled()?;
                source
                    .recover_cleanup_completion_from_receipt(
                        &self.residue,
                        password.as_str(),
                        &mut backup,
                        &self.backup_name,
                        public,
                        self.area_id,
                        start.generation,
                        self.snapshot_hash,
                        start.after_hash,
                        started_operation_id,
                        start.operation_id,
                        disposition,
                    )
                    .map_err(fail)?;
                return writeln!(output, "key_cleanup_completion_confirmed")
                    .and_then(|()| output.flush())
                    .map_err(|_| Error::HistoryOutput);
            }
            let expected = source
                .cleanup_completion_selection(
                    &backup,
                    &self.backup_name,
                    &self.area_id,
                    (&self.snapshot_hash, &start.after_hash),
                    &start.operation_id,
                    public,
                )
                .map_err(fail)?;
            if start.generation.checked_add(1) != Some(expected.state.generation) {
                return Err(fail(KeyFileError::RecoveryStateInvalid));
            }
            signals.check_cancelled()?;
            let (prepared, disposition, status) = if self.remove {
                let removal = source
                    .prepare_residue_removal(
                        &self.residue,
                        password.as_str(),
                        &mut backup,
                        &self.backup_name,
                        &expected,
                    )
                    .map_err(fail)?;
                signals.check_cancelled()?;
                writeln!(output, "key_cleanup_removal_requested")
                    .and_then(|()| output.flush())
                    .map_err(|_| Error::HistoryOutput)?;
                signals.check_cancelled()?;
                (
                    removal.remove().map_err(fail)?,
                    "removed_present",
                    "key_cleanup_removal_recorded",
                )
            } else {
                let prepared = source
                    .prepare_absent_residue_completion(
                        &self.residue,
                        password.as_str(),
                        &mut backup,
                        &self.backup_name,
                        &expected,
                    )
                    .map_err(fail)?;
                signals.check_cancelled()?;
                (
                    prepared,
                    "confirmed_absent_on_recovery",
                    "key_cleanup_absence_confirmed",
                )
            };
            let intent = prepared.intent();
            writeln!(output, "key_cleanup_completion_intent area_id={} generation={} before_hash={} after_hash={} started_operation_id={} operation_id={} disposition={disposition}",
                HEXLOWER.encode(&self.area_id), intent.before.generation,
                HEXLOWER.encode(&intent.before.snapshot_hash), HEXLOWER.encode(&intent.after.snapshot_hash),
                HEXLOWER.encode(&intent.started_operation_id), HEXLOWER.encode(&intent.operation_id),
            ).and_then(|()| output.flush()).map_err(|_| Error::HistoryOutput)?;
            prepared.record().map_err(fail)?;
            return writeln!(output, "{status}")
                .and_then(|()| output.flush())
                .map_err(|_| Error::HistoryOutput);
        }
        let public = source
            .check_recovery_file(&self.residue, password.as_str())
            .map_err(fail)?;
        if key_id(&public) != self.expected_key {
            return Err(fail(KeyFileError::UnexpectedPublicKey));
        }
        if let Some(recovery) = self.recovery {
            signals.check_cancelled()?;
            source
                .recover_residue_cleanup_from_receipt(
                    &self.residue,
                    password.as_str(),
                    &mut backup,
                    &self.backup_name,
                    public,
                    self.area_id,
                    recovery.generation,
                    self.snapshot_hash,
                    recovery.after_hash,
                    recovery.operation_id,
                )
                .map_err(fail)?;
            return writeln!(output, "key_cleanup_start_confirmed")
                .and_then(|()| output.flush())
                .map_err(|_| Error::HistoryOutput);
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
