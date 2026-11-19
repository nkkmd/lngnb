//! 履歴付き鍵の初回更新と、指定した一段階の明示復旧。
use super::*;
use lngnb::keyfile::{
    KeyPassphraseCompletedIntent, KeyPassphrasePreparedIntent, KeyPassphraseStartIntent,
    KeyResumeIntent, KeyResumePreservation, KeyResumeRelease, KeyStateDiagnostic,
};

#[derive(Debug, PartialEq, Eq)]
enum Stage {
    RecordResume,
    RecoverResumeRecord,
    ReleaseResume,
    Preserve,
    VerifyPreserved,
    Update,
    Start(KeyPassphraseStartIntent),
    Prepared(KeyPassphraseStartIntent, KeyPassphrasePreparedIntent),
    Exchange(KeyPassphraseStartIntent, KeyPassphrasePreparedIntent),
    Complete(KeyPassphraseStartIntent, KeyPassphrasePreparedIntent),
    Completed(
        KeyPassphraseStartIntent,
        KeyPassphrasePreparedIntent,
        KeyPassphraseCompletedIntent,
    ),
    Release(
        KeyPassphraseStartIntent,
        KeyPassphrasePreparedIntent,
        KeyPassphraseCompletedIntent,
    ),
}

#[derive(Debug, PartialEq, Eq)]
enum Anchor {
    First(Box<KeyResumeIntent>),
    Held {
        area_id: [u8; 32],
        snapshot_hash: [u8; 32],
        key: Id,
    },
    Rotation(KeyStateDiagnostic),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Request {
    stage: Stage,
    anchor: Anchor,
    backup_dir: PathBuf,
    backup_name: String,
    preservations: Vec<([u8; 32], PathBuf, String)>,
}

pub(super) fn parse(args: &[OsString], rotation: bool) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage(if rotation {
            "key history-passphrase-rotation の操作と引数を確認してください"
        } else {
            "key history-passphrase の操作と引数を確認してください"
        })
    };
    let [stage, args @ ..] = args else {
        return Err(usage());
    };
    let mut options = std::collections::BTreeMap::new();
    let mut preservations = Vec::new();
    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args.next().ok_or_else(usage)?;
        if option == "--preservation" {
            let mut id = [0; 32];
            let path = args.next().filter(|v| !v.is_empty()).ok_or_else(usage)?;
            let name = args
                .next()
                .and_then(|v| v.to_str())
                .filter(|v| regular_name(v))
                .ok_or_else(usage)?;
            if value.len() != 64
                || data_encoding::HEXLOWER
                    .decode_mut(value.as_encoded_bytes(), &mut id)
                    .is_err()
                || preservations.len() >= 1024
                || preservations.iter().any(|(existing, _, _)| *existing == id)
            {
                return Err(usage());
            }
            preservations.push((id, PathBuf::from(path), name.to_owned()));
        } else if options.insert(option.as_os_str(), value).is_some() {
            return Err(usage());
        }
    }
    let mut take = |flag: &str| {
        options
            .remove(std::ffi::OsStr::new(flag))
            .filter(|v| !v.is_empty())
            .ok_or_else(usage)
    };
    let mut parse_line = |flag| take(flag)?.to_str().ok_or_else(usage);
    let anchor = if !rotation && stage == "resume-record" {
        let decode = |value: &str| {
            let mut id = [0; 32];
            if value.len() != 64
                || data_encoding::HEXLOWER
                    .decode_mut(value.as_bytes(), &mut id)
                    .is_err()
            {
                return Err(usage());
            }
            Ok(id)
        };
        Anchor::Held {
            area_id: decode(parse_line("--expect-area-id")?)?,
            snapshot_hash: decode(parse_line("--snapshot-hash")?)?,
            key: Id::parse(Kind::Key, parse_line("--expect-key-id")?).map_err(|_| usage())?,
        }
    } else if rotation {
        Anchor::Rotation(
            KeyPassphraseCompletedIntent::parse_previous_completion(parse_line(
                "--previous-completed",
            )?)
            .map_err(|_| usage())?,
        )
    } else {
        Anchor::First(Box::new(
            KeyResumeIntent::parse_receipt(parse_line("--resume")?).map_err(|_| usage())?,
        ))
    };
    let stage = match stage.to_str() {
        Some("preserve") if rotation && preservations.is_empty() => Stage::Preserve,
        Some("verify-preserved") if rotation && preservations.is_empty() => Stage::VerifyPreserved,
        Some("resume-record") if !rotation => Stage::RecordResume,
        Some("recover-resume-record") if !rotation => Stage::RecoverResumeRecord,
        Some("release-resume") if !rotation => Stage::ReleaseResume,
        Some("update") if !rotation => Stage::Update,
        Some("prepare") if rotation => Stage::Update,
        Some(
            "recover-start" | "recover-prepared" | "exchange" | "complete" | "recover-completed"
            | "release",
        ) => {
            let line = parse_line("--start")?;
            let start = match &anchor {
                Anchor::Held { .. } => return Err(usage()),
                Anchor::First(resume) => KeyPassphraseStartIntent::parse_receipt(line, resume),
                Anchor::Rotation(previous) => {
                    KeyPassphraseStartIntent::parse_rotation_receipt(line, previous)
                }
            }
            .map_err(|_| usage())?;
            if stage == "recover-start" {
                Stage::Start(start)
            } else {
                let line = parse_line("--prepared")?;
                let prepared = if rotation {
                    KeyPassphrasePreparedIntent::parse_rotation_receipt(line, &start)
                } else {
                    KeyPassphrasePreparedIntent::parse_receipt(line, &start)
                }
                .map_err(|_| usage())?;
                match stage.to_str() {
                    Some("recover-prepared") => Stage::Prepared(start, prepared),
                    Some("exchange") => Stage::Exchange(start, prepared),
                    Some("complete") => Stage::Complete(start, prepared),
                    _ => {
                        let line = parse_line("--completed")?;
                        let completed = if rotation {
                            KeyPassphraseCompletedIntent::parse_rotation_receipt(line, &prepared)
                        } else {
                            KeyPassphraseCompletedIntent::parse_receipt(line, &start, &prepared)
                        }
                        .map_err(|_| usage())?;
                        if stage == "release" {
                            Stage::Release(start, prepared, completed)
                        } else {
                            Stage::Completed(start, prepared, completed)
                        }
                    }
                }
            }
        }
        _ => return Err(usage()),
    };
    let directory = PathBuf::from(take("--key-dir")?);
    let backup_dir = PathBuf::from(take("--backup-dir")?);
    let mut name = |flag| {
        take(flag)?
            .to_str()
            .filter(|v| regular_name(v))
            .map(str::to_owned)
            .ok_or_else(usage)
    };
    let target = name("--name")?;
    let backup_name = name("--backup-name")?;
    if !options.is_empty() {
        return Err(usage());
    }
    Ok(Command {
        action: Action::HistoryPassphrase(Box::new(Request {
            stage,
            anchor,
            backup_dir,
            backup_name,
            preservations,
        })),
        directory,
        name: Some(target),
        backup: None,
        restoration: None,
    })
}

impl Request {
    pub(super) fn run(
        self,
        source: &mut KeyDirectory,
        name: &str,
        signals: TerminalSignals,
        output: &mut impl Write,
    ) -> Result<(), Error> {
        let fail = Error::HistoryPassphrase;
        let first = match &self.anchor {
            Anchor::First(resume) => Some((
                resume,
                match self.stage {
                    Stage::RecoverResumeRecord => {
                        source.key_resume_record_recovery_expected(name, &self.backup_name, resume)
                    }
                    Stage::ReleaseResume => {
                        source.key_resume_release_expected(name, &self.backup_name, resume)
                    }
                    _ => source.key_passphrase_recovery_expected(name, &self.backup_name, resume),
                }
                .map_err(fail)?,
            )),
            Anchor::Held { .. } | Anchor::Rotation(_) => None,
        };
        let mut paths = vec![self.backup_dir];
        let mut indices = Vec::new();
        for (_, path, _) in &self.preservations {
            let index = paths
                .iter()
                .position(|known| known == path)
                .unwrap_or(paths.len());
            if index == paths.len() {
                paths.push(path.clone());
            }
            indices.push(index);
        }
        let mut backups = paths
            .iter()
            .map(|path| KeyDirectory::open(path))
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        let mut terminal = SecretTerminal::open_interruptible(signals)?;
        let old = terminal.current_passphrase()?;
        let new = match self.stage {
            Stage::RecordResume
            | Stage::RecoverResumeRecord
            | Stage::ReleaseResume
            | Stage::Start(_)
            | Stage::Preserve
            | Stage::VerifyPreserved => None,
            Stage::Update => Some(terminal.new_passphrase()?),
            _ => Some(terminal.recovery_passphrase()?),
        };
        let mut passwords = Vec::new();
        for _ in &self.preservations {
            passwords.push(terminal.recovery_passphrase()?);
        }
        signals.check_cancelled()?;
        drop(terminal);
        let proofs: Vec<_> = self
            .preservations
            .iter()
            .zip(indices)
            .zip(&passwords)
            .map(
                |(((id, _, name), directory_index), pass)| KeyResumePreservation {
                    completed_operation_id: *id,
                    directory_index,
                    name,
                    passphrase: pass.as_str(),
                },
            )
            .collect();
        let old = old.as_str();
        let new = new.as_ref().map_or("", |p| p.as_str());
        let backup = self.backup_name.as_str();
        let status = if let Anchor::Held {
            area_id,
            snapshot_hash,
            key,
        } = &self.anchor
        {
            let public = source.load(name, old).map_err(fail)?.public_key();
            if key_id(&public) != *key {
                return Err(fail(KeyFileError::UnexpectedPublicKey));
            }
            let expected = source
                .key_resume_selection(name, &backups[0], backup, area_id, snapshot_hash, public)
                .map_err(fail)?;
            signals.check_cancelled()?;
            let prepared = source
                .prepare_key_resume(name, old, &mut backups, 0, backup, &proofs, &expected)
                .map_err(fail)?;
            signals.check_cancelled()?;
            prepared.intent().write_receipt(output).map_err(fail)?;
            output.flush().map_err(|_| Error::HistoryOutput)?;
            prepared.record().map_err(fail)?;
            "key_resume_recorded_guard_retained"
        } else if let Anchor::Rotation(previous) = &self.anchor {
            self.stage.run_rotation(
                source,
                name,
                old,
                new,
                &mut backups,
                backup,
                &proofs,
                previous,
                output,
            )?
        } else {
            let (resume, expected) = first.expect("first update anchor");
            match self.stage {
                Stage::RecordResume | Stage::Preserve | Stage::VerifyPreserved => {
                    unreachable!("rotation-only stage")
                }
                Stage::RecoverResumeRecord => {
                    source
                        .recover_key_resume_record(
                            name,
                            old,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                        )
                        .map_err(fail)?;
                    "key_resume_record_confirmed_guard_retained"
                }
                Stage::ReleaseResume => match source
                    .recover_key_resume_release(
                        name,
                        old,
                        &mut backups,
                        0,
                        backup,
                        &proofs,
                        &expected,
                        resume,
                    )
                    .map_err(fail)?
                {
                    KeyResumeRelease::RemovedRecordedGuard(_) => "key_resume_guard_removed",
                    KeyResumeRelease::ConfirmedGuardAbsent(_) => {
                        "key_resume_guard_absence_confirmed"
                    }
                },
                Stage::Update => release_status(
                    source
                        .change_first_key_passphrase(
                            name,
                            old,
                            new,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            resume,
                            output,
                        )
                        .map_err(fail)?,
                ),
                Stage::Start(start) => {
                    source
                        .recover_key_passphrase_start(
                            name,
                            old,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                            &start,
                        )
                        .map_err(fail)?;
                    "key_passphrase_start_recovery_confirmed_guard_retained"
                }
                Stage::Prepared(start, prepared) => {
                    source
                        .recover_key_passphrase_prepared(
                            name,
                            old,
                            new,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                            &start,
                            &prepared,
                        )
                        .map_err(fail)?;
                    "key_passphrase_prepared_recovery_confirmed_guard_retained"
                }
                Stage::Exchange(start, prepared) => {
                    source
                        .exchange_key_passphrase(
                            name,
                            old,
                            new,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                            &start,
                            &prepared,
                        )
                        .map_err(fail)?;
                    "key_passphrase_exchange_confirmed_guard_retained"
                }
                Stage::Complete(start, prepared) => {
                    let completion = source
                        .prepare_key_passphrase_completion(
                            name,
                            old,
                            new,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                            &start,
                            &prepared,
                        )
                        .map_err(fail)?;
                    completion.intent().write_receipt(output).map_err(fail)?;
                    completion.record().map_err(fail)?;
                    "key_passphrase_completion_confirmed_guard_retained"
                }
                Stage::Completed(start, prepared, completed) => {
                    source
                        .recover_key_passphrase_completed(
                            name,
                            old,
                            new,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                            &start,
                            &prepared,
                            &completed,
                        )
                        .map_err(fail)?;
                    "key_passphrase_completion_confirmed_guard_retained"
                }
                Stage::Release(start, prepared, completed) => release_status(
                    source
                        .recover_key_passphrase_release(
                            name,
                            old,
                            new,
                            &mut backups,
                            0,
                            backup,
                            &proofs,
                            &expected,
                            resume,
                            &start,
                            &prepared,
                            &completed,
                        )
                        .map_err(fail)?,
                ),
            }
        };
        writeln!(output, "{status}")
            .and_then(|()| output.flush())
            .map_err(|_| Error::HistoryOutput)
    }
}

impl Stage {
    #[allow(clippy::too_many_arguments)]
    fn run_rotation(
        self,
        source: &mut KeyDirectory,
        name: &str,
        old: &str,
        new: &str,
        backups: &mut [KeyDirectory],
        backup: &str,
        proofs: &[KeyResumePreservation<'_>],
        previous: &KeyStateDiagnostic,
        output: &mut impl Write,
    ) -> Result<&'static str, Error> {
        let fail = Error::HistoryPassphrase;
        Ok(match self {
            Self::RecordResume | Self::RecoverResumeRecord | Self::ReleaseResume => {
                unreachable!("resume record is not a rotation stage")
            }
            Self::Preserve => {
                source
                    .preserve_key_for_passphrase_rotation(
                        previous,
                        name,
                        old,
                        &mut backups[0],
                        backup,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_preserved"
            }
            Self::VerifyPreserved => {
                source
                    .verify_key_preserved_for_passphrase_rotation(
                        previous,
                        name,
                        old,
                        &mut backups[0],
                        backup,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_preservation_confirmed"
            }
            Self::Update => {
                source
                    .record_passphrase_rotation_prepared(
                        previous, name, old, new, backups, 0, backup, proofs, output,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_prepared_guard_retained"
            }
            Self::Start(start) => {
                source
                    .recover_passphrase_rotation_start(
                        name, old, backups, 0, backup, proofs, &start,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_start_recovery_confirmed_guard_retained"
            }
            Self::Prepared(start, prepared) => {
                source
                    .recover_passphrase_rotation_prepared(
                        name, old, backups, 0, backup, proofs, &start, &prepared, new,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_prepared_recovery_confirmed_guard_retained"
            }
            Self::Exchange(start, prepared) => {
                source
                    .exchange_passphrase_rotation(
                        name, old, new, backups, 0, backup, proofs, &start, &prepared,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_exchange_confirmed_guard_retained"
            }
            Self::Complete(start, prepared) => {
                source
                    .complete_passphrase_rotation(
                        name, old, new, backups, 0, backup, proofs, &start, &prepared, output,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_completion_confirmed_guard_retained"
            }
            Self::Completed(start, prepared, completed) => {
                source
                    .recover_passphrase_rotation_completed(
                        name, old, new, backups, 0, backup, proofs, &start, &prepared, &completed,
                    )
                    .map_err(fail)?;
                "key_passphrase_rotation_completion_confirmed_guard_retained"
            }
            Self::Release(start, prepared, completed) => {
                match source
                    .release_passphrase_rotation(
                        name, old, new, backups, 0, backup, proofs, &start, &prepared, &completed,
                    )
                    .map_err(fail)?
                {
                    KeyResumeRelease::RemovedRecordedGuard(_) => {
                        "key_passphrase_rotation_guard_removed"
                    }
                    KeyResumeRelease::ConfirmedGuardAbsent(_) => {
                        "key_passphrase_rotation_guard_absence_confirmed"
                    }
                }
            }
        })
    }
}

fn release_status(release: KeyResumeRelease) -> &'static str {
    match release {
        KeyResumeRelease::RemovedRecordedGuard(_) => "key_passphrase_change_guard_removed",
        KeyResumeRelease::ConfirmedGuardAbsent(_) => {
            "key_passphrase_change_guard_absence_confirmed"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lngnb::keyfile::{KeyHistoryState, KeyInitialState, KeyStateDiagnostic};

    #[test]
    fn history_passphrase_requires_exact_stage_inputs() {
        let parse = |args: &[OsString]| super::parse(args, false);
        let before = KeyStateDiagnostic {
            initial: KeyInitialState {
                area_id: [1; 32],
                snapshot_hash: [2; 32],
                operation_id: [3; 32],
                generation: 1,
            },
            generation: 2,
            snapshot_hash: [4; 32],
            state: KeyHistoryState::Held,
        };
        let resume = KeyResumeIntent {
            before,
            after: KeyStateDiagnostic {
                generation: 3,
                snapshot_hash: [5; 32],
                state: KeyHistoryState::Ready {
                    resumed_operation_id: [6; 32],
                },
                ..before
            },
            operation_id: [6; 32],
        };
        let mut output = Vec::new();
        resume.write_receipt(&mut output).unwrap();
        let receipt = String::from_utf8(output).unwrap();
        let args = |stage: &str, extra: &[&str]| {
            [
                stage,
                "--key-dir",
                "/keys",
                "--name",
                "publisher",
                "--backup-dir",
                "/copy",
                "--backup-name",
                "saved",
                "--resume",
                &receipt,
            ]
            .into_iter()
            .chain(extra.iter().copied())
            .map(OsString::from)
            .collect::<Vec<_>>()
        };
        assert!(parse(&args("update", &[])).is_ok());
        let operation = "07".repeat(32);
        let proof = ["--preservation", &operation, "/copy", "previous"];
        assert!(parse(&args("update", &proof)).is_ok());
        assert!(parse(&args("release-resume", &proof)).is_ok());
        assert!(parse(&args("release-resume", &["--start", &receipt])).is_err());
        assert!(parse(&args("update", &[proof, proof].concat())).is_err());
        assert!(parse(&args("update", &["--key-dir", "/other"])).is_err());
        assert!(parse(&args("update", &["--start", &receipt])).is_err());
        assert!(parse(&args("recover-start", &[])).is_err());
        assert!(parse(&args("release", &["--start", &receipt])).is_err());
        assert!(parse(&args("unknown", &[])).is_err());
    }
}
