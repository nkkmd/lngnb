//! 公開fixtureと隔離領域のみ。復旧成功後もguardを保持する。
use super::*;

impl Fixture {
    fn interrupt(&mut self, point: S) -> KeyResumeIntent {
        let prepared = self.prepare().unwrap();
        let intent = prepared.intent();
        assert!(
            prepared
                .record_with(&mut |stage| if stage == point {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                })
                .is_err()
        );
        self.reopen();
        intent
    }
    fn recover(
        &mut self,
        intent: &KeyResumeIntent,
        hook: &mut impl FnMut(S) -> Result<()>,
    ) -> Result<KeyStateDiagnostic> {
        let proofs: Vec<_> = self
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: self.indices[i],
                name: &self.names[i],
                passphrase: &self.pass,
            })
            .collect();
        self.source
            .as_mut()
            .unwrap()
            .recover_key_resume_record_with(
                "publisher",
                &self.pass,
                &mut self.backups,
                0,
                "saved",
                &proofs,
                &self.expected,
                intent,
                hook,
            )
    }
    fn temp(&self) -> PathBuf {
        self.a.0.join(format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&self.operation)
        ))
    }
}

#[test]
fn resume_recovery_complete_layouts_keep_exact_history_guard_and_keys() {
    for (separate, count) in [(false, 0), (false, 2), (true, 2)] {
        for point in [S::Prepared, S::Exchanged, S::OldSnapshotRemoved] {
            let mut f = Fixture::new(separate, count);
            let intent = f.interrupt(point);
            assert_eq!(f.recover(&intent, &mut |_| Ok(())).unwrap(), intent.after);
            assert!(!f.temp().exists());
            f.retained();
            f.independent(intent);
            f.reopen();
            assert_eq!(f.recover(&intent, &mut |_| Ok(())).unwrap(), intent.after);
            assert!(f.prepare().is_err());
            assert!(
                f.source
                    .as_mut()
                    .unwrap()
                    .initialize_key_state(&intent.before.initial.area_id)
                    .is_err()
            );
            f.retained();
        }
    }
}

#[test]
fn resume_recovery_receipt_mismatches_never_change_complete_candidates() {
    let mut f = Fixture::new(true, 2);
    let intent = f.interrupt(S::Prepared);
    let pending = stdfs::read(f.temp()).unwrap();
    for variant in 0..6 {
        let mut wrong = intent;
        match variant {
            0 => wrong.operation_id[0] ^= 1,
            1 => wrong.before.snapshot_hash[0] ^= 1,
            2 => wrong.after.snapshot_hash[0] ^= 1,
            3 => wrong.after.generation += 1,
            4 => wrong.after.initial.snapshot_hash[0] ^= 1,
            _ => wrong.after.state = KeyHistoryState::Held,
        }
        assert!(f.recover(&wrong, &mut |_| Ok(())).is_err());
        assert_eq!(stdfs::read(f.temp()).unwrap(), pending);
        assert_eq!(
            stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
            f.old
        );
    }
    f.retained();
}

#[test]
fn resume_recovery_missing_partial_unknown_and_guard_absence_preserve_stop() {
    for variant in 0..5 {
        let mut f = Fixture::new(false, 0);
        let intent = f.interrupt(if variant == 4 {
            S::OldSnapshotRemoved
        } else {
            S::Prepared
        });
        match variant {
            0 => {
                stdfs::remove_file(f.temp()).unwrap();
            }
            1 => {
                stdfs::write(f.temp(), [0xa1]).unwrap();
            }
            2 => {
                f.a.put(".lngnb-key-state-update-unknown", b"preserve");
            }
            3 => {
                let bytes = stdfs::read(f.temp()).unwrap();
                f.a.put(".lngnb-key-state-update-extra", &bytes);
            }
            _ => {
                stdfs::remove_file(f.a.0.join(recovery_hold::GUARD)).unwrap();
            }
        }
        let state = stdfs::read(f.a.0.join(initial_state::STATE)).unwrap();
        let candidate = stdfs::read(f.temp()).ok();
        assert!(f.recover(&intent, &mut |_| Ok(())).is_err());
        assert_eq!(
            stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
            state
        );
        assert_eq!(stdfs::read(f.temp()).ok(), candidate);
        assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), f.key);
        assert_eq!(
            stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap(),
            f.marker
        );
        if variant != 4 {
            f.retained();
        } else {
            assert!(!f.a.0.join(recovery_hold::GUARD).exists());
        }
    }
}

#[test]
fn resume_recovery_every_boundary_can_be_reopened_and_explicitly_retried() {
    for point in [
        S::CurrentSynced,
        S::PreservationSynced(0),
        S::PreservationSynced(1),
        S::PreservationSynced(2),
        S::DirectoriesSynced,
        S::ControlsSynced,
        S::Qualified,
        S::SnapshotsSynced,
        S::Prepared,
        S::BeforeExchange,
        S::Exchanged,
        S::StateSynced,
        S::BeforeCleanup,
        S::OldSnapshotRemoved,
        S::CleanupSynced,
    ] {
        let mut f = Fixture::new(true, 2);
        let intent = f.interrupt(S::Prepared);
        let error = f.recover(&intent, &mut |stage| {
            if stage == point {
                Err(KeyFileError::Io)
            } else {
                Ok(())
            }
        });
        e(
            error,
            if matches!(
                point,
                S::StateSynced | S::BeforeCleanup | S::OldSnapshotRemoved | S::CleanupSynced
            ) {
                KeyFileError::RecoveryStateCleanupUncertain
            } else {
                KeyFileError::RecoveryStateUncertain
            },
        );
        f.retained();
        f.reopen();
        assert_eq!(f.recover(&intent, &mut |_| Ok(())).unwrap(), intent.after);
        f.retained();
        f.independent(intent);
    }
}

#[test]
fn resume_recovery_reauthenticates_all_preservations_and_rejects_replacement() {
    for variant in 0..5 {
        let mut f = Fixture::new(true, 2);
        let intent = f.interrupt(S::Exchanged);
        let pending = stdfs::read(f.temp()).unwrap();
        match variant {
            0 => f.ids.swap(0, 1),
            1 => {
                f.ids.pop();
            }
            2 => f.pass.push('!'),
            3 => {
                stdfs::remove_file(f.areas[1].0.join("past1")).unwrap();
            }
            _ => {
                let path = f.areas[1].0.join("past0");
                stdfs::rename(&path, f.areas[1].0.join("original")).unwrap();
                f.areas[1].put("past0", &f.key);
            }
        }
        assert!(f.recover(&intent, &mut |_| Ok(())).is_err());
        assert_eq!(stdfs::read(f.temp()).unwrap(), pending);
        assert_eq!(
            stdfs::read(f.a.0.join(recovery_hold::GUARD)).unwrap(),
            f.guard
        );
        assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), f.key);
    }
}

#[test]
fn resume_recovery_same_bytes_candidate_replacement_is_not_deleted() {
    for layout in [S::Prepared, S::Exchanged] {
        let mut f = Fixture::new(false, 0);
        let intent = f.interrupt(layout);
        let path = f.temp();
        let kept = f.a.0.join("kept-candidate");
        let mut content = Vec::new();
        let mut changed = false;
        assert!(
            f.recover(&intent, &mut |stage| {
                if stage == S::BeforeCleanup {
                    content = stdfs::read(&path).unwrap();
                    stdfs::rename(&path, &kept).unwrap();
                    let mut file = stdfs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)
                        .unwrap();
                    file.write_all(&content).unwrap();
                    file.sync_all().unwrap();
                    changed = true;
                }
                Ok(())
            })
            .is_err()
        );
        assert!(changed);
        assert_eq!(stdfs::read(&path).unwrap(), content);
        assert_eq!(stdfs::read(&kept).unwrap(), content);
        f.retained();
    }
}

#[test]
fn resume_recovery_process_kill_then_explicit_retry_retains_guard() {
    if let Some(mut context) = child_context() {
        let new = data_encoding::HEXLOWER
            .decode(std::env::var("LNGNB_PUBLIC_RESUME_NEW").unwrap().as_bytes())
            .unwrap();
        let marker = stdfs::read(
            Path::new(&std::env::var_os("LNGNB_PUBLIC_RESUME_SOURCE").unwrap())
                .join(recovery_hold::MARKER),
        )
        .unwrap();
        let mut original = marker[..73].to_vec();
        original[19] = b'1';
        let initial = context.expected.state.initial;
        let after =
            state_history::decode_history(&new, &original, initial.area_id, initial.snapshot_hash)
                .unwrap();
        let intent = KeyResumeIntent {
            before: context.expected.state,
            after,
            operation_id: context.operation,
        };
        let proofs: Vec<_> = context
            .manifest
            .iter()
            .map(|(id, index, name)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: *index,
                name,
                passphrase: &context.pass,
            })
            .collect();
        let point = std::env::var("LNGNB_PUBLIC_RESUME_POINT").unwrap();
        let _ = context.source.recover_key_resume_record_with(
            "publisher",
            &context.pass,
            &mut context.backups,
            0,
            "saved",
            &proofs,
            &context.expected,
            &intent,
            &mut |stage| {
                if format!("{stage:?}") == point {
                    println!("READY");
                    std::io::stdout().flush().unwrap();
                    loop {
                        std::thread::park();
                    }
                }
                Ok(())
            },
        );
        panic!("kill point not reached");
    }
    for point in ["Prepared", "Exchanged", "OldSnapshotRemoved"] {
        let mut f = Fixture::new(true, 2);
        let intent = f.interrupt(S::Prepared);
        let new = stdfs::read(f.temp()).unwrap();
        f.source.take();
        f.backups.clear();
        let mut command = child_command(
            &f,
            "keyfile::files::tests::resume_record_tests::recovery_tests::resume_recovery_process_kill_then_explicit_retry_retains_guard",
        );
        let mut child = command
            .env(
                "LNGNB_PUBLIC_RESUME_OLD",
                data_encoding::HEXLOWER.encode(&f.old),
            )
            .env(
                "LNGNB_PUBLIC_RESUME_NEW",
                data_encoding::HEXLOWER.encode(&new),
            )
            .env("LNGNB_PUBLIC_RESUME_POINT", point)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut ready = false;
        for _ in 0..10 {
            let mut line = String::new();
            if output.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.trim() == "READY" {
                ready = true;
                break;
            }
        }
        assert!(ready, "recovery kill boundary not reached");
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        f.reopen();
        f.retained();
        assert_eq!(f.recover(&intent, &mut |_| Ok(())).unwrap(), intent.after);
        f.retained();
        f.independent(intent);
    }
}

#[test]
fn resume_recovery_other_layouts_interrupted_then_explicit_retry() {
    for layout in [S::Exchanged, S::OldSnapshotRemoved] {
        for point in [
            S::CurrentSynced,
            S::PreservationSynced(0),
            S::DirectoriesSynced,
            S::ControlsSynced,
            S::Qualified,
            S::SnapshotsSynced,
            S::Prepared,
            S::StateSynced,
            S::BeforeCleanup,
            S::OldSnapshotRemoved,
            S::CleanupSynced,
        ] {
            if layout == S::OldSnapshotRemoved && point == S::OldSnapshotRemoved {
                continue;
            }
            let mut f = Fixture::new(false, 0);
            let intent = f.interrupt(layout);
            assert!(
                f.recover(&intent, &mut |stage| if stage == point {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                })
                .is_err()
            );
            f.reopen();
            assert_eq!(f.recover(&intent, &mut |_| Ok(())).unwrap(), intent.after);
            f.retained();
        }
    }
}

#[test]
fn resume_recovery_valid_new_hash_cannot_replace_the_expected_old_prefix() {
    let mut f = Fixture::new(true, 2);
    let mut intent = f.interrupt(S::OldSnapshotRemoved);
    let path = f.a.0.join(initial_state::STATE);
    let mut value = cbor::decode(&stdfs::read(&path).unwrap()).unwrap();
    let mut history = events(&value).to_vec();
    set(&mut history[1], "recorded_unix_seconds", Value::Int(40));
    set(&mut value, "events", Value::Array(history));
    let encoded = cbor::encode(&value).unwrap();
    intent.after.snapshot_hash = Sha256::digest(&encoded).into();
    stdfs::write(&path, &encoded).unwrap();
    // new snapshot is codec-valid and matches the supplied new hash; old prefix differs.
    assert_eq!(
        f.source
            .as_mut()
            .unwrap()
            .key_state_history(&intent.before.initial.area_id)
            .unwrap(),
        intent.after
    );
    assert!(f.recover(&intent, &mut |_| Ok(())).is_err());
    assert_eq!(stdfs::read(&path).unwrap(), encoded);
    f.retained();
}

#[test]
fn resume_recovery_full_inventory_needs_no_new_entry_but_over_limit_is_refused() {
    let mut f = Fixture::new(false, 0);
    let intent = f.interrupt(S::Prepared);
    for i in stdfs::read_dir(&f.a.0).unwrap().count()..10_000 {
        stdfs::write(f.a.0.join(format!("ordinary-{i}")), []).unwrap();
    }
    stdfs::write(f.a.0.join("over-limit"), []).unwrap();
    assert!(f.recover(&intent, &mut |_| Ok(())).is_err());
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        f.old
    );
    stdfs::remove_file(f.a.0.join("over-limit")).unwrap();
    assert_eq!(f.recover(&intent, &mut |_| Ok(())).unwrap(), intent.after);
    assert_eq!(stdfs::read_dir(&f.a.0).unwrap().count(), 9_999);
    f.retained();
}

use crate::keyfile::KeyResumeRelease;
use crate::keyfile::files::cleanup_start::resume_record::release::ReleaseStage as G;

impl Fixture {
    fn release(
        &mut self,
        intent: &KeyResumeIntent,
        hook: &mut impl FnMut(G) -> Result<()>,
    ) -> Result<KeyResumeRelease> {
        let proofs: Vec<_> = self
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: self.indices[i],
                name: &self.names[i],
                passphrase: &self.pass,
            })
            .collect();
        self.source
            .as_mut()
            .unwrap()
            .recover_key_resume_release_with(
                "publisher",
                &self.pass,
                &mut self.backups,
                0,
                "saved",
                &proofs,
                &self.expected,
                intent,
                hook,
            )
    }
}

#[test]
fn resume_release_requires_fixed_ready_and_a_clean_inventory() {
    for point in [S::Prepared, S::Exchanged, S::OldSnapshotRemoved] {
        let mut f = Fixture::new(false, 0);
        let intent = f.interrupt(point);
        let guard = f.a.0.join(recovery_hold::GUARD);
        let state = f.a.0.join(initial_state::STATE);
        let fixed = stdfs::read(&state).unwrap();
        let temporary = stdfs::read(f.temp()).ok();
        let unknown = f.a.0.join(".lngnb-key-unknown");
        stdfs::write(&unknown, []).unwrap();
        assert!(f.release(&intent, &mut |_| Ok(())).is_err());
        stdfs::remove_file(unknown).unwrap();
        if temporary.is_some() {
            assert!(f.release(&intent, &mut |_| Ok(())).is_err());
            f.retained();
            stdfs::remove_file(&guard).unwrap();
            assert!(f.release(&intent, &mut |_| Ok(())).is_err());
            assert_eq!(stdfs::read(f.temp()).ok(), temporary);
            assert_eq!(stdfs::read(state).unwrap(), fixed);
            continue;
        }
        for change in 0..5 {
            let mut wrong = intent;
            match change {
                0 => wrong.before.initial.area_id[0] ^= 1,
                1 => wrong.before.initial.snapshot_hash[0] ^= 1,
                2 => wrong.before.snapshot_hash[0] ^= 1,
                3 => wrong.after.generation += 1,
                _ => wrong.operation_id[0] ^= 1,
            }
            assert!(f.release(&wrong, &mut |_| Ok(())).is_err());
        }
        f.retained();
    }
}

#[test]
fn resume_release_rechecks_all_proofs_and_recovers_an_absent_guard() {
    let mut f = Fixture::new(true, 2);
    let intent = f.interrupt(S::OldSnapshotRemoved);
    let last_id = f.ids.pop().unwrap();
    assert!(f.release(&intent, &mut |_| Ok(())).is_err());
    f.ids.push(last_id);
    let pass = std::mem::replace(&mut f.pass, "invalid fixture password".into());
    assert!(f.release(&intent, &mut |_| Ok(())).is_err());
    f.pass = pass;
    let mut proofs: Vec<_> = f
        .ids
        .iter()
        .enumerate()
        .map(|(i, id)| KeyResumePreservation {
            completed_operation_id: *id,
            directory_index: f.indices[i],
            name: &f.names[i],
            passphrase: &f.pass,
        })
        .collect();
    proofs[1].passphrase = "invalid past-preservation fixture password";
    assert!(matches!(
        f.source.as_mut().unwrap().recover_key_resume_release(
            "publisher",
            &f.pass,
            &mut f.backups,
            0,
            "saved",
            &proofs,
            &f.expected,
            &intent,
        ),
        Err(KeyFileError::Key(_))
    ));
    let backup = f.areas[f.indices[1]].0.join(&f.names[1]);
    let hidden = backup.with_extension("hidden");
    stdfs::rename(&backup, &hidden).unwrap();
    assert!(f.release(&intent, &mut |_| Ok(())).is_err());
    stdfs::rename(&hidden, &backup).unwrap();
    // Rename changes the recorded ctime. A fresh fixture is needed for success.
    f.retained();
    let mut f = Fixture::new(true, 2);
    let intent = f.interrupt(S::OldSnapshotRemoved);
    let guard = f.a.0.join(recovery_hold::GUARD);
    let held = stdfs::File::open(&guard).unwrap();
    let fixed = stdfs::read(f.a.0.join(initial_state::STATE)).unwrap();
    f.independent(intent);
    assert_eq!(
        f.release(&intent, &mut |_| Ok(())).unwrap(),
        KeyResumeRelease::RemovedRecordedGuard(intent.after)
    );
    assert_eq!(held.metadata().unwrap().nlink(), 0);
    assert!(!guard.exists());
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        fixed
    );
    f.independent_release(intent);
    f.reopen();
    for point in [G::BeforeDirectorySync, G::DirectorySynced] {
        assert_eq!(
            f.release(&intent, &mut |stage| if stage == point {
                Err(KeyFileError::Io)
            } else {
                Ok(())
            })
            .unwrap_err(),
            KeyFileError::RecoveryGuardReleaseUncertain,
        );
        assert!(!guard.exists());
        f.reopen();
    }
    assert!(f.recover(&intent, &mut |_| Ok(())).is_err());
    assert_eq!(
        f.release(&intent, &mut |_| Ok(())).unwrap(),
        KeyResumeRelease::ConfirmedGuardAbsent(intent.after)
    );
    let source = f.source.as_mut().unwrap();
    e(
        source.create("later", &f.pass),
        KeyFileError::PendingRecovery,
    );
    e(
        source.change_passphrase("publisher", &f.pass, &f.pass),
        KeyFileError::PendingRecovery,
    );
    assert!(
        source
            .initialize_key_state(&intent.before.initial.area_id)
            .is_err()
    );
}

#[test]
fn resume_release_failure_boundaries_require_explicit_retry() {
    for point in [
        G::Qualification(S::CurrentSynced),
        G::Qualification(S::PreservationSynced(0)),
        G::Qualification(S::DirectoriesSynced),
        G::Qualification(S::ControlsSynced),
        G::Qualification(S::Qualified),
        G::BeforeUnlink,
        G::Unlinked,
        G::BeforeDirectorySync,
        G::DirectorySynced,
    ] {
        let mut f = Fixture::new(false, 0);
        let intent = f.interrupt(S::OldSnapshotRemoved);
        let after_unlink = matches!(
            point,
            G::Unlinked | G::BeforeDirectorySync | G::DirectorySynced
        );
        let err = f
            .release(&intent, &mut |stage| {
                if stage == point {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(
            err,
            if after_unlink {
                KeyFileError::RecoveryGuardReleaseUncertain
            } else {
                KeyFileError::Io
            }
        );
        assert_eq!(f.a.0.join(recovery_hold::GUARD).exists(), !after_unlink);
        f.reopen();
        let result = f.release(&intent, &mut |_| Ok(())).unwrap();
        assert_eq!(
            result,
            if after_unlink {
                KeyResumeRelease::ConfirmedGuardAbsent(intent.after)
            } else {
                KeyResumeRelease::RemovedRecordedGuard(intent.after)
            }
        );
        assert!(!f.a.0.join(recovery_hold::GUARD).exists());
    }
}

#[test]
fn resume_release_preserves_replacements_before_and_after_unlink() {
    for point in [G::BeforeUnlink, G::Unlinked, G::DirectorySynced] {
        let mut f = Fixture::new(false, 0);
        let intent = f.interrupt(S::OldSnapshotRemoved);
        let guard = f.a.0.join(recovery_hold::GUARD);
        let saved_guard = guard.with_file_name("saved-guard");
        let bytes = f.guard.clone();
        let err = f
            .release(&intent, &mut |stage| {
                if stage == point {
                    if stage == G::BeforeUnlink {
                        stdfs::rename(&guard, &saved_guard).unwrap();
                    }
                    stdfs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&guard)
                        .unwrap()
                        .write_all(&bytes)
                        .unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            err,
            if point == G::BeforeUnlink {
                KeyFileError::RecoveryChanged
            } else {
                KeyFileError::RecoveryGuardReleaseUncertain
            }
        );
        assert_eq!(stdfs::read(&guard).unwrap(), bytes);
        f.reopen();
        assert!(f.release(&intent, &mut |_| Ok(())).is_err());
        assert_eq!(stdfs::read(&guard).unwrap(), bytes);
    }
}

#[test]
fn resume_release_process_kill_and_lost_response_use_explicit_recovery() {
    if let Some(mut context) = child_context() {
        let source = PathBuf::from(std::env::var_os("LNGNB_PUBLIC_RESUME_SOURCE").unwrap());
        let state = stdfs::read(source.join(initial_state::STATE)).unwrap();
        let mut marker = stdfs::read(source.join(recovery_hold::MARKER)).unwrap();
        marker.truncate(73);
        marker[19] = b'1';
        let initial = context.expected.state.initial;
        let intent = KeyResumeIntent {
            before: context.expected.state,
            after: state_history::decode_history(
                &state,
                &marker,
                initial.area_id,
                initial.snapshot_hash,
            )
            .unwrap(),
            operation_id: context.operation,
        };
        let proofs: Vec<_> = context
            .manifest
            .iter()
            .map(|(id, index, name)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: *index,
                name,
                passphrase: &context.pass,
            })
            .collect();
        let point = std::env::var("LNGNB_PUBLIC_RESUME_POINT").unwrap();
        if point == "FdExhausted" {
            assert!(
                Command::new("prlimit")
                    .args(["--pid", &std::process::id().to_string(), "--nofile=32:32"])
                    .status()
                    .unwrap()
                    .success()
            );
            let mut reserve = Vec::new();
            loop {
                match stdfs::File::open("/dev/null") {
                    Ok(file) => reserve.push(file),
                    Err(error) => {
                        assert_eq!(error.raw_os_error(), Some(24));
                        break;
                    }
                }
            }
            // Permit the initial directory scan, but exhaust fds while holding the state.
            reserve.pop();
            assert!(
                context
                    .source
                    .recover_key_resume_release(
                        "publisher",
                        &context.pass,
                        &mut context.backups,
                        0,
                        "saved",
                        &proofs,
                        &context.expected,
                        &intent,
                    )
                    .is_err()
            );
            return;
        }
        let pause = || {
            println!("READY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        };
        let receipt = context
            .source
            .recover_key_resume_release_with(
                "publisher",
                &context.pass,
                &mut context.backups,
                0,
                "saved",
                &proofs,
                &context.expected,
                &intent,
                &mut |stage| {
                    if format!("{stage:?}") == point {
                        pause();
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            receipt,
            KeyResumeRelease::RemovedRecordedGuard(intent.after)
        );
        // Test the caller's output failure separately from the completed storage result.
        assert!(
            std::io::Write::write_all(&mut stdfs::File::open("/dev/null").unwrap(), b"result")
                .is_err()
        );
        assert_eq!(point, "OutputFailed");
        pause();
    }
    for point in [
        "BeforeUnlink",
        "Unlinked",
        "DirectorySynced",
        "OutputFailed",
        "FdExhausted",
    ] {
        let mut f = Fixture::new(false, 0);
        let intent = f.interrupt(S::OldSnapshotRemoved);
        f.source.take();
        f.backups.clear();
        let mut child = child_command(
            &f,
            "keyfile::files::tests::resume_record_tests::recovery_tests::resume_release_process_kill_and_lost_response_use_explicit_recovery",
        )
        .env("LNGNB_PUBLIC_RESUME_OLD", data_encoding::HEXLOWER.encode(&f.old))
        .env("LNGNB_PUBLIC_RESUME_POINT", point)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().unwrap();
        if point == "FdExhausted" {
            assert!(child.wait_with_output().unwrap().status.success());
            f.reopen();
            f.retained();
            assert_eq!(
                f.release(&intent, &mut |_| Ok(())).unwrap(),
                KeyResumeRelease::RemovedRecordedGuard(intent.after)
            );
            continue;
        }
        let output = std::io::BufReader::new(child.stdout.take().unwrap());
        let ready = output.lines().take(10).any(|line| line.unwrap() == "READY");
        if ready {
            child.kill().unwrap();
        }
        let status = child.wait().unwrap();
        assert!(
            ready && !status.success(),
            "release kill boundary not reached: {point}"
        );
        f.reopen();
        let expected = if point == "BeforeUnlink" {
            KeyResumeRelease::RemovedRecordedGuard(intent.after)
        } else {
            KeyResumeRelease::ConfirmedGuardAbsent(intent.after)
        };
        assert_eq!(
            f.source
                .as_mut()
                .unwrap()
                .recover_key_resume_release(
                    "publisher",
                    &f.pass,
                    &mut f.backups,
                    0,
                    "saved",
                    &[],
                    &f.expected,
                    &intent,
                )
                .unwrap(),
            expected
        );
        f.independent_release(intent);
    }
}

#[test]
fn resume_release_checks_held_state_and_preservations_again_before_unlink() {
    for changed in ["state", "preserved", "guard"] {
        let mut f = Fixture::new(true, 2);
        let intent = f.interrupt(S::OldSnapshotRemoved);
        let guard = f.a.0.join(recovery_hold::GUARD);
        let path = match changed {
            "state" => f.a.0.join(initial_state::STATE),
            "preserved" => f.areas[f.indices[1]].0.join(&f.names[1]),
            _ => guard.clone(),
        };
        let mut bytes = stdfs::read(&path).unwrap();
        let saved = path.with_file_name("release-kept");
        let error = f
            .release(&intent, &mut |stage| {
                if stage == G::BeforeUnlink {
                    if changed == "guard" {
                        bytes[0] ^= 1;
                        stdfs::write(&path, &bytes).unwrap();
                    } else {
                        stdfs::rename(&path, &saved).unwrap();
                        stdfs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&path)
                            .unwrap()
                            .write_all(&bytes)
                            .unwrap();
                    }
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, KeyFileError::RecoveryChanged);
        assert_eq!(stdfs::read(&path).unwrap(), bytes);
        assert!(guard.exists());
    }
}

#[test]
fn resume_release_accepts_full_inventory_but_rejects_over_limit() {
    let mut f = Fixture::new(false, 0);
    let intent = f.interrupt(S::OldSnapshotRemoved);
    for i in stdfs::read_dir(&f.a.0).unwrap().count()..10_000 {
        stdfs::write(f.a.0.join(format!("ordinary-{i}")), []).unwrap();
    }
    let excess = f.a.0.join("excess");
    stdfs::write(&excess, []).unwrap();
    assert_eq!(
        f.release(&intent, &mut |_| Ok(())).unwrap_err(),
        KeyFileError::ScanLimit
    );
    f.retained();
    stdfs::remove_file(excess).unwrap();
    assert_eq!(
        f.release(&intent, &mut |_| Ok(())).unwrap(),
        KeyResumeRelease::RemovedRecordedGuard(intent.after)
    );
    assert_eq!(stdfs::read_dir(&f.a.0).unwrap().count(), 9_999);
}
