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

impl Fixture {
    fn prepare_passphrase_change(
        &mut self,
        intent: &KeyResumeIntent,
        new_passphrase: &str,
    ) -> Result<PreparedFirstPassphraseChange<'_>> {
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
            .prepare_first_passphrase_change(
                "publisher",
                &self.pass,
                new_passphrase,
                &mut self.backups,
                0,
                "saved",
                &proofs,
                &self.expected,
                intent,
            )
    }
}

#[test]
fn first_passphrase_preparation_keeps_files_and_rechecks_preservation() {
    let mut f = Fixture::new(true, 2);
    let intent = f.interrupt(S::OldSnapshotRemoved);
    let guard = f.a.0.join(recovery_hold::GUARD);
    let fixed = f.a.0.join(initial_state::STATE);
    let marker = f.a.0.join(recovery_hold::MARKER);
    let publisher = f.a.0.join("publisher");
    let backup = f.areas[0].0.join("saved");
    let before = stdfs::read(&fixed).unwrap();
    let marker_before = stdfs::read(&marker).unwrap();
    let key_before = stdfs::read(&publisher).unwrap();
    let backup_before = stdfs::read(&backup).unwrap();
    let new_passphrase = "different public passphrase";
    assert!(
        f.prepare_passphrase_change(&intent, new_passphrase)
            .is_err()
    );
    assert!(guard.exists());
    f.release(&intent, &mut |_| Ok(())).unwrap();
    let mut stale = intent;
    stale.after.snapshot_hash[0] ^= 1;
    assert!(f.prepare_passphrase_change(&stale, new_passphrase).is_err());
    assert!(f.prepare_passphrase_change(&intent, "").is_err());
    let old = std::mem::replace(&mut f.pass, "wrong public passphrase".into());
    assert!(
        f.prepare_passphrase_change(&intent, new_passphrase)
            .is_err()
    );
    f.pass = old;
    let missing = f.ids.pop().unwrap();
    assert!(
        f.prepare_passphrase_change(&intent, new_passphrase)
            .is_err()
    );
    f.ids.push(missing);
    let unexpected = f.a.0.join(".lngnb-key-unknown");
    stdfs::write(&unexpected, []).unwrap();
    assert!(
        f.prepare_passphrase_change(&intent, new_passphrase)
            .is_err()
    );
    stdfs::remove_file(unexpected).unwrap();
    {
        let old_hash = f.expected.ciphertext_sha256;
        let prepared = f
            .prepare_passphrase_change(&intent, new_passphrase)
            .unwrap();
        let (length, hash) = prepared.new_ciphertext_metadata();
        assert!((1..=4096).contains(&length));
        assert_ne!(hash, old_hash);
        prepared.recheck().unwrap();
        // 同じbytesの書き戻しでも、記録済みidentityが変われば失効。
        let moved = backup.with_extension("old");
        stdfs::rename(&backup, &moved).unwrap();
        stdfs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)
            .unwrap()
            .write_all(&backup_before)
            .unwrap();
        assert!(prepared.recheck().is_err());
    }
    assert!(!guard.exists());
    assert_eq!(stdfs::read(&fixed).unwrap(), before);
    assert_eq!(stdfs::read(&marker).unwrap(), marker_before);
    assert_eq!(stdfs::read(&publisher).unwrap(), key_before);
    assert_eq!(stdfs::read(&backup).unwrap(), backup_before);
    assert_eq!(
        f.source
            .as_mut()
            .unwrap()
            .change_passphrase("publisher", &f.pass, new_passphrase)
            .err(),
        Some(KeyFileError::PendingRecovery),
    );
}

#[test]
fn first_passphrase_preparation_requires_two_directory_slots() {
    let mut f = Fixture::new(false, 0);
    let intent = f.interrupt(S::OldSnapshotRemoved);
    f.release(&intent, &mut |_| Ok(())).unwrap();
    let path = f.a.0.clone();
    let entries = stdfs::read_dir(&path).unwrap().count();
    for index in entries..10_000 - 2 {
        stdfs::write(path.join(format!("filler-{index}")), []).unwrap();
    }
    let prepared = f
        .prepare_passphrase_change(&intent, "new public passphrase")
        .unwrap();
    let extra = path.join("one-slot-left");
    stdfs::write(&extra, []).unwrap();
    assert_eq!(prepared.recheck().err(), Some(KeyFileError::ScanLimit));
    drop(prepared);
    assert_eq!(
        f.prepare_passphrase_change(&intent, "new public passphrase")
            .err(),
        Some(KeyFileError::ScanLimit),
    );
    assert!(!path.join(recovery_hold::GUARD).exists());
    assert_eq!(stdfs::read_dir(&path).unwrap().count(), 9_999);
}

impl Fixture {
    fn recover_passphrase_start(
        &mut self,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
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
        self.source.as_mut().unwrap().recover_key_passphrase_start(
            "publisher",
            &self.pass,
            &mut self.backups,
            0,
            "saved",
            &proofs,
            &self.expected,
            resume,
            start,
        )
    }
}

#[test]
fn passphrase_start_record_and_recovery_keep_guard_and_original_key() {
    for stage in [
        None,
        Some(S::Prepared),
        Some(S::Exchanged),
        Some(S::OldSnapshotRemoved),
    ] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let source = f.a.0.clone();
        let publisher = source.join("publisher");
        let before = stdfs::read(&publisher).unwrap();
        let mut prepared = f
            .prepare_passphrase_change(&resume, "new public passphrase")
            .unwrap()
            .prepare_start()
            .unwrap();
        let intent = prepared.intent();
        assert_eq!(intent.before, resume.after);
        let result = prepared.record_with(&mut |step| {
            if stage == Some(step) {
                Err(KeyFileError::Io)
            } else {
                Ok(())
            }
        });
        if stage.is_some() {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), intent.after);
        }
        drop(prepared);
        f.reopen();
        let mut wrong = intent;
        wrong.after.snapshot_hash[0] ^= 1;
        assert!(f.recover_passphrase_start(&resume, &wrong).is_err());
        assert_eq!(
            f.recover_passphrase_start(&resume, &intent).unwrap(),
            intent.after
        );
        assert_eq!(stdfs::read(&publisher).unwrap(), before);
        assert!(source.join(recovery_hold::GUARD).exists());
        let journal_temp = source.join(format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        ));
        let key_temp = source.join(format!(
            ".lngnb-key-passphrase-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        ));
        assert!(!journal_temp.exists());
        assert!(!key_temp.exists());
        stdfs::write(&key_temp, []).unwrap();
        assert!(f.recover_passphrase_start(&resume, &intent).is_err());
        assert!(key_temp.exists());
    }
}

#[test]
fn passphrase_start_recovery_rejects_missing_partial_and_replaced_guard() {
    for failure in 0..3 {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let source = f.a.0.clone();
        let mut prepared = f
            .prepare_passphrase_change(&resume, "new public passphrase")
            .unwrap()
            .prepare_start()
            .unwrap();
        let intent = prepared.intent();
        if failure == 0 {
            drop(prepared);
        } else {
            let stage = if failure == 1 {
                S::Created
            } else {
                S::Prepared
            };
            assert!(
                prepared
                    .record_with(&mut |step| if step == stage {
                        Err(KeyFileError::Io)
                    } else {
                        Ok(())
                    })
                    .is_err()
            );
            drop(prepared);
        }
        let guard = source.join(recovery_hold::GUARD);
        if failure == 2 {
            let original = stdfs::read(&guard).unwrap();
            stdfs::rename(&guard, source.join("retained-guard")).unwrap();
            stdfs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&guard)
                .unwrap()
                .write_all(&original)
                .unwrap();
        }
        let state = source.join(initial_state::STATE);
        let fixed = stdfs::read(&state).unwrap();
        f.reopen();
        assert!(f.recover_passphrase_start(&resume, &intent).is_err());
        assert!(guard.exists());
        assert_eq!(stdfs::read(&state).unwrap(), fixed);
    }
}

#[test]
fn passphrase_start_guard_interruption_keeps_fixed_ready_and_stops_retry() {
    for boundary in [S::StartGuardCreated, S::StartGuardSynced] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let source = f.a.0.clone();
        let state = source.join(initial_state::STATE);
        let before = stdfs::read(&state).unwrap();
        let prepared = f
            .prepare_passphrase_change(&resume, "new public passphrase")
            .unwrap();
        let failed = prepared.prepare_start_with(&mut |stage| {
            if stage == boundary {
                Err(KeyFileError::Io)
            } else {
                Ok(())
            }
        });
        assert_eq!(failed.err(), Some(KeyFileError::RecoveryHoldUncertain));
        f.reopen();
        assert!(
            f.prepare_passphrase_change(&resume, "new public passphrase")
                .is_err()
        );
        assert!(source.join(recovery_hold::GUARD).exists());
        assert_eq!(stdfs::read(&state).unwrap(), before);
    }
}

impl Fixture {
    fn recover_passphrase_prepared(
        &mut self,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        passphrase: &str,
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
            .recover_key_passphrase_prepared(
                "publisher",
                &self.pass,
                passphrase,
                &mut self.backups,
                0,
                "saved",
                &proofs,
                &self.expected,
                resume,
                start,
                prepared,
            )
    }
}

#[test]
fn passphrase_prepared_record_recovers_only_complete_layouts() {
    const NEW_PASS: &str = "new public passphrase";
    for stage in [
        None,
        Some(S::Created),
        Some(S::Written),
        Some(S::Prepared),
        Some(S::Exchanged),
        Some(S::OldSnapshotRemoved),
    ] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let path = f.a.0.clone();
        let old = stdfs::read(path.join("publisher")).unwrap();
        let mut start = f
            .prepare_passphrase_change(&resume, NEW_PASS)
            .unwrap()
            .prepare_start()
            .unwrap();
        let started = start.intent();
        start.record().unwrap();
        assert!(start.record().is_err());
        let prepared = start.prepare_ciphertext(NEW_PASS).unwrap();
        let intent = prepared.intent();
        let key_path = path.join(format!(
            ".lngnb-key-passphrase-{}",
            data_encoding::HEXLOWER.encode(&started.operation_id)
        ));
        let staged = stdfs::read(&key_path).unwrap();
        let result = prepared.record_with(&mut |step| {
            if stage == Some(step) {
                Err(KeyFileError::Io)
            } else {
                Ok(())
            }
        });
        if stage.is_some() {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), intent.after);
        }
        f.reopen();
        if stage == Some(S::Created) {
            assert!(
                f.recover_passphrase_prepared(&resume, &started, &intent, NEW_PASS)
                    .is_err()
            );
            assert_eq!(stdfs::read(path.join("publisher")).unwrap(), old);
            assert_eq!(stdfs::read(&key_path).unwrap(), staged);
            assert!(path.join(recovery_hold::GUARD).exists());
            continue;
        }
        assert!(f.recover_passphrase_start(&resume, &started).is_err());
        assert!(
            f.recover_passphrase_prepared(&resume, &started, &intent, "wrong public passphrase")
                .is_err()
        );
        let mut wrong = intent;
        wrong.after.snapshot_hash[0] ^= 1;
        assert!(
            f.recover_passphrase_prepared(&resume, &started, &wrong, NEW_PASS)
                .is_err()
        );
        assert_eq!(
            f.recover_passphrase_prepared(&resume, &started, &intent, NEW_PASS)
                .unwrap(),
            intent.after
        );
        assert_eq!(
            f.recover_passphrase_prepared(&resume, &started, &intent, NEW_PASS)
                .unwrap(),
            intent.after
        );
        assert_eq!(stdfs::read(path.join("publisher")).unwrap(), old);
        assert_eq!(stdfs::read(&key_path).unwrap(), staged);
        assert!(path.join(recovery_hold::GUARD).exists());
        let displaced = path.join("displaced");
        stdfs::rename(&key_path, &displaced).unwrap();
        stdfs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap()
            .write_all(&staged)
            .unwrap();
        assert!(
            f.recover_passphrase_prepared(&resume, &started, &intent, NEW_PASS)
                .is_err()
        );
        assert_eq!(stdfs::read(&key_path).unwrap(), staged);
    }
}

#[test]
fn passphrase_staging_interruption_keeps_old_key_and_guard() {
    const NEW_PASS: &str = "new public passphrase";
    for stage in [
        S::StagedKeyCreated,
        S::StagedKeyWritten,
        S::StagedKeyFileSynced,
        S::StagedKeyDirectorySynced,
    ] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let path = f.a.0.clone();
        let old = stdfs::read(path.join("publisher")).unwrap();
        let mut start = f
            .prepare_passphrase_change(&resume, NEW_PASS)
            .unwrap()
            .prepare_start()
            .unwrap();
        let intent = start.intent();
        start.record().unwrap();
        assert_eq!(
            start
                .prepare_ciphertext_with(NEW_PASS, &mut |step| {
                    if step == stage {
                        Err(KeyFileError::Io)
                    } else {
                        Ok(())
                    }
                })
                .err(),
            Some(KeyFileError::RecoveryStateUncertain)
        );
        f.reopen();
        assert!(f.recover_passphrase_start(&resume, &intent).is_err());
        assert_eq!(stdfs::read(path.join("publisher")).unwrap(), old);
        assert!(path.join(recovery_hold::GUARD).exists());
    }
}

impl Fixture {
    fn exchange_passphrase(
        &mut self,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        passphrase: &str,
        hook: &mut impl FnMut(S) -> Result<()>,
    ) -> Result<KeyPassphraseExchange> {
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
        self.source.as_mut().unwrap().exchange_key_passphrase_with(
            "publisher",
            &self.pass,
            passphrase,
            &mut self.backups,
            0,
            "saved",
            &proofs,
            &self.expected,
            resume,
            start,
            prepared,
            hook,
        )
    }
}

#[test]
fn passphrase_key_exchange_retries_without_reversing_and_retains_both_keys() {
    const NEW_PASS: &str = "new public passphrase";
    if let Some(mut context) = child_context() {
        let path = PathBuf::from(std::env::var_os("LNGNB_PUBLIC_RESUME_SOURCE").unwrap());
        let mut marker = stdfs::read(path.join(recovery_hold::MARKER)).unwrap();
        marker.truncate(73);
        marker[19] = b'1';
        let initial = context.expected.state.initial;
        let decode = |snapshot: &Value| {
            state_history::decode_history(
                &cbor::encode(snapshot).unwrap(),
                &marker,
                initial.area_id,
                initial.snapshot_hash,
            )
            .unwrap()
        };
        let last_id = |snapshot: &Value| {
            let Value::Bytes(id) =
                crate::keyfile::get(events(snapshot).last().unwrap(), "operation_id").unwrap()
            else {
                panic!("fixture operation ID");
            };
            id.as_slice().try_into().unwrap()
        };
        let pop = |snapshot: &mut Value| {
            let mut prefix = events(snapshot).to_vec();
            prefix.pop().unwrap();
            set(snapshot, "events", Value::Array(prefix));
        };
        let mut snapshot =
            cbor::decode(&stdfs::read(path.join(initial_state::STATE)).unwrap()).unwrap();
        let prepared_after = decode(&snapshot);
        let prepared_id = last_id(&snapshot);
        pop(&mut snapshot);
        let started_after = decode(&snapshot);
        let start_id = last_id(&snapshot);
        pop(&mut snapshot);
        let ready = decode(&snapshot);
        context.expected.guard =
            state_history::recorded_guard_identity(events(&snapshot).last().unwrap()).unwrap();
        let resume = KeyResumeIntent {
            before: context.expected.state,
            after: ready,
            operation_id: last_id(&snapshot),
        };
        let start = KeyPassphraseStartIntent {
            before: ready,
            after: started_after,
            operation_id: start_id,
        };
        let prepared = KeyPassphrasePreparedIntent {
            before: started_after,
            after: prepared_after,
            operation_id: prepared_id,
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
        let pause = || {
            println!("READY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        };
        let mut hook = |stage| {
            if format!("{stage:?}") == point {
                pause();
            }
            Ok(())
        };
        if let Ok(ctime) = std::env::var("LNGNB_PUBLIC_CLEANUP_OLD_CTIME") {
            let (seconds, nanoseconds) = ctime.split_once(':').unwrap();
            let temporary = path.join(format!(
                ".lngnb-key-passphrase-{}",
                data_encoding::HEXLOWER.encode(&start_id)
            ));
            context.expected.current = identity(&temporary);
            context.expected.current.ctime_seconds = seconds.parse().unwrap();
            context.expected.current.ctime_nanoseconds = nanoseconds.parse().unwrap();
            context.expected.ciphertext_sha256 =
                Sha256::digest(stdfs::read(&temporary).unwrap()).into();
            if std::env::var_os("LNGNB_PUBLIC_COMPLETE_PASSPHRASE").is_some() {
                let completion = context
                    .source
                    .prepare_key_passphrase_completion(
                        "publisher",
                        &context.pass,
                        NEW_PASS,
                        &mut context.backups,
                        0,
                        "saved",
                        &proofs,
                        &context.expected,
                        &resume,
                        &start,
                        &prepared,
                    )
                    .unwrap();
                let intent = completion.intent();
                println!(
                    "INTENT {} {}",
                    data_encoding::HEXLOWER.encode(&intent.operation_id),
                    data_encoding::HEXLOWER.encode(&intent.after.snapshot_hash)
                );
                std::io::stdout().flush().unwrap();
                assert_eq!(completion.record_with(&mut hook).unwrap(), intent.after);
            } else {
                assert_eq!(
                    context
                        .source
                        .cleanup_key_passphrase_with(
                            "publisher",
                            &context.pass,
                            NEW_PASS,
                            &mut context.backups,
                            0,
                            "saved",
                            &proofs,
                            &context.expected,
                            &resume,
                            &start,
                            &prepared,
                            &mut hook,
                        )
                        .unwrap(),
                    KeyPassphraseCleanup::RemovedRetainedOldCiphertext
                );
            }
        } else {
            assert_eq!(
                context
                    .source
                    .exchange_key_passphrase_with(
                        "publisher",
                        &context.pass,
                        NEW_PASS,
                        &mut context.backups,
                        0,
                        "saved",
                        &proofs,
                        &context.expected,
                        &resume,
                        &start,
                        &prepared,
                        &mut hook,
                    )
                    .unwrap(),
                KeyPassphraseExchange::Exchanged
            );
        }
        assert_eq!(point, "OutputFailed");
        assert!(
            stdfs::File::open("/dev/null")
                .unwrap()
                .write_all(b"result")
                .is_err()
        );
        pause();
    }
    for (stage, kill) in [
        (None, None),
        (Some(S::BeforeKeyExchange), None),
        (Some(S::KeyExchanged), None),
        (Some(S::KeyExchangeDirectorySynced), None),
        (Some(S::BeforeKeyExchange), Some("BeforeKeyExchange")),
        (Some(S::KeyExchanged), Some("KeyExchanged")),
        (
            Some(S::KeyExchangeDirectorySynced),
            Some("KeyExchangeDirectorySynced"),
        ),
        (None, Some("OutputFailed")),
    ] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let path = f.a.0.clone();
        let normal = path.join("publisher");
        let old = stdfs::read(&normal).unwrap();
        let mut begin = f
            .prepare_passphrase_change(&resume, NEW_PASS)
            .unwrap()
            .prepare_start()
            .unwrap();
        let start = begin.intent();
        begin.record().unwrap();
        let record = begin.prepare_ciphertext(NEW_PASS).unwrap();
        let prepared = record.intent();
        record.record().unwrap();
        let temporary = path.join(format!(
            ".lngnb-key-passphrase-{}",
            data_encoding::HEXLOWER.encode(&start.operation_id)
        ));
        let new = stdfs::read(&temporary).unwrap();
        let state = stdfs::read(path.join(initial_state::STATE)).unwrap();
        let mut wrong = prepared;
        wrong.after.snapshot_hash[0] ^= 1;
        assert!(
            f.exchange_passphrase(&resume, &start, &wrong, NEW_PASS, &mut |_| Ok(()))
                .is_err()
        );
        assert!(
            f.exchange_passphrase(
                &resume,
                &start,
                &prepared,
                "wrong public passphrase",
                &mut |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(stdfs::read(&normal).unwrap(), old);
        if let Some(point) = kill {
            f.source.take();
            f.backups.clear();
            let mut child = child_command(
                &f,
                "keyfile::files::tests::resume_record_tests::recovery_tests::passphrase_key_exchange_retries_without_reversing_and_retains_both_keys",
            )
            .env("LNGNB_PUBLIC_RESUME_OLD", data_encoding::HEXLOWER.encode(&f.old))
            .env("LNGNB_PUBLIC_RESUME_POINT", point)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn().unwrap();
            let output = std::io::BufReader::new(child.stdout.take().unwrap());
            let ready = output.lines().take(10).any(|line| line.unwrap() == "READY");
            if ready {
                child.kill().unwrap();
            }
            let result = child.wait_with_output().unwrap();
            assert!(
                ready && !result.status.success(),
                "{point}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        } else {
            let first = f.exchange_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |point| {
                if stage == Some(point) {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            });
            match stage {
                None => assert_eq!(first.unwrap(), KeyPassphraseExchange::Exchanged),
                Some(S::BeforeKeyExchange) => assert_eq!(first.err(), Some(KeyFileError::Io)),
                _ => assert_eq!(first.err(), Some(KeyFileError::CommitUncertain)),
            }
        }
        f.reopen();
        let result = f
            .exchange_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(
            result,
            if stage == Some(S::BeforeKeyExchange) {
                KeyPassphraseExchange::Exchanged
            } else {
                KeyPassphraseExchange::ConfirmedExchanged
            }
        );
        assert_eq!(stdfs::read(&normal).unwrap(), new);
        assert_eq!(stdfs::read(&temporary).unwrap(), old);
        assert_eq!(stdfs::read(path.join(initial_state::STATE)).unwrap(), state);
        assert!(path.join(recovery_hold::GUARD).exists());
        assert!(
            f.recover_passphrase_prepared(&resume, &start, &prepared, NEW_PASS)
                .is_err()
        );
        let displaced = path.join("displaced-old");
        stdfs::rename(&temporary, &displaced).unwrap();
        assert!(
            f.exchange_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
                .is_err()
        );
        stdfs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .unwrap()
            .write_all(&old)
            .unwrap();
        assert!(
            f.exchange_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
                .is_err()
        );
        assert_eq!(stdfs::read(&normal).unwrap(), new);
        assert_eq!(stdfs::read(&temporary).unwrap(), old);
    }
}

impl Fixture {
    fn cleanup_passphrase(
        &mut self,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        passphrase: &str,
        hook: &mut impl FnMut(S) -> Result<()>,
    ) -> Result<KeyPassphraseCleanup> {
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
        self.source.as_mut().unwrap().cleanup_key_passphrase_with(
            "publisher",
            &self.pass,
            passphrase,
            &mut self.backups,
            0,
            "saved",
            &proofs,
            &self.expected,
            resume,
            start,
            prepared,
            hook,
        )
    }
}

#[test]
fn passphrase_old_ciphertext_cleanup_rechecks_absence_and_keeps_guard() {
    const NEW_PASS: &str = "new public passphrase";
    for (point, kill) in [
        (None, None),
        (Some(S::BeforeOldKeyUnlink), None),
        (Some(S::OldKeyUnlinked), None),
        (Some(S::BeforeOldKeyDirectorySync), None),
        (Some(S::OldKeyDirectorySynced), None),
        (Some(S::BeforeOldKeyUnlink), Some("BeforeOldKeyUnlink")),
        (Some(S::OldKeyUnlinked), Some("OldKeyUnlinked")),
        (
            Some(S::BeforeOldKeyDirectorySync),
            Some("BeforeOldKeyDirectorySync"),
        ),
        (
            Some(S::OldKeyDirectorySynced),
            Some("OldKeyDirectorySynced"),
        ),
        (None, Some("OutputFailed")),
    ] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let path = f.a.0.clone();
        let normal = path.join("publisher");
        let old = stdfs::read(&normal).unwrap();
        let mut begin = f
            .prepare_passphrase_change(&resume, NEW_PASS)
            .unwrap()
            .prepare_start()
            .unwrap();
        let start = begin.intent();
        begin.record().unwrap();
        let record = begin.prepare_ciphertext(NEW_PASS).unwrap();
        let prepared = record.intent();
        record.record().unwrap();
        let temporary = path.join(format!(
            ".lngnb-key-passphrase-{}",
            data_encoding::HEXLOWER.encode(&start.operation_id)
        ));
        let new = stdfs::read(&temporary).unwrap();
        let state = stdfs::read(path.join(initial_state::STATE)).unwrap();
        let guard = stdfs::read(path.join(recovery_hold::GUARD)).unwrap();
        assert!(
            f.cleanup_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
                .is_err()
        );
        assert_eq!(stdfs::read(&normal).unwrap(), old);
        f.exchange_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
            .unwrap();
        assert!(
            f.cleanup_passphrase(
                &resume,
                &start,
                &prepared,
                "wrong public passphrase",
                &mut |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(stdfs::read(&temporary).unwrap(), old);
        if let Some(stage) = kill {
            f.source.take();
            f.backups.clear();
            let mut child = child_command(
                &f,
                "keyfile::files::tests::resume_record_tests::recovery_tests::passphrase_key_exchange_retries_without_reversing_and_retains_both_keys",
            )
            .env("LNGNB_PUBLIC_RESUME_OLD", data_encoding::HEXLOWER.encode(&f.old))
            .env("LNGNB_PUBLIC_RESUME_POINT", stage)
            .env("LNGNB_PUBLIC_CLEANUP_OLD_CTIME", format!("{}:{}", f.expected.current.ctime_seconds, f.expected.current.ctime_nanoseconds))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn().unwrap();
            let output = std::io::BufReader::new(child.stdout.take().unwrap());
            let ready = output.lines().take(10).any(|line| line.unwrap() == "READY");
            if ready {
                child.kill().unwrap();
            }
            let result = child.wait_with_output().unwrap();
            assert!(
                ready && !result.status.success(),
                "{stage}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        } else {
            let first = f.cleanup_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |stage| {
                if point == Some(stage) {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            });
            match point {
                None => assert_eq!(
                    first.unwrap(),
                    KeyPassphraseCleanup::RemovedRetainedOldCiphertext
                ),
                Some(S::BeforeOldKeyUnlink) => assert_eq!(first.err(), Some(KeyFileError::Io)),
                _ => assert_eq!(first.err(), Some(KeyFileError::CleanupUncertain)),
            }
        }
        f.reopen();
        let second = f
            .cleanup_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(
            second,
            if point == Some(S::BeforeOldKeyUnlink) {
                KeyPassphraseCleanup::RemovedRetainedOldCiphertext
            } else {
                KeyPassphraseCleanup::ConfirmedOldCiphertextAbsent
            }
        );
        assert_eq!(stdfs::read(&normal).unwrap(), new);
        assert_eq!(stdfs::read(path.join(initial_state::STATE)).unwrap(), state);
        assert_eq!(stdfs::read(path.join(recovery_hold::GUARD)).unwrap(), guard);
        assert!(!temporary.exists());

        // 再確認のfsync境界で同じbytesの別inodeが再出現しても削除しない。
        assert!(
            f.cleanup_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |stage| {
                if stage == S::Qualified {
                    stdfs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&temporary)
                        .unwrap()
                        .write_all(&old)
                        .unwrap();
                }
                Ok(())
            })
            .is_err()
        );
        assert!(
            f.cleanup_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
                .is_err()
        );
        assert_eq!(stdfs::read(&temporary).unwrap(), old);
    }
}

impl Fixture {
    fn prepare_passphrase_completion(
        &mut self,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        new_passphrase: &str,
    ) -> Result<PreparedKeyPassphraseCompletion<'_>> {
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
            .prepare_key_passphrase_completion(
                "publisher",
                &self.pass,
                new_passphrase,
                &mut self.backups,
                0,
                "saved",
                &proofs,
                &self.expected,
                resume,
                start,
                prepared,
            )
    }

    fn recover_passphrase_completed(
        &mut self,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        completed: &KeyPassphraseCompletedIntent,
        new_passphrase: &str,
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
            .recover_key_passphrase_completed(
                "publisher",
                &self.pass,
                new_passphrase,
                &mut self.backups,
                0,
                "saved",
                &proofs,
                &self.expected,
                resume,
                start,
                prepared,
                completed,
            )
    }
}

#[test]
fn passphrase_completion_preserves_disposition_and_recovers_complete_candidates() {
    const NEW_PASS: &str = "new public passphrase";
    for (point, initially_absent, kill) in [
        (None, false, None),
        (Some(S::Prepared), false, None),
        (Some(S::Exchanged), true, None),
        (Some(S::OldSnapshotRemoved), true, None),
        (Some(S::Created), false, None),
        (Some(S::Created), false, Some("Created")),
        (Some(S::Prepared), false, Some("Prepared")),
        (Some(S::Exchanged), false, Some("Exchanged")),
        (
            Some(S::OldSnapshotRemoved),
            false,
            Some("OldSnapshotRemoved"),
        ),
        (None, false, Some("OutputFailed")),
    ] {
        let mut f = Fixture::new(false, 0);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let path = f.a.0.clone();
        let mut begin = f
            .prepare_passphrase_change(&resume, NEW_PASS)
            .unwrap()
            .prepare_start()
            .unwrap();
        let start = begin.intent();
        begin.record().unwrap();
        let record = begin.prepare_ciphertext(NEW_PASS).unwrap();
        let prepared = record.intent();
        record.record().unwrap();
        assert!(
            f.prepare_passphrase_completion(&resume, &start, &prepared, NEW_PASS)
                .is_err()
        );
        f.exchange_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
            .unwrap();
        let normal = path.join("publisher");
        let new = stdfs::read(&normal).unwrap();
        let guard = stdfs::read(path.join(recovery_hold::GUARD)).unwrap();
        if initially_absent {
            f.cleanup_passphrase(&resume, &start, &prepared, NEW_PASS, &mut |_| Ok(()))
                .unwrap();
        }
        let intent = if let Some(stage) = kill {
            f.source.take();
            f.backups.clear();
            let mut child = child_command(
                &f,
                "keyfile::files::tests::resume_record_tests::recovery_tests::passphrase_key_exchange_retries_without_reversing_and_retains_both_keys",
            )
            .env("LNGNB_PUBLIC_RESUME_OLD", data_encoding::HEXLOWER.encode(&f.old))
            .env("LNGNB_PUBLIC_RESUME_POINT", stage)
            .env("LNGNB_PUBLIC_COMPLETE_PASSPHRASE", "1")
            .env("LNGNB_PUBLIC_CLEANUP_OLD_CTIME", format!("{}:{}", f.expected.current.ctime_seconds, f.expected.current.ctime_nanoseconds))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn().unwrap();
            let output = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut intent = None;
            let ready = output.lines().take(10).any(|line| {
                let line = line.unwrap();
                if let Some(fields) = line.strip_prefix("INTENT ") {
                    let (id, hash) = fields.split_once(' ').unwrap();
                    let decode = |hex: &str| {
                        data_encoding::HEXLOWER
                            .decode(hex.as_bytes())
                            .unwrap()
                            .try_into()
                            .unwrap()
                    };
                    let operation_id = decode(id);
                    intent = Some(KeyPassphraseCompletedIntent {
                        before: prepared.after,
                        after: KeyStateDiagnostic {
                            initial: prepared.after.initial,
                            generation: prepared.after.generation + 1,
                            snapshot_hash: decode(hash),
                            state: KeyHistoryState::PassphraseChangeCompleted {
                                completed_operation_id: operation_id,
                            },
                        },
                        operation_id,
                    });
                }
                line == "READY"
            });
            if ready {
                child.kill().unwrap();
            }
            let result = child.wait_with_output().unwrap();
            assert!(
                ready && !result.status.success(),
                "{stage}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            intent.unwrap()
        } else {
            let completion = f
                .prepare_passphrase_completion(&resume, &start, &prepared, NEW_PASS)
                .unwrap();
            let intent = completion.intent();
            let result = completion.record_with(&mut |stage| {
                if point == Some(stage) {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            });
            if point.is_none() {
                assert_eq!(result.unwrap(), intent.after);
            } else {
                assert!(result.is_err());
            }
            intent
        };
        f.reopen();
        let mut wrong = intent;
        wrong.after.snapshot_hash[0] ^= 1;
        assert!(
            f.recover_passphrase_completed(&resume, &start, &prepared, &wrong, NEW_PASS)
                .is_err()
        );
        assert!(
            f.recover_passphrase_completed(
                &resume,
                &start,
                &prepared,
                &intent,
                "wrong public passphrase"
            )
            .is_err()
        );
        let recovered =
            f.recover_passphrase_completed(&resume, &start, &prepared, &intent, NEW_PASS);
        if point == Some(S::Created) {
            assert!(recovered.is_err());
        } else {
            assert_eq!(recovered.unwrap(), intent.after);
            let snapshot =
                cbor::decode(&stdfs::read(path.join(initial_state::STATE)).unwrap()).unwrap();
            let disposition = if initially_absent {
                "confirmed_old_ciphertext_absent"
            } else {
                "removed_retained_old_ciphertext"
            };
            assert_eq!(
                crate::keyfile::get(events(&snapshot).last().unwrap(), "disposition").unwrap(),
                &Value::Text(disposition.to_owned()),
            );
            assert_eq!(
                f.recover_passphrase_completed(&resume, &start, &prepared, &intent, NEW_PASS)
                    .unwrap(),
                intent.after
            );
            let old_name = path.join(format!(
                ".lngnb-key-passphrase-{}",
                data_encoding::HEXLOWER.encode(&start.operation_id)
            ));
            stdfs::write(&old_name, &new).unwrap();
            assert!(
                f.recover_passphrase_completed(&resume, &start, &prepared, &intent, NEW_PASS)
                    .is_err()
            );
            assert_eq!(stdfs::read(old_name).unwrap(), new);
        }
        assert_eq!(stdfs::read(normal).unwrap(), new);
        assert_eq!(stdfs::read(path.join(recovery_hold::GUARD)).unwrap(), guard);
    }
}
