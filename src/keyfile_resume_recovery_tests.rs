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
