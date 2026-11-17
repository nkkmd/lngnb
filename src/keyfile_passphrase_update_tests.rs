//! 公開fixtureと隔離領域を使う初回更新の接続試験。
use super::*;

impl Fixture {
    fn change_first(
        &mut self,
        resume: &KeyResumeIntent,
        output: &mut impl std::io::Write,
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
        self.source.as_mut().unwrap().change_first_key_passphrase(
            "publisher",
            &self.pass,
            "different public passphrase",
            &mut self.backups,
            0,
            "saved",
            &proofs,
            resume,
            output,
        )
    }
}

#[test]
fn first_passphrase_update_flushes_before_every_append() {
    struct Receipts {
        stage: usize,
        fail: usize,
        fail_write: bool,
        bytes: Vec<u8>,
    }
    impl std::io::Write for Receipts {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write && self.stage == self.fail {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.bytes.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.stage == self.fail {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.stage += 1;
            Ok(())
        }
    }
    for (fail, fail_write) in [
        (0, false),
        (1, false),
        (2, false),
        (0, true),
        (1, true),
        (2, true),
        (3, false),
    ] {
        let mut f = Fixture::new(true, 1);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let backup = f.areas[0].0.join("saved");
        let old = stdfs::read(&backup).unwrap();
        let guard = f.a.0.join(recovery_hold::GUARD);
        let mut output = Receipts {
            stage: 0,
            fail,
            fail_write,
            bytes: Vec::new(),
        };
        let result = f.change_first(&resume, &mut output);
        assert_eq!(output.stage, fail);
        f.reopen();
        let marker = stdfs::read(f.a.0.join(recovery_hold::MARKER)).unwrap();
        let mut source_marker = marker[..73].to_vec();
        source_marker[19] = b'1';
        let snapshot = stdfs::read(f.a.0.join(initial_state::STATE)).unwrap();
        let state = state_history::decode_history(
            &snapshot,
            &source_marker,
            resume.after.initial.area_id,
            resume.after.initial.snapshot_hash,
        )
        .unwrap();
        let source = f.source.as_ref().unwrap();
        assert_eq!(
            source
                .key_passphrase_recovery_expected("publisher", "saved", &resume)
                .unwrap(),
            f.expected
        );
        let mut wrong = resume;
        wrong.after.snapshot_hash[0] ^= 1;
        assert!(
            source
                .key_passphrase_recovery_expected("publisher", "saved", &wrong)
                .is_err()
        );
        assert!(
            source
                .key_passphrase_recovery_expected("publisher", "other", &resume)
                .is_err()
        );
        assert_eq!(
            stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
            snapshot
        );
        assert_eq!(state.generation, resume.after.generation + fail as u64);
        assert_eq!(guard.exists(), fail < 3);
        if fail == 3 {
            assert_eq!(
                result.unwrap(),
                KeyResumeRelease::RemovedRecordedGuard(state)
            );
        } else {
            assert_eq!(result.unwrap_err(), KeyFileError::Io);
        }
        let lines = std::str::from_utf8(&output.bytes).unwrap();
        for (i, line) in lines.lines().enumerate() {
            assert!(line.starts_with(
                [
                    "key_passphrase_change_started ",
                    "key_passphrase_change_prepared ",
                    "key_passphrase_change_completed "
                ][i]
            ));
            assert!(line.contains(&format!(
                "after_generation={}",
                resume.after.generation + i as u64 + 1
            )));
        }
        let mut retried = Vec::new();
        assert!(f.change_first(&resume, &mut retried).is_err());
        assert!(retried.is_empty());
        assert_eq!(stdfs::read(&backup).unwrap(), old);
        let current = stdfs::read(f.a.0.join("publisher")).unwrap();
        if fail < 2 {
            assert_eq!(current, old);
        } else {
            assert_ne!(current, old);
            assert_eq!(
                unlock(&current, "different public passphrase")
                    .unwrap()
                    .public_key(),
                f.expected.public_key
            );
        }
    }
}

#[test]
fn rotation_preservation_uses_the_fixed_completed_ciphertext_without_overwriting() {
    let mut f = Fixture::new(true, 1);
    let resume = f.interrupt(S::OldSnapshotRemoved);
    f.release(&resume, &mut |_| Ok(())).unwrap();
    let KeyResumeRelease::RemovedRecordedGuard(completed) =
        f.change_first(&resume, &mut Vec::new()).unwrap()
    else {
        panic!("expected first update to remove its guard")
    };
    let path = f.a.0.join("publisher");
    let current = stdfs::read(&path).unwrap();
    let history = stdfs::read(f.a.0.join(initial_state::STATE)).unwrap();
    let preserved = f.areas[0].0.join("next-copy");
    let source = f.source.as_mut().unwrap();
    let backup = &mut f.backups[0];
    let preserve =
        |source: &mut KeyDirectory, backup: &mut KeyDirectory, expected, pass, target| {
            source.preserve_key_for_passphrase_rotation(expected, "publisher", pass, backup, target)
        };
    let mut stale = completed;
    stale.snapshot_hash[0] ^= 1;
    assert!(
        preserve(
            source,
            backup,
            &stale,
            "different public passphrase",
            "next-copy"
        )
        .is_err()
    );
    assert!(preserve(source, backup, &completed, &f.pass, "next-copy").is_err());
    assert!(!preserved.exists());
    preserve(
        source,
        backup,
        &completed,
        "different public passphrase",
        "next-copy",
    )
    .unwrap();
    assert_eq!(stdfs::read(&preserved).unwrap(), current);
    assert!(
        source
            .verify_key_preserved_for_passphrase_rotation(
                &completed,
                "publisher",
                "different public passphrase",
                backup,
                "saved",
            )
            .is_err()
    );
    source
        .verify_key_preserved_for_passphrase_rotation(
            &completed,
            "publisher",
            "different public passphrase",
            backup,
            "next-copy",
        )
        .unwrap();

    assert_eq!(
        preserve(
            source,
            backup,
            &completed,
            "different public passphrase",
            "next-copy"
        ),
        Err(KeyFileError::Exists),
    );
    let proofs = [
        KeyResumePreservation {
            completed_operation_id: f.ids[0],
            directory_index: f.indices[0],
            name: &f.names[0],
            passphrase: &f.pass,
        },
        KeyResumePreservation {
            completed_operation_id: resume.operation_id,
            directory_index: 0,
            name: "saved",
            passphrase: &f.pass,
        },
    ];
    let verify = |source: &mut KeyDirectory,
                  backups: &mut [KeyDirectory],
                  proofs: &[KeyResumePreservation<'_>]| {
        source.verify_all_passphrase_rotation_preservations(
            &completed,
            "publisher",
            "different public passphrase",
            backups,
            0,
            "next-copy",
            proofs,
        )
    };
    assert!(verify(source, &mut f.backups, &proofs[..1]).is_err());
    verify(source, &mut f.backups, &proofs).unwrap();
    let check_capacity = |source: &mut KeyDirectory, backups: &mut [KeyDirectory], length| {
        source.verify_passphrase_rotation_capacity(
            &completed,
            "publisher",
            "different public passphrase",
            backups,
            0,
            "next-copy",
            &proofs,
            length,
        )
    };
    assert!(check_capacity(source, &mut f.backups, 0).is_err());
    assert!(check_capacity(source, &mut f.backups, MAX_KEYFILE_BYTES + 1).is_err());
    check_capacity(source, &mut f.backups, current.len()).unwrap();
    assert_eq!(stdfs::read(path).unwrap(), current);
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        history
    );
    assert!(!f.a.0.join(recovery_hold::GUARD).exists());
}

#[test]
fn rotation_start_waits_for_receipt_flush_before_recording() {
    #[derive(Default)]
    struct Receipt {
        bytes: Vec<u8>,
        fail_flush: bool,
    }
    impl std::io::Write for Receipt {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            Ok(())
        }
    }

    for fail_flush in [true, false] {
        let mut f = Fixture::new(true, 1);
        let resume = f.interrupt(S::OldSnapshotRemoved);
        f.release(&resume, &mut |_| Ok(())).unwrap();
        let KeyResumeRelease::RemovedRecordedGuard(completed) =
            f.change_first(&resume, &mut Vec::new()).unwrap()
        else {
            panic!("expected first update to remove its guard")
        };
        let source = f.source.as_mut().unwrap();
        let current_passphrase = "different public passphrase";
        source
            .preserve_key_for_passphrase_rotation(
                &completed,
                "publisher",
                current_passphrase,
                &mut f.backups[0],
                "next-copy",
            )
            .unwrap();
        let history = f.a.0.join(initial_state::STATE);
        let old_history = stdfs::read(&history).unwrap();
        let old_key = stdfs::read(f.a.0.join("publisher")).unwrap();
        let proofs = [
            KeyResumePreservation {
                completed_operation_id: f.ids[0],
                directory_index: f.indices[0],
                name: &f.names[0],
                passphrase: &f.pass,
            },
            KeyResumePreservation {
                completed_operation_id: resume.operation_id,
                directory_index: 0,
                name: "saved",
                passphrase: &f.pass,
            },
        ];
        let mut receipt = Receipt {
            fail_flush,
            ..Receipt::default()
        };
        let result = source.record_passphrase_rotation_start(
            &completed,
            "publisher",
            current_passphrase,
            "rotation test passphrase",
            &mut f.backups,
            0,
            "next-copy",
            &proofs,
            &mut receipt,
        );
        assert!(
            receipt
                .bytes
                .starts_with(b"key_passphrase_rotation_started ")
        );
        let receipt = std::str::from_utf8(&receipt.bytes).unwrap();
        let intent = KeyPassphraseStartIntent::parse_rotation_receipt(receipt, &completed).unwrap();
        let mut stale = completed;
        stale.snapshot_hash[0] ^= 1;
        assert!(KeyPassphraseStartIntent::parse_rotation_receipt(receipt, &stale).is_err());
        assert!(KeyPassphraseStartIntent::parse_rotation_receipt(receipt, &resume.after).is_err());
        assert!(
            KeyPassphraseStartIntent::parse_rotation_receipt(
                &receipt.replacen(
                    "key_passphrase_rotation_started",
                    "key_passphrase_change_started",
                    1
                ),
                &completed,
            )
            .is_err()
        );
        assert!(f.a.0.join(recovery_hold::GUARD).is_file());
        assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), old_key);
        assert_eq!(
            stdfs::read(f.areas[0].0.join("next-copy")).unwrap(),
            old_key
        );
        let recover = |source: &mut KeyDirectory, backups: &mut [KeyDirectory]| {
            source.recover_passphrase_rotation_start(
                "publisher",
                current_passphrase,
                backups,
                0,
                "next-copy",
                &proofs,
                &intent,
            )
        };
        if fail_flush {
            assert!(matches!(result, Err(KeyFileError::Io)));
            assert!(recover(source, &mut f.backups).is_err());
            assert_eq!(stdfs::read(&history).unwrap(), old_history);
        } else {
            let (diagnostic, ciphertext) = result.unwrap();
            assert_eq!(intent.after, diagnostic);
            assert!(matches!(
                diagnostic.state,
                KeyHistoryState::PassphraseRotationStarted { .. }
            ));
            assert_eq!(diagnostic.generation, completed.generation + 1);
            assert_ne!(stdfs::read(&history).unwrap(), old_history);
            assert_ne!(ciphertext, old_key);
            assert_eq!(recover(source, &mut f.backups).unwrap(), diagnostic);
            let new_history = stdfs::read(&history).unwrap();
            let temp = format!(
                ".lngnb-key-state-update-{}",
                data_encoding::HEXLOWER.encode(&intent.operation_id),
            );
            f.a.put(initial_state::STATE, &old_history);
            f.a.put(&temp, &new_history[..new_history.len() - 1]);
            assert!(recover(source, &mut f.backups).is_err());
            assert_eq!(stdfs::read(&history).unwrap(), old_history);
            f.a.put(&temp, &new_history);
            assert_eq!(recover(source, &mut f.backups).unwrap(), diagnostic);
            assert_eq!(stdfs::read(&history).unwrap(), new_history);
            assert!(!f.a.0.join(&temp).exists());
            assert!(f.a.0.join(recovery_hold::GUARD).is_file());
            assert_eq!(stdfs::read(f.a.0.join("publisher")).unwrap(), old_key);
        }
    }
}
