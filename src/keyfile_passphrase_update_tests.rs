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
