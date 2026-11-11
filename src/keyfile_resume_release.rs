//! §5.108: 記録済み再開意思のguard解除と、解除中断の明示復旧。
use super::super::completion::removal::RemovedTarget;
use super::recovery::{decode_snapshot, source_marker, verify_prefix};
use super::*;
use std::os::unix::fs::FileExt;

/// 今回のguard不在と保存確認の結果。通常鍵変更の資格を保持しない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyResumeRelease {
    RemovedRecordedGuard(KeyStateDiagnostic),
    ConfirmedGuardAbsent(KeyStateDiagnostic),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super::super) enum ReleaseStage {
    Qualification(ResumeStage),
    BeforeUnlink,
    Unlinked,
    BeforeDirectorySync,
    DirectorySynced,
}

impl KeyDirectory {
    /// 追記済みの控えで、記録guard一件の解除または正確不在の今回保存確認を行う。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_key_resume_release(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        intent: &KeyResumeIntent,
    ) -> Result<KeyResumeRelease> {
        self.recover_key_resume_release_with(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            intent,
            &mut |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super::super) fn recover_key_resume_release_with(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        intent: &KeyResumeIntent,
        hook: &mut impl FnMut(ReleaseStage) -> Result<()>,
    ) -> Result<KeyResumeRelease> {
        inventory(self, None)?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let marker = source_marker(self, intent)?;
        if decode_snapshot(&fixed.bytes, &marker, intent)? != intent.after {
            return invalid();
        }
        let old_bytes = verify_prefix(&fixed.bytes, &marker, intent)?;
        let mut context = self.prepare_resume_snapshot(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            ResumeSnapshot::Existing {
                old_bytes,
                new_bytes: fixed.bytes.clone(),
                intent,
                allow_absent_guard: true,
            },
        )?;
        if context.state.bytes != fixed.bytes
            || fingerprint(&context.state.metadata) != fingerprint(&fixed.metadata)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        context.qualify_release(hook)?;
        let removed = if let Some(guard) = context.guard.take() {
            hook(ReleaseStage::BeforeUnlink)?;
            context.check_release_files()?;
            check_guard_for_unlink(context.source, &guard)?;
            let removed = (|| {
                os(fs::unlinkat(
                    &context.source.dir,
                    recovery_hold::GUARD,
                    AtFlags::empty(),
                ))?;
                let removed = RemovedTarget::capture(guard)?;
                hook(ReleaseStage::Unlinked)?;
                Ok(removed)
            })();
            Some(removed.map_err(|_: KeyFileError| KeyFileError::RecoveryGuardReleaseUncertain)?)
        } else {
            None
        };
        let check = || -> Result<()> {
            context.check_release_files()?;
            if let Some(removed) = &removed {
                removed.check()?;
            }
            absent(context.source, recovery_hold::GUARD)
        };
        let mut confirm = || -> Result<()> {
            hook(ReleaseStage::BeforeDirectorySync)?;
            check()?;
            io(context.source.dir.sync_all())?;
            hook(ReleaseStage::DirectorySynced)?;
            check()
        };
        confirm().map_err(|_| KeyFileError::RecoveryGuardReleaseUncertain)?;
        Ok(if removed.is_some() {
            KeyResumeRelease::RemovedRecordedGuard(intent.after)
        } else {
            KeyResumeRelease::ConfirmedGuardAbsent(intent.after)
        })
    }
}

impl PreparedKeyResume<'_> {
    fn check_release_files(&self) -> Result<()> {
        self.check_files(None)?;
        self.state.check(self.source, initial_state::STATE, true)
    }

    fn qualify_release(&self, hook: &mut impl FnMut(ReleaseStage) -> Result<()>) -> Result<()> {
        self.qualify(
            None,
            false,
            &mut |stage| hook(ReleaseStage::Qualification(stage)),
            &mut || Ok(()),
        )
    }
}

fn check_guard_for_unlink(source: &KeyDirectory, guard: &HeldFile) -> Result<()> {
    // 完全bytesを保持fdから読み、同じfdの全属性と固定名を最後に照合する。
    let mut bytes = [0; 49];
    io(guard.file.read_exact_at(&mut bytes, 0))?;
    let mut extra = [0];
    let trailing = io(guard.file.read_at(&mut extra, bytes.len() as u64))?;
    let actual = io(guard.file.metadata())?;
    if bytes.as_slice() != guard.bytes
        || trailing != 0
        || fingerprint(&actual) != fingerprint(&guard.metadata)
    {
        return Err(KeyFileError::RecoveryChanged);
    }
    let path = os(fs::statat(
        &source.dir,
        recovery_hold::GUARD,
        AtFlags::SYMLINK_NOFOLLOW,
    ))?;
    if path.st_dev != actual.dev() || path.st_ino != actual.ino() {
        return Err(KeyFileError::RecoveryChanged);
    }
    Ok(())
}
