//! 固定完了後の明示guard解除。
use super::release::{KeyResumeRelease, ReleaseStage};
use super::*;

impl KeyDirectory {
    /// 固定完了を再認証し、記録guardを解除するか今回の正確不在を確認する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_key_passphrase_release(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        completed: &KeyPassphraseCompletedIntent,
    ) -> Result<KeyResumeRelease> {
        self.recover_key_passphrase_release_with(
            current_name,
            old_passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            prepared,
            completed,
            &mut |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super::super::super) fn recover_key_passphrase_release_with(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        expected: &KeyResumeExpected,
        resume: &KeyResumeIntent,
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        completed: &KeyPassphraseCompletedIntent,
        hook: &mut impl FnMut(ReleaseStage) -> Result<()>,
    ) -> Result<KeyResumeRelease> {
        check_completed_intent(start, prepared, completed)?;
        self.with_passphrase_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            expected,
            resume,
            start,
            Some((prepared, new_passphrase)),
            Some(completed),
            true,
            |context, _, _, _, intent| context.release_recorded_guard(intent.after, hook),
        )
    }
}
