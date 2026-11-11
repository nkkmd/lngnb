//! §5.104: 保存済みActiveの一対象だけを明示整理。成功後もHeld/停止を維持する。
use super::*;
use std::os::unix::fs::FileExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super::super) enum RemovalStage {
    TargetSynced,
    PreservedSynced,
    DirectoriesSynced,
    ControlsSynced,
    StateSynced,
    Qualified,
    BeforeUnlink,
    Unlinked,
    RemovalSynced,
    CompletionIdentified,
    CompletionPrepared,
}

pub(in super::super) struct RemovedTarget {
    held: HeldFile,
    after: Metadata,
}
impl RemovedTarget {
    pub(in super::super) fn capture(held: HeldFile) -> Result<Self> {
        let after = io(held.file.metadata())?;
        let removed = Self { held, after };
        removed.check()?;
        Ok(removed)
    }
    pub(in super::super) fn check(&self) -> Result<()> {
        let before = io(self.held.file.metadata())?;
        let original = KeyFileIdentity::from_metadata(&self.held.metadata);
        let mut current = KeyFileIdentity::from_metadata(&before);
        if current.nlink != 0 || fingerprint(&before) != fingerprint(&self.after) {
            return Err(KeyFileError::RecoveryChanged);
        }
        // 自身のunlinkで変わるnlink/ctime以外は元の全属性と一致すること。
        current.nlink = original.nlink;
        current.ctime_seconds = original.ctime_seconds;
        current.ctime_nanoseconds = original.ctime_nanoseconds;
        if current != original {
            return Err(KeyFileError::RecoveryChanged);
        }
        let mut bytes = vec![0; self.held.bytes.len()];
        io(self.held.file.read_exact_at(&mut bytes, 0))?;
        let mut extra = [0];
        if bytes != self.held.bytes
            || io(self.held.file.read_at(&mut extra, bytes.len() as u64))? != 0
            || fingerprint(&io(self.held.file.metadata())?) != fingerprint(&before)
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        Ok(())
    }
}

/// 両領域と対象/保全先/固定二名/Activeのfdを保持する一回限りの資格。
/// 準備/Dropは削除しない。remove成功は完了履歴の保存成功ではない。
pub struct PreparedResidueRemoval<'a> {
    context: CompletionContext<'a>,
    state: HeldFile,
    target: HeldFile,
}
impl PreparedResidueRemoval<'_> {
    fn check(&self) -> Result<()> {
        self.context.check_controls()?;
        self.target
            .check(self.context.source, &self.context.residue, true)?;
        self.state
            .check(self.context.source, initial_state::STATE, true)?;
        if self.context.source.reject_state_artifacts(true)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
        }
        Ok(())
    }
}

impl<'a> PreparedResidueRemoval<'a> {
    /// 指定一件をunlinkし、今回の不在/dir fsync確認後に正常完了を準備する。
    /// intentを控えてrecordする。戻り値だけでは完了保存の証明にならない。
    pub fn remove(self) -> Result<PreparedAbsentCleanup<'a>> {
        self.remove_with(&mut || completion_identity(), &mut |_| Ok(()))
    }

    pub(in super::super::super) fn remove_with(
        self,
        identify: &mut impl FnMut() -> Result<([u8; 32], i64)>,
        hook: &mut impl FnMut(RemovalStage) -> Result<()>,
    ) -> Result<PreparedAbsentCleanup<'a>> {
        use RemovalStage as S;
        self.check()?;
        hook(S::BeforeUnlink)?;
        self.check()?;
        let Self {
            mut context,
            state,
            target,
        } = self;
        let mut saved = false;
        let result = (|| -> Result<PreparedAbsentCleanup<'a>> {
            os(fs::unlinkat(
                &context.source.dir,
                context.residue.as_str(),
                AtFlags::empty(),
            ))?;
            hook(S::Unlinked)?;
            context.removed_target = Some(RemovedTarget::capture(target)?);
            context.check()?;
            state.check(context.source, initial_state::STATE, true)?;
            context.source.reject_state_artifacts(true)?;
            io(context.source.dir.sync_all())?;
            context.check()?;
            state.check(context.source, initial_state::STATE, true)?;
            context.source.reject_state_artifacts(true)?;
            saved = true;
            hook(S::RemovalSynced)?;
            let (operation_id, now) = identify()?;
            hook(S::CompletionIdentified)?;
            context.check()?;
            state.check(context.source, initial_state::STATE, true)?;
            let (new_bytes, intent) = completion_value(
                &context,
                &state,
                operation_id,
                now,
                KeyCleanupDisposition::RemovedPresent,
            )?;
            hook(S::CompletionPrepared)?;
            context.check()?;
            state.check(context.source, initial_state::STATE, true)?;
            if context.source.reject_state_artifacts(true)? >= SCAN_LIMIT {
                return Err(KeyFileError::ScanLimit);
            }
            Ok(PreparedAbsentCleanup {
                context,
                state,
                new_bytes,
                intent,
            })
        })();
        result.map_err(|_| {
            if saved {
                KeyFileError::ResidueCompletionRequired
            } else {
                KeyFileError::ResidueRemovalUncertain
            }
        })
    }
}

impl KeyDirectory {
    /// 保存済み未完了開始と現在の両暗号文を認証/照合し、今回fsyncして保持する。
    pub fn prepare_residue_removal<'a>(
        &'a mut self,
        residue: &str,
        passphrase: &str,
        backup: &'a mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
    ) -> Result<PreparedResidueRemoval<'a>> {
        self.prepare_residue_removal_with(
            residue,
            passphrase,
            backup,
            backup_name,
            expected,
            &mut |_| Ok(()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(in super::super::super) fn prepare_residue_removal_with<'a>(
        &'a mut self,
        residue: &str,
        passphrase: &str,
        backup: &'a mut KeyDirectory,
        backup_name: &str,
        expected: &KeyCleanupExpected,
        hook: &mut impl FnMut(RemovalStage) -> Result<()>,
    ) -> Result<PreparedResidueRemoval<'a>> {
        use RemovalStage as S;
        active_id(&expected.state)?;
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(backup_name)?;
        if self.reject_state_artifacts(true)? >= SCAN_LIMIT {
            return Err(KeyFileError::ScanLimit);
        }
        let state = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let target = HeldFile::open(self, residue, MAX_KEYFILE_BYTES)?;
        if KeyFileIdentity::from_metadata(&target.metadata) != expected.target {
            return Err(KeyFileError::RecoveryChanged);
        }
        let context = CompletionContext::open_controls(
            self,
            backup,
            residue,
            backup_name,
            expected,
            &state.bytes,
        )?;
        if target.bytes != context.preserved.bytes {
            return Err(KeyFileError::PreservationMismatch);
        }
        if unlock(&target.bytes, passphrase)?.public_key() != expected.public_key {
            return Err(KeyFileError::UnexpectedPublicKey);
        }
        let prepared = PreparedResidueRemoval {
            context,
            state,
            target,
        };
        prepared.check()?;
        prepared.target.sync()?;
        hook(S::TargetSynced)?;
        prepared.check()?;
        prepared.context.preserved.sync()?;
        hook(S::PreservedSynced)?;
        prepared.check()?;
        io(prepared.context.backup.dir.sync_all())?;
        io(prepared.context.source.dir.sync_all())?;
        hook(S::DirectoriesSynced)?;
        prepared.check()?;
        prepared.context.marker.sync()?;
        prepared.context.guard.sync()?;
        hook(S::ControlsSynced)?;
        prepared.check()?;
        prepared.state.sync()?;
        hook(S::StateSynced)?;
        prepared.check()?;
        io(prepared.context.source.dir.sync_all())?;
        hook(S::Qualified)?;
        prepared.check()?;
        Ok(prepared)
    }
}
