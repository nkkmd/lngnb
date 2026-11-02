//! A案の初期停止だけ。恒久互換marker/停止guardは自動導入・採用・削除しない。
use super::*;

pub(super) const MARKER: &str = ".lngnb-key-control";
pub(super) const GUARD: &str = ".lngnb-key-hold";
const MARKER_MAGIC: &[u8] = b"lngnb:key-recovery:1\0";
const GUARD_MAGIC: &[u8] = b"lngnb:key-hold:1\0";

/// 現在の二fileの診断。過去のfsync・整理資格・領域全体の正常性ではない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRecoveryHold {
    /// 二名とも現在不在。他の残存物や過去の状態の不存在は示さない。
    NotInitialized,
    /// 同じ領域に束縛したmarkerとguardが一致。解除状態はまだ提供しない。
    Held { area_id: [u8; 32] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HoldStage {
    Created,
    Written,
    FileSynced,
    DirectorySynced,
}

impl KeyDirectory {
    /// 同じ排他/fdの下で二名を読むだけ。open/診断では状態を作成・補完しない。
    pub fn recovery_hold_status(&mut self) -> Result<KeyRecoveryHold> {
        let read = |n| match self.read(n) {
            Ok(b) => Ok(Some(b)),
            Err(KeyFileError::Missing) => Ok(None),
            Err(e) => Err(e),
        };
        let marker = read(MARKER)?;
        let guard = read(GUARD)?;
        // 各読取り時点の診断。原子的snapshotや返却後の不変は保証しない。
        if read(MARKER)? != marker || read(GUARD)? != guard {
            return Err(KeyFileError::RecoveryChanged);
        }
        match (marker, guard) {
            (None, None) => Ok(KeyRecoveryHold::NotInitialized),
            (Some(marker), Some(guard)) => {
                let m = io(self.dir.metadata())?;
                let mut suffix = Vec::new();
                suffix.extend_from_slice(&m.dev().to_be_bytes());
                suffix.extend_from_slice(&m.ino().to_be_bytes());
                suffix.extend_from_slice(&m.uid().to_be_bytes());
                if marker.len() != MARKER_MAGIC.len() + 32 + suffix.len()
                    || !marker.starts_with(MARKER_MAGIC)
                    || marker[MARKER_MAGIC.len() + 32..] != suffix
                {
                    return Err(KeyFileError::RecoveryStateInvalid);
                }
                let area_id: [u8; 32] = marker[MARKER_MAGIC.len()..MARKER_MAGIC.len() + 32]
                    .try_into()
                    .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
                let mut expected = GUARD_MAGIC.to_vec();
                expected.extend_from_slice(&area_id);
                if guard != expected {
                    return Err(KeyFileError::RecoveryStateInvalid);
                }
                Ok(KeyRecoveryHold::Held { area_id })
            }
            _ => Err(KeyFileError::RecoveryStateInvalid),
        }
    }

    /// 既存領域へ初期停止を明示導入。既存二名は不正でも上書き/採用しない。
    /// 成功後も既存pending()は通常変更を拒否する。秘密/鍵fileは扱わない。
    pub fn initialize_recovery_hold(&mut self) -> Result<KeyRecoveryHold> {
        let mut area_id = [0; 32];
        super::super::random(&mut area_id)?;
        self.initialize_recovery_hold_with(area_id, &mut |_, _| Ok(()))
    }

    pub(super) fn initialize_recovery_hold_with(
        &mut self,
        area_id: [u8; 32],
        hook: &mut impl FnMut(usize, HoldStage) -> Result<()>,
    ) -> Result<KeyRecoveryHold> {
        self.secure()?;
        // 不在は生成前の条件だけ。競合作成はO_EXCLでも拒否する。
        for n in [MARKER, GUARD] {
            match fs::statat(&self.dir, n, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => return Err(KeyFileError::Exists),
                Err(rustix::io::Errno::NOENT) => (),
                Err(_) => return Err(KeyFileError::Io),
            }
        }
        let m = io(self.dir.metadata())?;
        let mut marker = MARKER_MAGIC.to_vec();
        marker.extend_from_slice(&area_id);
        marker.extend_from_slice(&m.dev().to_be_bytes());
        marker.extend_from_slice(&m.ino().to_be_bytes());
        marker.extend_from_slice(&m.uid().to_be_bytes());
        let mut guard = GUARD_MAGIC.to_vec();
        guard.extend_from_slice(&area_id);
        for (i, (n, bytes)) in [(MARKER, marker), (GUARD, guard)].into_iter().enumerate() {
            let fd = fs::openat(
                &self.dir,
                n,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|e| {
                if i == 0 && e == rustix::io::Errno::EXIST {
                    KeyFileError::Exists
                } else {
                    KeyFileError::RecoveryHoldUncertain
                }
            })?;
            // 作成後の失敗は一切片付けない。空/不完全でも予約prefixが停止を維持。
            let saved = (|| -> Result<()> {
                let mut file = File::from(fd);
                os(fs::fchmod(&file, Mode::RUSR | Mode::WUSR))?;
                hook(i, HoldStage::Created)?;
                io(file.write_all(&bytes))?;
                hook(i, HoldStage::Written)?;
                io(file.sync_all())?;
                hook(i, HoldStage::FileSynced)?;
                if self.read(n)? != bytes {
                    return Err(KeyFileError::RecoveryChanged);
                }
                io(self.dir.sync_all())?;
                hook(i, HoldStage::DirectorySynced)?;
                Ok(())
            })();
            saved.map_err(|_| KeyFileError::RecoveryHoldUncertain)?;
        }
        let status = self
            .recovery_hold_status()
            .map_err(|_| KeyFileError::RecoveryHoldUncertain)?;
        if status != (KeyRecoveryHold::Held { area_id }) {
            return Err(KeyFileError::RecoveryHoldUncertain);
        }
        Ok(status)
    }
}
