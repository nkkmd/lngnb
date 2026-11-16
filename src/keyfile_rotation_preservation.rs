//! §5.122: 次回更新に先立つ通常名の暗号文保全。
use super::*;

// 固定完了と通常鍵を同じ領域fdの下で保持する。
struct FixedRotationKey {
    marker: HeldFile,
    snapshot: HeldFile,
    key: HeldFile,
    history: Value,
    public: [u8; 32],
}

impl FixedRotationKey {
    fn open(
        source: &KeyDirectory,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
    ) -> Result<Self> {
        inventory(source, None)?;
        absent(source, recovery_hold::GUARD)?;
        let completed_operation_id = match expected.state {
            KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id,
            }
            | KeyHistoryState::PassphraseRotationCompleted {
                completed_operation_id,
            } => completed_operation_id,
            _ => return invalid(),
        };
        let marker = HeldFile::open(source, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        if marker.bytes.len() != 105 || !marker.bytes.starts_with(b"lngnb:key-recovery:2\0") {
            return invalid();
        }
        let mut source_marker = marker.bytes[..73].to_vec();
        source_marker[19] = b'1';
        let root = expected.initial.snapshot_hash;
        let area_id = source.marker_area_id(&source_marker)?;
        if area_id != expected.initial.area_id || marker.bytes[73..] != root {
            return invalid();
        }
        let snapshot = HeldFile::open(source, initial_state::STATE, initial_state::STATE_LIMIT)?;
        if state_history::decode_history(&snapshot.bytes, &source_marker, area_id, root)?
            != *expected
        {
            return invalid();
        }
        let value =
            cbor::decode(&snapshot.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let events = array(field(&value, "events")?)?;
        let [.., started, _, completed] = events else {
            return invalid();
        };
        if id(field(completed, "operation_id")?)? != completed_operation_id
            || string(field(started, "name")?)? != current_name
        {
            return invalid();
        }
        let key = HeldFile::open(source, current_name, MAX_KEYFILE_BYTES)?;
        let current_hash: [u8; 32] = Sha256::digest(&key.bytes).into();
        let public = id(field(started, "public_key")?)?;
        if state_history::recorded_file_identity(field(completed, "installed_identity")?)?
            != KeyFileIdentity::from_metadata(&key.metadata)
            || current_hash != id(field(started, "new_ciphertext_sha256")?)?
            || unlock(&key.bytes, passphrase)?.public_key() != public
        {
            return invalid();
        }

        let fixed = Self {
            marker,
            snapshot,
            key,
            history: value,
            public,
        };
        fixed.recheck(source, current_name)?;
        Ok(fixed)
    }

    fn recheck(&self, source: &KeyDirectory, current_name: &str) -> Result<()> {
        inventory(source, None)?;
        absent(source, recovery_hold::GUARD)?;
        self.marker.check(source, recovery_hold::MARKER, true)?;
        self.snapshot.check(source, initial_state::STATE, true)?;
        self.key.check(source, current_name, true)
    }

    fn reject_recorded_backup(
        &self,
        backup_id: KeyDirectoryIdentity,
        backup_name: &str,
        candidate: Option<KeyFileIdentity>,
    ) -> Result<()> {
        let backup_directory = backup_id.value();
        for event in array(field(&self.history, "events")?)?.iter().skip(1) {
            if matches!(
                string(field(event, "kind")?)?,
                "residue_cleanup_started"
                    | "key_changes_resumed"
                    | "key_passphrase_rotation_started"
            ) {
                let saved = field(event, "preserved")?;
                let saved_identity =
                    state_history::recorded_file_identity(field(saved, "identity")?)?;
                if candidate
                    .is_some_and(|id| id.dev == saved_identity.dev && id.ino == saved_identity.ino)
                    || (string(field(saved, "name")?)? == backup_name
                        && equal(field(saved, "directory")?, &backup_directory)?)
                {
                    return Err(KeyFileError::Exists);
                }
            }
        }
        Ok(())
    }

    fn sync(&self, source: &KeyDirectory, current_name: &str) -> Result<()> {
        self.key.sync()?;
        self.marker.sync()?;
        self.snapshot.sync()?;
        io(source.dir.sync_all())?;
        self.recheck(source, current_name)
    }
}

impl KeyDirectory {
    /// 固定完了に対応する通常名の暗号文を、別領域の空き名へ非上書きで保存する。
    /// 履歴・元鍵・guardは変更しない。返却値は認証した公開鍵のみ。
    pub fn preserve_key_for_passphrase_rotation(
        &mut self,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
    ) -> Result<[u8; 32]> {
        name(current_name)?;
        name(backup_name)?;
        inventory(self, None)?;
        absent(self, recovery_hold::GUARD)?;
        backup.pending()?;
        let source_id = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        let backup_id = KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?);
        if source_id.dev == backup_id.dev && source_id.ino == backup_id.ino {
            return Err(KeyFileError::UnsafePath);
        }
        match fs::statat(&backup.dir, backup_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(KeyFileError::Exists),
            Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err(KeyFileError::Io),
        }

        let fixed = FixedRotationKey::open(self, expected, current_name, passphrase)?;
        fixed.reject_recorded_backup(backup_id, backup_name, None)?;
        fixed.sync(self, current_name)?;
        let recheck = || fixed.recheck(self, current_name);
        let copied = backup
            .install(
                backup_name,
                &fixed.key.bytes,
                passphrase,
                None,
                &mut |stage| {
                    if stage == Stage::BeforeInstall {
                        recheck()?;
                    }
                    Ok(())
                },
            )
            .map_err(|err| match err {
                KeyFileError::CleanupUncertain => KeyFileError::PreservationReviewRequired,
                _ => err,
            })?;
        // 配置済みのコピーは最終照合に失敗しても保持する。
        let verify = || {
            backup.pending()?;
            let preserved = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
            if preserved.bytes != fixed.key.bytes || copied != fixed.public {
                return invalid();
            }
            preserved.sync()?;
            io(backup.dir.sync_all())?;
            preserved.check(backup, backup_name, true)?;
            recheck()
        };
        verify().map_err(|_| KeyFileError::PreservationReviewRequired)?;
        Ok(fixed.public)
    }

    /// 既存の保全コピーを、固定完了に対応する現在鍵と再照合して保存確認する。
    /// 返却値は認証済み公開鍵のみ。更新開始には別途、全保全の照合が必要。
    pub fn verify_key_preserved_for_passphrase_rotation(
        &mut self,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
    ) -> Result<[u8; 32]> {
        name(current_name)?;
        name(backup_name)?;
        backup.pending()?;
        let source_id = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        let backup_id = KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?);
        if source_id.dev == backup_id.dev && source_id.ino == backup_id.ino {
            return Err(KeyFileError::UnsafePath);
        }
        let fixed = FixedRotationKey::open(self, expected, current_name, passphrase)?;
        let kept = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
        let candidate = KeyFileIdentity::from_metadata(&kept.metadata);
        fixed.reject_recorded_backup(backup_id, backup_name, Some(candidate))?;
        if kept.bytes != fixed.key.bytes
            || (candidate.dev == fixed.key.metadata.dev()
                && candidate.ino == fixed.key.metadata.ino())
        {
            return invalid();
        }
        fixed.sync(self, current_name)?;
        kept.sync()?;
        io(backup.dir.sync_all())?;
        backup.pending()?;
        kept.check(backup, backup_name, true)?;
        fixed.recheck(self, current_name)?;
        Ok(fixed.public)
    }
}
