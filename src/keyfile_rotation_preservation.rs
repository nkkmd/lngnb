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

fn matches_rotation_key_identity(held: &HeldFile, expected: KeyFileIdentity, moved: bool) -> bool {
    let mut actual = KeyFileIdentity::from_metadata(&held.metadata);
    if moved {
        actual.ctime_seconds = expected.ctime_seconds;
        actual.ctime_nanoseconds = expected.ctime_nanoseconds;
    }
    actual == expected
}

enum RotationOldKey<'a> {
    Normal,
    Moved(&'a str),
    Preserved(&'a KeyDirectory, &'a str),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RotationAction<'a> {
    RecoverHistory,
    Exchange,
    Complete,
    RecoverCompletion(&'a KeyPassphraseCompletedIntent),
    Release(&'a KeyPassphraseCompletedIntent),
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
        let fixed = Self::from_completed_history(
            source,
            expected,
            current_name,
            passphrase,
            marker,
            snapshot,
            value,
            RotationOldKey::Normal,
        )?;
        fixed.recheck(source, current_name)?;
        Ok(fixed)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_completed_history(
        source: &KeyDirectory,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        marker: HeldFile,
        snapshot: HeldFile,
        value: Value,
        location: RotationOldKey<'_>,
    ) -> Result<Self> {
        let completed_operation_id = match expected.state {
            KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id,
            }
            | KeyHistoryState::PassphraseRotationCompleted {
                completed_operation_id,
            } => completed_operation_id,
            _ => return invalid(),
        };
        let events = array(field(&value, "events")?)?;
        let [.., started, _, completed] = events else {
            return invalid();
        };
        if id(field(completed, "operation_id")?)? != completed_operation_id
            || string(field(started, "name")?)? != current_name
        {
            return invalid();
        }
        let (key, check_identity, moved) = match location {
            RotationOldKey::Normal => (
                HeldFile::open(source, current_name, MAX_KEYFILE_BYTES)?,
                true,
                false,
            ),
            RotationOldKey::Moved(path) => {
                (HeldFile::open(source, path, MAX_KEYFILE_BYTES)?, true, true)
            }
            RotationOldKey::Preserved(directory, path) => (
                HeldFile::open(directory, path, MAX_KEYFILE_BYTES)?,
                false,
                false,
            ),
        };
        let current_hash: [u8; 32] = Sha256::digest(&key.bytes).into();
        let public = id(field(started, "public_key")?)?;
        let expected =
            state_history::recorded_file_identity(field(completed, "installed_identity")?)?;
        if (check_identity && !matches_rotation_key_identity(&key, expected, moved))
            || current_hash != id(field(started, "new_ciphertext_sha256")?)?
            || unlock(&key.bytes, passphrase)?.public_key() != public
        {
            return invalid();
        }

        Ok(Self {
            marker,
            snapshot,
            key,
            history: value,
            public,
        })
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

    fn open_history_preservations(
        &self,
        backups: &[KeyDirectory],
        proofs: &[KeyResumePreservation<'_>],
        used: &mut [bool],
    ) -> Result<Vec<Preservation>> {
        let events = array(field(&self.history, "events")?)?;
        let mut proofs = proofs.iter();
        let mut held = Vec::new();
        for (index, event) in events.iter().enumerate().skip(1) {
            let (record, target, hash_key) = match string(field(event, "kind")?)? {
                "residue_cleanup_completed" => {
                    let started = &events[index - 1];
                    (started, field(started, "target")?, "ciphertext_sha256")
                }
                "key_changes_resumed" => (event, field(event, "current")?, "ciphertext_sha256"),
                "key_passphrase_rotation_completed" => {
                    let started = &events[index - 2];
                    (started, started, "old_ciphertext_sha256")
                }
                _ => continue,
            };
            let proof = proofs.next().ok_or(KeyFileError::RecoveryStateInvalid)?;
            if proof.completed_operation_id != id(field(event, "operation_id")?)? {
                return invalid();
            }
            let directory = backups
                .get(proof.directory_index)
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            let saved = field(record, "preserved")?;
            name(proof.name)?;
            if proof.name != string(field(saved, "name")?)?
                || !equal(
                    field(saved, "directory")?,
                    &KeyDirectoryIdentity::from_metadata(&io(directory.dir.metadata())?).value(),
                )?
            {
                return invalid();
            }
            used[proof.directory_index] = true;
            let kept = HeldFile::open(directory, proof.name, MAX_KEYFILE_BYTES)?;
            if KeyFileIdentity::from_metadata(&kept.metadata)
                != state_history::recorded_file_identity(field(saved, "identity")?)?
                || <[u8; 32]>::from(Sha256::digest(&kept.bytes)) != id(field(target, hash_key)?)?
            {
                return Err(KeyFileError::RecoveryChanged);
            }
            if unlock(&kept.bytes, proof.passphrase)?.public_key()
                != id(field(target, "public_key")?)?
            {
                return Err(KeyFileError::UnexpectedPublicKey);
            }
            held.push(Preservation {
                directory: proof.directory_index,
                name: proof.name.into(),
                held: kept,
            });
        }
        if proofs.next().is_some() || used.iter().any(|used| !used) {
            return invalid();
        }
        Ok(held)
    }

    fn sync(&self, source: &KeyDirectory, current_name: &str) -> Result<()> {
        self.key.sync()?;
        self.marker.sync()?;
        self.snapshot.sync()?;
        io(source.dir.sync_all())?;
        self.recheck(source, current_name)
    }
}

// 照合した領域と現物fdを、同じ排他の下で保持する。
struct CheckedRotationPreservations<'a> {
    source: &'a mut KeyDirectory,
    backups: &'a mut [KeyDirectory],
    current_name: &'a str,
    fixed: FixedRotationKey,
    preservations: Vec<Preservation>,
}

impl CheckedRotationPreservations<'_> {
    fn start_record(&self, expected: &KeyStateDiagnostic, new_length: usize) -> Result<Value> {
        let fixed = &self.fixed;
        let current = &self.preservations[0];
        let current_name = self.current_name;
        let backup_name = &current.name;
        let source_id = KeyDirectoryIdentity::from_metadata(&io(self.source.dir.metadata())?);
        let backup_id = KeyDirectoryIdentity::from_metadata(&io(self.backups[current.directory]
            .dir
            .metadata())?);
        let candidate = KeyFileIdentity::from_metadata(&current.held.metadata);
        let events = array(field(&fixed.history, "events")?)?;
        let completed = events.last().ok_or(KeyFileError::RecoveryStateInvalid)?;
        let old_identity = KeyFileIdentity::from_metadata(&fixed.key.metadata).value();
        // IDとhashは固定幅。guardの時刻は予約関数で最大幅に広げる。
        let start = map(vec![
            ("sequence", Value::Int((events.len() + 1) as i64)),
            ("operation_id", bytes([0; 32])),
            ("kind", text("key_passphrase_rotation_started")),
            ("actor_uid", bytes(source_id.uid.to_be_bytes())),
            ("recorded_unix_seconds", Value::Int(0)),
            ("rules", text("lngnb-key-operations-1")),
            ("previous_snapshot_sha256", bytes(expected.snapshot_hash)),
            ("name", text(current_name)),
            ("old_identity", old_identity.clone()),
            (
                "old_ciphertext_sha256",
                bytes(<[u8; 32]>::from(Sha256::digest(&fixed.key.bytes))),
            ),
            ("new_ciphertext_sha256", bytes([0; 32])),
            ("new_ciphertext_length", Value::Int(new_length as i64)),
            ("public_key", bytes(fixed.public)),
            ("guard_identity", old_identity),
            (
                "previous_completed_operation_id",
                field(completed, "operation_id")?.clone(),
            ),
            (
                "preserved",
                map(vec![
                    ("directory", backup_id.value()),
                    ("name", text(backup_name)),
                    ("identity", candidate.value()),
                ]),
            ),
        ]);
        if !state_history::start_reservation_fits(
            events.len(),
            fixed.snapshot.bytes.len(),
            &start,
            initial_state::STATE_LIMIT,
        )? {
            return invalid();
        }
        Ok(start)
    }

    fn sync_and_recheck(&self) -> Result<()> {
        self.fixed.sync(self.source, self.current_name)?;
        for saved in &self.preservations {
            saved.held.sync()?;
        }
        for directory in self.backups.iter() {
            io(directory.dir.sync_all())?;
            directory.pending()?;
        }
        for saved in &self.preservations {
            saved
                .held
                .check(&self.backups[saved.directory], &saved.name, true)?;
        }
        self.fixed.recheck(self.source, self.current_name)
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

    /// 今回の完全一致コピーと、履歴に記録した全保全を同じ排他下で保存確認する。
    /// proofsは履歴順に整理完了、明示再開、連続更新完了の各操作IDを指定する。
    /// 成功は今回の照合のみ。履歴書込みや更新開始は行わない。
    #[allow(clippy::too_many_arguments)]
    pub fn verify_all_passphrase_rotation_preservations(
        &mut self,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
    ) -> Result<[u8; 32]> {
        self.hold_rotation_preservations(
            expected,
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            None,
        )
        .map(|checked| checked.fixed.public)
    }

    /// 同じ排他と現物fdで全保全を照合し、指定した新暗号文長で履歴三件分の容量を確認する。
    /// この確認はguardや履歴を作らず、後の書込みを許可する控えを発行しない。
    #[allow(clippy::too_many_arguments)]
    pub fn verify_passphrase_rotation_capacity(
        &mut self,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        new_ciphertext_length: usize,
    ) -> Result<[u8; 32]> {
        if !(1..=MAX_KEYFILE_BYTES).contains(&new_ciphertext_length) {
            return invalid();
        }
        self.hold_rotation_preservations(
            expected,
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            Some(new_ciphertext_length),
        )
        .map(|checked| checked.fixed.public)
    }

    /// 連続更新の開始記録を保存する。鍵の置換は後続段階が行う。
    #[allow(clippy::too_many_arguments)]
    pub fn record_passphrase_rotation_start(
        &mut self,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        receipts: &mut impl std::io::Write,
    ) -> Result<(KeyStateDiagnostic, Vec<u8>)> {
        let mut start = self.prepare_passphrase_rotation_start(
            expected,
            current_name,
            passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            receipts,
            false,
        )?;
        let diagnostic = start.record()?;
        Ok((diagnostic, start.into_ciphertext()))
    }

    /// 開始と準備の履歴を、同じ排他と保全の保持下で個別に保存する。
    #[allow(clippy::too_many_arguments)]
    pub fn record_passphrase_rotation_prepared(
        &mut self,
        expected: &KeyStateDiagnostic,
        current_name: &str,
        passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        receipts: &mut impl std::io::Write,
    ) -> Result<KeyStateDiagnostic> {
        let mut start = self.prepare_passphrase_rotation_start(
            expected,
            current_name,
            passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            receipts,
            true,
        )?;
        start.record()?;
        let prepared = start.prepare_ciphertext(new_passphrase)?;
        let intent = prepared.intent();
        passphrase_start::update::receipt(
            receipts,
            "key_passphrase_rotation_prepared",
            intent.before,
            intent.after,
            intent.operation_id,
        )?;
        prepared.record()
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_passphrase_rotation_start<'a>(
        &'a mut self,
        expected: &KeyStateDiagnostic,
        current_name: &'a str,
        passphrase: &str,
        new_passphrase: &str,
        backups: &'a mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        receipts: &mut impl std::io::Write,
        reserve_staged_key: bool,
    ) -> Result<passphrase_start::PreparedKeyPassphraseStart<'a>> {
        let mut checked = self.hold_rotation_preservations(
            expected,
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            None,
        )?;
        let new_ciphertext =
            unlock(&checked.fixed.key.bytes, passphrase)?.encrypt(new_passphrase)?;
        let new_hash: [u8; 32] = Sha256::digest(&new_ciphertext).into();
        if new_hash == <[u8; 32]>::from(Sha256::digest(&checked.fixed.key.bytes)) {
            return invalid();
        }
        let mut start = checked.start_record(expected, new_ciphertext.len())?;
        let mut operation = [0; 32];
        crate::keyfile::random(&mut operation)?;
        let events = array(field(&checked.fixed.history, "events")?)?;
        if events
            .iter()
            .any(|event| field(event, "operation_id").and_then(id) == Ok(operation))
        {
            return invalid();
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let now = i64::try_from(now.as_secs()).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let source_identity =
            KeyDirectoryIdentity::from_metadata(&io(checked.source.dir.metadata())?);
        let backup_identities = checked
            .backups
            .iter()
            .map(|directory| {
                Ok(KeyDirectoryIdentity::from_metadata(&io(directory
                    .dir
                    .metadata())?))
            })
            .collect::<Result<Vec<_>>>()?;
        checked.sync_and_recheck()?;
        let reserved_entries = 2 + usize::from(reserve_staged_key);
        if inventory(checked.source, None)? > SCAN_LIMIT - reserved_entries {
            return Err(KeyFileError::ScanLimit);
        }
        let guard = passphrase_start::create_start_guard(
            checked.source,
            &expected.initial.area_id,
            &mut |_| Ok(()),
        )?;
        let Value::Map(fields) = &mut start else {
            return invalid();
        };
        for (name, value) in fields {
            match name.as_str() {
                "operation_id" => *value = bytes(operation),
                "recorded_unix_seconds" => *value = Value::Int(now),
                "new_ciphertext_sha256" => *value = bytes(new_hash),
                "guard_identity" => {
                    *value = KeyFileIdentity::from_metadata(&guard.metadata).value()
                }
                _ => (),
            }
        }
        let Value::Map(fields) = &mut checked.fixed.history else {
            return invalid();
        };
        let Some((_, Value::Array(events))) = fields.iter_mut().find(|(key, _)| key == "events")
        else {
            return invalid();
        };
        events.push(start);
        let new_bytes = encoded(&checked.fixed.history)?;
        let mut marker = checked.fixed.marker.bytes[..73].to_vec();
        marker[19] = b'1';
        let after = state_history::decode_history(
            &new_bytes,
            &marker,
            expected.initial.area_id,
            expected.initial.snapshot_hash,
        )?;
        let prepared = PreparedKeyResume {
            source: checked.source,
            backups: checked.backups,
            source_identity,
            backup_identities,
            current_name: current_name.into(),
            current: checked.fixed.key,
            preservations: checked.preservations,
            absent_names: Vec::new(),
            marker: checked.fixed.marker,
            guard: Some(guard),
            state: checked.fixed.snapshot,
            new_bytes,
            staged_key: None,
            removed_key: None,
            intent: KeyResumeIntent {
                before: *expected,
                after,
                operation_id: operation,
            },
        };
        passphrase_start::update::receipt(
            receipts,
            "key_passphrase_rotation_started",
            *expected,
            after,
            operation,
        )?;
        Ok(passphrase_start::PreparedKeyPassphraseStart::new(
            prepared,
            new_ciphertext,
        ))
    }

    /// 控えと完全な開始候補が一致する場合に限り、開始履歴の保存を復旧する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_passphrase_rotation_start(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
    ) -> Result<KeyStateDiagnostic> {
        self.recover_passphrase_rotation_snapshot(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            None,
        )
    }

    /// 準備履歴と一時鍵の完全な候補を照合し、準備履歴を復旧する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_passphrase_rotation_prepared(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        new_passphrase: &str,
    ) -> Result<KeyStateDiagnostic> {
        self.recover_passphrase_rotation_snapshot(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            Some((prepared, new_passphrase)),
        )
    }

    /// 交換を行うか、交換済みの配置を再照合して保存を確認する。
    /// 旧暗号文とguardは保持する。
    #[allow(clippy::too_many_arguments)]
    pub fn exchange_passphrase_rotation(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
    ) -> Result<passphrase_start::KeyPassphraseExchange> {
        self.exchange_passphrase_rotation_with(
            current_name,
            old_passphrase,
            new_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            prepared,
            &mut |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super::super) fn exchange_passphrase_rotation_with(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        hook: &mut impl FnMut(ResumeStage) -> Result<()>,
    ) -> Result<passphrase_start::KeyPassphraseExchange> {
        self.with_passphrase_rotation_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            Some((prepared, new_passphrase)),
            RotationAction::Exchange,
            |mut context, _, _, _, _| {
                let staged = context
                    .staged_key
                    .take()
                    .ok_or(KeyFileError::RecoveryStateInvalid)?;
                let key_name = passphrase_start::staged_name(&start.operation_id);
                let before_exchange = context.current_name == current_name;
                context.qualify(Some(&key_name), false, hook, &mut || {
                    staged.1.check(context.source, &staged.0, true)
                })?;
                passphrase_start::exchange::exchange_passphrase_pair(
                    context,
                    staged,
                    &key_name,
                    before_exchange,
                    hook,
                )
            },
        )
    }

    /// 交換済み配置で旧一時鍵を整理し、完了控えをflushしてから完了を記録する。
    #[allow(clippy::too_many_arguments)]
    pub fn complete_passphrase_rotation(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        receipts: &mut impl std::io::Write,
    ) -> Result<KeyStateDiagnostic> {
        self.with_passphrase_rotation_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            Some((prepared, new_passphrase)),
            RotationAction::Complete,
            |mut context, _, _, _, _| {
                use passphrase_start::{KeyPassphraseCleanup, PreparedKeyPassphraseCompletion};
                let key_name = passphrase_start::staged_name(&start.operation_id);
                let cleanup = if let Some(staged) = context.staged_key.take() {
                    context.qualify(Some(&key_name), false, &mut |_| Ok(()), &mut || {
                        staged.1.check(context.source, &staged.0, true)
                    })?;
                    context = passphrase_start::exchange::remove_passphrase_old_key(
                        context,
                        staged,
                        key_name,
                        &mut |_| Ok(()),
                    )?;
                    KeyPassphraseCleanup::RemovedRetainedOldCiphertext
                } else {
                    context.qualify(None, false, &mut |_| Ok(()), &mut || {
                        absent(context.source, &key_name)
                    })?;
                    KeyPassphraseCleanup::ConfirmedOldCiphertextAbsent
                };
                let completion =
                    PreparedKeyPassphraseCompletion::new(context, cleanup, start, prepared)?;
                let intent = completion.intent();
                passphrase_start::update::receipt(
                    receipts,
                    "key_passphrase_rotation_completed",
                    intent.before,
                    intent.after,
                    intent.operation_id,
                )?;
                completion.record()
            },
        )
    }

    /// 完全な完了履歴の候補を復旧し、guardを維持する。
    #[allow(clippy::too_many_arguments)]
    pub fn recover_passphrase_rotation_completed(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        completed: &KeyPassphraseCompletedIntent,
    ) -> Result<KeyStateDiagnostic> {
        self.with_passphrase_rotation_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            Some((prepared, new_passphrase)),
            RotationAction::RecoverCompletion(completed),
            |context, temporary, temp, needs_exchange, intent| {
                recovery::recover_snapshot(
                    context,
                    temporary,
                    temp,
                    needs_exchange,
                    intent,
                    &mut |_| Ok(()),
                    false,
                )
            },
        )
    }

    /// 固定完了を再認証してguardを解除するか、正確不在を今回確認する。
    #[allow(clippy::too_many_arguments)]
    pub fn release_passphrase_rotation(
        &mut self,
        current_name: &str,
        old_passphrase: &str,
        new_passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: &KeyPassphrasePreparedIntent,
        completed: &KeyPassphraseCompletedIntent,
    ) -> Result<release::KeyResumeRelease> {
        self.with_passphrase_rotation_snapshot(
            current_name,
            old_passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            Some((prepared, new_passphrase)),
            RotationAction::Release(completed),
            |context, _, _, _, intent| {
                context.release_recorded_guard(intent.after, &mut |_| Ok(()))
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_passphrase_rotation_snapshot(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: Option<(&KeyPassphrasePreparedIntent, &str)>,
    ) -> Result<KeyStateDiagnostic> {
        self.with_passphrase_rotation_snapshot(
            current_name,
            passphrase,
            backups,
            current_backup,
            backup_name,
            proofs,
            start,
            prepared,
            RotationAction::RecoverHistory,
            |context, temporary, temp, needs_exchange, intent| {
                recovery::recover_snapshot(
                    context,
                    temporary,
                    temp,
                    needs_exchange,
                    intent,
                    &mut |_| Ok(()),
                    false,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_passphrase_rotation_snapshot<T>(
        &mut self,
        current_name: &str,
        passphrase: &str,
        backups: &mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        start: &KeyPassphraseStartIntent,
        prepared: Option<(&KeyPassphrasePreparedIntent, &str)>,
        action: RotationAction<'_>,
        apply: impl FnOnce(
            PreparedKeyResume<'_>,
            Option<&HeldFile>,
            &str,
            bool,
            &KeyResumeIntent,
        ) -> Result<T>,
    ) -> Result<T> {
        if proofs.len() >= 1024 || backups.len() > proofs.len() + 1 {
            return invalid();
        }
        name(current_name)?;
        name(backup_name)?;
        let start_intent = KeyResumeIntent {
            before: start.before,
            after: start.after,
            operation_id: start.operation_id,
        };
        if start_intent.after.state
            != (KeyHistoryState::PassphraseRotationStarted {
                started_operation_id: start_intent.operation_id,
            })
        {
            return invalid();
        }
        let (stage_intent, stage_kind, key_name) = if let Some((prepared, _)) = prepared {
            if prepared.before != start.after
                || prepared.after.state
                    != (KeyHistoryState::PassphraseRotationPrepared {
                        prepared_operation_id: prepared.operation_id,
                    })
            {
                return invalid();
            }
            (
                KeyResumeIntent {
                    before: prepared.before,
                    after: prepared.after,
                    operation_id: prepared.operation_id,
                },
                "key_passphrase_rotation_prepared",
                Some(passphrase_start::staged_name(&start.operation_id)),
            )
        } else {
            (start_intent, "key_passphrase_rotation_started", None)
        };
        let release = matches!(action, RotationAction::Release(_));
        let completion = match action {
            RotationAction::RecoverCompletion(completed) | RotationAction::Release(completed) => {
                if prepared.is_none()
                    || completed.before != stage_intent.after
                    || completed.after.state
                        != (KeyHistoryState::PassphraseRotationCompleted {
                            completed_operation_id: completed.operation_id,
                        })
                {
                    return invalid();
                }
                Some(KeyResumeIntent {
                    before: completed.before,
                    after: completed.after,
                    operation_id: completed.operation_id,
                })
            }
            _ => None,
        };
        let (intent, kind) = completion.map_or((stage_intent, stage_kind), |intent| {
            (intent, "key_passphrase_rotation_completed")
        });
        let recover_history = action == RotationAction::RecoverHistory
            || matches!(action, RotationAction::RecoverCompletion(_));
        let temp = format!(
            ".lngnb-key-state-update-{}",
            data_encoding::HEXLOWER.encode(&intent.operation_id)
        );
        inventory_with_key(
            self,
            recover_history.then_some(temp.as_str()),
            key_name.as_deref(),
        )?;
        let fixed = HeldFile::open(self, initial_state::STATE, initial_state::STATE_LIMIT)?;
        let temporary = match HeldFile::open(self, &temp, initial_state::STATE_LIMIT) {
            Ok(file) => Some(file),
            Err(KeyFileError::Missing) => None,
            Err(error) => return Err(error),
        };
        let marker = HeldFile::open(self, recovery_hold::MARKER, MAX_KEYFILE_BYTES)?;
        let source_marker = recovery::source_marker(self, &intent)?;
        marker.check(self, recovery_hold::MARKER, true)?;
        let decode =
            |file: &HeldFile| recovery::decode_snapshot(&file.bytes, &source_marker, &intent);
        let needs_exchange = decode(&fixed)? == intent.before;
        if !recover_history && (prepared.is_none() || needs_exchange || temporary.is_some()) {
            return invalid();
        }
        let (new, old) = if needs_exchange {
            (
                temporary
                    .as_ref()
                    .ok_or(KeyFileError::RecoveryStateInvalid)?,
                Some(&fixed),
            )
        } else {
            (&fixed, temporary.as_ref())
        };
        if decode(new)? != intent.after {
            return invalid();
        }
        let prefix = recovery::verify_event_prefix(&new.bytes, &source_marker, &intent, kind)?;
        if old.is_some_and(|held| held.bytes != prefix) {
            return invalid();
        }
        let (stage_bytes, stage_prefix) = if completion.is_some() {
            let started =
                recovery::verify_event_prefix(&prefix, &source_marker, &stage_intent, stage_kind)?;
            (prefix, started)
        } else {
            (new.bytes.clone(), prefix)
        };
        let (started, completed) = if prepared.is_some() {
            let completed = recovery::verify_event_prefix(
                &stage_prefix,
                &source_marker,
                &start_intent,
                "key_passphrase_rotation_started",
            )?;
            (stage_prefix, completed)
        } else {
            (stage_bytes.clone(), stage_prefix)
        };
        let value = cbor::decode(&started).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let event = array(field(&value, "events")?)?
            .last()
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        if string(field(event, "name")?)? != current_name {
            return invalid();
        }
        let mut moved_path = None;
        let mut staged_key = if let (Some(name), Some((_, new_passphrase))) =
            (key_name.as_deref(), prepared)
        {
            let next =
                cbor::decode(&stage_bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
            let preparation = array(field(&next, "events")?)?
                .last()
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            let expected =
                state_history::recorded_file_identity(field(preparation, "new_identity")?)?;
            let mut path = name;
            let mut moved = false;
            if action != RotationAction::RecoverHistory {
                let normal = HeldFile::open(self, current_name, MAX_KEYFILE_BYTES)?;
                let old_identity =
                    state_history::recorded_file_identity(field(event, "old_identity")?)?;
                if !matches_rotation_key_identity(&normal, old_identity, false) {
                    moved = true;
                    moved_path = Some(name);
                    path = current_name;
                } else if action == RotationAction::Complete || completion.is_some() {
                    return invalid();
                }
            }
            let held = HeldFile::open(self, path, MAX_KEYFILE_BYTES)?;
            if !matches_rotation_key_identity(&held, expected, moved) {
                return Err(KeyFileError::RecoveryChanged);
            }
            if completion.is_some() {
                let value =
                    cbor::decode(&new.bytes).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
                let finished = array(field(&value, "events")?)?
                    .last()
                    .ok_or(KeyFileError::RecoveryStateInvalid)?;
                let installed =
                    state_history::recorded_file_identity(field(finished, "installed_identity")?)?;
                if !matches_rotation_key_identity(&held, installed, false) {
                    return Err(KeyFileError::RecoveryChanged);
                }
            }
            passphrase_start::authenticate_staged(&held.bytes, event, new_passphrase)?;
            held.check(self, path, true)?;
            held.sync()?;
            held.check(self, path, true)?;
            Some((path.to_owned(), held))
        } else {
            None
        };
        let guard = match HeldFile::open(self, recovery_hold::GUARD, MAX_KEYFILE_BYTES) {
            Ok(guard) => {
                let mut guard_bytes = b"lngnb:key-hold:1\0".to_vec();
                guard_bytes.extend(intent.before.initial.area_id);
                if KeyFileIdentity::from_metadata(&guard.metadata)
                    != state_history::recorded_guard_identity(event)?
                    || guard.bytes != guard_bytes
                {
                    return invalid();
                }
                Some(guard)
            }
            Err(KeyFileError::Missing) if release => {
                absent(self, recovery_hold::GUARD)?;
                None
            }
            Err(error) => return Err(error),
        };
        let backup = backups
            .get(current_backup)
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        for directory in backups.iter() {
            directory.pending()?;
        }
        let saved = field(event, "preserved")?;
        let backup_identity = KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?);
        if backup_name != string(field(saved, "name")?)?
            || !equal(field(saved, "directory")?, &backup_identity.value())?
        {
            return invalid();
        }
        let current = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
        if KeyFileIdentity::from_metadata(&current.metadata)
            != state_history::recorded_file_identity(field(saved, "identity")?)?
        {
            return invalid();
        }
        let new_bytes = new.bytes.clone();
        let history = cbor::decode(&completed).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let absent_old = if completion.is_some() {
            absent(self, moved_path.ok_or(KeyFileError::RecoveryStateInvalid)?)?;
            true
        } else if action == RotationAction::Complete {
            let path = moved_path.ok_or(KeyFileError::RecoveryStateInvalid)?;
            match absent(self, path) {
                Ok(()) => true,
                Err(KeyFileError::RecoveryChanged) => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        let location = if absent_old {
            RotationOldKey::Preserved(backup, backup_name)
        } else if let Some(path) = moved_path {
            RotationOldKey::Moved(path)
        } else {
            RotationOldKey::Normal
        };
        let fixed = FixedRotationKey::from_completed_history(
            self,
            &start_intent.before,
            current_name,
            passphrase,
            marker,
            fixed,
            history,
            location,
        )?;
        if current.bytes != fixed.key.bytes {
            return Err(KeyFileError::PreservationMismatch);
        }
        let mut used = vec![false; backups.len()];
        used[current_backup] = true;
        let mut preservations = fixed.open_history_preservations(backups, proofs, &mut used)?;
        preservations.insert(
            0,
            Preservation {
                directory: current_backup,
                name: backup_name.into(),
                held: current,
            },
        );
        let source_identity = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        let backup_identities = backups
            .iter()
            .map(|directory| {
                Ok(KeyDirectoryIdentity::from_metadata(&io(directory
                    .dir
                    .metadata())?))
            })
            .collect::<Result<Vec<_>>>()?;
        let (current_name, current, absent_names) = if absent_old {
            let installed = staged_key
                .take()
                .ok_or(KeyFileError::RecoveryStateInvalid)?;
            (
                installed.0,
                installed.1,
                vec![moved_path.ok_or(KeyFileError::RecoveryStateInvalid)?.into()],
            )
        } else {
            (
                moved_path.unwrap_or(current_name).into(),
                fixed.key,
                Vec::new(),
            )
        };
        let context = PreparedKeyResume {
            source: self,
            backups,
            source_identity,
            backup_identities,
            current_name,
            current,
            preservations,
            absent_names,
            marker: fixed.marker,
            guard,
            state: fixed.snapshot,
            new_bytes,
            staged_key,
            removed_key: None,
            intent,
        };
        apply(context, temporary.as_ref(), &temp, needs_exchange, &intent)
    }

    #[allow(clippy::too_many_arguments)]
    fn hold_rotation_preservations<'a>(
        &'a mut self,
        expected: &KeyStateDiagnostic,
        current_name: &'a str,
        passphrase: &str,
        backups: &'a mut [KeyDirectory],
        current_backup: usize,
        backup_name: &str,
        proofs: &[KeyResumePreservation<'_>],
        new_ciphertext_length: Option<usize>,
    ) -> Result<CheckedRotationPreservations<'a>> {
        if proofs.len() >= 1024 || backups.len() > proofs.len() + 1 {
            return invalid();
        }
        name(current_name)?;
        name(backup_name)?;
        let backup = backups
            .get(current_backup)
            .ok_or(KeyFileError::RecoveryStateInvalid)?;
        let source_id = KeyDirectoryIdentity::from_metadata(&io(self.dir.metadata())?);
        let backup_id = KeyDirectoryIdentity::from_metadata(&io(backup.dir.metadata())?);
        if source_id.dev == backup_id.dev && source_id.ino == backup_id.ino {
            return Err(KeyFileError::UnsafePath);
        }
        for directory in backups.iter() {
            directory.pending()?;
        }
        let fixed = FixedRotationKey::open(self, expected, current_name, passphrase)?;
        let current = HeldFile::open(backup, backup_name, MAX_KEYFILE_BYTES)?;
        let candidate = KeyFileIdentity::from_metadata(&current.metadata);
        fixed.reject_recorded_backup(backup_id, backup_name, Some(candidate))?;
        if current.bytes != fixed.key.bytes
            || (candidate.dev == fixed.key.metadata.dev()
                && candidate.ino == fixed.key.metadata.ino())
        {
            return Err(KeyFileError::PreservationMismatch);
        }
        let mut used = vec![false; backups.len()];
        used[current_backup] = true;
        let past = fixed.open_history_preservations(backups, proofs, &mut used)?;
        let mut preservations = Vec::with_capacity(past.len() + 1);
        preservations.push(Preservation {
            directory: current_backup,
            name: backup_name.into(),
            held: current,
        });
        preservations.extend(past);
        let checked = CheckedRotationPreservations {
            source: self,
            backups,
            current_name,
            fixed,
            preservations,
        };
        if let Some(new_length) = new_ciphertext_length {
            checked.start_record(expected, new_length)?;
        }
        checked.sync_and_recheck()?;
        Ok(checked)
    }
}
