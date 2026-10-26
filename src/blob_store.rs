//! A8/A9.2の物理Blob保存。明示保持と期限付き内部仮保存。HTTP受付/公開資格は付与しない。
use super::*;
use crate::id::BlobHasher;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlobRecovery {
    pub incomplete_staging: Vec<String>,
    pub orphaned: Vec<Id>,
    pub missing: Vec<Id>,
    pub corrupt: Vec<Id>,
}
impl BlobRecovery {
    pub fn needs_review(&self) -> bool {
        !self.incomplete_staging.is_empty()
            || !self.orphaned.is_empty()
            || !self.missing.is_empty()
            || !self.corrupt.is_empty()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobStored {
    pub id: Id,
    pub byte_length: u64,
    pub newly_retained: bool,
}

/// 内部仮保存の集合上限。期限切れも整理されるまでは枠と保護を消費する。
#[derive(Debug, Clone, Copy)]
pub struct TemporaryLimits {
    pub bytes: u64,
    pub holds: u64,
}
impl Default for TemporaryLimits {
    fn default() -> Self {
        Self {
            bytes: 256 * 1024 * 1024,
            holds: 100_000,
        }
    }
}
/// 管理用の保存結果。HTTP receiptでも本人照会資格でもない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporaryBlob {
    pub id: Id,
    pub byte_length: u64,
    pub hold_id: [u8; 32],
    /// Unix秒。成功確定時点を基準とする。既存の約束は更新しない。
    pub created_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Copy)]
enum Hold {
    Manual,
    Temporary {
        ttl: u64,
        limits: TemporaryLimits,
        id: [u8; 32],
    },
}
fn temporary_budget(conn: &Connection, id: Id, length: u64, limits: TemporaryLimits) -> Result<()> {
    let (count, size, present): (i64,i64,bool) = conn.query_row(
        "SELECT (SELECT count(*) FROM temporary_blob_holds),coalesce((SELECT sum(byte_length) FROM blobs WHERE id IN (SELECT blob_id FROM temporary_blob_holds)),0),EXISTS(SELECT 1 FROM temporary_blob_holds WHERE blob_id=?1)",
        [&id.bytes], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if count < 0 || size < 0 {
        return Err(StorageError::Corrupt);
    }
    if count as u64 >= limits.holds
        || (size as u64)
            .checked_add(if present { 0 } else { length })
            .is_none_or(|n| n > limits.bytes)
    {
        return Err(StorageError::BudgetExceeded);
    }
    Ok(())
}
pub(super) fn validate_holds(conn: &Connection) -> Result<()> {
    // 約束を失った場合、明示保持済みの同じBlobがあっても黙って忘れない。
    let bad: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM blobs b LEFT JOIN blob_objects o ON o.id=b.id WHERE o.id IS NULL OR b.byte_length!=o.byte_length
        ) OR EXISTS(
            SELECT 1 FROM blob_objects o WHERE NOT EXISTS(SELECT 1 FROM blobs b WHERE b.id=o.id)
            AND NOT EXISTS(SELECT 1 FROM blob_cleanup_runs r JOIN blob_cleanup_plans p ON p.plan_id=r.plan_id WHERE p.blob_id=o.id AND r.finished_generation IS NOT NULL
                AND r.finished_generation>=(SELECT coalesce(max(h.generation),0) FROM history h WHERE h.target=o.id AND h.new_state IN ('blob_staged_local_only','blob_retained_local_only')))
        ) OR EXISTS(
            SELECT 1 FROM blobs b
            WHERE NOT EXISTS(SELECT 1 FROM manual_blob_holds m WHERE m.blob_id=b.id)
              AND NOT EXISTS(SELECT 1 FROM temporary_blob_holds t WHERE t.blob_id=b.id)
        ) OR EXISTS(
            SELECT 1 FROM manual_blob_holds m LEFT JOIN blobs b ON b.id=m.blob_id
            WHERE b.id IS NULL
        ) OR EXISTS(
            SELECT 1 FROM temporary_blob_holds t
            LEFT JOIN blob_objects b ON b.id=t.blob_id
            LEFT JOIN history h ON h.generation=t.generation
            WHERE b.id IS NULL OR length(t.hold_id)!=32 OR t.created_at<0
               OR t.expires_at<=t.created_at OR t.expires_at>253402300799
               OR h.generation IS NULL OR h.target IS NOT t.blob_id
               OR h.namespace IS NOT (SELECT namespace FROM storage_state WHERE singleton=1)
               OR h.new_state!='blob_staged_local_only' OR h.rules!='lngnb-validation-1'
               OR h.reason!='temporary_local_blob_promise:'||lower(hex(t.hold_id))||':'||t.created_at||':'||t.expires_at
        ) OR EXISTS(
            SELECT 1 FROM history h LEFT JOIN temporary_blob_holds t ON t.generation=h.generation
            WHERE h.new_state='blob_staged_local_only' AND t.hold_id IS NULL
        )", [], |r| r.get(0),
    )?;
    if bad {
        return Err(StorageError::Corrupt);
    }
    cleanup::validate(conn)?;
    Ok(())
}
pub(super) fn unix_now() -> Result<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StorageError::BudgetExceeded)?
        .as_secs();
    i64::try_from(now).map_err(|_| StorageError::BudgetExceeded)
}

pub(super) fn initialize_directories(root: &OwnedFd) -> Result<()> {
    for name in ["staging", "blobs"] {
        fs::mkdirat(root, name, Mode::RWXU)?;
        let dir = blob_directory(root, name)?;
        fs::fsync(&dir)?;
    }
    fs::fsync(root)?;
    Ok(())
}
pub(super) fn blob_directory(root: &OwnedFd, name: &str) -> Result<OwnedFd> {
    let fd = fs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    check_area(&fd)?;
    if fs::fstat(root)?.st_dev != fs::fstat(&fd)?.st_dev {
        return Err(StorageError::UnsafePath);
    }
    Ok(fd)
}
pub(super) fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut text, b| {
        write!(text, "{b:02x}").expect("writing to String");
        text
    })
}
pub(super) fn parse_name(name: &str) -> Result<Id> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StorageError::UnsafePath);
    }
    let mut bytes = [0; 32];
    for (i, out) in bytes.iter_mut().enumerate() {
        *out = u8::from_str_radix(&name[2 * i..2 * i + 2], 16)
            .map_err(|_| StorageError::UnsafePath)?;
    }
    Ok(Id {
        kind: Kind::Blob,
        bytes,
    })
}
pub(super) fn checked_file(dir: &OwnedFd, name: &str) -> Result<File> {
    let file: File = fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
        return Err(StorageError::UnsafePath);
    }
    Ok(file)
}
pub(super) fn verify_file(
    dir: &OwnedFd,
    id: Id,
    length: Option<u64>,
    budget: u64,
) -> Result<(File, u64)> {
    let mut file = checked_file(dir, &hex(&id.bytes))?;
    let expected_len = file.metadata()?.len();
    // 台帳/確定転送と異なる物理長は破損。検査の予算不足と混同しない。
    if length.is_some_and(|n| n != expected_len) {
        return Err(StorageError::Corrupt);
    }
    if expected_len > budget {
        return Err(StorageError::BudgetExceeded);
    }
    let mut hash = BlobHasher::default();
    let mut total = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(StorageError::Corrupt)?;
        if total > expected_len || total > budget {
            return Err(StorageError::Corrupt);
        }
        hash.update(&buffer[..n]);
    }
    if total != expected_len || hash.finish() != id {
        return Err(StorageError::Corrupt);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((file, total))
}
pub(super) fn entries(dir: &OwnedFd, remaining: &mut u64) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(anchored(dir, "."))? {
        if *remaining == 0 {
            return Err(StorageError::BudgetExceeded);
        }
        *remaining -= 1;
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| StorageError::UnsafePath)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}
impl RecordStore {
    pub(super) fn recovery_files(&self) -> Result<Vec<(String, String)>> {
        recovery_files(&self.dir, self.limits.scan_blob_files)
    }
    pub fn blob_recovery(&self) -> &BlobRecovery {
        &self.blob_recovery
    }
    /// 保持台帳にある正常な本文だけを返すローカル読取り。一般配信資格ではない。
    pub fn blob(&self, id: Id) -> Result<Option<File>> {
        if id.kind != Kind::Blob {
            return Err(StorageError::InvalidBlobId);
        }
        let length: Option<i64> = self
            .conn
            .query_row(
                "SELECT byte_length FROM blobs WHERE id=?1",
                [&id.bytes],
                |r| r.get(0),
            )
            .optional()?;
        match length {
            None => Ok(None),
            Some(n) if n >= 0 => {
                let dir = blob_directory(&self.dir, "blobs")?;
                match verify_file(&dir, id, Some(n as u64), self.limits.scan_blob_bytes) {
                    Ok((file, _)) => Ok(Some(file)),
                    Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        Err(StorageError::Corrupt)
                    }
                    Err(e) => Err(e),
                }
            }
            _ => Err(StorageError::Corrupt),
        }
    }
    pub(super) fn scan_blobs(&self) -> Result<BlobRecovery> {
        let dir = blob_directory(&self.dir, "blobs")?;
        let staging = blob_directory(&self.dir, "staging")?;
        let mut known = BTreeMap::new();
        let mut statement = self
            .conn
            .prepare("SELECT id,byte_length FROM blobs ORDER BY id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if known.len() as u64 >= self.limits.scan_blob_files {
                return Err(StorageError::BudgetExceeded);
            }
            let bytes: Vec<u8> = row.get(0)?;
            let n: i64 = row.get(1)?;
            if n < 0 {
                return Err(StorageError::Corrupt);
            }
            let id: [u8; 32] = bytes.try_into().map_err(|_| StorageError::Corrupt)?;
            known.insert(id, n as u64);
        }
        let mut report = BlobRecovery::default();
        let mut remaining = self.limits.scan_blob_files;
        let mut byte_budget = self.limits.scan_blob_bytes;
        for name in entries(&staging, &mut remaining)? {
            let stem = name.strip_suffix(".part").ok_or(StorageError::UnsafePath)?;
            parse_name(stem)?;
            let file = checked_file(&staging, &name)?;
            let size = file.metadata()?.len();
            byte_budget = byte_budget
                .checked_sub(size)
                .ok_or(StorageError::BudgetExceeded)?;
            report.incomplete_staging.push(name);
        }
        for name in entries(&dir, &mut remaining)? {
            let id = parse_name(&name)?;
            let expected = known.remove(&id.bytes);
            // 壊れたfileでも実長分の検査予算を先に差し引く。
            let size = checked_file(&dir, &name)?.metadata()?.len();
            if size > byte_budget {
                return Err(StorageError::BudgetExceeded);
            }
            match verify_file(&dir, id, expected, byte_budget) {
                Ok((_, n)) => {
                    byte_budget -= n;
                    if expected.is_none() {
                        report.orphaned.push(id);
                    }
                }
                Err(StorageError::Corrupt) => {
                    byte_budget -= size;
                    report.corrupt.push(id);
                }
                Err(e) => return Err(e),
            }
        }
        for (bytes, _) in known {
            report.missing.push(Id {
                kind: Kind::Blob,
                bytes,
            });
        }
        Ok(report)
    }
}
impl RecordWriter {
    pub fn blob(&mut self, id: Id) -> Result<Option<File>> {
        let result = self.store.blob(id);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// inputの全体転送を検査し、明示的に保持する。宣言長の採否や公開状態は扱わない。
    /// 転送は一Blob上限＋超過検出1byte、容量は上限全量を開始前に予約する。
    /// 中止した受信bytes/試行件数も消費し、予算不足ならreaderを読まない。
    pub fn put_blob(&mut self, id: Id, input: impl Read) -> Result<BlobStored> {
        self.put_with_hold(id, input, Hold::Manual)
            .map(|(stored, _)| stored)
    }
    /// 検査・配置・期限付き約束・履歴を確定する内部経路。既定TTLは呼出し側で86400秒。
    /// 全存続約束を保守的に数え、期限終了だけでは解放/削除しない。
    pub fn stage_blob(
        &mut self,
        id: Id,
        input: impl Read,
        ttl_seconds: u64,
        limits: TemporaryLimits,
    ) -> Result<TemporaryBlob> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if id.kind != Kind::Blob {
            return Err(StorageError::InvalidBlobId);
        }
        if ttl_seconds == 0 || ttl_seconds > 253402300799 {
            return Err(StorageError::BudgetExceeded);
        }
        if let Err(e) = validate_holds(&self.store.conn) {
            self.failed = true;
            return Err(e);
        }
        temporary_budget(
            &self.store.conn,
            id,
            self.store.limits.max_blob_bytes,
            limits,
        )?;
        let hold_id = Id::random_knowledge()
            .map_err(|_| StorageError::RandomUnavailable)?
            .bytes;
        let (_, temporary) = self.put_with_hold(
            id,
            input,
            Hold::Temporary {
                ttl: ttl_seconds,
                limits,
                id: hold_id,
            },
        )?;
        temporary.ok_or(StorageError::Corrupt)
    }
    fn put_with_hold(
        &mut self,
        id: Id,
        input: impl Read,
        hold: Hold,
    ) -> Result<(BlobStored, Option<TemporaryBlob>)> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if id.kind != Kind::Blob {
            return Err(StorageError::InvalidBlobId);
        }
        let max = self.store.limits.max_blob_bytes;
        let transfer_reserve = max.checked_add(1).ok_or(StorageError::BudgetExceeded)?;
        if self.blobs >= self.store.limits.session_blobs
            || transfer_reserve > self.store.limits.session_bytes.saturating_sub(self.bytes)
        {
            return Err(StorageError::BudgetExceeded);
        }
        let reserve = max.checked_add(65536).ok_or(StorageError::Capacity)?;
        let capacity = self.store.capacity()?;
        if capacity.available
            <= capacity
                .reserved_floor
                .saturating_add(self.reserved)
                .saturating_add(reserve)
        {
            return Err(StorageError::Capacity);
        }
        self.reserved += reserve;
        self.blobs += 1;
        let mut clean_abort = false;
        let result = self.put_blob_inner(id, input, max, &mut clean_abort, hold);
        // 壊れた転送は宣言矛盾の証明ではない。失敗観測だけを別に記録する。
        let failure = match &result {
            Err(StorageError::BlobHashMismatch) => Some("transfer_hash_mismatch"),
            Err(StorageError::Io(_)) => Some("transfer_failed"),
            _ => None,
        };
        if let Some(reason) = failure {
            if let Err(e) = self.observe_blob_failure(id, reason) {
                self.reserved -= reserve;
                self.failed = true;
                return Err(e);
            }
        }
        self.reserved -= reserve;
        match &result {
            Ok(_) => (),
            Err(_) if clean_abort => (),
            Err(_) => self.failed = true,
        }
        result
    }
    fn put_blob_inner(
        &mut self,
        id: Id,
        mut input: impl Read,
        max: u64,
        clean_abort: &mut bool,
        hold: Hold,
    ) -> Result<(BlobStored, Option<TemporaryBlob>)> {
        let staging = blob_directory(&self.store.dir, "staging")?;
        let target = blob_directory(&self.store.dir, "blobs")?;
        let random = Id::random_knowledge().map_err(|_| StorageError::RandomUnavailable)?;
        let name = format!("{}.part", hex(&random.bytes));
        let mut file: File = fs::openat(
            &staging,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?
        .into();
        let mut hash = BlobHasher::default();
        let mut length = 0u64;
        let mut buffer = [0; 65536];
        loop {
            let request = usize::try_from(
                max.saturating_sub(length)
                    .saturating_add(1)
                    .min(buffer.len() as u64),
            )
            .map_err(|_| StorageError::BudgetExceeded)?;
            let n = input.read(&mut buffer[..request])?;
            if n > request {
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "reader exceeded buffer",
                )));
            }
            if n == 0 {
                break;
            }
            // 書込み/ハッシュ/上限判定より先に、受信済み量を計上する。
            self.bytes = self
                .bytes
                .checked_add(n as u64)
                .ok_or(StorageError::BudgetExceeded)?;
            if n as u64 > max - length {
                drop(file);
                remove_staging(&staging, &name)?;
                *clean_abort = true;
                return Err(StorageError::BudgetExceeded);
            }
            file.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
            length += n as u64;
        }
        if hash.finish() != id {
            drop(file);
            remove_staging(&staging, &name)?;
            *clean_abort = true;
            return Err(StorageError::BlobHashMismatch);
        }
        #[cfg(test)]
        self.blob_fault_point(BlobFault::BeforeFileSync)?;
        file.sync_all()?;
        #[cfg(test)]
        self.blob_fault_point(BlobFault::AfterFileSync)?;
        drop(file);
        let target_name = hex(&id.bytes);
        match fs::renameat_with(
            &staging,
            name.as_str(),
            &target,
            target_name.as_str(),
            fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => (),
            Err(rustix::io::Errno::EXIST) => {
                if matches!(hold, Hold::Temporary { .. }) {
                    let registered: bool = self.store.conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1)",
                        [&id.bytes],
                        |r| r.get(0),
                    )?;
                    if !registered {
                        return Err(StorageError::Corrupt);
                    }
                }
                let (old, _) =
                    verify_file(&target, id, Some(length), self.store.limits.scan_blob_bytes)?;
                old.sync_all()?;
                remove_staging(&staging, &name)?;
            }
            Err(e) => return Err(e.into()),
        }
        #[cfg(test)]
        self.blob_fault_point(BlobFault::AfterPlace)?;
        fs::fsync(&target)?;
        fs::fsync(&staging)?;
        #[cfg(test)]
        self.blob_fault_point(BlobFault::AfterDirectorySync)?;
        #[cfg(test)]
        self.blob_fault_point(BlobFault::BeforeCommit)?;
        let tx = self.store.conn.transaction()?;
        let old: Option<i64> = tx
            .query_row(
                "SELECT byte_length FROM blobs WHERE id=?1",
                [&id.bytes],
                |r| r.get(0),
            )
            .optional()?;
        if old.is_some_and(|n| n < 0 || n as u64 != length) {
            return Err(StorageError::Corrupt);
        }
        let manual: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM manual_blob_holds WHERE blob_id=?1)",
            [&id.bytes],
            |r| r.get(0),
        )?;
        if manual && matches!(hold, Hold::Manual) {
            return Ok((
                BlobStored {
                    id,
                    byte_length: length,
                    newly_retained: false,
                },
                None,
            ));
        }
        let temporary = match hold {
            Hold::Manual => None,
            Hold::Temporary {
                ttl,
                limits,
                id: hold_id,
            } => {
                temporary_budget(&tx, id, length, limits)?;
                let now = unix_now()?;
                let previous: i64 = tx.query_row(
                    "SELECT coalesce(max(created_at),0) FROM temporary_blob_holds",
                    [],
                    |r| r.get(0),
                )?;
                let expires = now
                    .checked_add(i64::try_from(ttl).map_err(|_| StorageError::BudgetExceeded)?)
                    .filter(|n| *n <= 253402300799)
                    .ok_or(StorageError::BudgetExceeded)?;
                // 時計巻戻りで新しい約束を短くせず、既存台帳も更新しない。
                if now < previous {
                    return Err(StorageError::BudgetExceeded);
                }
                Some(TemporaryBlob {
                    id,
                    byte_length: length,
                    hold_id,
                    created_at: now,
                    expires_at: expires,
                })
            }
        };
        if old.is_none() {
            tx.execute(
                "INSERT INTO blobs(id,byte_length) VALUES(?1,?2)",
                params![
                    &id.bytes,
                    i64::try_from(length).map_err(|_| StorageError::BudgetExceeded)?
                ],
            )?;
        }
        advance(&tx)?;
        if let Some(t) = temporary {
            tx.execute("INSERT INTO temporary_blob_holds(hold_id,blob_id,created_at,expires_at,generation) SELECT ?1,?2,?3,?4,generation FROM storage_state WHERE singleton=1",params![&t.hold_id,&id.bytes,t.created_at,t.expires_at])?;
        } else {
            tx.execute(
                "INSERT INTO manual_blob_holds(blob_id) VALUES(?1)",
                [&id.bytes],
            )?;
        }
        audit(
            &tx,
            Some(&id.bytes),
            if old.is_some() {
                "blob_recorded"
            } else {
                "absent"
            },
            if temporary.is_some() {
                "blob_staged_local_only"
            } else {
                "blob_retained_local_only"
            },
            &temporary
                .map(|t| {
                    format!(
                        "temporary_local_blob_promise:{}:{}:{}",
                        hex(&t.hold_id),
                        t.created_at,
                        t.expires_at
                    )
                })
                .unwrap_or_else(|| "explicit_local_blob_retention".into()),
        )?;
        cleanup::cancel(
            &tx,
            &id.bytes,
            if temporary.is_some() {
                "temporary_promise"
            } else {
                "manual_retention"
            },
        )?;
        #[cfg(test)]
        cleanup::cancel_point(self.cleanup_cancel_pause, true)?;
        tx.commit()?;
        #[cfg(test)]
        cleanup::cancel_point(self.cleanup_cancel_pause, false)?;
        #[cfg(test)]
        self.blob_fault_point(BlobFault::AfterCommit)?;
        Ok((
            BlobStored {
                id,
                byte_length: length,
                newly_retained: temporary.is_none(),
            },
            temporary,
        ))
    }
}
fn remove_staging(dir: &OwnedFd, name: &str) -> Result<()> {
    fs::unlinkat(dir, name, fs::AtFlags::empty())?;
    fs::fsync(dir)?;
    Ok(())
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlobFault {
    BeforeFileSync,
    AfterFileSync,
    AfterPlace,
    AfterDirectorySync,
    BeforeCommit,
    AfterCommit,
    PauseAfterPlace,
}
#[cfg(test)]
impl RecordWriter {
    fn blob_fault_point(&self, point: BlobFault) -> Result<()> {
        if self.blob_fault == Some(BlobFault::PauseAfterPlace) && point == BlobFault::AfterPlace {
            println!("LNGNB_BLOB_PLACED");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
        }
        if self.blob_fault == Some(point) {
            return Err(StorageError::Io(std::io::Error::from_raw_os_error(5)));
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "blob_store_tests.rs"]
mod tests;

// 全保持実体とstagingの変更検出。hashとは別に確定直前まで同じ一覧を要求する。
pub(super) fn recovery_files(root: &OwnedFd, max_files: u64) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut remaining = max_files;
    for area in ["blobs", "staging"] {
        let dir = blob_directory(root, area)?;
        out.push((
            area.into(),
            fingerprint(&std::fs::metadata(anchored(&dir, "."))?),
        ));
        for name in entries(&dir, &mut remaining)? {
            let file = checked_file(&dir, &name)?;
            out.push((format!("{area}/{name}"), fingerprint(&file.metadata()?)));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "temporary_blob_tests.rs"]
mod temporary_tests;
