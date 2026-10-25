//! A9.2の物理Blob保存。ローカル管理者による明示保持のみ。投稿/公開/Revision判定は行わない。
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
fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut text, b| {
        write!(text, "{b:02x}").expect("writing to String");
        text
    })
}
fn parse_name(name: &str) -> Result<Id> {
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
fn checked_file(dir: &OwnedFd, name: &str) -> Result<File> {
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
    if expected_len > budget {
        return Err(StorageError::BudgetExceeded);
    }
    if length.is_some_and(|n| n != expected_len) {
        return Err(StorageError::Corrupt);
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
fn entries(dir: &OwnedFd, remaining: &mut u64) -> Result<Vec<String>> {
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
        let result = self.put_blob_inner(id, input, max, &mut clean_abort);
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
    ) -> Result<BlobStored> {
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
        let old: Option<i64> = self
            .store
            .conn
            .query_row(
                "SELECT byte_length FROM blobs WHERE id=?1",
                [&id.bytes],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            if old < 0 || old as u64 != length {
                return Err(StorageError::Corrupt);
            }
            return Ok(BlobStored {
                id,
                byte_length: length,
                newly_retained: false,
            });
        }
        #[cfg(test)]
        self.blob_fault_point(BlobFault::BeforeCommit)?;
        let tx = self.store.conn.transaction()?;
        tx.execute(
            "INSERT INTO blobs(id,byte_length) VALUES(?1,?2)",
            params![
                &id.bytes,
                i64::try_from(length).map_err(|_| StorageError::BudgetExceeded)?
            ],
        )?;
        advance(&tx)?;
        audit(
            &tx,
            Some(&id.bytes),
            "absent",
            "blob_retained_local_only",
            "explicit_local_blob_retention",
        )?;
        tx.commit()?;
        #[cfg(test)]
        self.blob_fault_point(BlobFault::AfterCommit)?;
        Ok(BlobStored {
            id,
            byte_length: length,
            newly_retained: true,
        })
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
