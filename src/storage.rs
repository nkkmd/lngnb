//! 工程④: 不変Record/Blobのローカル保存と書込みセッション。
//! 親依存評価は管理用内部機能。pin、配信許可、管理者の復旧確認の代替にはならない。
use crate::{
    cbor::MAX_RECORD,
    id::{Id, Kind},
    record::LocalRecord,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, CWD, FlockOperation, Mode, OFlags},
};
use std::{
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

pub const IMPLEMENTATION: &str = "lngnb-rust-sqlite-1";
pub const SCHEMA_VERSION: i64 = 8;
const DB: &str = "database.sqlite";
const SCHEMA: &str = "
CREATE TABLE storage_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 implementation TEXT NOT NULL,
 namespace BLOB NOT NULL CHECK(length(namespace)=32),
 generation INTEGER NOT NULL CHECK(generation>=0),
 state TEXT NOT NULL CHECK(state IN ('clean','running'))
) STRICT;
CREATE TABLE records (
 id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=32),
 bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 2097152)
) STRICT;
CREATE TRIGGER records_no_update BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT,'immutable_record'); END;
CREATE TRIGGER records_no_delete BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'immutable_record'); END;
CREATE TABLE record_inspection (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 source_epoch INTEGER NOT NULL CHECK(source_epoch>=0),
 phase TEXT NOT NULL CHECK(phase IN ('idle','records','blobs','complete')),
 cursor BLOB CHECK(cursor IS NULL OR length(cursor)=32),
 checked_records INTEGER NOT NULL CHECK(checked_records>=0),
 checked_bytes INTEGER NOT NULL CHECK(checked_bytes>=0),
 checkpoint_generation INTEGER,
 checked_blob_files INTEGER NOT NULL CHECK(checked_blob_files>=0),
 checked_blob_bytes INTEGER NOT NULL CHECK(checked_blob_bytes>=0)
) STRICT;
INSERT INTO record_inspection VALUES(1,0,'idle',NULL,0,0,NULL,0,0);
CREATE TABLE blob_inspection_inventory (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL CHECK(epoch>=0),
 blobs_fingerprint TEXT NOT NULL, staging_fingerprint TEXT NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32)
) STRICT;
CREATE TABLE blob_inspection_files (
 area TEXT NOT NULL CHECK(area IN ('blobs','staging')), name TEXT NOT NULL,
 expected_length INTEGER CHECK(expected_length IS NULL OR expected_length>=0),
 size INTEGER CHECK(size IS NULL OR size>=0), fingerprint TEXT,
 result TEXT NOT NULL CHECK(result IN ('pending','verified','orphaned','missing','corrupt','incomplete')),
 examined_bytes INTEGER NOT NULL CHECK(examined_bytes>=0),
 PRIMARY KEY(area,name)
) STRICT;
CREATE TRIGGER record_invalidates_inspection AFTER INSERT ON records BEGIN
 UPDATE record_inspection SET source_epoch=source_epoch+1,
 phase=CASE WHEN phase IN ('records','blobs') THEN 'records' ELSE 'idle' END,
 cursor=NULL,checked_records=0,checked_bytes=0,checkpoint_generation=NULL,checked_blob_files=0,checked_blob_bytes=0;
 DELETE FROM blob_inspection_files; DELETE FROM blob_inspection_inventory;
END;
CREATE TABLE blobs (
 id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=32),
 byte_length INTEGER NOT NULL CHECK(byte_length>=0)
) STRICT;
CREATE TRIGGER blob_invalidates_inspection AFTER INSERT ON blobs BEGIN
 UPDATE record_inspection SET source_epoch=source_epoch+1,
 phase=CASE WHEN phase IN ('records','blobs') THEN 'records' ELSE 'idle' END,
 cursor=NULL,checked_records=0,checked_bytes=0,checkpoint_generation=NULL,checked_blob_files=0,checked_blob_bytes=0;
 DELETE FROM blob_inspection_files; DELETE FROM blob_inspection_inventory;
END;
CREATE TRIGGER blobs_no_update BEFORE UPDATE ON blobs BEGIN SELECT RAISE(ABORT,'immutable_blob'); END;
CREATE TRIGGER blobs_no_delete BEFORE DELETE ON blobs BEGIN SELECT RAISE(ABORT,'immutable_blob'); END;
CREATE TABLE blob_failures (
 id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=32),
 reason TEXT NOT NULL CHECK(reason IN ('transfer_hash_mismatch','transfer_failed')),
 generation INTEGER NOT NULL, at TEXT NOT NULL
) STRICT;
CREATE TABLE evaluation_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 dirty INTEGER NOT NULL CHECK(dirty IN (0,1)),
 generation INTEGER,
 job_started INTEGER NOT NULL CHECK(job_started IN (0,1)),
 input_started INTEGER NOT NULL CHECK(input_started IN (0,1)),
 record_epoch INTEGER NOT NULL CHECK(record_epoch>=0),
 payload_epoch INTEGER NOT NULL CHECK(payload_epoch>=0),
 blob_input_started INTEGER NOT NULL CHECK(blob_input_started IN (0,1))
) STRICT;
INSERT INTO evaluation_state VALUES(1,1,NULL,0,0,0,0,0);
CREATE TABLE evaluation_blob_input (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), record_epoch INTEGER NOT NULL CHECK(record_epoch>=0),
 payload_epoch INTEGER NOT NULL CHECK(payload_epoch>=0), directory TEXT NOT NULL CHECK(length(directory) BETWEEN 1 AND 512),
 digest BLOB NOT NULL CHECK(length(digest)=32), total INTEGER NOT NULL CHECK(total>=0),
 complete INTEGER NOT NULL CHECK(complete IN (0,1)), checkpoint_generation INTEGER NOT NULL CHECK(checkpoint_generation>=0)
) STRICT;
CREATE TABLE evaluation_blob_facts (
 blob_id BLOB PRIMARY KEY NOT NULL CHECK(length(blob_id)=32),
 byte_length INTEGER CHECK(byte_length IS NULL OR byte_length>=0),
 size INTEGER CHECK(size IS NULL OR size>=0), fingerprint TEXT CHECK(fingerprint IS NULL OR length(fingerprint) BETWEEN 1 AND 512),
 transfer TEXT CHECK(transfer IN ('transfer_hash_mismatch','transfer_failed')),
 state TEXT NOT NULL CHECK(state IN ('pending','verified','missing','failed','unavailable')),
 examined_bytes INTEGER NOT NULL CHECK(examined_bytes>=0)
) STRICT;
CREATE TABLE evaluation_input (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL CHECK(epoch>=0),
 cursor BLOB CHECK(cursor IS NULL OR length(cursor)=32),
 records INTEGER NOT NULL CHECK(records>=0), bytes INTEGER NOT NULL CHECK(bytes>=0),
 edges INTEGER NOT NULL CHECK(edges>=0), complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 digest BLOB NOT NULL CHECK(length(digest)=32), checkpoint_generation INTEGER NOT NULL CHECK(checkpoint_generation>=0)
) STRICT;
CREATE TABLE evaluation_nodes (
 record_id BLOB PRIMARY KEY NOT NULL REFERENCES records(id),
 source_length INTEGER NOT NULL CHECK(source_length BETWEEN 1 AND 2097152),
 summary BLOB NOT NULL CHECK(length(summary) BETWEEN 1 AND 16384)
) STRICT;
CREATE TABLE evaluation_job (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 input BLOB NOT NULL CHECK(length(input)=32),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 total INTEGER NOT NULL CHECK(total>=0),
 complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 checkpoint_generation INTEGER NOT NULL CHECK(checkpoint_generation>=0)
) STRICT;
CREATE TABLE evaluation_work (
 record_id BLOB PRIMARY KEY NOT NULL REFERENCES records(id),
 result BLOB NOT NULL CHECK(length(result) BETWEEN 1 AND 1024)
) STRICT;
CREATE TRIGGER record_invalidates_evaluation AFTER INSERT ON records BEGIN UPDATE evaluation_state SET dirty=1,record_epoch=record_epoch+1; END;
CREATE TRIGGER blob_invalidates_evaluation AFTER INSERT ON blobs BEGIN UPDATE evaluation_state SET dirty=1,payload_epoch=payload_epoch+1; END;
CREATE TRIGGER failed_blob_invalidates_evaluation AFTER INSERT ON blob_failures BEGIN UPDATE evaluation_state SET dirty=1,payload_epoch=payload_epoch+1; END;
CREATE TRIGGER changed_blob_failure_invalidates_evaluation AFTER UPDATE ON blob_failures BEGIN UPDATE evaluation_state SET dirty=1,payload_epoch=payload_epoch+1; END;
CREATE TABLE parent_edges (
 child BLOB NOT NULL REFERENCES records(id), parent BLOB NOT NULL CHECK(length(parent)=32),
 PRIMARY KEY(child,parent)
) STRICT;
CREATE INDEX parent_reverse ON parent_edges(parent,child);
CREATE TABLE evaluations (
 record_id BLOB PRIMARY KEY NOT NULL REFERENCES records(id),
 validation TEXT NOT NULL CHECK(validation IN ('valid','pending','invalid')),
 payload TEXT CHECK(payload IN ('verified','missing','unavailable')),
 reason TEXT, related BLOB CHECK(related IS NULL OR length(related)=32), payload_reason TEXT
) STRICT;
CREATE TABLE known_invalid (
 record_id BLOB PRIMARY KEY NOT NULL REFERENCES records(id),
 reason TEXT NOT NULL CHECK(reason='declared_length_mismatch'),
 blob_id BLOB NOT NULL REFERENCES blobs(id), actual_length INTEGER NOT NULL CHECK(actual_length>=0),
 rules TEXT NOT NULL CHECK(rules='lngnb-validation-1'),
 generation INTEGER NOT NULL, at TEXT NOT NULL
) STRICT;
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON known_invalid BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON known_invalid BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
CREATE TABLE history (
 generation INTEGER PRIMARY KEY CHECK(generation>=0),
 namespace BLOB NOT NULL CHECK(length(namespace)=32),
 target BLOB, old_state TEXT NOT NULL, new_state TEXT NOT NULL,
 actor TEXT NOT NULL, reason TEXT NOT NULL, rules TEXT NOT NULL,
 at TEXT NOT NULL
) STRICT;
";

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    UnsafePath,
    Busy,
    UnsupportedFormat,
    Corrupt,
    NeedsReview,
    BudgetExceeded,
    Capacity,
    UnresolvedFailure,
    RandomUnavailable,
    BlobHashMismatch,
    InvalidBlobId,
    InspectionPending,
    EvaluationInputPending,
    StaleRecoveryReview,
    InvalidRecoveryReview,
}
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io(_) | Self::Sql(_) => "storage_unavailable",
            Self::UnsafePath => "unsafe_data_path",
            Self::Busy => "data_area_busy",
            Self::UnsupportedFormat => "unsupported_storage_format",
            Self::Corrupt => "storage_corruption",
            Self::NeedsReview => "manual_review_required",
            Self::BudgetExceeded => "policy_limit",
            Self::Capacity => "storage_pressure",
            Self::UnresolvedFailure => "unresolved_storage_failure",
            Self::RandomUnavailable => "random_unavailable",
            Self::BlobHashMismatch => "transfer_hash_mismatch",
            Self::InvalidBlobId => "invalid_blob_id",
            Self::InspectionPending => "startup_inspection_pending",
            Self::EvaluationInputPending => "evaluation_input_pending",
            Self::StaleRecoveryReview => "stale_recovery_review",
            Self::InvalidRecoveryReview => "invalid_recovery_review",
        })
    }
}
impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Sql(e) => Some(e),
            _ => None,
        }
    }
}
impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rustix::io::Errno> for StorageError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}
impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
pub type Result<T> = std::result::Result<T, StorageError>;

// 起動検査と評価で同じ変更検出条件を使う。hashの代替にはしない。
fn fingerprint(m: &std::fs::Metadata) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
        m.nlink()
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub scan_records: u64,
    pub scan_bytes: u64,
    pub scan_blob_files: u64,
    pub scan_blob_bytes: u64,
    pub max_blob_bytes: u64,
    pub session_blobs: u64,
    pub session_records: u64,
    pub session_bytes: u64,
    pub reserve_min_bytes: u64,
    pub reserve_percent: u8,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_records: 10_000,
            scan_bytes: 64 * 1024 * 1024,
            scan_blob_files: 10_000,
            scan_blob_bytes: 64 * 1024 * 1024,
            max_blob_bytes: 16 * 1024 * 1024,
            session_blobs: 10_000,
            session_records: 10_000,
            session_bytes: 64 * 1024 * 1024,
            reserve_min_bytes: 64 * 1024 * 1024,
            reserve_percent: 2,
        }
    }
}
impl Limits {
    fn check(self) -> Result<Self> {
        if self.scan_records == 0
            || self.scan_bytes == 0
            || self.scan_blob_files == 0
            || self.scan_blob_bytes == 0
            || self.session_blobs == 0
            || self.session_records == 0
            || self.session_bytes == 0
            || self.reserve_percent > 100
        {
            return Err(StorageError::BudgetExceeded);
        }
        Ok(self)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupState {
    Clean,
    NeedsReview,
    InspectionPending,
}
#[derive(Debug, Clone, Copy)]
pub struct Capacity {
    pub total: u64,
    pub available: u64,
    pub reserved_floor: u64,
    pub warning_threshold: u64,
    pub warning: bool,
}

fn directory(path: &Path) -> Result<OwnedFd> {
    // 途中のsymlinkも辿らない。..は管理パスでも曖昧さを避けて拒否。
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::openat(CWD, ".", flags, Mode::empty())?;
    for component in path.components() {
        match component {
            Component::RootDir => fd = fs::openat(CWD, "/", flags, Mode::empty())?,
            Component::CurDir => (),
            Component::Normal(name) => fd = fs::openat(&fd, name, flags, Mode::empty())?,
            _ => return Err(StorageError::UnsafePath),
        }
    }
    Ok(fd)
}
fn anchored(fd: &OwnedFd, name: &str) -> std::path::PathBuf {
    Path::new(&format!("/proc/self/fd/{}", fd.as_raw_fd())).join(name)
}
fn check_area(fd: &OwnedFd) -> Result<()> {
    let meta = std::fs::metadata(anchored(fd, "."))?;
    let uid = rustix::process::geteuid().as_raw();
    if !meta.is_dir() || meta.mode() & 0o077 != 0 || (meta.uid() != uid && uid != 0) {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}
fn check_files(fd: &OwnedFd) -> Result<()> {
    for name in [
        "lock",
        DB,
        "database.sqlite-wal",
        "database.sqlite-shm",
        "database.sqlite-journal",
    ] {
        match std::fs::symlink_metadata(anchored(fd, name)) {
            Ok(meta) if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 => {
                return Err(StorageError::UnsafePath);
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
// closeだけでは、同じopen-file-descriptionを一時継承した子プロセスが
// execするまでflockが残る。所有Storeの接続終了後に明示解除してからfdを閉じる。
struct DataLock(OwnedFd);
impl Drop for DataLock {
    fn drop(&mut self) {
        let _ = fs::flock(&self.0, FlockOperation::Unlock);
    }
}
fn lock(fd: &OwnedFd, create: bool) -> Result<DataLock> {
    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    let lock = fs::openat(fd, "lock", flags, Mode::RUSR | Mode::WUSR)?;
    match fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(DataLock(lock)),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(StorageError::Busy),
        Err(e) => Err(e.into()),
    }
}
fn connection(fd: &OwnedFd, readonly: bool) -> Result<Connection> {
    let flags = if readonly {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    // SQLiteのNOFOLLOWは/proc/self/fd自体もsymlinkとみなすため、
    // NOFOLLOWで辿ったdirectory fdの実パスを使用し、同一inodeを再確認する。
    let path = std::fs::canonicalize(anchored(fd, "."))?;
    let identity = fs::fstat(fd)?;
    let verify_directory = || -> Result<()> {
        let check = directory(&path)?;
        let check = fs::fstat(&check)?;
        if identity.st_dev != check.st_dev || identity.st_ino != check.st_ino {
            return Err(StorageError::UnsafePath);
        }
        Ok(())
    };
    verify_directory()?;
    let conn = Connection::open_with_flags(
        path.join(DB),
        flags | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    verify_directory()?;
    check_files(fd)?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    Ok(conn)
}
fn check_format(conn: &Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(StorageError::UnsupportedFormat);
    }
    let (implementation, namespace, generation, state): (String, Vec<u8>, i64, String) = conn
        .query_row(
            "SELECT implementation,namespace,generation,state FROM storage_state WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    if implementation != IMPLEMENTATION {
        return Err(StorageError::UnsupportedFormat);
    }
    if namespace.len() != 32 || generation < 0 || !["clean", "running"].contains(&state.as_str()) {
        return Err(StorageError::Corrupt);
    }
    let (audit_namespace, audit_state, rules): (Vec<u8>, String, String) = conn.query_row(
        "SELECT namespace,new_state,rules FROM history WHERE generation=?1",
        [generation],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let expected_state = if [
        "stored_local_only",
        "blob_retained_local_only",
        "evaluated_local_only",
        "blob_failure_observed",
        "record_inspection_pending",
        "record_inspection_complete",
        "evaluation_job_pending",
        "evaluation_job_complete",
        "evaluation_input_pending",
        "evaluation_input_complete",
        "evaluation_blob_pending",
        "evaluation_blob_complete",
    ]
    .contains(&audit_state.as_str())
    {
        "running"
    } else {
        audit_state.as_str()
    };
    if audit_namespace != namespace || expected_state != state || rules != "lngnb-validation-1" {
        return Err(StorageError::Corrupt);
    }
    Ok(())
}
fn configure(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA read_uncommitted=OFF; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096; PRAGMA mmap_size=0;")?;
    let journal: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(StorageError::UnsupportedFormat);
    }
    for (name, want) in [
        ("synchronous", 2i64),
        ("foreign_keys", 1),
        ("read_uncommitted", 0),
        ("trusted_schema", 0),
        ("cache_size", -4096),
        ("mmap_size", 0),
    ] {
        let actual: i64 = conn.pragma_query_value(None, name, |r| r.get(0))?;
        if actual != want {
            return Err(StorageError::UnsupportedFormat);
        }
    }
    Ok(())
}
fn state(conn: &Connection) -> Result<StartupState> {
    let value: String = conn.query_row(
        "SELECT state FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    match value.as_str() {
        "clean" => Ok(StartupState::Clean),
        "running" => Ok(StartupState::NeedsReview),
        _ => Err(StorageError::Corrupt),
    }
}
fn audit(
    tx: &Transaction<'_>,
    target: Option<&[u8]>,
    old: &str,
    new: &str,
    reason: &str,
) -> Result<()> {
    tx.execute("INSERT INTO history(generation,namespace,target,old_state,new_state,actor,reason,rules,at) SELECT generation,namespace,?1,?2,?3,?4,?5,'lngnb-validation-1',strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM storage_state WHERE singleton=1",params![target,old,new,format!("uid:{}",rustix::process::geteuid().as_raw()),reason])?;
    Ok(())
}
fn advance(tx: &Transaction<'_>) -> Result<()> {
    if tx.execute("UPDATE storage_state SET generation=generation+1 WHERE singleton=1 AND generation<9223372036854775807",[])?!=1 {return Err(StorageError::Corrupt);}
    Ok(())
}
fn transition(conn: &mut Connection, new: &str, reason: &str) -> Result<()> {
    let tx = conn.transaction()?;
    let old: String = tx.query_row(
        "SELECT state FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    advance(&tx)?;
    tx.execute("UPDATE storage_state SET state=?1 WHERE singleton=1", [new])?;
    audit(&tx, None, &old, new, reason)?;
    tx.commit()?;
    Ok(())
}

/// 排他lockと単一writer接続を所有する。Clone/共有接続/遠隔操作は提供しない。
pub struct RecordStore {
    // Rustのfield drop順で、接続を閉じてからlockとdirectoryを解放する。
    conn: Connection,
    _lock: DataLock,
    dir: OwnedFd,
    limits: Limits,
    blob_recovery: BlobRecovery,
    records_checked: bool,
}
impl RecordStore {
    /// 新しい最終ディレクトリだけを作る。既存/未完了領域を上書きしない。
    /// 管理CLIの初期化手順は工程⑤で接続する。
    pub fn initialize(path: &Path, limits: Limits) -> Result<Self> {
        let limits = limits.check()?;
        let name = path.file_name().ok_or(StorageError::UnsafePath)?;
        let parent = directory(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        fs::mkdirat(&parent, name, Mode::RWXU)?;
        fs::fsync(&parent)?;
        let dir = fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        check_area(&dir)?;
        let lock = lock(&dir, true)?;
        fs::fsync(&lock.0)?;
        let db = fs::openat(
            &dir,
            DB,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        fs::fsync(&db)?;
        fs::fsync(&dir)?;
        drop(db);
        blobs::initialize_directories(&dir)?;
        let mut conn = connection(&dir, false)?;
        configure(&conn)?;
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        let mut namespace = [0u8; 32];
        getrandom::getrandom(&mut namespace).map_err(|_| StorageError::RandomUnavailable)?;
        tx.execute(
            "INSERT INTO storage_state VALUES(1,?1,?2,0,'clean')",
            params![IMPLEMENTATION, &namespace],
        )?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        audit(&tx, None, "absent", "clean", "explicit_initialize")?;
        tx.commit()?;
        fs::fsync(&dir)?;
        check_files(&dir)?;
        Ok(Self {
            conn,
            _lock: lock,
            dir,
            limits,
            blob_recovery: BlobRecovery::default(),
            records_checked: true,
        })
    }
    /// 欠損DB・未知保存版を作成/移行しない。稼働中印は読取りで解除しない。
    pub fn open(path: &Path, limits: Limits) -> Result<Self> {
        let mut store = Self::open_locked(path, limits)?;
        inspection::validate_aux(&store)?;
        store.check_records()?;
        store.records_checked = true;
        store.blob_recovery = store.scan_blobs()?;
        if store.blob_recovery.needs_review() && state(&store.conn)? == StartupState::Clean {
            transition(&mut store.conn, "running", "blob_recovery_required")?;
        }
        Ok(store)
    }
    fn open_locked(path: &Path, limits: Limits) -> Result<Self> {
        let limits = limits.check()?;
        let dir = directory(path)?;
        check_area(&dir)?;
        check_files(&dir)?;
        let lock = lock(&dir, false)?;
        // 未対応版のDBを設定変更する前にread-onlyで照合する。
        let probe = connection(&dir, true)?;
        check_format(&probe)?;
        inspection::checkpoint(&probe)?;
        drop(probe);
        let conn = connection(&dir, false)?;
        configure(&conn)?;
        Ok(Self {
            conn,
            _lock: lock,
            dir,
            limits,
            blob_recovery: BlobRecovery::default(),
            records_checked: false,
        })
    }
    fn check_records(&self) -> Result<()> {
        let mut statement = self
            .conn
            .prepare("SELECT id,length(bytes) FROM records ORDER BY id")?;
        let mut rows = statement.query([])?;
        let mut total = 0u64;
        let mut count = 0u64;
        while let Some(row) = rows.next()? {
            count = count.checked_add(1).ok_or(StorageError::BudgetExceeded)?;
            let id: Vec<u8> = row.get(0)?;
            let length: i64 = row.get(1)?;
            if length <= 0 || length > MAX_RECORD as i64 || id.len() != 32 {
                return Err(StorageError::Corrupt);
            }
            total = total
                .checked_add(length as u64)
                .ok_or(StorageError::BudgetExceeded)?;
            if count > self.limits.scan_records || total > self.limits.scan_bytes {
                return Err(StorageError::BudgetExceeded);
            }
            let id = Id {
                kind: Kind::Record,
                bytes: id.try_into().map_err(|_| StorageError::Corrupt)?,
            };
            self.record(id)?.ok_or(StorageError::Corrupt)?;
        }
        let check: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(StorageError::Corrupt);
        }
        Ok(())
    }
    pub fn startup_state(&self) -> Result<StartupState> {
        if self.blob_recovery.needs_review() || state(&self.conn)? == StartupState::NeedsReview {
            return Ok(StartupState::NeedsReview);
        }
        if !self.records_checked || inspection::checkpoint(&self.conn)?.pending() {
            return Ok(StartupState::InspectionPending);
        }
        Ok(StartupState::Clean)
    }
    pub fn generation(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT generation FROM storage_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn record(&self, id: Id) -> Result<Option<LocalRecord>> {
        if id.kind != Kind::Record {
            return Err(StorageError::Corrupt);
        }
        let length: Option<i64> = self
            .conn
            .query_row(
                "SELECT length(bytes) FROM records WHERE id=?1",
                [&id.bytes],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(n) = length {
            if n <= 0 || n > MAX_RECORD as i64 {
                return Err(StorageError::Corrupt);
            }
        }
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT bytes FROM records WHERE id=?1", [&id.bytes], |r| {
                r.get(0)
            })
            .optional()?;
        bytes
            .map(|b| LocalRecord::check(&b, Some(id)).map_err(|_| StorageError::Corrupt))
            .transpose()
    }
    pub fn capacity(&self) -> Result<Capacity> {
        let s = fs::fstatvfs(&self.dir)?;
        let total = s
            .f_blocks
            .checked_mul(s.f_frsize)
            .ok_or(StorageError::Capacity)?;
        let available = s
            .f_bavail
            .checked_mul(s.f_frsize)
            .ok_or(StorageError::Capacity)?;
        let reserved_floor = self.limits.reserve_min_bytes.max(
            ((u128::from(total) * u128::from(self.limits.reserve_percent)).div_ceil(100)) as u64,
        );
        let warning_threshold = (128 * 1024 * 1024).max(total / 10);
        Ok(Capacity {
            total,
            available,
            reserved_floor,
            warning_threshold,
            warning: available <= warning_threshold,
        })
    }
    pub fn begin(mut self) -> Result<RecordWriter> {
        match self.startup_state()? {
            StartupState::Clean => (),
            StartupState::NeedsReview => return Err(StorageError::NeedsReview),
            StartupState::InspectionPending => return Err(StorageError::InspectionPending),
        }
        transition(&mut self.conn, "running", "begin_record_session")?;
        Ok(RecordWriter::new(self))
    }
}

/// 稼働中印の確定後だけ書く。drop/クラッシュでは正常停止印を残さない。
pub struct RecordWriter {
    store: RecordStore,
    failed: bool,
    records: u64,
    bytes: u64,
    reserved: u64,
    blobs: u64,
    #[cfg(test)]
    blob_fault: Option<blobs::BlobFault>,
    #[cfg(test)]
    evaluation_pause: bool,
}
impl RecordWriter {
    fn new(store: RecordStore) -> Self {
        Self {
            store,
            failed: false,
            records: 0,
            bytes: 0,
            reserved: 0,
            blobs: 0,
            #[cfg(test)]
            blob_fault: None,
            #[cfg(test)]
            evaluation_pause: false,
        }
    }
    pub fn record(&mut self, id: Id) -> Result<Option<LocalRecord>> {
        let result = self.store.record(id);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn insert(&mut self, record: &LocalRecord) -> Result<bool> {
        let result = self.insert_inner(record);
        if let Err(ref error) = result {
            if !matches!(error, StorageError::BudgetExceeded | StorageError::Capacity) {
                self.failed = true;
            }
        }
        result
    }
    fn insert_inner(&mut self, record: &LocalRecord) -> Result<bool> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if let Some(old) = self.store.record(record.id())? {
            if old.bytes() != record.bytes() {
                self.failed = true;
                return Err(StorageError::Corrupt);
            }
            return Ok(false);
        }
        let bytes = record.bytes().len() as u64;
        if self.records >= self.store.limits.session_records
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|n| n > self.store.limits.session_bytes)
        {
            return Err(StorageError::BudgetExceeded);
        }
        // 単一同期writerなので予約は同時に一枠だけ。別の受付と重ねない。
        let reserve = bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(65536))
            .ok_or(StorageError::Capacity)?;
        let c = self.store.capacity()?;
        if c.available
            <= c.reserved_floor
                .saturating_add(self.reserved)
                .saturating_add(reserve)
        {
            return Err(StorageError::Capacity);
        }
        self.reserved += reserve;
        let result: Result<()> = (|| {
            let tx = self.store.conn.transaction()?;
            tx.execute(
                "INSERT INTO records(id,bytes) VALUES(?1,?2)",
                params![&record.id().bytes, record.bytes()],
            )?;
            advance(&tx)?;
            audit(
                &tx,
                Some(&record.id().bytes),
                "absent",
                "stored_local_only",
                "store_record",
            )?;
            tx.commit()?;
            Ok(())
        })();
        self.reserved -= reserve;
        match result {
            Ok(()) => {
                self.records += 1;
                self.bytes += bytes;
                Ok(true)
            }
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }
    /// 配信等は未実装。書込みと必要履歴が全て正常に終わった時だけ呼べる。
    /// selfを消費するので、正常停止印の後にこのwriterから変更できない。
    pub fn finish(mut self) -> Result<()> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        transition(&mut self.store.conn, "clean", "finish_record_session")?;
        self.store
            .conn
            .close()
            .map_err(|(_, e)| StorageError::Sql(e))?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

#[path = "blob_store.rs"]
mod blobs;
pub use blobs::{BlobRecovery, BlobStored};

#[path = "evaluation.rs"]
mod evaluation;
pub use evaluation::{
    Assessment, EvaluationBlobBudget, EvaluationBlobProgress, EvaluationInputBudget,
    EvaluationInputProgress, EvaluationJob, EvaluationLimits, EvaluationProgress,
    EvaluationSnapshot, EvaluationStepBudget, EvidenceRecoveryReview, PayloadReason, PayloadStatus,
    Reason, Validation,
};

#[path = "record_inspection.rs"]
mod inspection;
pub use inspection::{InspectionBudget, InspectionProgress, RecordInspection};
