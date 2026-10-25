//! R24/R27/R28/R30（工程④の最初の範囲）。公開試験鍵のみ。実運用へ流用しない。
use super::*;
use std::{
    fs as stdfs,
    io::{BufRead, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Stdio},
};

pub(super) struct Temp {
    pub(super) root: PathBuf,
}
impl Temp {
    pub(super) fn new() -> Self {
        let id = crate::id::Id::random_knowledge().unwrap();
        let root = std::env::temp_dir().join(format!("lngnb-store-test-{id}"));
        stdfs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self { root }
    }
    pub(super) fn data(&self) -> PathBuf {
        self.root.join("data")
    }
    pub(super) fn store(&self) -> RecordStore {
        RecordStore::initialize(&self.data(), Limits::default()).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = stdfs::remove_dir_all(&self.root);
    }
}
pub(super) fn fixture_data() -> serde_json::Value {
    let spec = include_str!("../docs/specification-v1.0.0.md");
    let part = spec
        .split("## 付録A13 Record・IDの固定計算例")
        .nth(1)
        .unwrap()
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    serde_json::from_str(part).unwrap()
}
pub(super) fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
pub(super) fn fixture() -> LocalRecord {
    let f = fixture_data();
    LocalRecord::check(
        &unhex(f["genesis"]["envelope_cbor_hex"].as_str().unwrap()),
        None,
    )
    .unwrap()
}
fn generated_record(n: u8) -> LocalRecord {
    use crate::cbor::Value;
    let mut b = fixture().body().clone();
    if let Value::Map(fields) = &mut b {
        for (key, value) in fields {
            if key == "knowledge_id" {
                *value = Value::Bytes(vec![n; 32]);
            }
        }
    }
    let f = fixture_data();
    let seed = unhex(f["seed_hex"].as_str().unwrap()).try_into().unwrap();
    LocalRecord::sign(b, &ed25519_dalek::SigningKey::from_bytes(&seed)).unwrap()
}
fn raw_conn(path: &Path) -> Connection {
    Connection::open(path.join(DB)).unwrap()
}

#[test]
fn explicit_initialization_pragmas_and_immutable_roundtrip() {
    let t = Temp::new();
    let store = t.store();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(store.generation().unwrap(), 0);
    for name in [
        "synchronous",
        "foreign_keys",
        "read_uncommitted",
        "trusted_schema",
        "cache_size",
        "mmap_size",
    ] {
        let actual: i64 = store
            .conn
            .pragma_query_value(None, name, |r| r.get(0))
            .unwrap();
        let expected = match name {
            "synchronous" => 2,
            "foreign_keys" => 1,
            "cache_size" => -4096,
            _ => 0,
        };
        assert_eq!(actual, expected);
    }
    let wal: String = store
        .conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(wal, "wal");
    let record = fixture();
    let mut writer = store.begin().unwrap();
    assert!(writer.insert(&record).unwrap());
    let generation = writer.store.generation().unwrap();
    assert!(!writer.insert(&record).unwrap());
    assert_eq!(writer.store.generation().unwrap(), generation);
    assert_eq!(
        writer.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    assert!(
        writer
            .store
            .conn
            .execute("UPDATE records SET bytes=x'00'", [])
            .is_err()
    );
    assert!(
        writer
            .store
            .conn
            .execute("DELETE FROM records", [])
            .is_err()
    );
    writer.finish().unwrap();
    let reopened = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(reopened.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(reopened.generation().unwrap(), 3);
    assert_eq!(
        reopened.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    let history: i64 = reopened
        .conn
        .query_row("SELECT count(*) FROM history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(history, 4);
    let at: String = reopened
        .conn
        .query_row("SELECT at FROM history WHERE generation=3", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(at.len(), 24);
    assert!(at.ends_with('Z'));
    assert!(RecordStore::initialize(&t.data(), Limits::default()).is_err());
    assert_eq!(reopened.generation().unwrap(), 3);
}

#[test]
fn missing_database_and_unknown_versions_are_not_initialized_or_modified() {
    let t = Temp::new();
    drop(t.store());
    let before = stdfs::read(t.data().join(DB)).unwrap();
    let c = raw_conn(&t.data());
    c.pragma_update(None, "user_version", 999).unwrap();
    drop(c);
    let unknown = stdfs::read(t.data().join(DB)).unwrap();
    assert_ne!(before, unknown);
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(stdfs::read(t.data().join(DB)).unwrap(), unknown);
    let c = raw_conn(&t.data());
    c.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    c.execute(
        "UPDATE storage_state SET implementation='other-implementation'",
        [],
    )
    .unwrap();
    drop(c);
    let unknown = stdfs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(stdfs::read(t.data().join(DB)).unwrap(), unknown);
    stdfs::remove_file(t.data().join(DB)).unwrap();
    assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
    assert!(!t.data().join(DB).exists());
    let absent = t.root.join("absent");
    assert!(RecordStore::open(&absent, Limits::default()).is_err());
    assert!(!absent.exists());
}

#[test]
fn unsafe_paths_permissions_symlinks_and_hardlinks_are_rejected() {
    let t = Temp::new();
    drop(t.store());
    let alias = t.root.join("alias");
    symlink(t.data(), &alias).unwrap();
    assert!(RecordStore::open(&alias, Limits::default()).is_err());
    assert!(RecordStore::initialize(&alias.join("child"), Limits::default()).is_err());
    for name in [
        "lock",
        DB,
        "database.sqlite-wal",
        "database.sqlite-shm",
        "database.sqlite-journal",
    ] {
        let t = Temp::new();
        drop(t.store());
        let file = t.data().join(name);
        if file.exists() {
            stdfs::remove_file(&file).unwrap();
        }
        let target = t.root.join("sentinel");
        stdfs::write(&target, b"unchanged").unwrap();
        symlink(&target, &file).unwrap();
        assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
        assert_eq!(stdfs::read(target).unwrap(), b"unchanged");
    }
    let t = Temp::new();
    drop(t.store());
    let other = t.root.join("linked-db");
    stdfs::hard_link(t.data().join(DB), other).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsafePath)
    ));
    let t = Temp::new();
    drop(t.store());
    stdfs::set_permissions(t.data(), stdfs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsafePath)
    ));
}

#[test]
fn dropped_writer_requires_review_and_reading_does_not_clear_it() {
    let t = Temp::new();
    let mut writer = t.store().begin().unwrap();
    let record = fixture();
    writer.insert(&record).unwrap();
    drop(writer);
    for _ in 0..2 {
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(
            s.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
        assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
    }
}

#[test]
fn running_mark_failure_prevents_any_record_write() {
    let t = Temp::new();
    let store = t.store();
    store.conn.execute_batch("CREATE TRIGGER deny_running BEFORE UPDATE OF state ON storage_state WHEN NEW.state='running' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store.begin().is_err());
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(s.generation().unwrap(), 0);
    assert!(s.record(fixture().id()).unwrap().is_none());
}

#[test]
fn audit_failure_rolls_back_record_and_generation_and_prevents_clean_stop() {
    let t = Temp::new();
    let mut writer = t.store().begin().unwrap();
    writer.store.conn.execute_batch("CREATE TRIGGER deny_history BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT,'injected_history_failure'); END;").unwrap();
    let record = fixture();
    assert!(writer.insert(&record).is_err());
    assert_eq!(writer.store.generation().unwrap(), 1);
    assert!(writer.record(record.id()).unwrap().is_none());
    assert!(matches!(
        writer.finish(),
        Err(StorageError::UnresolvedFailure)
    ));
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}

#[test]
fn clean_mark_failure_leaves_running_and_no_success() {
    let t = Temp::new();
    let writer = t.store().begin().unwrap();
    writer.store.conn.execute_batch("CREATE TRIGGER deny_clean BEFORE UPDATE OF state ON storage_state WHEN NEW.state='clean' BEGIN SELECT RAISE(ABORT,'injected_clean_failure'); END;").unwrap();
    assert!(writer.finish().is_err());
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(s.generation().unwrap(), 1);
}

#[test]
fn sql_capacity_failure_is_not_record_success() {
    let t = Temp::new();
    let mut writer = t.store().begin().unwrap();
    let pages: i64 = writer
        .store
        .conn
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    writer
        .store
        .conn
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    // 実ディスクは埋めず、SQLiteのpage上限でSQLITE_FULLを注入する。
    let mut full = false;
    for n in 0..255 {
        let r = generated_record(n);
        match writer.insert(&r) {
            Ok(_) => (),
            Err(StorageError::Sql(e)) => {
                assert_eq!(e.sqlite_error_code(), Some(rusqlite::ErrorCode::DiskFull));
                assert!(writer.record(r.id()).unwrap().is_none());
                full = true;
                break;
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(full);
    assert!(matches!(
        writer.finish(),
        Err(StorageError::UnresolvedFailure)
    ));
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
}

#[test]
fn budget_and_reserve_limits_do_not_make_records_invalid() {
    let t = Temp::new();
    let limits = Limits {
        session_records: 1,
        ..Limits::default()
    };
    let mut writer = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    let a = fixture();
    writer.insert(&a).unwrap();
    let b = generated_record(9);
    assert!(matches!(
        writer.insert(&b),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(writer.record(b.id()).unwrap().is_none());
    assert_eq!(writer.record(a.id()).unwrap().unwrap().bytes(), a.bytes());
    writer.finish().unwrap();
    let scan = Limits {
        scan_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(
        RecordStore::open(&t.data(), scan),
        Err(StorageError::BudgetExceeded)
    ));
    let t = Temp::new();
    let reserve = Limits {
        reserve_min_bytes: u64::MAX,
        ..Limits::default()
    };
    let store = RecordStore::initialize(&t.data(), reserve).unwrap();
    let cap = store.capacity().unwrap();
    assert_eq!(cap.reserved_floor, u64::MAX);
    let mut writer = store.begin().unwrap();
    assert!(matches!(
        writer.insert(&fixture()),
        Err(StorageError::Capacity)
    ));
    writer.finish().unwrap();
}

#[test]
fn startup_detects_record_and_history_corruption() {
    let t = Temp::new();
    let mut writer = t.store().begin().unwrap();
    let r = fixture();
    writer.insert(&r).unwrap();
    writer.finish().unwrap();
    let c = raw_conn(&t.data());
    c.execute_batch("DROP TRIGGER records_no_update; UPDATE records SET bytes=x'00';")
        .unwrap();
    drop(c);
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::Corrupt)
    ));
    let t = Temp::new();
    drop(t.store());
    let c = raw_conn(&t.data());
    c.execute("DELETE FROM history", []).unwrap();
    drop(c);
    assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
}

#[test]
fn process_lock_and_kill() {
    if let Some(path) = std::env::var_os("LNGNB_STORE_TEST_CHILD") {
        let store = RecordStore::open(Path::new(&path), Limits::default()).unwrap();
        let mut writer = store.begin().unwrap();
        writer.insert(&fixture()).unwrap();
        println!("LNGNB_STORAGE_READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        writer.finish().unwrap();
        return;
    }
    let t = Temp::new();
    drop(t.store());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage::tests::process_lock_and_kill",
            "--nocapture",
        ])
        .env("LNGNB_STORE_TEST_CHILD", t.data())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready = false;
    for _ in 0..20 {
        let mut line = String::new();
        if output.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.contains("LNGNB_STORAGE_READY") {
            ready = true;
            break;
        }
    }
    assert!(ready, "child did not acquire the store");
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::Busy)
    ));
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(
        s.record(fixture().id()).unwrap().unwrap().bytes(),
        fixture().bytes()
    );
    assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
}

#[test]
fn byte_and_startup_count_boundaries_are_explicit() {
    let t = Temp::new();
    let a = fixture();
    let b = generated_record(20);
    let limits = Limits {
        session_bytes: a.bytes().len() as u64,
        ..Limits::default()
    };
    let mut writer = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    assert!(writer.insert(&a).unwrap());
    assert!(matches!(
        writer.insert(&b),
        Err(StorageError::BudgetExceeded)
    ));
    writer.finish().unwrap();
    let exact = Limits {
        scan_bytes: a.bytes().len() as u64,
        ..Limits::default()
    };
    drop(RecordStore::open(&t.data(), exact).unwrap());
    let below = Limits {
        scan_bytes: a.bytes().len() as u64 - 1,
        ..Limits::default()
    };
    assert!(matches!(
        RecordStore::open(&t.data(), below),
        Err(StorageError::BudgetExceeded)
    ));
    let mut writer = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&b).unwrap();
    writer.finish().unwrap();
    let one = Limits {
        scan_records: 1,
        ..Limits::default()
    };
    assert!(matches!(
        RecordStore::open(&t.data(), one),
        Err(StorageError::BudgetExceeded)
    ));
    let two = Limits {
        scan_records: 2,
        ..Limits::default()
    };
    drop(RecordStore::open(&t.data(), two).unwrap());
    let absent = t.root.join("invalid-policy");
    assert!(
        RecordStore::initialize(
            &absent,
            Limits {
                scan_records: 0,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(!absent.exists());
}

#[test]
fn corruption_discovered_during_session_prevents_clean_stop() {
    for via_insert in [false, true] {
        let t = Temp::new();
        let mut writer = t.store().begin().unwrap();
        let r = fixture();
        writer.insert(&r).unwrap();
        writer
            .store
            .conn
            .execute_batch("DROP TRIGGER records_no_update; UPDATE records SET bytes=x'00';")
            .unwrap();
        if via_insert {
            assert!(matches!(writer.insert(&r), Err(StorageError::Corrupt)));
        } else {
            assert!(matches!(writer.record(r.id()), Err(StorageError::Corrupt)));
        }
        assert!(matches!(
            writer.finish(),
            Err(StorageError::UnresolvedFailure)
        ));
    }
}
