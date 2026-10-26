//! R24/R27/R28/R30: 明示した使い捨てext4 loop FSだけで実行する。
//! 実デバイスEIO・電源断・正式性能の試験ではない。公開試験鍵のみ。
use super::tests::{Temp, fixture};
use super::*;
use crate::id;
use std::{
    cell::Cell,
    io::{Cursor, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    rc::Rc,
};

fn isolated() -> (Temp, Limits) {
    assert_eq!(
        std::env::var("LNGNB_FS_TESTING").unwrap(),
        "disposable-loop-ext4-v1"
    );
    let root = PathBuf::from(std::env::var_os("LNGNB_EXT4_TEST_ROOT").unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(root, std::env::temp_dir().canonicalize().unwrap());
    assert_eq!(
        root.file_name().unwrap(),
        "mounted",
        "disposable ext4 root required"
    );
    assert!(
        root.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("lngnb-ext4."),
        "disposable ext4 sandbox required"
    );
    assert_eq!(
        std::fs::read(root.join(".lngnb-disposable-ext4")).unwrap(),
        b"disposable-loop-ext4-v1\n"
    );
    let output = std::process::Command::new("findmnt")
        .args(["--noheadings", "--output", "FSTYPE", "--target"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "ext4",
        "disposable ext4 filesystem required"
    );
    let source = std::process::Command::new("findmnt")
        .args(["--noheadings", "--output", "SOURCE", "--target"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(source.status.success());
    let source = String::from_utf8(source.stdout).unwrap();
    let number = source
        .trim()
        .strip_prefix("/dev/loop")
        .expect("disposable ext4 loop source required");
    assert!(!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()));
    let backing =
        std::fs::read_to_string(format!("/sys/class/block/loop{number}/loop/backing_file"))
            .unwrap();
    let image = root
        .parent()
        .unwrap()
        .join("disposable.img")
        .canonicalize()
        .unwrap();
    assert_eq!(PathBuf::from(backing.trim()).canonicalize().unwrap(), image);
    assert_eq!(std::fs::metadata(&image).unwrap().len(), 96 * 1024 * 1024);
    let stats = fs::fstatvfs(std::fs::File::open(&root).unwrap()).unwrap();
    let total = stats.f_blocks.checked_mul(stats.f_frsize).unwrap();
    assert!(
        (32 * 1024 * 1024..=128 * 1024 * 1024).contains(&total),
        "disposable ext4 capacity must be 32..128 MiB"
    );
    let t = Temp::new();
    let limits = Limits {
        reserve_min_bytes: 0,
        reserve_percent: 0,
        max_blob_bytes: 65536,
        session_bytes: 131072,
        ..Limits::default()
    };
    let store = RecordStore::initialize(&t.data(), limits).unwrap();
    let c = store.capacity().unwrap();
    assert!((32 * 1024 * 1024..=128 * 1024 * 1024).contains(&c.total));
    assert_eq!(
        std::fs::metadata(&root).unwrap().dev(),
        std::fs::metadata(t.data()).unwrap().dev()
    );
    drop(store);
    (t, limits)
}
#[test]
#[ignore = "requires the bounded disposable ext4 image; CI runs this explicitly"]
fn isolated_ext4_pragmas_lock_and_atomic_blob_placement() {
    let (t, limits) = isolated();
    let s = RecordStore::open(&t.data(), limits).unwrap();
    let journal: String = s
        .conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    let mut settings = std::collections::BTreeMap::new();
    for (name, want) in [
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("read_uncommitted", 0),
        ("trusted_schema", 0),
        ("cache_size", -4096),
        ("mmap_size", 0),
    ] {
        let actual: i64 = s.conn.pragma_query_value(None, name, |r| r.get(0)).unwrap();
        assert_eq!(actual, want);
        settings.insert(name, actual);
    }
    assert!(matches!(
        RecordStore::open(&t.data(), limits),
        Err(StorageError::Busy)
    ));
    let mut w = s.begin().unwrap();
    let r = fixture();
    w.insert(&r).unwrap();
    let body = b"ext4 committed body";
    let blob = id::blob_id(body);
    w.put_blob(blob, Cursor::new(body)).unwrap();
    let expected_dev = std::fs::metadata(t.data()).unwrap().dev();
    for name in ["blobs", "staging", DB] {
        assert_eq!(
            std::fs::metadata(t.data().join(name)).unwrap().dev(),
            expected_dev
        );
    }
    assert_eq!(
        std::fs::read_dir(t.data().join("staging")).unwrap().count(),
        0
    );
    std::fs::File::open(t.data().join("blobs"))
        .unwrap()
        .sync_all()
        .unwrap();
    w.finish().unwrap();
    let s = RecordStore::open(&t.data(), limits).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(s.record(r.id()).unwrap().unwrap().bytes(), r.bytes());
    let mut actual = Vec::new();
    s.blob(blob)
        .unwrap()
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, body);
    println!(
        "LNGNB_EXT4_SETTINGS={}",
        serde_json::json!({"sqlite":rusqlite::version(),"journal_mode":journal,"settings":settings,"capacity_bytes":s.capacity().unwrap().total,"test_reserve_min_bytes":limits.reserve_min_bytes,"test_reserve_percent":limits.reserve_percent})
    );
}
struct FillOnRead {
    file: PathBuf,
    observed: Rc<Cell<bool>>,
    input: Cursor<Vec<u8>>,
    filled: bool,
}
impl Read for FillOnRead {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.filled {
            self.filled = true;
            // O_SYNCで実ブロックの割当失敗を確認する。疎fileの長さだけは増やさない。
            let mut filler = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(fs::OFlags::SYNC.bits() as i32)
                .open(&self.file)?;
            let block = [0x5au8; 65536];
            for _ in 0..2048 {
                match filler.write_all(&block) {
                    Ok(()) => (),
                    Err(e) if e.raw_os_error() == Some(28) => {
                        self.observed.set(true);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            assert!(
                self.observed.get(),
                "bounded image must reach real ENOSPC within 128 MiB"
            );
        }
        self.input.read(out)
    }
}
#[test]
#[ignore = "requires the bounded disposable ext4 image; CI runs this explicitly"]
fn isolated_ext4_real_enospc_after_preflight_preserves_running_and_primary() {
    let (t, limits) = isolated();
    let mut w = RecordStore::open(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    let record = fixture();
    w.insert(&record).unwrap();
    let before = w.store.generation().unwrap();
    let observed = Rc::new(Cell::new(false));
    let filler = t.root.join("bounded-filler");
    let body = vec![0x41; 65536];
    let blob = id::blob_id(&body);
    let result = w.put_blob(
        blob,
        FillOnRead {
            file: filler.clone(),
            observed: Rc::clone(&observed),
            input: Cursor::new(body),
            filled: false,
        },
    );
    assert!(observed.get());
    // 失敗観測のDB書込みも容量不足になれば、元のI/OエラーをSQLITE_FULLが上書きし得る。
    assert!(
        matches!(result,Err(StorageError::Io(ref e)) if e.raw_os_error()==Some(28))
            || matches!(result,Err(StorageError::Sql(ref e)) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "{result:?}"
    );
    assert!(w.failed);
    std::fs::remove_file(&filler).unwrap();
    std::fs::File::open(&t.root).unwrap().sync_all().unwrap();
    assert_eq!(
        w.store.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    assert!(w.store.blob(blob).unwrap().is_none());
    assert!(w.store.generation().unwrap() >= before);
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    let s = RecordStore::open(&t.data(), limits).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(
        s.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    assert!(s.blob(blob).unwrap().is_none());
    assert!(!s.blob_recovery().incomplete_staging.is_empty());
    assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
    println!(
        "LNGNB_EXT4_ENOSPC=filesystem_errno_28_observed; no_blob_commit; primary_preserved; manual_review_retained"
    );
}

#[test]
fn ordinary_workspace_cannot_authorize_enospc_fill() {
    let t = Temp::new();
    std::fs::write(
        t.root.join(".lngnb-disposable-ext4"),
        b"disposable-loop-ext4-v1\n",
    )
    .unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "storage::filesystem_tests::isolated_ext4_real_enospc_after_preflight_preserves_running_and_primary", "--nocapture"])
        .env("LNGNB_FS_TESTING", "disposable-loop-ext4-v1")
        .env("LNGNB_EXT4_TEST_ROOT", &t.root)
        .env("TMPDIR", &t.root)
        .output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("disposable ext4"));
    // 偽のmarkerだけでは、広い通常領域にDBやfillerを作る資格にならない。
    assert_eq!(std::fs::read_dir(&t.root).unwrap().count(), 1);
}
