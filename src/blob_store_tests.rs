//! R08/R24/R27/R28/R30の物理保存範囲。公開fixtureのみ、実運用へ流用しない。
use super::*;
use crate::{
    id,
    storage::tests::{Temp, fixture, fixture_data, unhex},
};
use std::{
    io::{BufRead, Cursor},
    os::unix::fs::{PermissionsExt, symlink},
    process::{Command, Stdio},
};
fn body_bytes() -> Vec<u8> {
    unhex(fixture_data()["blob_hex"].as_str().unwrap())
}
fn read_blob(store: &RecordStore, id: Id) -> Vec<u8> {
    let mut file = store.blob(id).unwrap().unwrap();
    let mut b = Vec::new();
    file.read_to_end(&mut b).unwrap();
    b
}
fn disk_path(t: &Temp, id: Id) -> std::path::PathBuf {
    t.data().join("blobs").join(hex(&id.bytes))
}

#[test]
fn roundtrip_fixed_id_empty_payload_and_repeated_put() {
    let t = Temp::new();
    let mut writer = t.store().begin().unwrap();
    let bytes = body_bytes();
    let id = id::blob_id(&bytes);
    assert_eq!(id.to_string(), fixture_data()["blob_id"]);
    let result = writer.put_blob(id, Cursor::new(&bytes)).unwrap();
    assert_eq!(result.byte_length, bytes.len() as u64);
    assert!(result.newly_retained);
    let generation = writer.store.generation().unwrap();
    assert!(
        !writer
            .put_blob(id, Cursor::new(&bytes))
            .unwrap()
            .newly_retained
    );
    assert_eq!(writer.store.generation().unwrap(), generation);
    let empty = id::blob_id(b"");
    assert_eq!(empty.to_string(), fixture_data()["empty_blob_id"]);
    assert_eq!(
        writer.put_blob(empty, Cursor::new([])).unwrap().byte_length,
        0
    );
    writer.insert(&fixture()).unwrap();
    writer.finish().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(read_blob(&store, id), bytes);
    assert_eq!(read_blob(&store, empty), b"");
    assert!(!store.blob_recovery().needs_review());
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert!(
        t.data()
            .join("staging")
            .read_dir()
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn streaming_limit_boundaries_and_hash_failure_preserve_existing_blob() {
    let t = Temp::new();
    let limits = Limits {
        max_blob_bytes: 3,
        ..Limits::default()
    };
    let mut writer = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    for bytes in [b"ab".as_slice(), b"abc"] {
        writer
            .put_blob(id::blob_id(bytes), Cursor::new(bytes))
            .unwrap();
    }
    assert!(matches!(
        writer.put_blob(id::blob_id(b"abcd"), Cursor::new(b"abcd")),
        Err(StorageError::BudgetExceeded)
    ));
    let id = id::blob_id(b"abc");
    assert!(matches!(
        writer.put_blob(id, Cursor::new(b"bad")),
        Err(StorageError::BlobHashMismatch)
    ));
    assert_eq!(read_blob(&writer.store, id), b"abc");
    assert_eq!(writer.reserved, 0);
    writer.finish().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert!(!store.blob_recovery().needs_review());
}

#[test]
fn empty_only_policy_and_budget_before_read() {
    let t = Temp::new();
    let limits = Limits {
        max_blob_bytes: 0,
        ..Limits::default()
    };
    let mut writer = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    writer.put_blob(id::blob_id(b""), Cursor::new([])).unwrap();
    assert!(matches!(
        writer.put_blob(id::blob_id(b"a"), Cursor::new(b"a")),
        Err(StorageError::BudgetExceeded)
    ));
    writer.finish().unwrap();
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("budget must be checked before receiving");
        }
    }
    let t = Temp::new();
    let limits = Limits {
        max_blob_bytes: 5,
        session_bytes: 4,
        ..Limits::default()
    };
    let mut w = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    assert!(matches!(
        w.put_blob(id::blob_id(b"x"), MustNotRead),
        Err(StorageError::BudgetExceeded)
    ));
    w.finish().unwrap();
}

#[test]
fn file_io_fault_points_never_create_durable_success() {
    for point in [
        BlobFault::BeforeFileSync,
        BlobFault::AfterFileSync,
        BlobFault::AfterPlace,
        BlobFault::AfterDirectorySync,
        BlobFault::BeforeCommit,
    ] {
        let t = Temp::new();
        let mut writer = t.store().begin().unwrap();
        writer.blob_fault = Some(point);
        let bytes = body_bytes();
        let id = id::blob_id(&bytes);
        assert!(matches!(
            writer.put_blob(id, Cursor::new(bytes)),
            Err(StorageError::Io(_))
        ));
        assert!(writer.store.blob(id).unwrap().is_none());
        assert_eq!(writer.reserved, 0);
        assert!(matches!(
            writer.finish(),
            Err(StorageError::UnresolvedFailure)
        ));
        let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        if [BlobFault::BeforeFileSync, BlobFault::AfterFileSync].contains(&point) {
            assert_eq!(store.blob_recovery().incomplete_staging.len(), 1);
        } else {
            assert_eq!(store.blob_recovery().orphaned, vec![id]);
            assert_eq!(std::fs::read(disk_path(&t, id)).unwrap(), body_bytes());
        }
        assert!(store.blob(id).unwrap().is_none());
    }
}

#[test]
fn sqlite_ledger_failure_keeps_orphan_and_rolls_back_generation() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let generation = w.store.generation().unwrap();
    w.store.conn.execute_batch("CREATE TRIGGER deny_blob_history BEFORE INSERT ON history WHEN NEW.new_state='blob_retained_local_only' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let bytes = body_bytes();
    let id = id::blob_id(&bytes);
    assert!(w.put_blob(id, Cursor::new(bytes)).is_err());
    assert_eq!(w.store.generation().unwrap(), generation);
    assert!(w.store.blob(id).unwrap().is_none());
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.blob_recovery().orphaned, vec![id]);
    assert!(s.blob(id).unwrap().is_none());
}

#[test]
fn corrupt_or_missing_retained_blob_does_not_invalidate_record_bytes() {
    for remove in [false, true] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let bytes = body_bytes();
        let id = id::blob_id(&bytes);
        w.put_blob(id, Cursor::new(bytes)).unwrap();
        let record = fixture();
        w.insert(&record).unwrap();
        w.finish().unwrap();
        if remove {
            std::fs::remove_file(disk_path(&t, id)).unwrap();
        } else {
            std::fs::write(disk_path(&t, id), b"bad").unwrap();
        }
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(
            s.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
        assert!(matches!(s.blob(id), Err(StorageError::Corrupt)));
        assert_eq!(
            if remove {
                &s.blob_recovery().missing
            } else {
                &s.blob_recovery().corrupt
            },
            &vec![id]
        );
        drop(s);
        // bytesが後で戻っても、既に永続化した確認待ちは自動解除しない。
        std::fs::write(disk_path(&t, id), body_bytes()).unwrap();
        std::fs::set_permissions(disk_path(&t, id), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert!(!s.blob_recovery().needs_review());
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn existing_target_is_verified_and_never_overwritten() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let bytes = body_bytes();
    let id = id::blob_id(&bytes);
    std::fs::write(disk_path(&t, id), b"not matching").unwrap();
    std::fs::set_permissions(disk_path(&t, id), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(w.put_blob(id, Cursor::new(bytes)).is_err());
    assert_eq!(std::fs::read(disk_path(&t, id)).unwrap(), b"not matching");
    assert!(w.store.blob(id).unwrap().is_none());
    assert!(w.finish().is_err());
}

#[test]
fn symlink_and_hardlink_blob_targets_and_directories_are_rejected() {
    for directory in ["staging", "blobs"] {
        let t = Temp::new();
        drop(t.store());
        std::fs::remove_dir(t.data().join(directory)).unwrap();
        let other = t.root.join("other");
        std::fs::create_dir(&other).unwrap();
        symlink(&other, t.data().join(directory)).unwrap();
        assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
    }
    for hard in [false, true] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let id = id::blob_id(b"body");
        let sentinel = t.root.join("sentinel");
        std::fs::write(&sentinel, b"original").unwrap();
        if hard {
            std::fs::hard_link(&sentinel, disk_path(&t, id)).unwrap();
        } else {
            symlink(&sentinel, disk_path(&t, id)).unwrap();
        }
        assert!(w.put_blob(id, Cursor::new(b"body")).is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"original");
        assert!(w.finish().is_err());
    }
}

#[test]
fn reader_error_preserves_partial_and_prohibits_clean_finish() {
    struct Broken {
        once: bool,
    }
    impl Read for Broken {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.once {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            self.once = true;
            out[..2].copy_from_slice(b"ab");
            Ok(2)
        }
    }
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    assert!(
        w.put_blob(id::blob_id(b"abcd"), Broken { once: false })
            .is_err()
    );
    assert_eq!(w.reserved, 0);
    assert!(w.finish().is_err());
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.blob_recovery().incomplete_staging.len(), 1);
}

#[test]
fn startup_blob_budgets_do_not_claim_complete_inspection() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.put_blob(id::blob_id(b"abcd"), Cursor::new(b"abcd"))
        .unwrap();
    w.put_blob(id::blob_id(b"efgh"), Cursor::new(b"efgh"))
        .unwrap();
    w.finish().unwrap();
    assert!(matches!(
        RecordStore::open(
            &t.data(),
            Limits {
                scan_blob_bytes: 7,
                ..Limits::default()
            }
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(matches!(
        RecordStore::open(
            &t.data(),
            Limits {
                scan_blob_files: 1,
                ..Limits::default()
            }
        ),
        Err(StorageError::BudgetExceeded)
    ));
    let s = RecordStore::open(
        &t.data(),
        Limits {
            scan_blob_bytes: 8,
            scan_blob_files: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
}

#[test]
fn schema_one_is_preserved_without_automatic_migration() {
    let t = Temp::new();
    drop(t.store());
    let c = Connection::open(t.data().join(DB)).unwrap();
    c.pragma_update(None, "user_version", 1).unwrap();
    c.close().unwrap();
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(std::fs::read(t.data().join(DB)).unwrap(), before);
}

#[test]
fn process_kill_between_placement_and_database_commit() {
    if let Some(path) = std::env::var_os("LNGNB_BLOB_TEST_CHILD") {
        let store = RecordStore::open(Path::new(&path), Limits::default()).unwrap();
        let mut w = store.begin().unwrap();
        w.blob_fault = Some(BlobFault::PauseAfterPlace);
        w.put_blob(id::blob_id(&body_bytes()), Cursor::new(body_bytes()))
            .unwrap();
        return;
    }
    let t = Temp::new();
    drop(t.store());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage::blobs::tests::process_kill_between_placement_and_database_commit",
            "--nocapture",
        ])
        .env("LNGNB_BLOB_TEST_CHILD", t.data())
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
        if line.contains("LNGNB_BLOB_PLACED") {
            ready = true;
            break;
        }
    }
    assert!(ready);
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    let id = id::blob_id(&body_bytes());
    assert_eq!(s.blob_recovery().orphaned, vec![id]);
    assert!(s.blob(id).unwrap().is_none());
    assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
}

#[test]
fn commit_success_followed_by_response_failure_is_inspected_not_assumed_absent() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let id = id::blob_id(&body_bytes());
    w.blob_fault = Some(BlobFault::AfterCommit);
    assert!(w.put_blob(id, Cursor::new(body_bytes())).is_err());
    assert!(w.store.blob(id).unwrap().is_some());
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(read_blob(&s, id), body_bytes());
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}

#[test]
fn multi_buffer_streaming_and_session_count_limit() {
    struct SmallChunks<'a> {
        bytes: &'a [u8],
    }
    impl Read for SmallChunks<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(997).min(self.bytes.len());
            out[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }
    let bytes: Vec<u8> = (0..131079).map(|n| (n % 251) as u8).collect();
    let id = id::blob_id(&bytes);
    let t = Temp::new();
    let limits = Limits {
        session_blobs: 1,
        ..Limits::default()
    };
    let mut w = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    assert_eq!(
        w.put_blob(id, SmallChunks { bytes: &bytes })
            .unwrap()
            .byte_length,
        bytes.len() as u64
    );
    assert!(matches!(
        w.put_blob(id::blob_id(b""), Cursor::new([])),
        Err(StorageError::BudgetExceeded)
    ));
    w.finish().unwrap();
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(read_blob(&s, id), bytes);
}

#[test]
fn aborted_transfers_consume_bytes_and_attempts_even_after_cleanup() {
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("exhausted budget must reject before receiving");
        }
    }
    for over_limit in [false, true] {
        for count_limited in [false, true] {
            let t = Temp::new();
            let limits = Limits {
                max_blob_bytes: 3,
                session_bytes: if count_limited { 100 } else { 6 },
                session_blobs: if count_limited { 1 } else { 100 },
                ..Limits::default()
            };
            let mut w = RecordStore::initialize(&t.data(), limits)
                .unwrap()
                .begin()
                .unwrap();
            let result = if over_limit {
                w.put_blob(id::blob_id(b"abcd"), Cursor::new(b"abcd"))
            } else {
                w.put_blob(id::blob_id(b"abc"), Cursor::new(b"bad"))
            };
            assert!(matches!(
                result,
                Err(StorageError::BudgetExceeded | StorageError::BlobHashMismatch)
            ));
            assert_eq!(w.blobs, 1);
            assert_eq!(w.bytes, if over_limit { 4 } else { 3 });
            assert_eq!(w.reserved, 0);
            assert!(matches!(
                w.put_blob(id::blob_id(b"abc"), MustNotRead),
                Err(StorageError::BudgetExceeded)
            ));
            assert_eq!(w.blobs, 1);
            assert!(w.store.blob_recovery().incomplete_staging.is_empty());
            w.finish().unwrap();
            assert!(
                !RecordStore::open(&t.data(), Limits::default())
                    .unwrap()
                    .blob_recovery()
                    .needs_review()
            );
        }
    }
    // 上限超過検出の1byteもジョブ予算内に確保できなければ、最初から受信しない。
    let t = Temp::new();
    let limits = Limits {
        max_blob_bytes: 3,
        session_bytes: 3,
        ..Limits::default()
    };
    let mut w = RecordStore::initialize(&t.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    assert!(matches!(
        w.put_blob(id::blob_id(b"abc"), MustNotRead),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(w.bytes, 0);
    assert_eq!(w.blobs, 0);
    w.finish().unwrap();
}
