//! R20/R24/R27/R28/R30。fixtureは公開試験用のみ。
use super::*;
use crate::{
    id,
    storage::tests::{Temp, fixture},
};
use std::{
    io::{BufRead, Cursor},
    os::unix::fs::{PermissionsExt, symlink},
    process::{Command, Stdio},
};
fn budget() -> InspectionBudget {
    InspectionBudget {
        blob_files: 1,
        blob_bytes: 3,
        ..InspectionBudget::default()
    }
}
fn path(t: &Temp, area: &str, name: &str) -> std::path::PathBuf {
    t.data().join(area).join(name)
}
fn blob_path(t: &Temp, bytes: &[u8]) -> std::path::PathBuf {
    path(t, "blobs", &blobs::hex(&id::blob_id(bytes).bytes))
}
fn populate(t: &Temp) {
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    for b in [b"aaa", b"bbb", b"ccc", b"ddd"] {
        w.put_blob(id::blob_id(b), Cursor::new(b)).unwrap();
    }
    w.finish().unwrap();
}
fn start(t: &Temp) -> RecordInspection {
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert!(check.step(budget()).unwrap().records_complete);
    check
}
fn complete(check: &mut RecordInspection) {
    for _ in 0..20 {
        if check.step(budget()).unwrap().checks_complete {
            return;
        }
    }
    panic!("not making progress");
}

#[test]
fn blob_hash_progress_persists_across_jobs_with_smaller_total_byte_budget() {
    for b in [
        InspectionBudget {
            blob_files: 1,
            blob_bytes: 64,
            ..budget()
        },
        InspectionBudget {
            blob_files: 10,
            blob_bytes: 3,
            ..budget()
        },
    ] {
        let t = Temp::new();
        populate(&t);
        let mut check = start(&t);
        for n in 1..=4 {
            let p = check.step(b).unwrap();
            assert_eq!(p.checked_blob_files, n);
            assert_eq!(p.checked_blob_bytes, n * 3);
            assert_eq!(p.checks_complete, n == 4);
            if n < 4 {
                check.pause().unwrap();
                check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
                assert_eq!(check.progress().unwrap().checked_blob_files, n);
            }
        }
        let store = check.into_store().unwrap();
        assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
        store.begin().unwrap().finish().unwrap();
    }
}
#[test]
fn too_small_file_budget_does_not_claim_progress_and_can_be_adjusted() {
    let t = Temp::new();
    populate(&t);
    let mut check = start(&t);
    let old = check.progress().unwrap();
    let generation = check.store.generation().unwrap();
    for b in [
        InspectionBudget {
            blob_files: 0,
            ..budget()
        },
        InspectionBudget {
            blob_bytes: 2,
            ..budget()
        },
    ] {
        assert!(matches!(check.step(b), Err(StorageError::BudgetExceeded)));
        assert_eq!(check.progress().unwrap(), old);
        assert_eq!(check.store.generation().unwrap(), generation);
    }
    complete(&mut check);
    check.into_store().unwrap();
}
#[test]
fn discovery_limit_is_explicit_and_does_not_slice_a_partial_manifest_as_complete() {
    let t = Temp::new();
    populate(&t);
    let mut check = RecordInspection::open(
        &t.data(),
        Limits {
            scan_blob_files: 3,
            ..Limits::default()
        },
    )
    .unwrap();
    check.step(budget()).unwrap();
    assert!(matches!(
        check.step(budget()),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(!check.progress().unwrap().checks_complete);
    check.pause().unwrap();
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    check.into_store().unwrap();
}
#[test]
fn recovery_findings_survive_pause_drop_and_restart_without_auto_adoption() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    w.put_blob(id::blob_id(b"gone"), Cursor::new(b"gone"))
        .unwrap();
    w.put_blob(id::blob_id(b"bad"), Cursor::new(b"bad"))
        .unwrap();
    w.finish().unwrap();
    std::fs::remove_file(blob_path(&t, b"gone")).unwrap();
    std::fs::write(blob_path(&t, b"bad"), b"BAD").unwrap();
    let orphan = blob_path(&t, b"free");
    std::fs::write(&orphan, b"free").unwrap();
    std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o600)).unwrap();
    let stage = path(&t, "staging", &format!("{}.part", "a".repeat(64)));
    std::fs::write(&stage, b"part").unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut check = start(&t);
    let b = InspectionBudget {
        blob_files: 1,
        blob_bytes: 4,
        ..budget()
    };
    check.step(b).unwrap();
    drop(check);
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    for _ in 0..10 {
        if check.step(b).unwrap().checks_complete {
            break;
        }
    }
    let store = check.into_store().unwrap();
    let report = store.blob_recovery();
    assert_eq!(report.missing, vec![id::blob_id(b"gone")]);
    assert_eq!(report.corrupt, vec![id::blob_id(b"bad")]);
    assert_eq!(report.orphaned, vec![id::blob_id(b"free")]);
    assert_eq!(report.incomplete_staging.len(), 1);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(store.blob(id::blob_id(b"free")).unwrap().is_none());
    assert!(orphan.exists() && stage.exists());
}
#[test]
fn finding_cannot_be_cleanly_paused_then_forgotten() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.put_blob(id::blob_id(b"bad"), Cursor::new(b"bad"))
        .unwrap();
    w.finish().unwrap();
    std::fs::write(blob_path(&t, b"bad"), b"BAD").unwrap();
    let mut check = start(&t);
    check.step(budget()).unwrap();
    assert!(matches!(
        check.pause(),
        Err(StorageError::UnresolvedFailure)
    ));
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    complete(&mut check);
    assert_eq!(
        check.into_store().unwrap().startup_state().unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn directory_or_already_checked_file_change_invalidates_saved_evidence() {
    for mutate in [0, 1, 2] {
        let t = Temp::new();
        populate(&t);
        let mut check = start(&t);
        check.step(budget()).unwrap();
        let name: String = check
            .store
            .conn
            .query_row(
                "SELECT name FROM blob_inspection_files WHERE result='verified'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        check.pause().unwrap();
        match mutate {
            0 => std::fs::write(path(&t, "blobs", &name), b"XYZ").unwrap(),
            1 => {
                let p = blob_path(&t, b"new");
                std::fs::write(&p, b"new").unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => std::fs::remove_file(path(&t, "blobs", &name)).unwrap(),
        }
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        assert!(check.step(budget()).is_err());
        assert!(check.pause().is_err());
    }
}
#[test]
fn changed_file_after_last_step_is_not_exposed_as_clean_store() {
    let t = Temp::new();
    populate(&t);
    let mut check = start(&t);
    complete(&mut check);
    std::fs::write(blob_path(&t, b"aaa"), b"XYZ").unwrap();
    assert!(check.into_store().is_err());
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn manifest_or_progress_corruption_is_not_reset_on_resume() {
    for sql in [
        "UPDATE blob_inspection_files SET size=size+1",
        "DELETE FROM blob_inspection_files WHERE name=(SELECT min(name) FROM blob_inspection_files)",
        "UPDATE blob_inspection_inventory SET epoch=epoch+1",
        "UPDATE blob_inspection_files SET examined_bytes=0 WHERE result='verified'",
    ] {
        let t = Temp::new();
        populate(&t);
        let mut check = start(&t);
        check.step(budget()).unwrap();
        check.pause().unwrap();
        let conn = Connection::open(t.data().join(DB)).unwrap();
        conn.execute(sql, []).unwrap();
        drop(conn);
        let before = std::fs::read(t.data().join(DB)).unwrap();
        assert!(RecordInspection::open(&t.data(), Limits::default()).is_err());
        assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
    }
}
#[test]
fn ledger_change_discards_old_manifest_and_invalidates_active_handle() {
    let t = Temp::new();
    populate(&t);
    let mut check = start(&t);
    check.step(budget()).unwrap();
    check
        .store
        .conn
        .execute(
            "INSERT INTO blobs VALUES(?1,3)",
            [&id::blob_id(b"new").bytes],
        )
        .unwrap();
    assert!(check.step(budget()).is_err());
    assert!(check.pause().is_err());
    let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(check.progress().unwrap().checked_records, 0);
    complete(&mut check);
    let store = check.into_store().unwrap();
    assert_eq!(store.blob_recovery().missing, vec![id::blob_id(b"new")]);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn blob_result_and_record_checkpoint_rollback_with_history_failure() {
    for (table, operation) in [
        ("blob_inspection_files", "INSERT"),
        ("blob_inspection_files", "UPDATE"),
        ("blob_inspection_inventory", "UPDATE"),
        ("record_inspection", "UPDATE"),
        ("history", "INSERT"),
    ] {
        let t = Temp::new();
        populate(&t);
        let mut check = start(&t);
        if operation == "UPDATE" && table == "blob_inspection_files" {
            check.step(budget()).unwrap();
        }
        let old = check.progress().unwrap();
        let generation = check.store.generation().unwrap();
        check.store.conn.execute_batch(&format!("CREATE TRIGGER reject_blob_check BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(check.step(budget()).is_err());
        assert_eq!(check.progress().unwrap(), old);
        assert_eq!(check.store.generation().unwrap(), generation);
        assert!(check.pause().is_err());
    }
}
#[test]
fn unsafe_manifest_paths_links_and_partial_files_are_not_followed() {
    for area in ["blobs", "staging"] {
        let t = Temp::new();
        populate(&t);
        let outside = t.root.join("sentinel");
        std::fs::write(&outside, b"outside").unwrap();
        let name = if area == "blobs" {
            blobs::hex(&id::blob_id(b"link").bytes)
        } else {
            format!("{}.part", "b".repeat(64))
        };
        symlink(&outside, path(&t, area, &name)).unwrap();
        let mut check = start(&t);
        assert!(check.step(budget()).is_err());
        assert!(check.pause().is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"outside");
    }
}
#[test]
fn schema_four_is_rejected_without_migration_or_data_change() {
    let t = Temp::new();
    drop(t.store());
    let conn = Connection::open(t.data().join(DB)).unwrap();
    conn.pragma_update(None, "user_version", 4).unwrap();
    drop(conn);
    let old = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordInspection::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(old, std::fs::read(t.data().join(DB)).unwrap());
}
#[test]
fn kill_before_blob_checkpoint_resumes_committed_hash_progress_and_keeps_review() {
    use std::io::Write;
    if let Some(path) = std::env::var_os("LNGNB_BLOB_CHECK_CHILD") {
        let mut check = RecordInspection::open(Path::new(&path), Limits::default()).unwrap();
        check.pause_before_checkpoint = std::env::var_os("LNGNB_BLOB_CHECK_BEFORE").is_some();
        check.step(budget()).unwrap();
        println!("LNGNB_BLOB_CHECK_AFTER_CHECKPOINT");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must kill child");
    }
    for before in [true, false] {
        let t = Temp::new();
        populate(&t);
        let mut check = start(&t);
        check.step(budget()).unwrap();
        check.pause().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact","storage::inspection::blob_checks::tests::kill_before_blob_checkpoint_resumes_committed_hash_progress_and_keeps_review","--nocapture"]).env("LNGNB_BLOB_CHECK_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped());
        if before {
            command.env("LNGNB_BLOB_CHECK_BEFORE", "1");
        }
        let mut child = command.spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let marker = if before {
            "LNGNB_RECORD_CHECK_BEFORE_CHECKPOINT"
        } else {
            "LNGNB_BLOB_CHECK_AFTER_CHECKPOINT"
        };
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line.contains(marker) {
                break;
            }
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let mut check = RecordInspection::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(
            check.progress().unwrap().checked_blob_files,
            if before { 1 } else { 2 }
        );
        complete(&mut check);
        assert_eq!(
            check.into_store().unwrap().startup_state().unwrap(),
            StartupState::NeedsReview
        );
    }
}

#[test]
fn retained_ledger_length_change_cannot_reuse_an_old_manifest() {
    let t = Temp::new();
    populate(&t);
    let mut check = start(&t);
    check.step(budget()).unwrap();
    check.pause().unwrap();
    let conn = Connection::open(t.data().join(DB)).unwrap();
    // 保存破損の模擬。製品の不変台帳を更新できる管理操作は提供しない。
    conn.execute_batch("DROP TRIGGER blobs_no_update; UPDATE blobs SET byte_length=byte_length+1;")
        .unwrap();
    drop(conn);
    assert!(RecordInspection::open(&t.data(), Limits::default()).is_err());
}

#[test]
fn a_changed_valid_result_value_cannot_erase_a_persisted_recovery_finding() {
    for finding in 0..3 {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        if finding == 0 {
            w.put_blob(id::blob_id(b"bad"), Cursor::new(b"bad"))
                .unwrap();
        }
        w.finish().unwrap();
        let p = if finding == 0 {
            let p = blob_path(&t, b"bad");
            std::fs::write(&p, b"BAD").unwrap();
            p
        } else if finding == 1 {
            let p = blob_path(&t, b"free");
            std::fs::write(&p, b"free").unwrap();
            p
        } else {
            let p = path(&t, "staging", &format!("{}.part", "c".repeat(64)));
            std::fs::write(&p, b"part").unwrap();
            p
        };
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut check = start(&t);
        assert!(
            check
                .step(InspectionBudget {
                    blob_bytes: 4,
                    ..budget()
                })
                .unwrap()
                .checks_complete
        );
        assert!(check.store.blob_recovery().needs_review());
        drop(check);
        let conn = Connection::open(t.data().join(DB)).unwrap();
        assert_eq!(
            conn.execute("UPDATE blob_inspection_files SET result='verified'", [])
                .unwrap(),
            1
        );
        drop(conn);
        let before = std::fs::read(t.data().join(DB)).unwrap();
        assert!(RecordInspection::open(&t.data(), Limits::default()).is_err());
        assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
    }
}
