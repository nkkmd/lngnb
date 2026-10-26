//! R23/R24/R26/R27/R28/R30: 期限付き内部台帳。公開試験鍵のみ、実運用へ流用しない。
use super::*;
use crate::{
    id,
    storage::{
        evaluation::tests::{bytes, rev},
        tests::{Temp, fixture},
    },
};
use std::{
    io::{BufRead, Cursor, Read},
    process::{Command, Stdio},
};
fn stage(w: &mut RecordWriter, data: &[u8], ttl: u64) -> TemporaryBlob {
    w.stage_blob(
        id::blob_id(data),
        Cursor::new(data),
        ttl,
        TemporaryLimits::default(),
    )
    .unwrap()
}
fn count(s: &RecordStore, table: &str) -> i64 {
    s.conn
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
#[test]
fn temporary_promise_is_durable_without_becoming_manual_retention() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let held = stage(&mut w, &bytes(), 86400);
    assert_eq!(held.expires_at - held.created_at, 86400);
    assert_eq!(held.byte_length, 14);
    assert_eq!(count(&w.store, "manual_blob_holds"), 0);
    let snapshot = w.blob_protection(ProtectionBudget::default()).unwrap();
    let b = &snapshot.blobs[0];
    assert!(!b.manual_retention_recorded);
    assert_eq!(b.temporary_holds, vec![held.hold_id]);
    assert_eq!(b.recorded_length, Some(14));
    w.finish().unwrap();
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(count(&s, "temporary_blob_holds"), 1);
    let mut b = Vec::new();
    s.blob(held.id)
        .unwrap()
        .unwrap()
        .read_to_end(&mut b)
        .unwrap();
    assert_eq!(b, bytes());
}
#[test]
fn repost_reuses_physical_bytes_and_preserves_every_promised_deadline() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w, b"", 86400);
    let b = stage(&mut w, b"", 1);
    assert_ne!(a.hold_id, b.hold_id);
    assert_eq!(count(&w.store, "blobs"), 1);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 2);
    let expires: i64 = w
        .store
        .conn
        .query_row(
            "SELECT expires_at FROM temporary_blob_holds WHERE hold_id=?1",
            [&a.hold_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(expires, a.expires_at);
    assert!(
        w.store
            .conn
            .execute(
                "UPDATE temporary_blob_holds SET expires_at=expires_at-1",
                []
            )
            .is_err()
    );
    assert!(
        w.store
            .conn
            .execute("DELETE FROM temporary_blob_holds", [])
            .is_err()
    );
    assert!(w.store.conn.execute("DELETE FROM blobs", []).is_err());
    w.finish().unwrap();
}
#[test]
fn explicit_retention_promotes_existing_temporary_blob_without_erasing_promises() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w, &bytes(), 1);
    let saved = w.put_blob(a.id, Cursor::new(bytes())).unwrap();
    assert!(saved.newly_retained);
    assert!(
        !w.put_blob(a.id, Cursor::new(bytes()))
            .unwrap()
            .newly_retained
    );
    let p = w.blob_protection(ProtectionBudget::default()).unwrap();
    assert!(p.blobs[0].manual_retention_recorded);
    assert_eq!(p.blobs[0].temporary_holds, vec![a.hold_id]);
    let b = stage(&mut w, &bytes(), 10);
    assert_ne!(a.hold_id, b.hold_id);
    assert_eq!(count(&w.store, "manual_blob_holds"), 1);
    w.finish().unwrap();
}
#[test]
fn record_references_and_invalid_evidence_protect_temporary_body_in_both_orders() {
    for first in [true, false] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let bad = rev(&[], 15, "temporary bad");
        if first {
            stage(&mut w, &bytes(), 1);
        }
        w.insert(&fixture()).unwrap();
        w.insert(&bad).unwrap();
        if !first {
            stage(&mut w, &bytes(), 1);
        }
        w.revalidate(EvaluationLimits::default()).unwrap();
        let p = w.blob_protection(ProtectionBudget::default()).unwrap();
        let b = &p.blobs[0];
        assert!(!b.manual_retention_recorded);
        assert_eq!(b.referencing_records, vec![bad.id()]);
        assert_eq!(b.known_invalid_records, vec![bad.id()]);
        assert_eq!(count(&w.store, "known_invalid"), 1);
        w.finish().unwrap();
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    }
}
#[test]
fn elapsed_deadline_alone_never_deletes_or_drops_protection() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w, &bytes(), 1);
    // 固定した過去の有効な約束を注入する。期限整理はまだ提供しない。
    w.store.conn.execute_batch("DROP TRIGGER temporary_no_update; UPDATE temporary_blob_holds SET created_at=1,expires_at=2; UPDATE history SET reason='temporary_local_blob_promise:'||(SELECT lower(hex(hold_id)) FROM temporary_blob_holds)||':1:2' WHERE new_state='blob_staged_local_only';").unwrap();
    let p = w.blob_protection(ProtectionBudget::default()).unwrap();
    assert_eq!(p.blobs[0].temporary_holds, vec![a.hold_id]);
    assert!(w.blob(a.id).unwrap().is_some());
    w.finish().unwrap();
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(count(&s, "temporary_blob_holds"), 1);
    assert!(s.blob(a.id).unwrap().is_some());
}
struct NeverRead;
impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("preflight must reject")
    }
}
#[test]
fn quota_ttl_and_kind_reject_before_reading_or_changing_state() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let generation = w.store.generation().unwrap();
    for limits in [
        TemporaryLimits { bytes: 0, holds: 1 },
        TemporaryLimits {
            bytes: u64::MAX,
            holds: 0,
        },
    ] {
        assert!(matches!(
            w.stage_blob(id::blob_id(b""), NeverRead, 1, limits),
            Err(StorageError::BudgetExceeded)
        ));
    }
    for ttl in [0, u64::MAX] {
        assert!(matches!(
            w.stage_blob(id::blob_id(b""), NeverRead, ttl, TemporaryLimits::default()),
            Err(StorageError::BudgetExceeded)
        ));
    }
    assert!(matches!(
        w.stage_blob(fixture().id(), NeverRead, 1, TemporaryLimits::default()),
        Err(StorageError::InvalidBlobId)
    ));
    assert_eq!(w.store.generation().unwrap(), generation);
    assert_eq!(count(&w.store, "blobs"), 0);
    w.finish().unwrap();
}
#[test]
fn temporary_quota_counts_unique_bodies_but_each_promise_and_all_expired_rows() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.store.limits.max_blob_bytes = 14;
    let limits = TemporaryLimits {
        bytes: 14,
        holds: 2,
    };
    let id = id::blob_id(&bytes());
    w.stage_blob(id, Cursor::new(bytes()), 1, limits).unwrap();
    w.stage_blob(id, Cursor::new(bytes()), 1, limits).unwrap();
    assert!(matches!(
        w.stage_blob(id, NeverRead, 1, limits),
        Err(StorageError::BudgetExceeded)
    ));
    let adjusted = TemporaryLimits { holds: 3, ..limits };
    assert!(matches!(
        w.stage_blob(id::blob_id(b"x"), NeverRead, 1, adjusted),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(count(&w.store, "blobs"), 1);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 2);
    w.finish().unwrap();
}
#[test]
fn protected_collection_budget_cannot_return_a_partial_temporary_set() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    stage(&mut w, b"", 1);
    assert!(matches!(
        w.blob_protection(ProtectionBudget {
            temporary_holds: 0,
            ..ProtectionBudget::default()
        }),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(
        w.blob_protection(ProtectionBudget {
            temporary_holds: 1,
            ..ProtectionBudget::default()
        })
        .unwrap()
        .blobs
        .len(),
        1
    );
    w.finish().unwrap();
}
#[test]
fn sql_failure_rolls_back_body_promise_generation_and_history_together() {
    for table in ["blobs", "temporary_blob_holds", "history"] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let gen_before = w.store.generation().unwrap();
        w.store.conn.execute_batch(&format!("CREATE TRIGGER reject_temporary BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(
            w.stage_blob(
                id::blob_id(&bytes()),
                Cursor::new(bytes()),
                1,
                TemporaryLimits::default()
            )
            .is_err()
        );
        assert_eq!(w.store.generation().unwrap(), gen_before);
        assert_eq!(count(&w.store, "blobs"), 0);
        assert_eq!(count(&w.store, "temporary_blob_holds"), 0);
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(s.blob_recovery().orphaned.len(), 1);
    }
}
#[test]
fn fault_before_and_after_commit_reports_uncertainty_without_faking_success() {
    for point in [BlobFault::BeforeCommit, BlobFault::AfterCommit] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        w.blob_fault = Some(point);
        assert!(
            w.stage_blob(
                id::blob_id(&bytes()),
                Cursor::new(bytes()),
                1,
                TemporaryLimits::default()
            )
            .is_err()
        );
        let expected = if point == BlobFault::AfterCommit {
            1
        } else {
            0
        };
        assert_eq!(count(&w.store, "temporary_blob_holds"), expected);
        assert_eq!(count(&w.store, "blobs"), expected);
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn missing_body_does_not_erase_promise_or_become_record_signature_failure() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w, &bytes(), 86400);
    w.finish().unwrap();
    std::fs::remove_file(t.data().join("blobs").join(hex(&a.id.bytes))).unwrap();
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.blob_recovery().missing, vec![a.id]);
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(
        s.blob_protection(ProtectionBudget::default())
            .unwrap()
            .blobs[0]
            .temporary_holds,
        vec![a.hold_id]
    );
}
#[test]
fn clock_rollback_rejects_new_promise_and_keeps_old_one() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w, &bytes(), 1);
    w.store.conn.execute_batch("DROP TRIGGER temporary_no_update; UPDATE temporary_blob_holds SET created_at=253402300790,expires_at=253402300799; UPDATE history SET reason='temporary_local_blob_promise:'||(SELECT lower(hex(hold_id)) FROM temporary_blob_holds)||':253402300790:253402300799' WHERE new_state='blob_staged_local_only';").unwrap();
    assert!(
        w.stage_blob(a.id, Cursor::new(bytes()), 1, TemporaryLimits::default())
            .is_err()
    );
    assert_eq!(count(&w.store, "temporary_blob_holds"), 1);
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
}
#[test]
fn old_schemas_are_rejected_without_mutation_or_automatic_migration() {
    for version in 1..=8 {
        let t = Temp::new();
        drop(t.store());
        let c = Connection::open(t.data().join(DB)).unwrap();
        c.pragma_update(None, "user_version", version).unwrap();
        drop(c);
        let before = std::fs::read(t.data().join(DB)).unwrap();
        assert!(matches!(
            RecordStore::open(&t.data(), Limits::default()),
            Err(StorageError::UnsupportedFormat)
        ));
        assert_eq!(std::fs::read(t.data().join(DB)).unwrap(), before);
    }
}
#[test]
fn lost_promise_is_corruption_and_never_implicitly_manual_retention() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    stage(&mut w, &bytes(), 1);
    w.finish().unwrap();
    let c = Connection::open(t.data().join(DB)).unwrap();
    c.execute_batch("DROP TRIGGER temporary_no_delete; DELETE FROM temporary_blob_holds;")
        .unwrap();
    drop(c);
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::Corrupt)
    ));
}
#[test]
fn kill_after_file_placement_keeps_manual_wait_and_never_invents_a_promise() {
    if let Some(p) = std::env::var_os("LNGNB_TEMPORARY_KILL") {
        let mut w = RecordStore::open(Path::new(&p), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        w.blob_fault = Some(BlobFault::PauseAfterPlace);
        stage(&mut w, &bytes(), 1);
        panic!("must be killed");
    }
    let t = Temp::new();
    drop(t.store());
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::blobs::temporary_tests::kill_after_file_placement_keeps_manual_wait_and_never_invents_a_promise","--nocapture"]).env("LNGNB_TEMPORARY_KILL",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line.contains("LNGNB_BLOB_PLACED") {
            break;
        }
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(count(&s, "temporary_blob_holds"), 0);
    assert_eq!(s.blob_recovery().orphaned.len(), 1);
}

#[test]
fn missing_promise_on_manually_retained_body_is_still_detected_from_history() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w, &bytes(), 1);
    w.put_blob(a.id, Cursor::new(bytes())).unwrap();
    w.finish().unwrap();
    let c = Connection::open(t.data().join(DB)).unwrap();
    c.execute_batch("DROP TRIGGER temporary_no_delete; DELETE FROM temporary_blob_holds;")
        .unwrap();
    drop(c);
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::Corrupt)
    ));
}
#[test]
fn normal_local_startup_checks_temporary_body_and_abnormal_start_never_clears_wait() {
    for clean in [true, false] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w, &bytes(), 1);
        if clean {
            w.finish().unwrap();
        } else {
            drop(w);
        }
        let mut startup = LocalStartup::open(&t.data(), Limits::default()).unwrap();
        loop {
            if startup
                .step(EvaluationLimits::default(), LocalStartupBudget::default())
                .unwrap()
                .checks_complete()
            {
                break;
            }
        }
        assert_eq!(startup.needs_review(), !clean);
        if clean {
            let mut w = startup.into_writer().unwrap();
            assert!(w.blob(a.id).unwrap().is_some());
            w.finish().unwrap();
        } else {
            assert!(matches!(
                startup.into_writer(),
                Err(StorageError::NeedsReview)
            ));
        }
    }
}
#[test]
fn temporary_upload_does_not_adopt_an_unregistered_existing_file() {
    use std::os::unix::fs::PermissionsExt;
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let data = bytes();
    let id = id::blob_id(&data);
    let path = t.data().join("blobs").join(hex(&id.bytes));
    std::fs::write(&path, &data).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        w.stage_blob(id, Cursor::new(&data), 1, TemporaryLimits::default()),
        Err(StorageError::Corrupt)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), data);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 0);
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
}
