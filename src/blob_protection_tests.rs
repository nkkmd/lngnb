//! R23/R26/R28: 保護根拠の収集。公開試験鍵のみ、実運用への流用禁止。
use super::*;
use crate::cbor::Value;
use crate::{
    id,
    storage::{
        evaluation::tests::{bytes, key, rev, set},
        tests::{Temp, fixture},
    },
};
use std::{
    io::{BufRead, Cursor, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
fn open(t: &Temp) -> RecordStore {
    RecordStore::open(&t.data(), Limits::default()).unwrap()
}
fn path(t: &Temp) -> std::path::PathBuf {
    t.data()
        .join("blobs")
        .join(blobs::hex(&id::blob_id(&bytes()).bytes))
}
fn collect(s: &RecordStore) -> BlobProtectionSnapshot {
    s.blob_protection(ProtectionBudget::default()).unwrap()
}
fn populate(t: &Temp, bad: bool) -> (RecordWriter, LocalRecord) {
    let mut w = t.store().begin().unwrap();
    let r = rev(&[], if bad { 15 } else { 14 }, "reference");
    w.insert(&fixture()).unwrap();
    w.insert(&r).unwrap();
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    if bad {
        w.revalidate(EvaluationLimits::default()).unwrap();
    }
    (w, r)
}
fn other() -> LocalRecord {
    let mut body = rev(&[], 0, "other").body().clone();
    let Value::Map(fields) = &mut body else {
        panic!()
    };
    let p = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1;
    set(p, "blob_id", Value::Bytes(id::blob_id(b"").bytes.to_vec()));
    LocalRecord::sign(body, &key()).unwrap()
}
#[test]
fn explicit_retention_and_all_shared_references_have_stable_ids() {
    let t = Temp::new();
    let (mut w, r) = populate(&t, false);
    let child = rev(&[r.id()], 14, "child");
    w.insert(&child).unwrap();
    let extra = id::blob_id(b"extra");
    w.put_blob(extra, Cursor::new(b"extra")).unwrap();
    let snapshot = w.blob_protection(ProtectionBudget::default()).unwrap();
    assert_eq!(snapshot.blobs.len(), 2);
    assert!(
        snapshot
            .blobs
            .windows(2)
            .all(|p| p[0].blob_id.bytes < p[1].blob_id.bytes)
    );
    let row = snapshot
        .blobs
        .iter()
        .find(|r| r.blob_id == id::blob_id(&bytes()))
        .unwrap();
    let mut expected = vec![r.id(), child.id()];
    expected.sort_by_key(|id| id.bytes);
    assert_eq!(row.referencing_records, expected);
    assert!(row.manual_retention_recorded);
    assert_eq!(row.recorded_length, Some(14));
    assert!(row.known_invalid_records.is_empty());
    let row = snapshot.blobs.iter().find(|r| r.blob_id == extra).unwrap();
    assert!(row.manual_retention_recorded);
    assert!(row.referencing_records.is_empty());
    w.finish().unwrap();
}
#[test]
fn unheld_payload_and_pending_or_wrong_publisher_records_still_protect_references() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let pending = rev(
        &[Id {
            kind: Kind::Record,
            bytes: [42; 32],
        }],
        14,
        "pending",
    );
    w.insert(&pending).unwrap();
    let wrong = LocalRecord::sign(
        rev(&[], 14, "wrong").body().clone(),
        &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    w.insert(&wrong).unwrap();
    let s = w.revalidate(EvaluationLimits::default()).unwrap();
    assert!(
        s.records
            .iter()
            .any(|a| a.reason == Some(Reason::WrongPublisher))
    );
    let p = w.blob_protection(ProtectionBudget::default()).unwrap();
    let row = &p.blobs[0];
    assert_eq!(row.referencing_records.len(), 2);
    assert!(!row.manual_retention_recorded);
    assert_eq!(row.recorded_length, None);
    w.finish().unwrap();
}
#[test]
fn known_evidence_protection_survives_missing_corrupt_and_restored_body() {
    let t = Temp::new();
    let (w, bad) = populate(&t, true);
    let before = collect(&w.store);
    assert_eq!(before.blobs[0].known_invalid_records, vec![bad.id()]);
    std::fs::remove_file(path(&t)).unwrap();
    assert_eq!(collect(&w.store), before);
    std::fs::write(path(&t), b"broken").unwrap();
    assert_eq!(collect(&w.store), before);
    std::fs::write(path(&t), bytes()).unwrap();
    std::fs::set_permissions(path(&t), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(collect(&w.store), before);
    // この診断は本文の正常性検査ではなく、保護根拠を消さないことだけを確認する。
}
#[test]
fn record_and_blob_arrival_order_converges_without_using_generations_as_identity() {
    let mut expected = None;
    for blob_first in [false, true] {
        for reverse in [false, true] {
            let t = Temp::new();
            let mut w = t.store().begin().unwrap();
            let mut records = vec![fixture(), rev(&[], 14, "one"), other()];
            if reverse {
                records.reverse();
            }
            if blob_first {
                w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
                    .unwrap();
            }
            for r in &records {
                w.insert(r).unwrap();
            }
            if !blob_first {
                w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
                    .unwrap();
            }
            let s = w.blob_protection(ProtectionBudget::default()).unwrap();
            if let Some(expected) = &expected {
                assert_eq!(&s.blobs, expected);
            } else {
                expected = Some(s.blobs);
            }
            w.finish().unwrap();
        }
    }
}
#[test]
fn dirty_or_absent_derived_evaluation_does_not_hide_primary_references() {
    let t = Temp::new();
    let (w, _) = populate(&t, true);
    let expected = collect(&w.store);
    w.store.conn.execute_batch("DELETE FROM evaluations; DELETE FROM parent_edges; UPDATE evaluation_state SET dirty=1;").unwrap();
    assert_eq!(collect(&w.store), expected);
}
#[test]
fn unfinished_collection_does_not_drop_uncollected_primary_references() {
    let t = Temp::new();
    let (w, _) = populate(&t, false);
    let extra = other();
    let mut w = w;
    w.insert(&extra).unwrap();
    w.finish().unwrap();
    let mut j = open(&t).evaluation_job().unwrap();
    j.prepare(
        EvaluationLimits::default(),
        EvaluationInputBudget {
            records: 1,
            ..EvaluationInputBudget::default()
        },
    )
    .unwrap();
    j.pause().unwrap();
    let s = open(&t);
    let state = s.startup_state().unwrap();
    let p = collect(&s);
    assert_eq!(p.blobs.len(), 2);
    assert!(
        p.blobs
            .iter()
            .any(|b| b.referencing_records == vec![extra.id()])
    );
    assert_eq!(s.startup_state().unwrap(), state);
}
#[test]
fn malformed_primary_record_fails_and_writer_cannot_mark_clean() {
    let t = Temp::new();
    let (mut w, _) = populate(&t, false);
    w.store
        .conn
        .execute_batch(
            "DROP TRIGGER records_no_update; UPDATE records SET bytes=zeroblob(length(bytes));",
        )
        .unwrap();
    assert!(matches!(
        w.blob_protection(ProtectionBudget::default()),
        Err(StorageError::Corrupt)
    ));
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    let c = Connection::open(t.data().join(DB)).unwrap();
    assert_eq!(state(&c).unwrap(), StartupState::NeedsReview);
}
#[test]
fn inconsistent_known_evidence_never_becomes_a_successful_partial_snapshot() {
    for sql in [
        "UPDATE known_invalid SET actual_length=13",
        "UPDATE known_invalid SET generation=9223372036854775807",
        "UPDATE known_invalid SET at=''",
        "UPDATE known_invalid SET record_id=(SELECT id FROM records WHERE id NOT IN (SELECT record_id FROM known_invalid) LIMIT 1)",
    ] {
        let t = Temp::new();
        let (mut w, _) = populate(&t, true);
        w.store
            .conn
            .execute_batch("DROP TRIGGER evidence_no_update;")
            .unwrap();
        w.store.conn.execute_batch(sql).unwrap();
        assert!(matches!(
            w.blob_protection(ProtectionBudget::default()),
            Err(StorageError::Corrupt)
        ));
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    }
}
#[test]
fn all_count_byte_and_time_boundaries_reject_partial_results_and_allow_adjustment() {
    let t = Temp::new();
    let (mut w, _) = populate(&t, true);
    let baseline = w.blob_protection(ProtectionBudget::default()).unwrap();
    let total: i64 = w
        .store
        .conn
        .query_row("SELECT sum(length(bytes)) FROM records", [], |r| r.get(0))
        .unwrap();
    for b in [
        ProtectionBudget {
            records: 1,
            ..ProtectionBudget::default()
        },
        ProtectionBudget {
            record_bytes: total as u64 - 1,
            ..ProtectionBudget::default()
        },
        ProtectionBudget {
            retained_blobs: 0,
            ..ProtectionBudget::default()
        },
        ProtectionBudget {
            evidence: 0,
            ..ProtectionBudget::default()
        },
        ProtectionBudget {
            targets: 0,
            ..ProtectionBudget::default()
        },
        ProtectionBudget {
            elapsed: Duration::ZERO,
            ..ProtectionBudget::default()
        },
    ] {
        assert!(matches!(
            w.blob_protection(b),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(
            w.blob_protection(ProtectionBudget::default()).unwrap(),
            baseline
        );
    }
    let exact = ProtectionBudget {
        records: 2,
        record_bytes: total as u64,
        retained_blobs: 1,
        evidence: 1,
        targets: 1,
        ..ProtectionBudget::default()
    };
    assert_eq!(w.blob_protection(exact).unwrap(), baseline);
    w.finish().unwrap();
}
#[test]
fn empty_snapshot_accepts_zero_counts_and_reading_never_changes_history_or_state() {
    let t = Temp::new();
    let s = t.store();
    let p = s
        .blob_protection(ProtectionBudget {
            records: 0,
            record_bytes: 0,
            retained_blobs: 0,
            evidence: 0,
            targets: 0,
            ..ProtectionBudget::default()
        })
        .unwrap();
    assert!(p.blobs.is_empty());
    assert_eq!(s.generation().unwrap(), 0);
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    drop(s);
    let t = Temp::new();
    let (w, _) = populate(&t, true);
    let generation = w.store.generation().unwrap();
    let count: i64 = w
        .store
        .conn
        .query_row("SELECT count(*) FROM history", [], |r| r.get(0))
        .unwrap();
    w.store.conn.execute_batch("CREATE TRIGGER reject_read_write BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT,'test'); END; CREATE TRIGGER reject_state_write BEFORE UPDATE ON storage_state BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    collect(&w.store);
    assert_eq!(w.store.generation().unwrap(), generation);
    assert_eq!(
        w.store
            .conn
            .query_row("SELECT count(*) FROM history", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        count
    );
    assert_eq!(w.store.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn concurrent_input_change_is_reported_as_stale_not_as_protection_success() {
    for sql in [
        "UPDATE evaluation_state SET record_epoch=record_epoch+1",
        "UPDATE evaluation_state SET payload_epoch=payload_epoch+1",
        "UPDATE record_inspection SET source_epoch=source_epoch+1",
        "UPDATE storage_state SET generation=generation+1",
    ] {
        let t = Temp::new();
        let (w, _) = populate(&t, false);
        let s = w.store;
        let p = s.protection_inner(ProtectionBudget::default(), || {
            let c = Connection::open(t.data().join(DB))?;
            c.execute_batch(sql)?;
            Ok(())
        });
        assert!(matches!(p, Err(StorageError::ProtectionChanged)));
    }
}
#[test]
fn unregistered_files_are_not_adopted_deleted_or_claimed_safe_to_clean() {
    let t = Temp::new();
    let (w, _) = populate(&t, false);
    let orphan = id::blob_id(b"orphan");
    let name = blobs::hex(&orphan.bytes);
    let p = t.data().join("blobs").join(&name);
    let q = t.data().join("staging").join(format!("{name}.part"));
    for f in [&p, &q] {
        std::fs::write(f, b"orphan").unwrap();
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let snapshot = collect(&w.store);
    assert!(!snapshot.blobs.iter().any(|b| b.blob_id == orphan));
    assert_eq!(std::fs::read(p).unwrap(), b"orphan");
    assert_eq!(std::fs::read(q).unwrap(), b"orphan");
    assert_eq!(
        w.store
            .conn
            .query_row("SELECT count(*) FROM blobs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn killing_readonly_collection_does_not_change_clean_or_manual_state() {
    if let Some(p) = std::env::var_os("LNGNB_PROTECTION_KILL_CHILD") {
        let s = RecordStore::open(Path::new(&p), Limits::default()).unwrap();
        s.protection_inner(ProtectionBudget::default(), || {
            println!("LNGNB_PROTECTION_READING");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(())
        })
        .unwrap();
        panic!("killされる必要がある");
    }
    for clean in [false, true] {
        let t = Temp::new();
        let (w, _) = populate(&t, true);
        if clean {
            w.finish().unwrap();
        } else {
            drop(w);
        }
        let original = if clean {
            StartupState::Clean
        } else {
            StartupState::NeedsReview
        };
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::protection::tests::killing_readonly_collection_does_not_change_clean_or_manual_state","--nocapture"]).env("LNGNB_PROTECTION_KILL_CHILD",t.data()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains("LNGNB_PROTECTION_READING") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(open(&t).startup_state().unwrap(), original);
    }
}
