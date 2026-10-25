//! R26/R27/R30、P09/X13: 根拠の復旧確認だけを試験。公開試験鍵を実運用へ流用しない。
use super::super::tests::{assert_state, bytes, rev};
use super::*;
use crate::{
    id,
    storage::tests::{Temp, fixture},
};
use std::os::unix::fs::PermissionsExt;
use std::{
    io::{BufRead, Cursor, Write},
    process::{Command, Stdio},
};

pub(super) fn open(t: &Temp) -> RecordStore {
    RecordStore::open(&t.data(), Limits::default()).unwrap()
}
pub(super) fn path(t: &Temp) -> std::path::PathBuf {
    t.data()
        .join("blobs")
        .join(blobs::hex(&id::blob_id(&bytes()).bytes))
}
pub(super) fn populated(t: &Temp) -> LocalRecord {
    let bad = rev(&[], 15, "bad");
    let child = rev(&[bad.id()], 14, "child");
    let mut w = t.store().begin().unwrap();
    for r in [&fixture(), &bad, &child] {
        w.insert(r).unwrap();
    }
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    w.revalidate(EvaluationLimits::default()).unwrap();
    // 正常終了を記録しない。異常終了後の手動待ちを模擬する。
    drop(w);
    bad
}
pub(super) fn review(s: RecordStore) -> Result<EvidenceRecoveryReview> {
    let g = s.generation()?;
    s.confirm_evidence_recovery(
        g,
        "真正本文を復元しIDを照合",
        "公開設定・未確定制限は未確認",
        EvaluationLimits::default(),
    )
}
fn confirmations(s: &RecordStore) -> i64 {
    s.conn
        .query_row(
            "SELECT count(*) FROM history WHERE reason LIKE 'evidence_recovery_review:%'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn dirty(s: &RecordStore) -> i64 {
    s.conn
        .query_row("SELECT dirty FROM evaluation_state", [], |r| r.get(0))
        .unwrap()
}
#[test]
fn restored_evidence_is_audited_without_clearing_review_or_invalidity() {
    let t = Temp::new();
    let bad = populated(&t);
    std::fs::remove_file(path(&t)).unwrap();
    let s = open(&t);
    assert_state(
        &s.evaluate(EvaluationLimits::default()).unwrap(),
        &bad,
        Validation::Pending,
        Some(Reason::EvidenceUnavailable),
    );
    drop(s);
    std::fs::write(path(&t), bytes()).unwrap();
    std::fs::set_permissions(path(&t), std::fs::Permissions::from_mode(0o600)).unwrap();
    let s = open(&t);
    assert_eq!(dirty(&s), 0);
    let source = s.generation().unwrap();
    let r = review(s).unwrap();
    assert_eq!(
        r,
        EvidenceRecoveryReview {
            source_generation: source,
            recorded_generation: source + 2,
            checked_evidence: 1
        }
    );
    let s = open(&t);
    assert_eq!(s.generation().unwrap(), r.recorded_generation);
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(dirty(&s), 1);
    assert_eq!(confirmations(&s), 1);
    assert_eq!(
        s.conn
            .query_row("SELECT count(*) FROM known_invalid", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_state(
        &s.evaluate(EvaluationLimits::default()).unwrap(),
        &bad,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    let (reason, actor, rules): (String, String, String) = s
        .conn
        .query_row(
            "SELECT reason,actor,rules FROM history ORDER BY generation DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let raw = data_encoding::HEXLOWER
        .decode(
            reason
                .strip_prefix("evidence_recovery_review:")
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    let note = crate::cbor::decode(&raw).unwrap();
    assert!(format!("{note:?}").contains("公開設定・未確定制限は未確認"));
    assert!(actor.starts_with("uid:"));
    assert_eq!(rules, "lngnb-validation-1");
    assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
}
#[test]
fn missing_and_corrupt_evidence_never_get_confirmation() {
    for missing in [true, false] {
        let t = Temp::new();
        let bad = populated(&t);
        if missing {
            std::fs::remove_file(path(&t)).unwrap();
        } else {
            std::fs::write(path(&t), vec![b'x'; 14]).unwrap();
        }
        assert!(matches!(review(open(&t)), Err(StorageError::Corrupt)));
        let s = open(&t);
        assert_eq!(confirmations(&s), 0);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert_state(
            &s.evaluate(EvaluationLimits::default()).unwrap(),
            &bad,
            Validation::Pending,
            Some(Reason::EvidenceUnavailable),
        );
    }
}
#[test]
fn clean_stale_and_invalid_notes_do_not_record_confirmation() {
    let t = Temp::new();
    let s = t.store();
    assert!(matches!(
        review(s),
        Err(StorageError::InvalidRecoveryReview)
    ));
    populated_existing(&t);
    let s = open(&t);
    let g = s.generation().unwrap();
    assert!(matches!(
        s.confirm_evidence_recovery(g - 1, "復元", "なし", EvaluationLimits::default()),
        Err(StorageError::StaleRecoveryReview)
    ));
    for note in [
        String::new(),
        "  \n".into(),
        "x".repeat(4097),
        "bad\0note".into(),
    ] {
        let s = open(&t);
        assert!(matches!(
            s.confirm_evidence_recovery(g, &note, "なし", EvaluationLimits::default()),
            Err(StorageError::InvalidRecoveryReview)
        ));
        let s = open(&t);
        assert_eq!(s.generation().unwrap(), g);
        assert_eq!(confirmations(&s), 0);
    }
}
fn populated_existing(t: &Temp) {
    let w = open(t).begin().unwrap();
    drop(w);
}
#[test]
fn pending_startup_inspection_cannot_be_bypassed() {
    let t = Temp::new();
    populated(&t);
    let inspection = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    drop(inspection);
    let s = RecordStore::open_locked(&t.data(), Limits::default()).unwrap();
    let g = s.generation().unwrap();
    assert!(matches!(
        s.confirm_evidence_recovery(g, "復元", "なし", EvaluationLimits::default()),
        Err(StorageError::InspectionPending)
    ));
}
#[test]
fn normal_missing_and_transfer_failure_are_not_storage_corruption() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let r = rev(&[], 14, "not retained");
    w.insert(&fixture()).unwrap();
    w.insert(&r).unwrap();
    w.observe_blob_failure(id::blob_id(&bytes()), "transfer_failed")
        .unwrap();
    drop(w);
    let result = review(open(&t)).unwrap();
    assert_eq!(result.checked_evidence, 0);
    let s = open(&t);
    let a = s.evaluate(EvaluationLimits::default()).unwrap();
    assert_state(&a, &r, Validation::Valid, None);
    assert_eq!(
        a.records
            .iter()
            .find(|a| a.record_id == r.id())
            .unwrap()
            .payload_reason,
        Some(PayloadReason::TransferFailed)
    );
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn orphan_is_not_adopted_or_deleted_by_evidence_confirmation() {
    let t = Temp::new();
    populated(&t);
    let orphan = id::blob_id(b"orphan");
    let p = t.data().join("blobs").join(blobs::hex(&orphan.bytes));
    std::fs::write(&p, b"orphan").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    review(open(&t)).unwrap();
    let s = open(&t);
    assert_eq!(std::fs::read(p).unwrap(), b"orphan");
    assert_eq!(
        s.conn
            .query_row(
                "SELECT count(*) FROM blobs WHERE id=?1",
                [orphan.bytes],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn budget_and_capacity_failures_preserve_review() {
    for limits in [
        EvaluationLimits {
            records: 0,
            ..EvaluationLimits::default()
        },
        EvaluationLimits {
            blob_bytes: 13,
            ..EvaluationLimits::default()
        },
        EvaluationLimits {
            elapsed: Duration::ZERO,
            ..EvaluationLimits::default()
        },
    ] {
        let t = Temp::new();
        populated(&t);
        let s = open(&t);
        let g = s.generation().unwrap();
        assert!(matches!(
            s.confirm_evidence_recovery(g, "復元", "なし", limits),
            Err(StorageError::BudgetExceeded)
        ));
        let s = open(&t);
        assert_eq!(confirmations(&s), 0);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
    let t = Temp::new();
    populated(&t);
    let mut s = open(&t);
    s.limits.reserve_min_bytes = u64::MAX;
    assert!(matches!(review(s), Err(StorageError::Capacity)));
    assert_eq!(confirmations(&open(&t)), 0);
}
#[test]
fn history_or_dirty_save_failure_rolls_back_confirmation() {
    for sql in [
        "CREATE TRIGGER reject_review BEFORE INSERT ON history WHEN NEW.reason LIKE 'evidence_recovery_review:%' BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_review BEFORE UPDATE ON evaluation_state BEGIN SELECT RAISE(ABORT,'test'); END",
    ] {
        let t = Temp::new();
        populated(&t);
        let s = open(&t);
        let g = s.generation().unwrap();
        s.conn.execute_batch(sql).unwrap();
        assert!(matches!(review(s), Err(StorageError::Sql(_))));
        let s = open(&t);
        assert_eq!(s.generation().unwrap(), g + 1);
        assert_eq!(confirmations(&s), 0);
        assert_eq!(dirty(&s), 0);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn change_after_hash_aborts_confirmation() {
    for physical in [true, false] {
        let t = Temp::new();
        populated(&t);
        let s = open(&t);
        let g = s.generation().unwrap();
        let outcome = s.confirm_evidence_recovery_inner(
            g,
            "復元",
            "なし",
            EvaluationLimits::default(),
            |conn| {
                if physical {
                    std::fs::write(path(&t), vec![b'x'; 14])?;
                } else {
                    conn.execute(
                        "UPDATE evaluation_state SET record_epoch=record_epoch+1",
                        [],
                    )?;
                }
                Ok(())
            },
        );
        assert!(matches!(outcome, Err(StorageError::Corrupt)));
        let s = open(&t);
        assert_eq!(confirmations(&s), 0);
        assert_eq!(dirty(&s), 0);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn kill_before_and_after_commit_preserves_atomic_review_and_wait() {
    if let Some(p) = std::env::var_os("LNGNB_REVIEW_KILL_CHILD") {
        let s = RecordStore::open(Path::new(&p), Limits::default()).unwrap();
        let g = s.generation().unwrap();
        let phase = std::env::var("LNGNB_REVIEW_KILL_PHASE").unwrap();
        let wait = || {
            println!("LNGNB_REVIEW_COMMIT_{phase}");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
        };
        s.confirm_evidence_recovery_inner(
            g,
            "復元",
            "未確定制限は別途確認",
            EvaluationLimits::default(),
            |_| {
                if phase == "before" {
                    wait();
                }
                Ok(())
            },
        )
        .unwrap();
        if phase == "after" {
            wait();
        }
        panic!("killされる必要がある");
    }
    for phase in ["before", "after"] {
        let t = Temp::new();
        populated(&t);
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::recovery_review::tests::kill_before_and_after_commit_preserves_atomic_review_and_wait","--nocapture"]).env("LNGNB_REVIEW_KILL_CHILD",t.data()).env("LNGNB_REVIEW_KILL_PHASE",phase).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains("LNGNB_REVIEW_COMMIT_") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let s = open(&t);
        assert_eq!(confirmations(&s), i64::from(phase == "after"));
        assert_eq!(dirty(&s), i64::from(phase == "after"));
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
    }
}

#[test]
fn primary_record_corruption_and_false_known_length_cannot_be_acknowledged() {
    for sql in [
        "DROP TRIGGER records_no_update; UPDATE records SET bytes=zeroblob(length(bytes)) WHERE id IN (SELECT record_id FROM known_invalid)",
        "DROP TRIGGER evidence_no_update; UPDATE known_invalid SET actual_length=actual_length+1",
    ] {
        let t = Temp::new();
        populated(&t);
        // open後の保存破損を注入し、以前の起動検査成功を再利用しないことを確認。
        let s = open(&t);
        s.conn.execute_batch(sql).unwrap();
        assert!(matches!(review(s), Err(StorageError::Corrupt)));
        let conn = Connection::open(t.data().join(DB)).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM history WHERE reason LIKE 'evidence_recovery_review:%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(state(&conn).unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn repeated_review_uses_new_generation_and_cannot_clear_wait() {
    let t = Temp::new();
    populated(&t);
    let first = review(open(&t)).unwrap();
    let second = review(open(&t)).unwrap();
    assert_eq!(second.source_generation, first.recorded_generation);
    assert_eq!(second.checked_evidence, 1);
    let s = open(&t);
    assert_eq!(confirmations(&s), 2);
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn note_byte_boundaries_are_explicit_and_preserved() {
    let t = Temp::new();
    populated(&t);
    let note = "あ".repeat(1365) + "x";
    assert_eq!(note.len(), 4096);
    let s = open(&t);
    let g = s.generation().unwrap();
    s.confirm_evidence_recovery(g, &note, &note, EvaluationLimits::default())
        .unwrap();
    let s = open(&t);
    let g = s.generation().unwrap();
    assert!(matches!(
        s.confirm_evidence_recovery(g, "復元", &(note + "x"), EvaluationLimits::default()),
        Err(StorageError::InvalidRecoveryReview)
    ));
    assert_eq!(confirmations(&open(&t)), 1);
}
