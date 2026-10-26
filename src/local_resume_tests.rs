//! R24/R26/R27/R30: 明示的なローカルwriter再開。公開試験鍵のみ、実運用禁止。
use super::super::tests::{assert_state, key, rev, set};
use super::tests::{open, path, populated, review};
use super::*;
use crate::cbor::Value;
use crate::{
    id,
    storage::tests::{Temp, fixture},
};
use std::{
    io::{BufRead, Cursor, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
const CONFIRM: &str =
    "未確定だった制限を確認・再適用済み。現在の保存範囲に未解決障害なし。ローカル書込みだけ再開";
fn resumed(s: RecordStore, r: EvidenceRecoveryReview) -> Result<RecordWriter> {
    s.resume_local_writes(r, CONFIRM, EvaluationLimits::default())
}
fn resume_count(s: &RecordStore) -> i64 {
    s.conn
        .query_row(
            "SELECT count(*) FROM history WHERE reason LIKE 'explicit_local_resume:%'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn known(s: &RecordStore) -> i64 {
    s.conn
        .query_row("SELECT count(*) FROM known_invalid", [], |r| r.get(0))
        .unwrap()
}
#[test]
fn explicit_resume_keeps_invalid_roots_and_can_finish_cleanly() {
    let t = Temp::new();
    let bad = populated(&t);
    let r = review(open(&t)).unwrap();
    let mut w = resumed(open(&t), r).unwrap();
    assert_eq!(resume_count(&w.store), 1);
    assert_eq!(known(&w.store), 1);
    let s = w.store.evaluate(EvaluationLimits::default()).unwrap();
    assert_state(
        &s,
        &bad,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    assert!(
        s.records
            .iter()
            .any(|a| a.reason == Some(Reason::InvalidParent))
    );
    let added = rev(&[], 14, "after resume");
    w.insert(&added).unwrap();
    w.finish().unwrap();
    let s = open(&t);
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    assert_eq!(known(&s), 1);
    assert!(s.record(added.id()).unwrap().is_some());
}
#[test]
fn successful_resume_without_finish_still_requires_manual_review() {
    let t = Temp::new();
    populated(&t);
    let r = review(open(&t)).unwrap();
    drop(resumed(open(&t), r).unwrap());
    let s = open(&t);
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(resume_count(&s), 1);
    assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
}
#[test]
fn fabricated_stale_and_nonreview_history_are_not_authorization() {
    let t = Temp::new();
    populated(&t);
    let s = open(&t);
    let g = s.generation().unwrap();
    assert!(
        resumed(
            s,
            EvidenceRecoveryReview {
                source_generation: g - 2,
                recorded_generation: g,
                checked_evidence: 1
            }
        )
        .is_err()
    );
    let r = review(open(&t)).unwrap();
    let forged = EvidenceRecoveryReview {
        checked_evidence: 0,
        ..r
    };
    assert!(matches!(
        resumed(open(&t), forged),
        Err(StorageError::InvalidRecoveryReview)
    ));
    let mut job = open(&t).evaluation_job().unwrap();
    job.step(EvaluationLimits::default(), EvaluationStepBudget::default())
        .unwrap();
    job.pause().unwrap();
    assert!(matches!(
        resumed(open(&t), r),
        Err(StorageError::StaleRecoveryReview)
    ));
    assert_eq!(resume_count(&open(&t)), 0);
}
#[test]
fn incomplete_corrupt_or_damaged_review_history_blocks_resume() {
    for sql in [
        "UPDATE history SET reason='not a review' WHERE generation=(SELECT max(generation) FROM history)",
        "UPDATE history SET reason='evidence_recovery_review:00' WHERE generation=(SELECT max(generation) FROM history)",
        "UPDATE history SET reason='evidence_recovery_review:'||hex(zeroblob(10000)) WHERE generation=(SELECT max(generation) FROM history)",
        "UPDATE history SET old_state='clean' WHERE generation=(SELECT max(generation) FROM history)",
    ] {
        let t = Temp::new();
        populated(&t);
        let r = review(open(&t)).unwrap();
        let s = open(&t);
        s.conn.execute_batch(sql).unwrap();
        assert!(matches!(
            resumed(s, r),
            Err(StorageError::InvalidRecoveryReview)
        ));
        let s = open(&t);
        assert_eq!(resume_count(&s), 0);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn missing_corrupt_orphan_and_staging_objects_do_not_resume() {
    for kind in ["missing", "corrupt", "orphan", "staging"] {
        let t = Temp::new();
        populated(&t);
        let r = review(open(&t)).unwrap();
        let s = open(&t);
        match kind {
            "missing" => std::fs::remove_file(path(&t)).unwrap(),
            "corrupt" => std::fs::write(path(&t), vec![b'x'; 14]).unwrap(),
            _ => {
                let name = blobs::hex(&id::blob_id(b"extra").bytes);
                let p = if kind == "orphan" {
                    t.data().join("blobs").join(name)
                } else {
                    t.data().join("staging").join(format!("{name}.part"))
                };
                std::fs::write(&p, b"extra").unwrap();
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        assert!(resumed(s, r).is_err());
        let s = open(&t);
        assert_eq!(resume_count(&s), 0);
        assert_eq!(known(&s), 1);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn unreferenced_retained_corruption_is_also_checked() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let b = id::blob_id(b"unreferenced");
    w.put_blob(b, Cursor::new(b"unreferenced")).unwrap();
    drop(w);
    let r = review(open(&t)).unwrap();
    let s = open(&t);
    std::fs::write(t.data().join("blobs").join(blobs::hex(&b.bytes)), b"bad").unwrap();
    assert!(resumed(s, r).is_err());
    assert_eq!(resume_count(&open(&t)), 0);
}
#[test]
fn ordinary_missing_payload_and_missing_parent_do_not_fake_completion() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let r = rev(
        &[Id {
            kind: Kind::Record,
            bytes: [42; 32],
        }],
        14,
        "missing parent and payload",
    );
    w.insert(&r).unwrap();
    drop(w);
    let checked = review(open(&t)).unwrap();
    let w = resumed(open(&t), checked).unwrap();
    let s = w.store.evaluate(EvaluationLimits::default()).unwrap();
    assert_state(&s, &r, Validation::Pending, Some(Reason::MissingParent));
    assert_eq!(
        s.records
            .iter()
            .find(|a| a.record_id == r.id())
            .unwrap()
            .payload_status,
        Some(PayloadStatus::Missing)
    );
    w.finish().unwrap();
}
#[test]
fn pending_startup_and_pending_evaluation_queues_block_resume() {
    // 保存済みの収集/本文/判定cursorは完了・現在入力一致を要求する保守的な経路。
    for phase in ["records", "blobs", "evaluation"] {
        let t = Temp::new();
        populated(&t);
        let mut j = open(&t).evaluation_job().unwrap();
        match phase {
            "records" => {
                j.prepare(
                    EvaluationLimits::default(),
                    EvaluationInputBudget {
                        records: 1,
                        ..EvaluationInputBudget::default()
                    },
                )
                .unwrap();
            }
            "blobs" => {
                j.prepare(
                    EvaluationLimits::default(),
                    EvaluationInputBudget::default(),
                )
                .unwrap();
                let mut body = rev(&[], 5, "second payload").body().clone();
                let Value::Map(fields) = &mut body else {
                    panic!()
                };
                let payload = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1;
                set(
                    payload,
                    "blob_id",
                    Value::Bytes(id::blob_id(b"other").bytes.to_vec()),
                );
                let second = LocalRecord::sign(body, &key()).unwrap();
                j.writer.insert(&second).unwrap();
                j.writer
                    .put_blob(id::blob_id(b"other"), Cursor::new(b"other"))
                    .unwrap();
                j.prepare(
                    EvaluationLimits::default(),
                    EvaluationInputBudget::default(),
                )
                .unwrap();
                assert!(
                    !j.prepare_blobs(
                        EvaluationLimits::default(),
                        EvaluationBlobBudget {
                            targets: 1,
                            ..EvaluationBlobBudget::default()
                        }
                    )
                    .unwrap()
                    .checks_complete
                );
            }
            _ => {
                j.step(
                    EvaluationLimits::default(),
                    EvaluationStepBudget { nodes: 1 },
                )
                .unwrap();
            }
        }
        j.pause().unwrap();
        let r = review(open(&t)).unwrap();
        assert!(matches!(
            resumed(open(&t), r),
            Err(StorageError::EvaluationInputPending)
        ));
        assert_eq!(resume_count(&open(&t)), 0);
    }
    let t = Temp::new();
    populated(&t);
    let r = review(open(&t)).unwrap();
    let s = RecordStore::open_locked(&t.data(), Limits::default()).unwrap();
    assert!(matches!(
        resumed(s, r),
        Err(StorageError::InspectionPending)
    ));
}
#[test]
fn complete_saved_inputs_and_queue_are_checked_and_preserved() {
    let t = Temp::new();
    populated(&t);
    let mut j = open(&t).evaluation_job().unwrap();
    j.prepare(
        EvaluationLimits::default(),
        EvaluationInputBudget::default(),
    )
    .unwrap();
    j.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default())
        .unwrap();
    assert!(
        j.step(EvaluationLimits::default(), EvaluationStepBudget::default())
            .unwrap()
            .processed_complete
    );
    j.pause().unwrap();
    let r = review(open(&t)).unwrap();
    let w = resumed(open(&t), r).unwrap();
    assert_eq!(
        w.store
            .conn
            .query_row("SELECT count(*) FROM evaluation_work", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
    w.finish().unwrap();
}
#[test]
fn corrupted_saved_queues_and_inputs_cannot_be_bypassed_by_fresh_evaluation() {
    for sql in [
        "UPDATE evaluation_input SET digest=zeroblob(32)",
        "UPDATE evaluation_blob_input SET digest=zeroblob(32)",
        "UPDATE evaluation_job SET digest=zeroblob(32)",
    ] {
        let t = Temp::new();
        populated(&t);
        let mut j = open(&t).evaluation_job().unwrap();
        j.prepare(
            EvaluationLimits::default(),
            EvaluationInputBudget::default(),
        )
        .unwrap();
        j.prepare_blobs(EvaluationLimits::default(), EvaluationBlobBudget::default())
            .unwrap();
        j.step(EvaluationLimits::default(), EvaluationStepBudget::default())
            .unwrap();
        j.pause().unwrap();
        let r = review(open(&t)).unwrap();
        let s = open(&t);
        s.conn.execute_batch(sql).unwrap();
        assert!(matches!(resumed(s, r), Err(StorageError::Corrupt)));
        assert_eq!(resume_count(&open(&t)), 0);
    }
}
#[test]
fn evaluation_and_resume_history_failures_are_atomic() {
    for sql in [
        "CREATE TRIGGER reject_resume BEFORE INSERT ON history WHEN NEW.reason='begin_explicit_local_resume' BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_resume BEFORE INSERT ON history WHEN NEW.reason LIKE 'explicit_local_resume:%' BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_resume BEFORE INSERT ON evaluations BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_resume BEFORE UPDATE ON evaluation_state BEGIN SELECT RAISE(ABORT,'test'); END",
    ] {
        let t = Temp::new();
        populated(&t);
        let r = review(open(&t)).unwrap();
        let s = open(&t);
        let g = s.generation().unwrap();
        s.conn.execute_batch(sql).unwrap();
        assert!(matches!(resumed(s, r), Err(StorageError::Sql(_))));
        let s = open(&t);
        assert_eq!(
            s.generation().unwrap(),
            g + i64::from(!sql.contains("begin_explicit_local_resume"))
        );
        assert_eq!(resume_count(&s), 0);
        assert_eq!(
            s.conn
                .query_row("SELECT dirty FROM evaluation_state", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn file_or_epoch_change_before_commit_rolls_back_resume() {
    for change in ["blob", "staging", "record", "payload", "generation"] {
        let t = Temp::new();
        populated(&t);
        let r = review(open(&t)).unwrap();
        let s = open(&t);
        let result = s.resume_local_writes_inner(r, CONFIRM, EvaluationLimits::default(), |conn| {
            match change {
                "blob" => std::fs::write(path(&t), vec![b'x'; 14])?,
                "staging" => {
                    let p = t
                        .data()
                        .join("staging")
                        .join(format!("{}.part", blobs::hex(&id::blob_id(b"late").bytes)));
                    std::fs::write(&p, b"late")?;
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
                }
                "record" => {
                    conn.execute(
                        "UPDATE evaluation_state SET record_epoch=record_epoch+1",
                        [],
                    )?;
                }
                "payload" => {
                    conn.execute(
                        "UPDATE evaluation_state SET payload_epoch=payload_epoch+1",
                        [],
                    )?;
                }
                _ => {
                    conn.execute("UPDATE storage_state SET generation=generation+1", [])?;
                }
            }
            Ok(())
        });
        assert!(result.is_err());
        let s = open(&t);
        assert_eq!(resume_count(&s), 0);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}
#[test]
fn budget_capacity_and_confirmation_bounds_do_not_resume() {
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
        let r = review(open(&t)).unwrap();
        assert!(matches!(
            open(&t).resume_local_writes(r, CONFIRM, limits),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(resume_count(&open(&t)), 0);
    }
    let t = Temp::new();
    populated(&t);
    let r = review(open(&t)).unwrap();
    for note in [
        "".into(),
        " \n".into(),
        "x".repeat(4097),
        "bad\0note".into(),
    ] {
        assert!(matches!(
            open(&t).resume_local_writes(r, &note, EvaluationLimits::default()),
            Err(StorageError::InvalidRecoveryReview)
        ));
    }
    let mut s = open(&t);
    s.limits.reserve_min_bytes = u64::MAX;
    assert!(matches!(resumed(s, r), Err(StorageError::Capacity)));
    assert_eq!(resume_count(&open(&t)), 0);
}
#[test]
fn kill_before_or_after_resume_commit_never_marks_clean() {
    if let Some(p) = std::env::var_os("LNGNB_RESUME_KILL_CHILD") {
        let s = RecordStore::open(Path::new(&p), Limits::default()).unwrap();
        let g = s.generation().unwrap();
        let r = EvidenceRecoveryReview {
            recorded_generation: g,
            source_generation: g - 2,
            checked_evidence: 1,
        };
        let phase = std::env::var("LNGNB_RESUME_KILL_PHASE").unwrap();
        let wait = || {
            println!("LNGNB_RESUME_COMMIT_{phase}");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
        };
        let _writer = s
            .resume_local_writes_inner(r, CONFIRM, EvaluationLimits::default(), |_| {
                if phase == "before" {
                    wait();
                }
                Ok(())
            })
            .unwrap();
        if phase == "after" {
            wait();
        }
        panic!("killされる必要がある");
    }
    for phase in ["before", "after"] {
        let t = Temp::new();
        populated(&t);
        review(open(&t)).unwrap();
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::evaluation::recovery_review::local_resume_tests::kill_before_or_after_resume_commit_never_marks_clean","--nocapture"]).env("LNGNB_RESUME_KILL_CHILD",t.data()).env("LNGNB_RESUME_KILL_PHASE",phase).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains("LNGNB_RESUME_COMMIT_") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let s = open(&t);
        assert_eq!(resume_count(&s), i64::from(phase == "after"));
        assert_eq!(known(&s), 1);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn completed_startup_manifest_is_validated_again_before_resume() {
    let t = Temp::new();
    populated(&t);
    let mut inspection = RecordInspection::open(&t.data(), Limits::default()).unwrap();
    while !inspection
        .step(InspectionBudget::default())
        .unwrap()
        .checks_complete
    {}
    let s = inspection.into_store().unwrap();
    let r = review(s).unwrap();
    let w = resumed(open(&t), r).unwrap();
    w.finish().unwrap();
    // 壊れたmanifestを無関係な確認成功で迂回しない。
    let w = open(&t).begin().unwrap();
    drop(w);
    let r = review(open(&t)).unwrap();
    let s = open(&t);
    s.conn
        .execute(
            "UPDATE blob_inspection_inventory SET digest=zeroblob(32)",
            [],
        )
        .unwrap();
    assert!(matches!(resumed(s, r), Err(StorageError::Corrupt)));
    let c = Connection::open(t.data().join(DB)).unwrap();
    assert_eq!(state(&c).unwrap(), StartupState::NeedsReview);
}
#[test]
fn empty_storage_and_maximum_confirmation_are_supported_without_publication() {
    let t = Temp::new();
    let w = t.store().begin().unwrap();
    drop(w);
    let r = review(open(&t)).unwrap();
    assert_eq!(r.checked_evidence, 0);
    let note = "あ".repeat(1365) + "x";
    assert_eq!(note.len(), 4096);
    let w = open(&t)
        .resume_local_writes(r, &note, EvaluationLimits::default())
        .unwrap();
    let reason: String = w
        .store
        .conn
        .query_row(
            "SELECT reason FROM history ORDER BY generation DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let raw = data_encoding::HEXLOWER
        .decode(
            reason
                .strip_prefix("explicit_local_resume:")
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    let v = crate::cbor::decode(&raw).unwrap();
    assert!(format!("{v:?}").contains("local_storage_writes_only"));
    w.finish().unwrap();
    assert_eq!(open(&t).startup_state().unwrap(), StartupState::Clean);
}

#[test]
fn mixed_recovery_findings_and_scan_budgets_preserve_evidence_until_explicit_resume() {
    let t = Temp::new();
    let bad = rev(&[], 15, "mixed known bad");
    let child = rev(&[bad.id()], 14, "mixed descendant");
    let missing = id::blob_id(b"ordinary missing payload");
    let with_payload = |parents: &[Id], tag: &str| {
        let mut body = rev(parents, 24, tag).body().clone();
        let Value::Map(fields) = &mut body else {
            panic!()
        };
        let p = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1;
        set(p, "blob_id", Value::Bytes(missing.bytes.to_vec()));
        LocalRecord::sign(body, &key()).unwrap()
    };
    let ordinary = with_payload(&[], "ordinary unavailable");
    let ordinary_child = with_payload(&[ordinary.id()], "ordinary child");
    let retained = id::blob_id(b"independent retained");
    let mut w = t.store().begin().unwrap();
    let records = [
        fixture(),
        bad.clone(),
        child.clone(),
        ordinary.clone(),
        ordinary_child.clone(),
    ];
    for r in records.iter().rev() {
        w.insert(r).unwrap();
    }
    let original = super::super::tests::bytes();
    w.put_blob(id::blob_id(&original), Cursor::new(&original))
        .unwrap();
    w.put_blob(retained, Cursor::new(b"independent retained"))
        .unwrap();
    w.revalidate(EvaluationLimits::default()).unwrap();
    assert_eq!(known(&w.store), 1);
    drop(w);
    let retained_path = t.data().join("blobs").join(blobs::hex(&retained.bytes));
    std::fs::remove_file(path(&t)).unwrap();
    std::fs::write(&retained_path, b"corrupt").unwrap();
    let orphan = t
        .data()
        .join("blobs")
        .join(blobs::hex(&id::blob_id(b"orphan").bytes));
    let staging = t.data().join("staging").join(format!(
        "{}.part",
        blobs::hex(&id::blob_id(b"partial").bytes)
    ));
    for (p, b) in [
        (&orphan, b"orphan".as_slice()),
        (&staging, b"partial".as_slice()),
    ] {
        std::fs::write(p, b).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let s = open(&t);
    let snapshot = s.evaluate(EvaluationLimits::default()).unwrap();
    assert_state(
        &snapshot,
        &bad,
        Validation::Pending,
        Some(Reason::EvidenceUnavailable),
    );
    assert_eq!(
        snapshot
            .records
            .iter()
            .find(|r| r.record_id == child.id())
            .unwrap()
            .validation,
        Validation::Pending
    );
    for r in [&ordinary, &ordinary_child] {
        assert_state(&snapshot, r, Validation::Valid, None);
        assert_eq!(
            snapshot
                .records
                .iter()
                .find(|a| a.record_id == r.id())
                .unwrap()
                .payload_status,
            Some(PayloadStatus::Missing)
        );
    }
    assert!(matches!(review(s), Err(StorageError::Corrupt)));
    assert_eq!(resume_count(&open(&t)), 0);
    assert_eq!(known(&open(&t)), 1);
    // 真正根拠だけを復元しても、他の保存障害や未登録実体は解消したことにならない。
    std::fs::write(path(&t), &original).unwrap();
    std::fs::set_permissions(path(&t), std::fs::Permissions::from_mode(0o600)).unwrap();
    let r = review(open(&t)).unwrap();
    assert!(matches!(
        resumed(open(&t), r),
        Err(StorageError::NeedsReview)
    ));
    assert_eq!(std::fs::read(&orphan).unwrap(), b"orphan");
    assert_eq!(std::fs::read(&staging).unwrap(), b"partial");
    assert_eq!(resume_count(&open(&t)), 0);
    // 明示的な試験側操作で実体を修復し、未登録/途中実体を保存領域外へ退避する。
    std::fs::write(&retained_path, b"independent retained").unwrap();
    std::fs::rename(&orphan, t.root.join("orphan-preserved")).unwrap();
    std::fs::rename(&staging, t.root.join("staging-preserved")).unwrap();
    let s = open(&t);
    assert!(s.blob_recovery().missing.is_empty() && s.blob_recovery().corrupt.is_empty());
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    let r = review(s).unwrap();
    let mut s = open(&t);
    // open時の上限は十分でも、再開時の全走査を別に予算不足にする。
    s.limits.scan_blob_bytes = 1;
    assert!(matches!(resumed(s, r), Err(StorageError::BudgetExceeded)));
    let s = open(&t);
    assert_eq!(resume_count(&s), 0);
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(known(&s), 1);
    assert!(matches!(
        resumed(s, r),
        Err(StorageError::StaleRecoveryReview)
    ));
    let r = review(open(&t)).unwrap();
    let mut limited = open(&t);
    limited.limits.scan_blob_files = 1;
    assert!(matches!(
        resumed(limited, r),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(resume_count(&open(&t)), 0);
    assert_eq!(known(&open(&t)), 1);
    let r = review(open(&t)).unwrap();
    assert!(matches!(
        open(&t).resume_local_writes(
            r,
            CONFIRM,
            EvaluationLimits {
                blob_bytes: 13,
                ..EvaluationLimits::default()
            }
        ),
        Err(StorageError::BudgetExceeded)
    ));
    let r = review(open(&t)).unwrap();
    let w = resumed(open(&t), r).unwrap();
    let snapshot = w.store.evaluate(EvaluationLimits::default()).unwrap();
    assert_state(
        &snapshot,
        &bad,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    assert_state(
        &snapshot,
        &child,
        Validation::Invalid,
        Some(Reason::InvalidParent),
    );
    for r in [&ordinary, &ordinary_child] {
        assert_state(&snapshot, r, Validation::Valid, None);
        assert_eq!(
            snapshot
                .records
                .iter()
                .find(|a| a.record_id == r.id())
                .unwrap()
                .payload_status,
            Some(PayloadStatus::Missing)
        );
    }
    assert_eq!(known(&w.store), 1);
    for r in records {
        assert_eq!(w.store.record(r.id()).unwrap().unwrap().bytes(), r.bytes());
    }
    assert_eq!(
        std::fs::read(t.root.join("orphan-preserved")).unwrap(),
        b"orphan"
    );
    assert_eq!(
        std::fs::read(t.root.join("staging-preserved")).unwrap(),
        b"partial"
    );
    w.finish().unwrap();
    assert_eq!(open(&t).startup_state().unwrap(), StartupState::Clean);
}
