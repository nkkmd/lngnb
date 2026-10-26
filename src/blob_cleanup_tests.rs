//! R23/R24/R26/R27/R28/R30、A8.4: 削除予定・保持競合。公開試験鍵のみ、実運用禁止。
use super::*;
use crate::{
    id,
    storage::{
        evaluation::tests::{bytes, rev},
        tests::{Temp, fixture},
    },
};
use std::{
    io::{BufRead, Cursor, Read, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
fn stage(w: &mut RecordWriter) -> TemporaryBlob {
    w.stage_blob(
        id::blob_id(&bytes()),
        Cursor::new(bytes()),
        1,
        TemporaryLimits::default(),
    )
    .unwrap()
}
// 睡眠と実時計変更を避け、内部の検査時点だけを期限と一致させる。
fn plan(w: &mut RecordWriter, t: TemporaryBlob) -> BlobCleanupPlan {
    match w
        .plan_at(t.id, CleanupBudget::default(), t.expires_at, |_, _| Ok(()))
        .unwrap()
    {
        CleanupDecision::Planned(p) => p,
        _ => panic!("eligible temporary blob"),
    }
}
fn path(t: &Temp) -> std::path::PathBuf {
    t.data()
        .join("blobs")
        .join(blobs::hex(&id::blob_id(&bytes()).bytes))
}
fn count(s: &RecordStore, table: &str) -> i64 {
    s.conn
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
#[test]
fn boundary_deadline_and_repeated_planning_preserve_body_and_all_promises() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w);
    assert_eq!(
        w.plan_at(a.id, CleanupBudget::default(), a.expires_at - 1, |_, _| Ok(
            ()
        ))
        .unwrap(),
        CleanupDecision::Protected
    );
    let p = plan(&mut w, a);
    assert_eq!(p.byte_length, 14);
    assert_eq!(p.planned_at, a.expires_at);
    assert!(p.cancelled_generation.is_none());
    let g = w.store.generation().unwrap();
    assert_eq!(plan(&mut w, a), p);
    assert_eq!(w.store.generation().unwrap(), g);
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    assert_eq!(count(&w.store, "temporary_blob_holds"), 1);
    w.finish().unwrap();
    let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(s.blob_cleanup_plans(1).unwrap(), vec![p]);
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
}
#[test]
fn every_live_shared_promise_prevents_planning_and_shorter_repost_cannot_cut_it() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w);
    let b = w
        .stage_blob(
            a.id,
            Cursor::new(bytes()),
            86400,
            TemporaryLimits::default(),
        )
        .unwrap();
    assert_eq!(
        w.plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
            .unwrap(),
        CleanupDecision::Protected
    );
    assert_eq!(count(&w.store, "blob_cleanup_plans"), 0);
    plan(&mut w, b);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 2);
    w.finish().unwrap();
}
#[test]
fn record_arrival_cancels_pending_plan_in_the_same_transaction() {
    for pending in [false, true] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        let p = if pending { Some(plan(&mut w, a)) } else { None };
        let r = rev(&[], 14, "reference");
        w.insert(&r).unwrap();
        assert_eq!(
            w.plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
                .unwrap(),
            CleanupDecision::Protected
        );
        let ps = w.store.blob_cleanup_plans(10).unwrap();
        if let Some(p) = p {
            assert_eq!(ps.len(), 1);
            assert_eq!(ps[0].plan_id, p.plan_id);
            assert_eq!(ps[0].cancellation.as_deref(), Some("record_reference"));
            assert!(ps[0].cancelled_generation.unwrap() > p.planned_generation);
        } else {
            assert!(ps.is_empty());
        }
        assert_eq!(w.store.record(r.id()).unwrap().unwrap().bytes(), r.bytes());
        w.finish().unwrap();
    }
}
#[test]
fn manual_retention_and_new_temporary_promise_cancel_only_their_target() {
    for manual in [true, false] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        let p = plan(&mut w, a);
        let other = id::blob_id(b"other");
        let b = w
            .stage_blob(other, Cursor::new(b"other"), 1, TemporaryLimits::default())
            .unwrap();
        let q = plan(&mut w, b);
        if manual {
            w.put_blob(a.id, Cursor::new(bytes())).unwrap();
        } else {
            stage(&mut w);
        }
        let ps = w.store.blob_cleanup_plans(2).unwrap();
        let p = ps.iter().find(|r| r.plan_id == p.plan_id).unwrap();
        assert_eq!(
            p.cancellation.as_deref(),
            Some(if manual {
                "manual_retention"
            } else {
                "temporary_promise"
            })
        );
        assert!(
            ps.iter()
                .find(|r| r.plan_id == q.plan_id)
                .unwrap()
                .cancelled_generation
                .is_none()
        );
        assert_eq!(
            count(&w.store, "temporary_blob_holds"),
            if manual { 2 } else { 3 }
        );
        w.finish().unwrap();
    }
}
#[test]
fn metadata_only_pending_wrong_key_and_known_invalid_references_are_protected() {
    for mode in 0..3 {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        let p = plan(&mut w, a);
        let r = if mode == 0 {
            rev(
                &[Id {
                    kind: Kind::Record,
                    bytes: [42; 32],
                }],
                14,
                "pending",
            )
        } else if mode == 1 {
            LocalRecord::sign(
                rev(&[], 14, "wrong key").body().clone(),
                &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
            )
            .unwrap()
        } else {
            rev(&[], 15, "bad length")
        };
        w.insert(&fixture()).unwrap();
        w.insert(&r).unwrap();
        w.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(
            w.plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
                .unwrap(),
            CleanupDecision::Protected
        );
        let ps = w.store.blob_cleanup_plans(1).unwrap();
        assert_eq!(ps[0].plan_id, p.plan_id);
        assert_eq!(ps[0].cancellation.as_deref(), Some("record_reference"));
        if mode == 2 {
            assert_eq!(count(&w.store, "known_invalid"), 1);
        }
        w.finish().unwrap();
    }
}
#[test]
fn unregistered_or_missing_reference_is_never_adopted_from_an_orphan() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let id = id::blob_id(&bytes());
    std::fs::write(path(&t), bytes()).unwrap();
    std::fs::set_permissions(path(&t), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        w.plan_blob_cleanup(id, CleanupBudget::default()).unwrap(),
        CleanupDecision::Unregistered
    );
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    assert_eq!(count(&w.store, "blobs"), 0);
    w.insert(&rev(&[], 14, "no body ledger")).unwrap();
    assert_eq!(
        w.plan_blob_cleanup(id, CleanupBudget::default()).unwrap(),
        CleanupDecision::Unregistered
    );
    assert_eq!(count(&w.store, "blob_cleanup_plans"), 0);
}
#[test]
fn missing_corrupt_or_replaced_candidate_never_gets_a_successful_plan() {
    for damage in 0..3 {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        if damage == 0 {
            std::fs::remove_file(path(&t)).unwrap();
        } else if damage == 1 {
            std::fs::write(path(&t), b"broken").unwrap();
        }
        let result = w.plan_at(
            a.id,
            CleanupBudget::default(),
            a.expires_at,
            |point, _conn| {
                if point == Point::BeforeCommit && damage == 2 {
                    std::fs::write(path(&t), b"changed").unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(count(&w.store, "blob_cleanup_plans"), 0);
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    }
}
#[test]
fn plan_budget_time_hash_capacity_and_clock_reject_without_partial_progress() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w);
    let g = w.store.generation().unwrap();
    for b in [
        CleanupBudget {
            plans: 0,
            ..CleanupBudget::default()
        },
        CleanupBudget {
            hash_bytes: 13,
            ..CleanupBudget::default()
        },
        CleanupBudget {
            protection: ProtectionBudget {
                elapsed: std::time::Duration::ZERO,
                ..ProtectionBudget::default()
            },
            ..CleanupBudget::default()
        },
        CleanupBudget {
            protection: ProtectionBudget {
                temporary_holds: 0,
                ..ProtectionBudget::default()
            },
            ..CleanupBudget::default()
        },
    ] {
        assert!(matches!(
            w.plan_at(a.id, b, a.expires_at, |_, _| Ok(())),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(w.store.generation().unwrap(), g);
    }
    assert!(matches!(
        w.plan_at(a.id, CleanupBudget::default(), a.created_at - 1, |_, _| Ok(
            ()
        )),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(matches!(
        w.plan_at(
            fixture().id(),
            CleanupBudget::default(),
            a.expires_at,
            |_, _| Ok(())
        ),
        Err(StorageError::InvalidBlobId)
    ));
    w.store.limits.reserve_min_bytes = u64::MAX;
    assert!(matches!(
        w.plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(())),
        Err(StorageError::Capacity)
    ));
    w.store.limits.reserve_min_bytes = 64 * 1024 * 1024;
    let p = plan(&mut w, a);
    assert!(w.store.blob_cleanup_plans(0).is_err());
    assert_eq!(w.store.blob_cleanup_plans(1).unwrap(), vec![p]);
    w.finish().unwrap();
}
#[test]
fn plan_insert_and_history_failures_roll_back_generation_without_removing_bytes() {
    for table in ["blob_cleanup_plans", "history"] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        let g = w.store.generation().unwrap();
        w.store.conn.execute_batch(&format!("CREATE TRIGGER reject_plan BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(
            w.plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
                .is_err()
        );
        assert_eq!(count(&w.store, "blob_cleanup_plans"), 0);
        assert_eq!(w.store.generation().unwrap(), g);
        assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    }
}
#[test]
fn record_and_both_retention_changes_roll_back_if_plan_cancellation_cannot_persist() {
    for operation in 0..3 {
        for reject_history in [false, true] {
            let t = Temp::new();
            let mut w = t.store().begin().unwrap();
            let a = stage(&mut w);
            let p = plan(&mut w, a);
            let g = w.store.generation().unwrap();
            w.store.conn.execute_batch(if reject_history {"CREATE TRIGGER refuse_cancel_audit BEFORE INSERT ON history WHEN NEW.new_state='blob_cleanup_cancelled_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;"}else{"CREATE TRIGGER refuse_cancel BEFORE UPDATE ON blob_cleanup_plans BEGIN SELECT RAISE(ABORT,'test'); END;"}).unwrap();
            let r = rev(&[], 14, "racing reference");
            let result = match operation {
                0 => w.insert(&r).map(|_| ()),
                1 => w.put_blob(a.id, Cursor::new(bytes())).map(|_| ()),
                _ => w
                    .stage_blob(a.id, Cursor::new(bytes()), 1, TemporaryLimits::default())
                    .map(|_| ()),
            };
            assert!(result.is_err());
            assert_eq!(w.store.generation().unwrap(), g);
            assert!(w.store.record(r.id()).unwrap().is_none());
            assert_eq!(count(&w.store, "manual_blob_holds"), 0);
            assert_eq!(count(&w.store, "temporary_blob_holds"), 1);
            assert_eq!(w.store.blob_cleanup_plans(1).unwrap(), vec![p]);
            assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
        }
    }
}
#[test]
fn begin_immediate_excludes_another_database_writer_until_plan_is_committed() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w);
    w.plan_at(
        a.id,
        CleanupBudget::default(),
        a.expires_at,
        |point, _conn| {
            if point == Point::BeforeCommit {
                let other = Connection::open(t.data().join(DB))?;
                other.busy_timeout(std::time::Duration::ZERO)?;
                assert!(
                    other
                        .execute(
                            "UPDATE evaluation_state SET record_epoch=record_epoch+1",
                            []
                        )
                        .is_err()
                );
            }
            Ok(())
        },
    )
    .unwrap();
    w.finish().unwrap();
}
#[test]
fn same_connection_input_change_after_collection_never_commits_a_stale_plan() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let a = stage(&mut w);
    let result = w.plan_at(
        a.id,
        CleanupBudget::default(),
        a.expires_at,
        |point, _conn| {
            if point == Point::BeforeCommit {
                return Err(StorageError::ProtectionChanged);
            }
            Ok(())
        },
    );
    assert!(matches!(result, Err(StorageError::ProtectionChanged)));
    assert_eq!(count(&w.store, "blob_cleanup_plans"), 0);
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
}
#[test]
fn corrupted_or_lost_plan_history_never_becomes_a_fresh_plan_on_reopen() {
    for sql in [
        "DROP TRIGGER cleanup_only_cancel; UPDATE blob_cleanup_plans SET planned_at=planned_at+1",
        "UPDATE history SET reason='lost' WHERE new_state='blob_cleanup_planned_local_only'",
        "DROP TRIGGER cleanup_no_delete; DELETE FROM blob_cleanup_plans",
    ] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        plan(&mut w, a);
        w.finish().unwrap();
        let c = Connection::open(t.data().join(DB)).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        let before = std::fs::read(t.data().join(DB)).unwrap();
        assert!(matches!(
            RecordStore::open(&t.data(), Limits::default()),
            Err(StorageError::Corrupt)
        ));
        assert_eq!(std::fs::read(t.data().join(DB)).unwrap(), before);
    }
}
#[test]
fn schema_nine_is_rejected_without_migration_or_reinitialization() {
    let t = Temp::new();
    drop(t.store());
    let c = Connection::open(t.data().join(DB)).unwrap();
    c.pragma_update(None, "user_version", 9).unwrap();
    drop(c);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(std::fs::read(t.data().join(DB)).unwrap(), before);
}
#[test]
fn interruption_before_or_after_plan_commit_preserves_only_confirmed_history() {
    if let Some(dir) = std::env::var_os("LNGNB_CLEANUP_KILL") {
        let mut w = RecordStore::open(Path::new(&dir), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        let a = stage(&mut w);
        let at = std::env::var("LNGNB_CLEANUP_POINT").unwrap();
        w.plan_at(
            a.id,
            CleanupBudget::default(),
            a.expires_at,
            |point, _conn| {
                if (at == "before" && point == Point::BeforeCommit)
                    || (at == "after" && point == Point::AfterCommit)
                {
                    println!("LNGNB_CLEANUP_READY");
                    std::io::stdout().flush()?;
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                }
                Ok(())
            },
        )
        .unwrap();
        panic!("must be killed");
    }
    for at in ["before", "after"] {
        let t = Temp::new();
        drop(t.store());
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::cleanup::tests::interruption_before_or_after_plan_commit_preserves_only_confirmed_history","--nocapture"]).env("LNGNB_CLEANUP_KILL",t.data()).env("LNGNB_CLEANUP_POINT",at).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains("LNGNB_CLEANUP_READY") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(
            count(&s, "blob_cleanup_plans"),
            if at == "after" { 1 } else { 0 }
        );
        let mut body = Vec::new();
        s.blob(id::blob_id(&bytes()))
            .unwrap()
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, bytes());
        assert_eq!(count(&s, "temporary_blob_holds"), 1);
    }
}

#[test]
fn retention_change_after_collection_cannot_certify_an_old_plan() {
    for manual in [true, false] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        let result = w.plan_at(
            a.id,
            CleanupBudget::default(),
            a.expires_at,
            |point, conn| {
                if point == Point::BeforeCommit {
                    if manual {
                        conn.execute(
                            "INSERT INTO manual_blob_holds(blob_id) VALUES(?1)",
                            [&a.id.bytes],
                        )?;
                    } else {
                        conn.execute(
                            "UPDATE storage_state SET generation=generation+1 WHERE singleton=1",
                            [],
                        )?;
                    }
                }
                Ok(())
            },
        );
        // 入力世代の変更も実体保持の変更も、最終確認で拒否する。
        assert!(result.is_err());
        assert_eq!(count(&w.store, "blob_cleanup_plans"), 0);
        assert_eq!(count(&w.store, "manual_blob_holds"), 0);
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    }
}
#[test]
fn cancelling_before_or_after_commit_keeps_reference_and_plan_state_atomic_on_kill() {
    if let Some(dir) = std::env::var_os("LNGNB_CANCEL_KILL") {
        let mut w = RecordStore::open(Path::new(&dir), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        let a = stage(&mut w);
        plan(&mut w, a);
        w.cleanup_cancel_pause = Some(std::env::var("LNGNB_CANCEL_WHEN").unwrap() == "before");
        match std::env::var("LNGNB_CANCEL_OPERATION").unwrap().as_str() {
            "record" => {
                w.insert(&rev(&[], 14, "kill reference")).unwrap();
            }
            "manual" => {
                w.put_blob(a.id, Cursor::new(bytes())).unwrap();
            }
            _ => {
                stage(&mut w);
            }
        }
        panic!("must be killed");
    }
    for operation in ["record", "manual", "temporary"] {
        for when in ["before", "after"] {
            let t = Temp::new();
            drop(t.store());
            let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::cleanup::tests::cancelling_before_or_after_commit_keeps_reference_and_plan_state_atomic_on_kill","--nocapture"]).env("LNGNB_CANCEL_KILL",t.data()).env("LNGNB_CANCEL_WHEN",when).env("LNGNB_CANCEL_OPERATION",operation).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line.contains("LNGNB_CANCEL_READY") {
                    break;
                }
            }
            child.kill().unwrap();
            child.wait().unwrap();
            let s = RecordStore::open(&t.data(), Limits::default()).unwrap();
            assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
            let committed = when == "after";
            let p = s.blob_cleanup_plans(1).unwrap().remove(0);
            assert_eq!(p.cancelled_generation.is_some(), committed);
            assert_eq!(
                count(&s, "records"),
                if committed && operation == "record" {
                    1
                } else {
                    0
                }
            );
            assert_eq!(
                count(&s, "manual_blob_holds"),
                if committed && operation == "manual" {
                    1
                } else {
                    0
                }
            );
            assert_eq!(
                count(&s, "temporary_blob_holds"),
                if committed && operation == "temporary" {
                    2
                } else {
                    1
                }
            );
            assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
        }
    }
}

#[test]
fn cancellation_history_cannot_be_lost_or_reopened_as_a_live_plan() {
    for sql in [
        "UPDATE history SET reason='lost' WHERE new_state='blob_cleanup_cancelled_local_only'",
        "DROP TRIGGER cleanup_only_cancel; UPDATE blob_cleanup_plans SET cancelled_generation=NULL,cancellation=NULL",
        "DROP TRIGGER cleanup_only_cancel; UPDATE blob_cleanup_plans SET planned_generation=planned_generation-1",
    ] {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let a = stage(&mut w);
        plan(&mut w, a);
        w.insert(&rev(&[], 14, "saved reference")).unwrap();
        w.finish().unwrap();
        let c = Connection::open(t.data().join(DB)).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        assert!(matches!(
            RecordStore::open(&t.data(), Limits::default()),
            Err(StorageError::Corrupt)
        ));
        assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    }
}
