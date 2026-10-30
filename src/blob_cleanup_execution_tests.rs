//! R23/R24/R26/R27/R30: 内部物理整理・明示復旧。公開試験鍵のみ、実運用への流用禁止。
use super::*;
use crate::{
    id,
    storage::{
        evaluation::tests::{assert_oracle, bytes, oracle_case, rev},
        tests::{Temp, fixture},
    },
};
use std::{
    io::{BufRead, Cursor, Write},
    process::{Command, Stdio},
};
fn setup(t: &Temp) -> (RecordWriter, BlobCleanupPlan) {
    let mut w = t.store().begin().unwrap();
    let a = w
        .stage_blob(
            id::blob_id(&bytes()),
            Cursor::new(bytes()),
            1,
            TemporaryLimits::default(),
        )
        .unwrap();
    let CleanupDecision::Planned(p) = w
        .plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
        .unwrap()
    else {
        panic!()
    };
    (w, p)
}
fn execute(w: &mut RecordWriter, p: &BlobCleanupPlan) -> CleanupExecution {
    w.execute_at(p.plan_id, CleanupBudget::default(), p.planned_at, |_, _| {
        Ok(())
    })
    .unwrap()
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
fn reopen(t: &Temp) -> RecordStore {
    RecordStore::open(&t.data(), Limits::default()).unwrap()
}
fn recover(s: &mut RecordStore, r: &CleanupExecution, p: &BlobCleanupPlan) -> CleanupExecution {
    s.recover_at(
        r.run_id,
        CleanupBudget::default(),
        "保存済み削除意思と現在の根拠を確認し、この整理だけを完了",
        p.planned_at,
        |_, _| Ok(()),
    )
    .unwrap()
}
#[test]
fn expired_unreferenced_blob_is_removed_but_objects_promises_and_history_remain() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    let result = execute(&mut w, &p);
    assert_eq!(result.outcome, Some(CleanupOutcome::Removed));
    assert!(result.finished_generation.is_some());
    assert!(!path(&t).exists());
    assert_eq!(count(&w.store, "blobs"), 0);
    assert_eq!(count(&w.store, "blob_objects"), 1);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 1);
    assert!(w.blob(p.blob_id).unwrap().is_none());
    let ps = w.store.blob_cleanup_plans(1).unwrap();
    assert_eq!(ps[0].completed_generation, result.finished_generation);
    assert!(ps[0].cancelled_generation.is_none());
    let b = w.blob_protection(ProtectionBudget::default()).unwrap();
    assert_eq!(b.blobs[0].recorded_length, None);
    assert_eq!(b.blobs[0].temporary_holds.len(), 1);
    w.finish().unwrap();
    let s = reopen(&t);
    assert_eq!(s.startup_state().unwrap(), StartupState::Clean);
    assert!(!s.blob_recovery().needs_review());
    assert_eq!(s.blob_cleanup_executions(1).unwrap(), vec![result]);
    drop(s);
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
    let mut w = startup.into_writer().unwrap();
    assert!(w.blob(p.blob_id).unwrap().is_none());
    w.finish().unwrap();
}
#[test]
fn later_record_sees_missing_body_and_reupload_restores_the_same_id() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    execute(&mut w, &p);
    let r = rev(&[], 14, "after cleanup");
    w.insert(&fixture()).unwrap();
    w.insert(&r).unwrap();
    let s = w.revalidate(EvaluationLimits::default()).unwrap();
    let a = s.records.iter().find(|x| x.record_id == r.id()).unwrap();
    assert_eq!(a.payload_status, Some(PayloadStatus::Missing));
    assert_eq!(a.validation, Validation::Valid);
    let records = [fixture(), r.clone()];
    let mut cases = vec![(oracle_case(&records, false), s)];
    w.put_blob(p.blob_id, Cursor::new(bytes())).unwrap();
    let s = w.revalidate(EvaluationLimits::default()).unwrap();
    let a = s.records.iter().find(|x| x.record_id == r.id()).unwrap();
    assert_eq!(a.payload_status, Some(PayloadStatus::Verified));
    cases.push((oracle_case(&records, true), s));
    assert_oracle(&cases);
    assert_eq!(count(&w.store, "blob_objects"), 1);
    assert_eq!(count(&w.store, "blobs"), 1);
    assert_eq!(
        w.store.blob_cleanup_executions(1).unwrap()[0].outcome,
        Some(CleanupOutcome::Removed)
    );
    w.finish().unwrap();
}
#[test]
fn cancelled_plan_and_new_references_or_promises_are_never_executed() {
    for op in 0..3 {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        match op {
            0 => {
                w.insert(&rev(&[], 14, "protected")).unwrap();
            }
            1 => {
                w.put_blob(p.blob_id, Cursor::new(bytes())).unwrap();
            }
            _ => {
                w.stage_blob(
                    p.blob_id,
                    Cursor::new(bytes()),
                    1,
                    TemporaryLimits::default(),
                )
                .unwrap();
            }
        }
        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |_, _| Ok(())
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
        assert_eq!(count(&w.store, "blob_cleanup_runs"), 0);
    }
}
#[test]
fn fresh_checks_detect_missing_corruption_and_file_change_before_intent() {
    for damage in 0..3 {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        if damage == 0 {
            std::fs::remove_file(path(&t)).unwrap();
        } else if damage == 1 {
            std::fs::write(path(&t), b"bad").unwrap();
        }
        let e = w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |point, _| {
                if point == Point::BeforeIntentCommit && damage == 2 {
                    std::fs::write(path(&t), b"changed").unwrap();
                }
                Ok(())
            },
        );
        assert!(e.is_err());
        assert_eq!(count(&w.store, "blob_cleanup_runs"), 0);
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    }
}
#[test]
fn budget_clock_and_capacity_before_intent_leave_no_partial_execution() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    let generation = w.store.generation().unwrap();
    for b in [
        CleanupBudget {
            hash_bytes: 27,
            ..CleanupBudget::default()
        },
        CleanupBudget {
            hash_bytes: 14,
            ..CleanupBudget::default()
        },
        CleanupBudget {
            hash_bytes: 13,
            ..CleanupBudget::default()
        },
        CleanupBudget {
            plans: 0,
            ..CleanupBudget::default()
        },
        CleanupBudget {
            protection: ProtectionBudget {
                elapsed: std::time::Duration::ZERO,
                ..ProtectionBudget::default()
            },
            ..CleanupBudget::default()
        },
    ] {
        assert!(matches!(
            w.execute_at(p.plan_id, b, p.planned_at, |_, _| Ok(())),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(w.store.generation().unwrap(), generation);
    }
    assert!(matches!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at - 1,
            |_, _| Ok(())
        ),
        Err(StorageError::BudgetExceeded)
    ));
    w.store.limits.reserve_min_bytes = u64::MAX;
    assert!(matches!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |_, _| Ok(())
        ),
        Err(StorageError::Capacity)
    ));
    w.store.limits.reserve_min_bytes = 64 * 1024 * 1024;
    execute(&mut w, &p);
    w.finish().unwrap();
}
#[test]
fn intent_sql_failure_rolls_back_before_any_unlink() {
    for table in ["blob_cleanup_runs", "history"] {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        let generation = w.store.generation().unwrap();
        w.store.conn.execute_batch(&format!("CREATE TRIGGER refuse_start BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'test'); END;")).unwrap();
        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |_, _| Ok(())
            )
            .is_err()
        );
        assert_eq!(count(&w.store, "blob_cleanup_runs"), 0);
        assert_eq!(w.store.generation().unwrap(), generation);
        assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    }
}
#[test]
fn completion_sql_failure_keeps_intent_and_requires_explicit_recovery() {
    for sql in [
        "CREATE TRIGGER refuse_finish BEFORE DELETE ON blobs BEGIN SELECT RAISE(ABORT,'test'); END;",
        "CREATE TRIGGER refuse_finish BEFORE UPDATE ON blob_cleanup_plans BEGIN SELECT RAISE(ABORT,'test'); END;",
        "CREATE TRIGGER refuse_finish BEFORE UPDATE ON blob_cleanup_runs BEGIN SELECT RAISE(ABORT,'test'); END;",
        "CREATE TRIGGER refuse_finish BEFORE INSERT ON history WHEN NEW.new_state='blob_cleanup_completed_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;",
    ] {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        w.store.conn.execute_batch(sql).unwrap();
        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |_, _| Ok(())
            )
            .is_err()
        );
        assert!(!path(&t).exists());
        assert_eq!(count(&w.store, "blobs"), 1);
        let r = w.store.blob_cleanup_executions(1).unwrap().remove(0);
        assert!(r.finished_generation.is_none());
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
        let c = Connection::open(t.data().join(DB)).unwrap();
        c.execute_batch("DROP TRIGGER refuse_finish;").unwrap();
        drop(c);
        let mut s = reopen(&t);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        let done = recover(&mut s, &r, &p);
        assert_eq!(done.outcome, Some(CleanupOutcome::RecoveryAbsent));
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert!(!s.blob_recovery().needs_review());
    }
}
#[test]
fn each_io_failure_point_preserves_a_recoverable_intent_or_completed_result() {
    for point in [
        Point::AfterIntentCommit,
        Point::BeforeUnlink,
        Point::AfterUnlink,
        Point::AfterDirectorySync,
        Point::BeforeFinishCommit,
        Point::AfterFinishCommit,
    ] {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        if point == Point::AfterUnlink {
            w.finish().unwrap();
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
            w = startup.into_writer().unwrap();
        }

        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |at, _| {
                    if at == point {
                        Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
        let mut s = reopen(&t);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        let r = s.blob_cleanup_executions(1).unwrap().remove(0);
        if point == Point::AfterFinishCommit {
            assert_eq!(r.outcome, Some(CleanupOutcome::Removed));
            assert_eq!(count(&s, "blobs"), 0);
        } else {
            assert!(r.finished_generation.is_none());
            let before = path(&t).exists();
            let done = recover(&mut s, &r, &p);
            assert_eq!(
                done.outcome,
                Some(if before {
                    CleanupOutcome::RecoveryRemoved
                } else {
                    CleanupOutcome::RecoveryAbsent
                })
            );
        }
        assert!(!path(&t).exists());
        assert_eq!(count(&s, "temporary_blob_holds"), 1);
    }
}
#[test]
fn protection_added_after_intent_prevents_unlink_and_completion() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    let r = rev(&[], 14, "racing reference");
    assert!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |at, c| {
                if at == Point::AfterIntentCommit {
                    c.execute(
                        "INSERT INTO records(id,bytes) VALUES(?1,?2)",
                        params![&r.id().bytes, r.bytes()],
                    )?;
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    let run = w.store.blob_cleanup_executions(1).unwrap().remove(0);
    assert!(run.finished_generation.is_none());
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    let mut s = reopen(&t);
    assert!(matches!(
        s.recover_at(
            run.run_id,
            CleanupBudget::default(),
            "新たな根拠も再検査",
            p.planned_at,
            |_, _| Ok(())
        ),
        Err(StorageError::ProtectionChanged)
    ));
    assert!(path(&t).exists());
}
#[test]
fn normal_writer_resume_is_blocked_while_cleanup_is_pending() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    assert!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |at, _| {
                if at == Point::AfterIntentCommit {
                    Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
                } else {
                    Ok(())
                }
            }
        )
        .is_err()
    );
    drop(w);
    let s = reopen(&t);
    assert!(matches!(s.begin(), Err(StorageError::NeedsReview)));
    let s = reopen(&t);
    let generation = s.generation().unwrap();
    let review = s
        .confirm_evidence_recovery(
            generation,
            "根拠確認",
            "未完了の整理あり",
            EvaluationLimits::default(),
        )
        .unwrap();
    let s = reopen(&t);
    assert!(matches!(
        s.resume_local_writes(review, "整理を飛ばさない", EvaluationLimits::default()),
        Err(StorageError::CleanupPending)
    ));
}
#[test]
fn corrupted_or_lost_execution_proof_is_rejected_instead_of_authorizing_absence() {
    for sql in [
        "UPDATE history SET reason='lost' WHERE new_state='blob_cleanup_started_local_only'",
        "DROP TRIGGER cleanup_run_no_delete; DELETE FROM blob_cleanup_runs;",
    ] {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |at, _| {
                    if at == Point::AfterUnlink {
                        Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        drop(w);
        let c = Connection::open(t.data().join(DB)).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        assert!(matches!(
            RecordStore::open(&t.data(), Limits::default()),
            Err(StorageError::Corrupt)
        ));
    }
}
#[test]
fn schema_ten_is_preserved_without_automatic_migration() {
    let t = Temp::new();
    drop(t.store());
    let c = Connection::open(t.data().join(DB)).unwrap();
    c.pragma_update(None, "user_version", 10).unwrap();
    drop(c);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        RecordStore::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(std::fs::read(t.data().join(DB)).unwrap(), before);
}
#[test]
fn process_kill_at_each_execution_boundary_requires_manual_recovery() {
    if let Some(dir) = std::env::var_os("LNGNB_EXECUTION_KILL") {
        let mut w = RecordStore::open(Path::new(&dir), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        let a = w
            .stage_blob(
                id::blob_id(&bytes()),
                Cursor::new(bytes()),
                1,
                TemporaryLimits::default(),
            )
            .unwrap();
        let CleanupDecision::Planned(p) = w
            .plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
            .unwrap()
        else {
            panic!()
        };
        let point: usize = std::env::var("LNGNB_EXECUTION_POINT")
            .unwrap()
            .parse()
            .unwrap();
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |at, _| {
                if at as usize == point {
                    println!("LNGNB_EXECUTION_READY");
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
    for point in 0..7 {
        let t = Temp::new();
        drop(t.store());
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::cleanup::execution::tests::process_kill_at_each_execution_boundary_requires_manual_recovery","--nocapture"]).env("LNGNB_EXECUTION_KILL",t.data()).env("LNGNB_EXECUTION_POINT",point.to_string()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains("LNGNB_EXECUTION_READY") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let mut s = reopen(&t);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        let runs = s.blob_cleanup_executions(1).unwrap();
        if point == 0 {
            assert!(runs.is_empty());
            assert!(path(&t).exists());
        } else if point == 6 {
            assert!(runs[0].finished_generation.is_some());
            assert!(!path(&t).exists());
        } else {
            let p = s.blob_cleanup_plans(1).unwrap().remove(0);
            recover(&mut s, &runs[0], &p);
            assert!(!path(&t).exists());
            assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        }
    }
}

#[test]
fn a_reference_added_at_the_last_preunlink_boundary_preserves_the_file() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    let r = rev(&[], 14, "last moment reference");
    assert!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |at, c| {
                if at == Point::BeforeUnlink {
                    c.execute(
                        "INSERT INTO records(id,bytes) VALUES(?1,?2)",
                        params![&r.id().bytes, r.bytes()],
                    )?;
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    assert_eq!(count(&w.store, "records"), 0);
    assert!(
        w.store.blob_cleanup_executions(1).unwrap()[0]
            .finished_generation
            .is_none()
    );
}
#[test]
fn reappearance_before_completion_cannot_be_reported_as_finished_removal() {
    use std::os::unix::fs::PermissionsExt;
    for point in [Point::AfterUnlink, Point::BeforeFinishCommit] {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |at, _| {
                    if at == point {
                        std::fs::write(path(&t), bytes())?;
                        std::fs::set_permissions(path(&t), std::fs::Permissions::from_mode(0o600))?;
                    }
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(path(&t).exists());
        let r = w.store.blob_cleanup_executions(1).unwrap().remove(0);
        assert!(r.finished_generation.is_none());
        drop(w);
        let mut s = reopen(&t);
        let done = recover(&mut s, &r, &p);
        assert_eq!(done.outcome, Some(CleanupOutcome::RecoveryRemoved));
    }
}
#[test]
fn recovery_confirmation_clock_and_budget_do_not_release_pending_state() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    assert!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |at, _| if at == Point::AfterIntentCommit {
                Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
            } else {
                Ok(())
            }
        )
        .is_err()
    );
    drop(w);
    let mut s = reopen(&t);
    let r = s.blob_cleanup_executions(1).unwrap().remove(0);
    let g = s.generation().unwrap();
    assert!(matches!(
        s.recover_at(
            r.run_id,
            CleanupBudget::default(),
            "",
            p.planned_at,
            |_, _| Ok(())
        ),
        Err(StorageError::InvalidRecoveryReview)
    ));
    assert_eq!(s.generation().unwrap(), g);
    assert!(matches!(
        s.recover_at(
            r.run_id,
            CleanupBudget::default(),
            "確認",
            p.planned_at - 1,
            |_, _| Ok(())
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(matches!(
        s.recover_at(
            r.run_id,
            CleanupBudget {
                hash_bytes: 13,
                ..CleanupBudget::default()
            },
            "確認",
            p.planned_at,
            |_, _| Ok(())
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(path(&t).exists());
    assert!(
        s.blob_cleanup_executions(1).unwrap()[0]
            .finished_generation
            .is_none()
    );
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    recover(&mut s, &r, &p);
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn empty_body_uses_zero_hash_bytes_without_dropping_its_promise() {
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    let id = id::blob_id(b"");
    let a = w
        .stage_blob(id, Cursor::new(b""), 1, TemporaryLimits::default())
        .unwrap();
    let CleanupDecision::Planned(p) = w
        .plan_at(
            id,
            CleanupBudget {
                hash_bytes: 0,
                ..CleanupBudget::default()
            },
            a.expires_at,
            |_, _| Ok(()),
        )
        .unwrap()
    else {
        panic!()
    };
    w.execute_at(
        p.plan_id,
        CleanupBudget {
            hash_bytes: 0,
            ..CleanupBudget::default()
        },
        p.planned_at,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(count(&w.store, "temporary_blob_holds"), 1);
    assert!(w.blob(id).unwrap().is_none());
    w.finish().unwrap();
    assert_eq!(reopen(&t).startup_state().unwrap(), StartupState::Clean);
}
#[test]
fn an_older_cleanup_proof_does_not_hide_a_lost_later_upload() {
    for manual in [false, true] {
        let t = Temp::new();
        let (mut w, p) = setup(&t);
        execute(&mut w, &p);
        if manual {
            w.put_blob(p.blob_id, Cursor::new(bytes())).unwrap();
        } else {
            w.stage_blob(
                p.blob_id,
                Cursor::new(bytes()),
                86400,
                TemporaryLimits::default(),
            )
            .unwrap();
        }
        w.finish().unwrap();
        let c = Connection::open(t.data().join(DB)).unwrap();
        c.execute_batch(
            "DROP TRIGGER blobs_no_delete; DELETE FROM manual_blob_holds; DELETE FROM blobs;",
        )
        .unwrap();
        drop(c);
        std::fs::remove_file(path(&t)).unwrap();
        assert!(matches!(
            RecordStore::open(&t.data(), Limits::default()),
            Err(StorageError::Corrupt)
        ));
    }
}

#[test]
fn cleaned_blob_reupload_is_charged_again_even_though_old_promises_remain() {
    struct NeverRead;
    impl std::io::Read for NeverRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("quota must reject before reading")
        }
    }
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    execute(&mut w, &p);
    w.store.limits.max_blob_bytes = 14;
    let other = b"abcdefghijklmn";
    assert_eq!(other.len(), 14);
    let full = TemporaryLimits {
        bytes: 14,
        holds: 10,
    };
    w.stage_blob(id::blob_id(other), Cursor::new(other), 1, full)
        .unwrap();
    let generation = w.store.generation().unwrap();
    assert!(matches!(
        w.stage_blob(p.blob_id, NeverRead, 1, full),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(w.store.generation().unwrap(), generation);
    assert_eq!(count(&w.store, "blobs"), 1);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 2);
    let adjusted = TemporaryLimits { bytes: 28, ..full };
    w.stage_blob(p.blob_id, Cursor::new(bytes()), 1, adjusted)
        .unwrap();
    // 現在の集計に入っている本文の再投稿は、物理容量を重複計上しない。
    w.stage_blob(p.blob_id, Cursor::new(bytes()), 1, adjusted)
        .unwrap();
    let size:i64=w.store.conn.query_row("SELECT sum(byte_length) FROM blobs WHERE id IN (SELECT blob_id FROM temporary_blob_holds)",[],|r|r.get(0)).unwrap();
    assert_eq!(size, 28);
    assert_eq!(count(&w.store, "blobs"), 2);
    assert_eq!(count(&w.store, "temporary_blob_holds"), 4);
    w.finish().unwrap();
    assert_eq!(reopen(&t).startup_state().unwrap(), StartupState::Clean);
}

// R08/R20/R26/R30: 保存済みの全段階を通して整理・再取得・復旧を確認する。
fn split_startup(t: &Temp) -> (LocalStartup, EvaluationSnapshot) {
    let mut startup = LocalStartup::open(&t.data(), Limits::default()).unwrap();
    let budget = LocalStartupBudget {
        inspection: InspectionBudget {
            records: 1,
            blob_files: 1,
            ..InspectionBudget::default()
        },
        records: EvaluationInputBudget {
            records: 1,
            ..EvaluationInputBudget::default()
        },
        blobs: EvaluationBlobBudget {
            targets: 1,
            ..EvaluationBlobBudget::default()
        },
        evaluation: EvaluationStepBudget { nodes: 1 },
        evaluation_elapsed: None,
    };
    for _ in 0..100 {
        if let LocalStartupProgress::Evaluation(p) =
            startup.step(EvaluationLimits::default(), budget).unwrap()
        {
            if let Some(snapshot) = p.snapshot {
                return (startup, snapshot);
            }
        }
    }
    panic!("split startup did not complete");
}
fn epochs(s: &RecordStore) -> (i64, i64, i64) {
    s.conn.query_row("SELECT source_epoch,record_epoch,payload_epoch FROM record_inspection,evaluation_state WHERE record_inspection.singleton=1 AND evaluation_state.singleton=1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
}
#[test]
fn cleanup_invalidates_completed_startup_manifest_and_keeps_record_cache() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    w.insert(&fixture()).unwrap();
    w.finish().unwrap();
    let (startup, _) = split_startup(&t);
    let mut w = startup.into_writer().unwrap();
    let before = epochs(&w.store);
    assert_eq!(count(&w.store, "evaluation_nodes"), 1);
    assert_eq!(count(&w.store, "blob_inspection_inventory"), 1);
    assert_eq!(count(&w.store, "blob_inspection_files"), 1);
    execute(&mut w, &p);
    let after = epochs(&w.store);
    assert_eq!(after, (before.0 + 1, before.1, before.2 + 1));
    assert_eq!(count(&w.store, "evaluation_nodes"), 1);
    assert_eq!(count(&w.store, "blob_inspection_inventory"), 0);
    assert_eq!(count(&w.store, "blob_inspection_files"), 0);
    let phase: String = w
        .store
        .conn
        .query_row("SELECT phase FROM record_inspection", [], |r| r.get(0))
        .unwrap();
    assert_eq!(phase, "idle");
    let dirty: bool = w
        .store
        .conn
        .query_row("SELECT dirty FROM evaluation_state", [], |r| r.get(0))
        .unwrap();
    assert!(dirty);
    w.finish().unwrap();
    let (startup, snapshot) = split_startup(&t);
    assert!(snapshot.committed);
    let w = startup.into_writer().unwrap();
    let cp: (i64, String, i64, i64) = w.store.conn.query_row("SELECT source_epoch,phase,checked_blob_files,checked_blob_bytes FROM record_inspection", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(cp, (after.0, "complete".into(), 0, 0));
    w.finish().unwrap();
}
#[test]
fn split_reevaluation_after_cleanup_and_reupload_updates_descendants_and_keeps_evidence() {
    use crate::storage::evaluation::tests::assert_state;
    let t = Temp::new();
    let (w, p) = setup(&t);
    w.finish().unwrap();
    let (startup, _) = split_startup(&t);
    let mut w = startup.into_writer().unwrap();
    execute(&mut w, &p);
    let root = rev(&[], 15, "late wrong length");
    let child = rev(&[root.id()], 14, "late child");
    let grandchild = rev(&[child.id()], 14, "late grandchild");
    let branch = rev(&[], 14, "independent branch");
    let records = vec![
        fixture(),
        root.clone(),
        child.clone(),
        grandchild.clone(),
        branch.clone(),
    ];
    // 子を先に保存し、Record収集と親評価の順序に依存しないことも確認する。
    for r in records.iter().rev() {
        w.insert(r).unwrap();
    }
    w.finish().unwrap();
    let (startup, missing) = split_startup(&t);
    for r in &records[1..] {
        assert_state(&missing, r, Validation::Valid, None);
        assert_eq!(
            missing
                .records
                .iter()
                .find(|a| a.record_id == r.id())
                .unwrap()
                .payload_status,
            Some(PayloadStatus::Missing)
        );
    }
    let mut w = startup.into_writer().unwrap();
    w.put_blob(p.blob_id, Cursor::new(bytes())).unwrap();
    w.finish().unwrap();
    let (startup, present) = split_startup(&t);
    assert_state(
        &present,
        &root,
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    for r in [&child, &grandchild] {
        assert_state(
            &present,
            r,
            Validation::Invalid,
            Some(Reason::InvalidParent),
        );
        assert_eq!(
            present
                .records
                .iter()
                .find(|a| a.record_id == r.id())
                .unwrap()
                .payload_status,
            Some(PayloadStatus::Verified)
        );
    }
    assert_state(&present, &branch, Validation::Valid, None);
    assert_oracle(&[
        (oracle_case(&records, false), missing),
        (oracle_case(&records, true), present),
    ]);
    let mut w = startup.into_writer().unwrap();
    assert_eq!(count(&w.store, "known_invalid"), 1);
    // 再投稿・古い整理予定の再利用では既知不正や根拠を消さない。
    w.insert(&root).unwrap();
    // setupは待機せず未来のexpires_atで整理している。実時計へ戻すと、
    // 高速な環境では正当な時刻逆行拒否になるため、同じfixture時刻を使う。
    let generation = w.store.generation().unwrap();
    assert!(matches!(
        w.plan_at(
            p.blob_id,
            CleanupBudget::default(),
            p.planned_at - 1,
            |_, _| Ok(())
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(w.store.generation().unwrap(), generation);
    assert_eq!(count(&w.store, "known_invalid"), 1);
    assert!(matches!(
        w.plan_at(
            p.blob_id,
            CleanupBudget::default(),
            p.planned_at,
            |_, _| Ok(())
        )
        .unwrap(),
        CleanupDecision::Protected
    ));
    assert_eq!(count(&w.store, "known_invalid"), 1);
    for r in &records {
        assert_eq!(w.store.record(r.id()).unwrap().unwrap().bytes(), r.bytes());
    }
    w.finish().unwrap();
}
#[test]
fn interrupted_cleanup_with_saved_jobs_requires_fresh_checks_and_explicit_resume() {
    for point in [
        Point::AfterIntentCommit,
        Point::AfterUnlink,
        Point::BeforeFinishCommit,
    ] {
        let t = Temp::new();
        let (w, p) = setup(&t);
        w.finish().unwrap();
        let (startup, _) = split_startup(&t);
        let mut w = startup.into_writer().unwrap();
        let old = epochs(&w.store);
        assert!(
            w.execute_at(
                p.plan_id,
                CleanupBudget::default(),
                p.planned_at,
                |at, _| {
                    if at == point {
                        Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        drop(w);
        let mut s = reopen(&t);
        let run = s.blob_cleanup_executions(1).unwrap().remove(0);
        assert!(run.finished_generation.is_none());
        recover(&mut s, &run, &p);
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert_eq!(epochs(&s), (old.0 + 1, old.1, old.2 + 1));
        assert_eq!(count(&s, "blob_inspection_inventory"), 0);
        drop(s);
        let (startup, snapshot) = split_startup(&t);
        assert!(snapshot.committed);
        assert!(startup.needs_review());
        // 検査と評価が完了してもwriterは取得できない。
        assert!(matches!(
            startup.into_writer(),
            Err(StorageError::NeedsReview)
        ));
        let s = reopen(&t);
        let generation = s.generation().unwrap();
        let review = s
            .confirm_evidence_recovery(
                generation,
                "整理意思と完了台帳、全保存範囲を再検査",
                "本試験はSQL/I/O注入で実デバイス試験ではない",
                EvaluationLimits::default(),
            )
            .unwrap();
        let w = reopen(&t)
            .resume_local_writes(
                review,
                "未確定制限を確認、残る保存障害なし。ローカル書込みのみ再開",
                EvaluationLimits::default(),
            )
            .unwrap();
        assert!(w.store.blob(p.blob_id).unwrap().is_none());
        assert_eq!(count(&w.store, "temporary_blob_holds"), 1);
        w.finish().unwrap();
        assert_eq!(reopen(&t).startup_state().unwrap(), StartupState::Clean);
    }
}

#[test]
fn post_recovery_scan_budget_failure_keeps_committed_cleanup_and_manual_hold() {
    let t = Temp::new();
    let (mut w, p) = setup(&t);
    let other = id::blob_id(b"independent retained body");
    w.put_blob(other, Cursor::new(b"independent retained body"))
        .unwrap();
    assert!(
        w.execute_at(
            p.plan_id,
            CleanupBudget::default(),
            p.planned_at,
            |at, _| {
                if at == Point::AfterUnlink {
                    Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
                } else {
                    Ok(())
                }
            }
        )
        .is_err()
    );
    drop(w);
    let mut s = reopen(&t);
    let run = s.blob_cleanup_executions(1).unwrap().remove(0);
    // 整理完了後の全Blob再検査だけを予算不足にする。対象は既に不在。
    s.limits.scan_blob_bytes = 1;
    assert!(matches!(
        s.recover_at(
            run.run_id,
            CleanupBudget::default(),
            "削除意思と不在を確認",
            p.planned_at,
            |_, _| Ok(())
        ),
        Err(StorageError::BudgetExceeded)
    ));
    let done = s.blob_cleanup_executions(1).unwrap().remove(0);
    assert_eq!(done.outcome, Some(CleanupOutcome::RecoveryAbsent));
    assert!(done.finished_generation.is_some());
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(!path(&t).exists());
    // Errを「整理がrollbackした」と解釈せず、台帳を照合し直す。
    drop(s);
    let mut s = reopen(&t);
    assert_eq!(s.blob_cleanup_executions(1).unwrap(), vec![done]);
    assert!(s.blob(other).unwrap().is_some());
    assert!(matches!(
        s.recover_at(
            run.run_id,
            CleanupBudget::default(),
            "再実行しない",
            p.planned_at,
            |_, _| Ok(())
        ),
        Err(StorageError::Corrupt)
    ));
    drop(s);
    let (startup, _) = split_startup(&t);
    assert!(startup.needs_review());
    assert!(matches!(
        startup.into_writer(),
        Err(StorageError::NeedsReview)
    ));
}

// R24/R28/R30: 行数上限の外側で実行される台帳SQLも中断可能にする。
fn sql_ledger(t: &Temp) -> (RecordWriter, BlobCleanupPlan, i64) {
    let (mut w, first) = setup(t);
    for i in 0u8..32 {
        let body = [i; 3];
        let a = w
            .stage_blob(
                id::blob_id(&body),
                Cursor::new(body),
                1,
                TemporaryLimits::default(),
            )
            .unwrap();
        assert!(matches!(
            w.plan_at(a.id, CleanupBudget::default(), a.expires_at, |_, _| Ok(()))
                .unwrap(),
            CleanupDecision::Planned(_)
        ));
    }
    let now: i64 = w
        .store
        .conn
        .query_row("SELECT max(planned_at) FROM blob_cleanup_plans", [], |r| {
            r.get(0)
        })
        .unwrap();
    (w, first, now)
}
fn small_sql_cleanup() -> CleanupBudget {
    CleanupBudget {
        protection: ProtectionBudget {
            sql_inspection: SqlInspectionBudget {
                callbacks: 1,
                ..SqlInspectionBudget::default()
            },
            ..ProtectionBudget::default()
        },
        ..CleanupBudget::default()
    }
}
#[test]
fn cleanup_sql_budget_before_intent_is_retryable_and_diagnostics_are_bounded() {
    let t = Temp::new();
    let (mut w, p, now) = sql_ledger(&t);
    let generation = w.store.generation().unwrap();
    assert!(matches!(
        w.plan_at(p.blob_id, small_sql_cleanup(), now, |_, _| Ok(())),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(matches!(
        w.execute_at(p.plan_id, small_sql_cleanup(), now, |_, _| Ok(())),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(w.store.generation().unwrap(), generation);
    assert_eq!(count(&w.store, "blob_cleanup_runs"), 0);
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    assert!(!w.failed);
    w.store.limits.sql_inspection = small_sql_cleanup().protection.sql_inspection;
    assert!(matches!(
        w.store.blob_cleanup_plans(100),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(matches!(
        w.store.blob_cleanup_executions(100),
        Err(StorageError::BudgetExceeded)
    ));
    w.store.limits.sql_inspection = SqlInspectionBudget::default();
    w.execute_at(p.plan_id, CleanupBudget::default(), now, |_, _| Ok(()))
        .unwrap();
    assert_eq!(count(&w.store, "blob_cleanup_runs"), 1);
    w.finish().unwrap();
    assert_eq!(reopen(&t).startup_state().unwrap(), StartupState::Clean);
}
#[test]
fn cleanup_recovery_sql_budget_keeps_intent_and_requires_explicit_retry() {
    let t = Temp::new();
    let (mut w, p, now) = sql_ledger(&t);
    assert!(
        w.execute_at(p.plan_id, CleanupBudget::default(), now, |at, _| {
            if at == Point::AfterIntentCommit {
                Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    drop(w);
    let mut s = reopen(&t);
    let run = s.blob_cleanup_executions(100).unwrap().remove(0);
    let generation = s.generation().unwrap();
    assert!(matches!(
        s.recover_at(
            run.run_id,
            small_sql_cleanup(),
            "保存済み意思の確認",
            now,
            |_, _| Ok(())
        ),
        Err(StorageError::BudgetExceeded)
    ));
    assert_eq!(s.generation().unwrap(), generation);
    assert_eq!(s.blob_cleanup_executions(100).unwrap(), vec![run.clone()]);
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    let done = s
        .recover_at(
            run.run_id,
            CleanupBudget::default(),
            "予算を調整し意思と全根拠を再確認",
            now,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(done.outcome, Some(CleanupOutcome::RecoveryRemoved));
    assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
}
#[test]
fn interrupted_cancellation_sql_rolls_back_new_record_and_keeps_running_mark() {
    let t = Temp::new();
    let (mut w, p, _) = sql_ledger(&t);
    w.insert(&fixture()).unwrap();
    let r = rev(&[], 14, "SQL interrupted cancellation");
    let generation = w.store.generation().unwrap();
    w.store.limits.sql_inspection = small_sql_cleanup().protection.sql_inspection;
    assert!(matches!(w.insert(&r), Err(StorageError::BudgetExceeded)));
    assert!(w.failed);
    assert!(w.store.record(r.id()).unwrap().is_none());
    assert_eq!(w.store.generation().unwrap(), generation);
    w.store.limits.sql_inspection = SqlInspectionBudget::default();
    let p2 = w
        .store
        .blob_cleanup_plans(100)
        .unwrap()
        .into_iter()
        .find(|x| x.plan_id == p.plan_id)
        .unwrap();
    assert!(p2.cancelled_generation.is_none());
    assert_eq!(std::fs::read(path(&t)).unwrap(), bytes());
    assert!(matches!(w.finish(), Err(StorageError::UnresolvedFailure)));
    assert_eq!(
        reopen(&t).startup_state().unwrap(),
        StartupState::NeedsReview
    );
}
