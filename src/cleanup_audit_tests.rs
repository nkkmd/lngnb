//! R24/R26/R28/R30: 合成履歴の読取り負荷と、実際の末尾整理の中断復旧。
//! 使い捨て試験領域専用。受付性能・耐久性・実デバイス試験ではない。
use super::*;
use crate::{id, storage::tests::Temp};
use std::io::Cursor;

fn budget(n: u64) -> CleanupBudget {
    CleanupBudget {
        plans: n + 2,
        ..CleanupBudget::default()
    }
}
fn state_counts(s: &RecordStore) -> (i64, i64, i64, i64) {
    s.conn.query_row("SELECT generation,(SELECT count(*) FROM history),(SELECT count(*) FROM blob_cleanup_plans),(SELECT count(*) FROM blob_cleanup_runs) FROM storage_state", [], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
}
fn history_fixture(t: &Temp, n: u64) -> (RecordWriter, Id, CleanupBudget) {
    let mut w = t.store().begin().unwrap();
    let old = id::blob_id(b"synthetic historical object");
    w.put_blob(old, Cursor::new(b"synthetic historical object"))
        .unwrap();
    // 過去の取消/完了を、整合照合専用のSQL fixtureとして生成する。
    // 実体の削除資格・実際の受付履歴とは主張せず、このobjectは明示保持する。
    let tx = w.store.conn.transaction().unwrap();
    let mut generation: i64 = tx
        .query_row("SELECT generation FROM storage_state", [], |r| r.get(0))
        .unwrap();
    let audit = |g: i64, old_state: &str, new_state: &str, reason: String| {
        tx.execute("INSERT INTO history(generation,namespace,target,old_state,new_state,actor,reason,rules,at) SELECT ?1,namespace,?2,?3,?4,'synthetic_read_fixture',?5,'lngnb-validation-1','2026-10-23T00:00:00.000Z' FROM storage_state", params![g,&old.bytes,old_state,new_state,reason]).unwrap();
    };
    for i in 0..n {
        let mut plan = [0x61u8; 32];
        plan[..8].copy_from_slice(&i.to_be_bytes());
        let mut run = [0x72u8; 32];
        run[..8].copy_from_slice(&i.to_be_bytes());
        let g = generation + 1;
        let completed = i % 2 == 0;
        let end = g + if completed { 2 } else { 1 };
        tx.execute(
            "INSERT INTO blob_cleanup_plans VALUES(?1,?2,27,0,'synthetic',?3,?4,?5,?6)",
            params![
                &plan,
                &old.bytes,
                g,
                if completed { None } else { Some(end) },
                if completed {
                    None
                } else {
                    Some("manual_retention")
                },
                if completed { Some(end) } else { None }
            ],
        )
        .unwrap();
        audit(
            g,
            "temporary_blob_expired",
            "blob_cleanup_planned_local_only",
            format!("plan_blob_cleanup:{}:0:27:synthetic", blobs::hex(&plan)),
        );
        if completed {
            tx.execute(
                "INSERT INTO blob_cleanup_runs VALUES(?1,?2,?3,?4,'removed')",
                params![&run, &plan, g + 1, end],
            )
            .unwrap();
            audit(
                g + 1,
                "blob_cleanup_planned_local_only",
                "blob_cleanup_started_local_only",
                format!(
                    "start_blob_cleanup:{}:{}",
                    blobs::hex(&run),
                    blobs::hex(&plan)
                ),
            );
            audit(
                end,
                "blob_cleanup_started_local_only",
                "blob_cleanup_completed_local_only",
                format!(
                    "finish_blob_cleanup:{}:{}:removed",
                    blobs::hex(&run),
                    blobs::hex(&plan)
                ),
            );
        } else {
            audit(
                end,
                "blob_cleanup_planned_local_only",
                "blob_cleanup_cancelled_local_only",
                format!("cancel_blob_cleanup:{}:manual_retention", blobs::hex(&plan)),
            );
        }
        generation = end;
    }
    tx.execute("UPDATE storage_state SET generation=?1", [generation])
        .unwrap();
    tx.commit().unwrap();
    // 最後の対象だけは公開内部APIで実際に受信する。
    let candidate = id::blob_id(b"actual cleanup candidate");
    let _hold = w
        .stage_blob(
            candidate,
            Cursor::new(b"actual cleanup candidate"),
            1,
            TemporaryLimits::default(),
        )
        .unwrap();
    (w, candidate, budget(n))
}
#[test]
fn growing_cleanup_history_keeps_last_intent_and_allows_explicit_budget_retry() {
    let sizes = std::env::var("LNGNB_CLEANUP_PROBE_HISTORY").unwrap_or_else(|_| "64,256".into());
    let sizes: Vec<u64> = sizes.split(',').map(|s| s.parse().unwrap()).collect();
    assert!(
        !sizes.is_empty()
            && sizes.len() <= 3
            && sizes.iter().all(|n| (2..=20_000).contains(n) && n % 2 == 0)
    );
    for n in sizes {
        let t = Temp::new();
        let (mut w, candidate, b) = history_fixture(&t, n);
        let now: i64 = w
            .store
            .conn
            .query_row(
                "SELECT max(expires_at) FROM temporary_blob_holds",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let before = state_counts(&w.store);
        let low = CleanupBudget { plans: n - 1, ..b };
        assert!(matches!(
            w.plan_at(candidate, low, now, |_, _| Ok(())),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(state_counts(&w.store), before);
        assert!(!w.failed);
        let timer = Instant::now();
        let CleanupDecision::Planned(p) = w.plan_at(candidate, b, now, |_, _| Ok(())).unwrap()
        else {
            panic!()
        };
        let plan_ms = timer.elapsed().as_secs_f64() * 1000.;
        assert!(matches!(
            w.store.blob_cleanup_plans(n),
            Err(StorageError::BudgetExceeded)
        ));
        let all = w.store.blob_cleanup_plans(n + 1).unwrap();
        assert_eq!(all.last(), Some(&p));
        assert_eq!(
            all.iter()
                .filter(|p| p.cancelled_generation.is_some())
                .count() as u64,
            n / 2
        );
        assert_eq!(
            all.iter()
                .filter(|p| p.completed_generation.is_some())
                .count() as u64,
            n / 2
        );
        assert!(matches!(
            w.execute_at(p.plan_id, b, now, |at, _| if at == Point::AfterUnlink {
                Err(StorageError::Io(std::io::Error::from_raw_os_error(5)))
            } else {
                Ok(())
            }),
            Err(StorageError::Io(_))
        ));
        drop(w);
        let timer = Instant::now();
        let mut s = RecordStore::open(&t.data(), Limits::default()).unwrap();
        let open_ms = timer.elapsed().as_secs_f64() * 1000.;
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        assert!(pending(&s.conn, SqlInspectionBudget::default()).unwrap());
        assert!(matches!(
            s.blob_cleanup_executions(n / 2),
            Err(StorageError::BudgetExceeded)
        ));
        let runs = s.blob_cleanup_executions(n / 2 + 1).unwrap();
        let run = runs.last().unwrap();
        assert!(run.finished_generation.is_none());
        let sql_low = CleanupBudget {
            protection: ProtectionBudget {
                sql_inspection: SqlInspectionBudget {
                    callbacks: 1,
                    ..SqlInspectionBudget::default()
                },
                ..b.protection
            },
            ..b
        };
        for (limited, start_recorded) in [
            (CleanupBudget { plans: n / 2, ..b }, false),
            (low, true),
            (sql_low, false),
        ] {
            let before = state_counts(&s);
            assert!(matches!(
                s.recover_at(run.run_id, limited, "未完了意思を確認", now, |_, _| Ok(())),
                Err(StorageError::BudgetExceeded)
            ));
            // plansの不足は開始履歴の後にも起きる。意思/予定/実行行は未完了で残す。
            let delta = i64::from(start_recorded);
            assert_eq!(
                state_counts(&s),
                (before.0 + delta, before.1 + delta, before.2, before.3)
            );
            assert_eq!(
                s.blob_cleanup_executions(n / 2 + 1).unwrap().last(),
                Some(run)
            );
            assert!(pending(&s.conn, SqlInspectionBudget::default()).unwrap());
        }
        let timer = Instant::now();
        let done = s
            .recover_at(
                run.run_id,
                b,
                "末尾の実際の整理だけを明示復旧",
                now,
                |_, _| Ok(()),
            )
            .unwrap();
        let recovery_ms = timer.elapsed().as_secs_f64() * 1000.;
        assert_eq!(done.outcome, Some(CleanupOutcome::RecoveryAbsent));
        assert!(!pending(&s.conn, SqlInspectionBudget::default()).unwrap());
        assert_eq!(s.startup_state().unwrap(), StartupState::NeedsReview);
        let after = s.blob_cleanup_plans(n + 1).unwrap();
        assert_eq!(&after[..n as usize], &all[..n as usize]);
        assert_eq!(count_history_runs(&s), n / 2 + 1);
        let g = s.generation().unwrap();
        let review = s
            .confirm_evidence_recovery(
                g,
                "実体と整理履歴を確認",
                "正式耐久性試験は未実施",
                EvaluationLimits::default(),
            )
            .unwrap();
        let w = RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .resume_local_writes(review, "ローカルのみ再開", EvaluationLimits::default())
            .unwrap();
        w.finish().unwrap();
        assert_eq!(
            RecordStore::open(&t.data(), Limits::default())
                .unwrap()
                .startup_state()
                .unwrap(),
            StartupState::Clean
        );
        println!(
            "LNGNB_CLEANUP_REPORT={}",
            serde_json::json!({"synthetic_plans":n,"completed_runs":n/2,"total_runs":n/2+1,"plan_ms":plan_ms,"open_ms":open_ms,"recovery_ms":recovery_ms,"explicit_plan_limit":b.plans,"scope":"synthetic_read_history_actual_last_recovery"})
        );
    }
}
fn count_history_runs(s: &RecordStore) -> u64 {
    s.conn
        .query_row("SELECT count(*) FROM blob_cleanup_runs", [], |r| r.get(0))
        .unwrap()
}
