//! R20/R24/R26/R27/R30: 統合起動・正常停止・強制終了。公開試験鍵は実運用禁止。
use super::*;
use crate::{
    id,
    storage::{
        evaluation::tests::{assert_oracle, assert_state, bytes, oracle_case, rev},
        tests::{Temp, fixture},
    },
};
use std::{
    io::{BufRead, Cursor, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
fn populate(t: &Temp, bad: bool, clean: bool) -> Vec<LocalRecord> {
    let mut w = t.store().begin().unwrap();
    let a = rev(&[], if bad { 15 } else { 14 }, "parent");
    let child = rev(&[a.id()], 14, "child");
    let records = vec![fixture(), a, child, rev(&[], 14, "branch")];
    for r in &records {
        w.insert(r).unwrap();
    }
    w.put_blob(id::blob_id(&bytes()), Cursor::new(bytes()))
        .unwrap();
    if clean {
        w.finish().unwrap();
    }
    records
}
fn open(t: &Temp) -> LocalStartup {
    LocalStartup::open(&t.data(), Limits::default()).unwrap()
}
fn store(t: &Temp) -> RecordStore {
    RecordStore::open(&t.data(), Limits::default()).unwrap()
}
fn raw(t: &Temp) -> Connection {
    Connection::open(t.data().join(DB)).unwrap()
}
fn raw_state(t: &Temp) -> StartupState {
    state(&raw(t)).unwrap()
}
fn path(t: &Temp) -> std::path::PathBuf {
    t.data()
        .join("blobs")
        .join(blobs::hex(&id::blob_id(&bytes()).bytes))
}
fn split() -> LocalStartupBudget {
    LocalStartupBudget {
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
    }
}
fn drive(s: &mut LocalStartup) -> EvaluationSnapshot {
    for _ in 0..200 {
        let p = s.step(EvaluationLimits::default(), split()).unwrap();
        if let LocalStartupProgress::Evaluation(p) = p {
            if let Some(snapshot) = p.snapshot {
                return snapshot;
            }
        }
    }
    panic!("startup did not finish");
}
fn tag(p: &LocalStartupProgress) -> &'static str {
    match p {
        LocalStartupProgress::Inspection(_) => "inspection",
        LocalStartupProgress::Records(_) => "records",
        LocalStartupProgress::Blobs(_) => "blobs",
        LocalStartupProgress::Evaluation(_) => "evaluation",
        LocalStartupProgress::Ready => "ready",
    }
}
#[test]
fn ordered_stages_keep_running_until_writer_finishes_and_match_dfs() {
    let t = Temp::new();
    let records = populate(&t, true, true);
    let mut s = open(&t);
    assert!(!s.needs_review());
    let mut tags = Vec::new();
    let snapshot;
    loop {
        let p = s.step(EvaluationLimits::default(), split()).unwrap();
        assert_eq!(raw_state(&t), StartupState::NeedsReview);
        if tags.last() != Some(&tag(&p)) {
            tags.push(tag(&p));
        }
        if let LocalStartupProgress::Evaluation(p) = p {
            if let Some(v) = p.snapshot {
                snapshot = v;
                break;
            }
        }
    }
    assert_eq!(tags, vec!["inspection", "records", "blobs", "evaluation"]);
    assert!(snapshot.committed);
    assert_state(
        &snapshot,
        &records[1],
        Validation::Invalid,
        Some(Reason::DeclaredLengthMismatch),
    );
    assert_oracle(&[(oracle_case(&records, true), snapshot)]);
    assert!(
        s.step(EvaluationLimits::default(), LocalStartupBudget::default())
            .unwrap()
            .checks_complete()
    );
    let mut w = s.into_writer().unwrap();
    let after = rev(&[], 14, "after startup");
    w.insert(&after).unwrap();
    w.finish().unwrap();
    let r = store(&t);
    assert_eq!(r.startup_state().unwrap(), StartupState::Clean);
    assert!(r.record(after.id()).unwrap().is_some());
}
#[test]
fn every_unfinished_stage_refuses_writer_and_preserves_manual_wait() {
    for phase in ["inspection", "records", "blobs", "evaluation"] {
        let t = Temp::new();
        populate(&t, false, true);
        let mut s = open(&t);
        if phase != "inspection" {
            loop {
                let p = s.step(EvaluationLimits::default(), split()).unwrap();
                if tag(&p) == phase {
                    break;
                }
            }
        }
        assert!(matches!(
            s.into_writer(),
            Err(StorageError::InspectionPending)
        ));
        assert_eq!(raw_state(&t), StartupState::NeedsReview);
    }
}
#[test]
fn initial_manual_wait_survives_all_checks_and_pause() {
    for take_writer in [false, true] {
        let t = Temp::new();
        populate(&t, true, false);
        let mut s = open(&t);
        assert!(s.needs_review());
        drive(&mut s);
        assert!(s.needs_review());
        if take_writer {
            assert!(matches!(s.into_writer(), Err(StorageError::NeedsReview)));
        } else {
            s.pause().unwrap();
        }
        assert_eq!(
            store(&t).startup_state().unwrap(),
            StartupState::NeedsReview
        );
        assert_eq!(
            raw(&t)
                .query_row("SELECT count(*) FROM known_invalid", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
#[test]
fn normal_pause_preserves_input_cursor_and_can_complete_after_reopen() {
    let t = Temp::new();
    populate(&t, false, true);
    let mut s = open(&t);
    loop {
        if let LocalStartupProgress::Records(p) =
            s.step(EvaluationLimits::default(), split()).unwrap()
        {
            assert_eq!(p.collected_records, 1);
            break;
        }
    }
    s.pause().unwrap();
    assert_eq!(raw_state(&t), StartupState::Clean);
    let before: i64 = raw(&t)
        .query_row("SELECT records FROM evaluation_input", [], |r| r.get(0))
        .unwrap();
    let mut s = open(&t);
    loop {
        if let LocalStartupProgress::Records(p) =
            s.step(EvaluationLimits::default(), split()).unwrap()
        {
            assert!(p.collected_records > before as u64);
            break;
        }
    }
    drive(&mut s);
    s.into_writer().unwrap().finish().unwrap();
    assert_eq!(store(&t).startup_state().unwrap(), StartupState::Clean);
}
#[test]
fn ready_drop_is_not_normal_shutdown() {
    let t = Temp::new();
    populate(&t, false, true);
    let mut s = open(&t);
    drive(&mut s);
    drop(s);
    assert_eq!(
        store(&t).startup_state().unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn empty_data_and_missing_dependencies_are_distinguished_from_storage_faults() {
    let t = Temp::new();
    drop(t.store());
    let mut s = open(&t);
    assert!(drive(&mut s).records.is_empty());
    s.into_writer().unwrap().finish().unwrap();
    let t = Temp::new();
    let mut w = t.store().begin().unwrap();
    w.insert(&fixture()).unwrap();
    let r = rev(
        &[Id {
            kind: Kind::Record,
            bytes: [42; 32],
        }],
        14,
        "missing",
    );
    w.insert(&r).unwrap();
    w.finish().unwrap();
    let mut s = open(&t);
    let snap = drive(&mut s);
    assert_state(&snap, &r, Validation::Pending, Some(Reason::MissingParent));
    assert_eq!(
        snap.records
            .iter()
            .find(|a| a.record_id == r.id())
            .unwrap()
            .payload_status,
        Some(PayloadStatus::Missing)
    );
    s.into_writer().unwrap().finish().unwrap();
}
#[test]
fn missing_corrupt_orphan_and_staging_never_reach_writer() {
    for kind in ["missing", "corrupt", "orphan", "staging"] {
        let t = Temp::new();
        populate(&t, false, true);
        match kind {
            "missing" => std::fs::remove_file(path(&t)).unwrap(),
            "corrupt" => std::fs::write(path(&t), b"broken").unwrap(),
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
        let mut s = open(&t);
        let mut failed = false;
        for _ in 0..20 {
            if s.step(EvaluationLimits::default(), LocalStartupBudget::default())
                .is_err()
            {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(s.needs_review());
        assert!(s.pause().is_err());
        assert_eq!(raw_state(&t), StartupState::NeedsReview);
    }
}
#[test]
fn corrupt_record_or_saved_evaluation_is_not_hidden_by_startup() {
    for sql in [
        "DROP TRIGGER records_no_update; UPDATE records SET bytes=zeroblob(length(bytes))",
        "UPDATE evaluation_input SET digest=zeroblob(32)",
    ] {
        let t = Temp::new();
        populate(&t, false, true);
        if sql.contains("evaluation_input") {
            let mut s = open(&t);
            drive(&mut s);
            s.into_writer().unwrap().finish().unwrap();
        }
        raw(&t).execute_batch(sql).unwrap();
        let mut s = open(&t);
        let mut failed = false;
        for _ in 0..30 {
            if s.step(EvaluationLimits::default(), split()).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(s.pause().is_err());
        assert_eq!(raw_state(&t), StartupState::NeedsReview);
    }
}
#[test]
fn policy_limits_can_be_adjusted_without_fabricating_completion() {
    let t = Temp::new();
    populate(&t, false, true);
    let mut s = open(&t);
    let bad = LocalStartupBudget {
        inspection: InspectionBudget {
            records: 0,
            ..InspectionBudget::default()
        },
        ..LocalStartupBudget::default()
    };
    assert!(matches!(
        s.step(EvaluationLimits::default(), bad),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(!s.needs_review());
    drive(&mut s);
    s.into_writer().unwrap().finish().unwrap();
    let t = Temp::new();
    populate(&t, false, true);
    let mut s = open(&t);
    // 起動検査を終了させ、Record入力段階で0件予算を与える。
    loop {
        let p = s.step(EvaluationLimits::default(), split()).unwrap();
        if matches!(p,LocalStartupProgress::Inspection(p) if p.checks_complete) {
            break;
        }
    }
    let bad = LocalStartupBudget {
        records: EvaluationInputBudget {
            records: 0,
            ..EvaluationInputBudget::default()
        },
        ..LocalStartupBudget::default()
    };
    assert!(matches!(
        s.step(EvaluationLimits::default(), bad),
        Err(StorageError::BudgetExceeded)
    ));
    assert!(!s.needs_review());
    drive(&mut s);
    s.pause().unwrap();
}
#[test]
fn handoff_and_evaluation_failures_do_not_write_intermediate_clean() {
    for sql in [
        "CREATE TRIGGER reject_start BEFORE INSERT ON history WHEN NEW.reason='begin_evaluation_job' BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_start BEFORE INSERT ON evaluation_nodes BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_start BEFORE INSERT ON evaluations BEGIN SELECT RAISE(ABORT,'test'); END",
        "CREATE TRIGGER reject_start BEFORE INSERT ON known_invalid BEGIN SELECT RAISE(ABORT,'test'); END",
    ] {
        let t = Temp::new();
        populate(&t, true, true);
        raw(&t).execute_batch(sql).unwrap();
        let mut s = open(&t);
        let mut failed = false;
        for _ in 0..30 {
            if s.step(EvaluationLimits::default(), split()).is_err() {
                failed = true;
                break;
            }
            assert_eq!(raw_state(&t), StartupState::NeedsReview);
        }
        assert!(failed);
        assert!(s.pause().is_err());
        assert_eq!(raw_state(&t), StartupState::NeedsReview);
        assert_eq!(
            raw(&t)
                .query_row(
                    "SELECT count(*) FROM history WHERE reason='finish_record_inspection'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}
#[test]
fn normal_stop_failure_preserves_running_mark() {
    let t = Temp::new();
    populate(&t, false, true);
    let mut s = open(&t);
    drive(&mut s);
    let w = s.into_writer().unwrap();
    raw(&t).execute_batch("CREATE TRIGGER reject_stop BEFORE INSERT ON history WHEN NEW.reason='finish_record_session' BEGIN SELECT RAISE(ABORT,'test'); END").unwrap();
    assert!(matches!(w.finish(), Err(StorageError::Sql(_))));
    assert_eq!(
        store(&t).startup_state().unwrap(),
        StartupState::NeedsReview
    );
}
#[test]
fn file_or_epoch_changes_between_stages_or_before_writer_block_handoff() {
    for ready in [false, true] {
        for physical in [false, true] {
            let t = Temp::new();
            populate(&t, false, true);
            let mut s = open(&t);
            if ready {
                drive(&mut s);
            } else {
                loop {
                    let p = s.step(EvaluationLimits::default(), split()).unwrap();
                    if matches!(p,LocalStartupProgress::Inspection(p) if p.checks_complete) {
                        break;
                    }
                }
            }
            if physical {
                std::fs::write(path(&t), b"changed bytes!").unwrap();
            } else {
                raw(&t)
                    .execute(
                        "UPDATE evaluation_state SET record_epoch=record_epoch+1",
                        [],
                    )
                    .unwrap();
            }
            if ready {
                assert!(s.into_writer().is_err());
            } else {
                assert!(s.step(EvaluationLimits::default(), split()).is_err());
                assert!(s.pause().is_err());
            }
            assert_eq!(raw_state(&t), StartupState::NeedsReview);
        }
    }
}
#[test]
fn kill_at_each_stage_preserves_manual_wait_and_committed_progress() {
    if let Some(p) = std::env::var_os("LNGNB_STARTUP_KILL_CHILD") {
        let phase = std::env::var("LNGNB_STARTUP_KILL_PHASE").unwrap();
        let mut s = LocalStartup::open(Path::new(&p), Limits::default()).unwrap();
        loop {
            let p = s.step(EvaluationLimits::default(), split()).unwrap();
            if tag(&p) == phase || (phase == "ready" && p.checks_complete()) {
                println!("LNGNB_STARTUP_KILL_{phase}");
                std::io::stdout().flush().unwrap();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                panic!("killされる必要がある");
            }
        }
    }
    for phase in ["inspection", "records", "blobs", "evaluation", "ready"] {
        let t = Temp::new();
        populate(&t, false, true);
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","storage::startup::tests::kill_at_each_stage_preserves_manual_wait_and_committed_progress","--nocapture"]).env("LNGNB_STARTUP_KILL_CHILD",t.data()).env("LNGNB_STARTUP_KILL_PHASE",phase).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line.contains("LNGNB_STARTUP_KILL_") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(raw_state(&t), StartupState::NeedsReview);
        let mut s = open(&t);
        drive(&mut s);
        assert!(matches!(s.into_writer(), Err(StorageError::NeedsReview)));
    }
}
#[test]
fn unsupported_schema_is_rejected_without_modification() {
    let t = Temp::new();
    drop(t.store());
    let c = raw(&t);
    c.pragma_update(None, "user_version", 7).unwrap();
    drop(c);
    let before = std::fs::read(t.data().join(DB)).unwrap();
    assert!(matches!(
        LocalStartup::open(&t.data(), Limits::default()),
        Err(StorageError::UnsupportedFormat)
    ));
    assert_eq!(before, std::fs::read(t.data().join(DB)).unwrap());
}

#[test]
fn completed_manual_startup_connects_to_explicit_recovery_without_auto_unlock() {
    let t = Temp::new();
    populate(&t, true, false);
    let mut startup = open(&t);
    drive(&mut startup);
    assert!(startup.needs_review());
    startup.pause().unwrap();
    assert_eq!(raw_state(&t), StartupState::NeedsReview);
    let s = store(&t);
    let generation = s.generation().unwrap();
    let review = s
        .confirm_evidence_recovery(
            generation,
            "起動検査と根拠の照合済み",
            "なし",
            EvaluationLimits::default(),
        )
        .unwrap();
    assert_eq!(raw_state(&t), StartupState::NeedsReview);
    let writer = store(&t)
        .resume_local_writes(
            review,
            "未確定制限を確認済み。ローカル保存だけ明示再開",
            EvaluationLimits::default(),
        )
        .unwrap();
    writer.finish().unwrap();
    assert_eq!(store(&t).startup_state().unwrap(), StartupState::Clean);
    assert_eq!(
        raw(&t)
            .query_row("SELECT count(*) FROM known_invalid", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
