//! R20/R24/R26/R28/R30: 予備測定と予算不足からの完了経路。
//! 公開済み試験seedのみ。正式G5/実デバイス・電源断試験ではない。
#![cfg(target_os = "linux")]
use lngnb::{
    cbor::Value,
    id::{self, Id},
    record::LocalRecord,
    storage::*,
};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Cursor,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
struct Area(PathBuf);
impl Area {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lngnb-scale-test-{}",
            Id::random_knowledge().unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn data(&self) -> PathBuf {
        self.0.join("data")
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn set(body: &mut Value, name: &str, value: Value) {
    let Value::Map(fields) = body else {
        panic!("map")
    };
    fields.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
}
fn templates() -> (LocalRecord, LocalRecord, ed25519_dalek::SigningKey) {
    let spec = include_str!("../docs/specification-v1.0.0.md");
    let part = spec
        .split("## 付録A13 Record・IDの固定計算例")
        .nth(1)
        .unwrap()
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    let v: Json = serde_json::from_str(part).unwrap();
    let record = |name: &str| {
        LocalRecord::check(&unhex(v[name]["envelope_cbor_hex"].as_str().unwrap()), None).unwrap()
    };
    (
        record("genesis"),
        record("revision"),
        ed25519_dalek::SigningKey::from_bytes(
            &unhex(v["seed_hex"].as_str().unwrap()).try_into().unwrap(),
        ),
    )
}
fn id_digest(mut ids: Vec<[u8; 32]>) -> String {
    ids.sort();
    let mut hash = Sha256::new();
    hash.update(b"lngnb:scale-probe-ids:1\0");
    for id in ids {
        hash.update(id);
    }
    data_encoding::HEXLOWER.encode(&hash.finalize())
}
fn metadata(area: &Area, knowledge: u32) -> Json {
    let (g, r, key) = templates();
    let mut records = Vec::new();
    for i in 0..knowledge {
        let mut body = g.body().clone();
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        set(&mut body, "knowledge_id", Value::Bytes(k.to_vec()));
        let genesis = LocalRecord::sign(body, &key).unwrap();
        let gid = genesis.id();
        records.push(genesis);
        let mut revisions: Vec<Id> = Vec::new();
        for j in 0..10usize {
            let mut body = r.body().clone();
            set(&mut body, "knowledge_id", Value::Bytes(k.to_vec()));
            set(
                &mut body,
                "genesis_record_id",
                Value::Bytes(gid.bytes.to_vec()),
            );
            let mut parents = match j {
                0 => vec![],
                8 => vec![revisions[3]],
                9 => vec![revisions[7], revisions[8]],
                _ => vec![revisions[j - 1]],
            };
            parents.sort_by_key(|p| p.bytes);
            set(
                &mut body,
                "parents",
                Value::Array(
                    parents
                        .iter()
                        .map(|p| Value::Bytes(p.bytes.to_vec()))
                        .collect(),
                ),
            );
            let Value::Map(fields) = &mut body else {
                unreachable!()
            };
            let metadata = &mut fields.iter_mut().find(|(k, _)| k == "metadata").unwrap().1;
            set(
                metadata,
                "titles",
                Value::Map(vec![(
                    "en".into(),
                    Value::Text(format!("scale {i} revision {j}")),
                )]),
            );
            let revision = LocalRecord::sign(body, &key).unwrap();
            revisions.push(revision.id());
            records.push(revision);
        }
    }
    let n = records.len() as u64;
    let digest = id_digest(records.iter().map(|r| r.id().bytes).collect());
    let bytes: u64 = records.iter().map(|r| r.bytes().len() as u64).sum();
    let limits = Limits {
        session_records: n.max(Limits::default().session_records),
        ..Limits::default()
    };
    let mut writer = RecordStore::initialize(&area.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    for record in records.iter().rev() {
        writer.insert(record).unwrap();
    }
    writer.finish().unwrap();
    let fixture = json!({"format":"lngnb-storage-scale-test-1","knowledge":knowledge,"records":n,"record_bytes":bytes,"id_digest":digest});
    std::fs::write(area.0.join("fixture.json"), fixture.to_string()).unwrap();
    fixture
}
fn peak_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|s| {
            s.strip_prefix("VmHWM:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
        })
        .unwrap()
}
fn state(path: &Path) -> (i64, i64, i64) {
    let c = rusqlite::Connection::open_with_flags(
        path.join("database.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    c.query_row("SELECT (SELECT generation FROM storage_state),(SELECT count(*) FROM evaluation_nodes),(SELECT count(*) FROM evaluation_work)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
}
fn worker(root: &Path) {
    // 子プロセスは、この試験自身が作った一時fixtureにだけ接続する。
    assert_eq!(root.canonicalize().unwrap(), root);
    assert_eq!(
        root.parent().unwrap(),
        std::env::temp_dir().canonicalize().unwrap()
    );
    assert!(
        root.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("lngnb-scale-test-")
    );
    let fixture: Json =
        serde_json::from_slice(&std::fs::read(root.join("fixture.json")).unwrap()).unwrap();
    assert_eq!(fixture["format"], "lngnb-storage-scale-test-1");
    let total = fixture["records"].as_u64().unwrap();
    let knowledge = fixture["knowledge"].as_u64().unwrap();
    assert!((1..=1000).contains(&knowledge));
    assert_eq!(total, knowledge * 11);
    let data = root.join("data");
    let limits = Limits {
        scan_records: (total - 1).min(Limits::default().scan_records),
        ..Limits::default()
    };
    let initial = state(&data);
    let before = Instant::now();
    assert!(matches!(
        RecordStore::open(&data, limits),
        Err(StorageError::BudgetExceeded)
    ));
    let rejected_ms = before.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(state(&data), initial);
    let eval = EvaluationLimits {
        records: total.max(EvaluationLimits::default().records),
        ..EvaluationLimits::default()
    };
    let work = LocalStartupBudget {
        inspection: InspectionBudget {
            records: 128,
            ..InspectionBudget::default()
        },
        records: EvaluationInputBudget {
            records: 128.min(total / 2),
            ..EvaluationInputBudget::default()
        },
        ..LocalStartupBudget::default()
    };
    let before = Instant::now();
    let mut startup = LocalStartup::open(&data, limits).unwrap();
    let mut inject = false;
    let mut rejected = false;
    let mut paused = false;
    let mut phases: BTreeMap<&str, (u64, f64)> = BTreeMap::new();
    let mut snapshot = None;
    for _ in 0..3000 {
        let old = state(&data);
        let step = Instant::now();
        let result = startup.step(
            if inject {
                EvaluationLimits { records: 1, ..eval }
            } else {
                eval
            },
            work,
        );
        let ms = step.elapsed().as_secs_f64() * 1000.0;
        if inject {
            assert!(matches!(result, Err(StorageError::BudgetExceeded)));
            assert_eq!(state(&data), old);
            rejected = true;
            inject = false;
            continue;
        }
        let progress = result.unwrap();
        let tag = match &progress {
            LocalStartupProgress::Inspection(_) => "inspection",
            LocalStartupProgress::Records(_) => "record_input",
            LocalStartupProgress::Blobs(_) => "blob_input",
            LocalStartupProgress::Evaluation(_) => "evaluation",
            LocalStartupProgress::Ready => "ready",
        };
        let p = phases.entry(tag).or_default();
        p.0 += 1;
        p.1 = p.1.max(ms);
        match progress {
            LocalStartupProgress::Inspection(p) if p.checks_complete && !rejected => {
                inject = true;
            }
            LocalStartupProgress::Records(p) if !p.complete && !paused => {
                startup.pause().unwrap();
                startup = LocalStartup::open(&data, limits).unwrap();
                paused = true;
            }
            LocalStartupProgress::Evaluation(p) if p.processed_complete => {
                assert!(p.validation_complete);
                snapshot = p.snapshot;
                break;
            }
            _ => (),
        }
    }
    assert!(rejected && paused);
    let snapshot = snapshot.expect("bounded steps must complete");
    assert!(snapshot.committed);
    assert_eq!(snapshot.records.len() as u64, total);
    assert!(
        snapshot
            .records
            .iter()
            .all(|r| r.validation == Validation::Valid && r.reason.is_none())
    );
    assert_eq!(
        snapshot
            .records
            .iter()
            .filter(|r| r.payload_status == Some(PayloadStatus::Missing))
            .count() as u64,
        knowledge * 10
    );
    assert_eq!(
        id_digest(snapshot.records.iter().map(|r| r.record_id.bytes).collect()),
        fixture["id_digest"]
    );
    startup.into_writer().unwrap().finish().unwrap();
    let elapsed_ms = before.elapsed().as_secs_f64() * 1000.0;
    let report = json!({"scope":"metadata_only_preliminary","fixture":fixture,"normal_open_scan_records":limits.scan_records,"evaluation_total_limit":eval.records,"input_step_records":work.records.records,"evaluation_step_nodes":work.evaluation.nodes,"rejected_open_ms":rejected_ms,"startup_ms":elapsed_ms,"phases":phases,"worker_peak_kib":peak_kib(),"policy_retry":rejected,"pause_reopen":paused});
    println!("LNGNB_SCALE_REPORT={report}");
}
#[test]
fn metadata_scale_probe() {
    if let Some(root) = std::env::var_os("LNGNB_SCALE_WORKER") {
        worker(Path::new(&root));
        return;
    }
    let sizes = std::env::var("LNGNB_SCALE_KNOWLEDGE").unwrap_or_else(|_| "4,16".into());
    let sizes: Vec<u32> = sizes.split(',').map(|s| s.parse().unwrap()).collect();
    assert!(!sizes.is_empty() && sizes.len() <= 3 && sizes.iter().all(|n| (1..=1000).contains(n)));
    for n in sizes {
        let area = Area::new();
        let fixture = metadata(&area, n);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "metadata_scale_probe",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("LNGNB_SCALE_WORKER", &area.0)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = stdout
            .lines()
            .find_map(|s| s.split_once("LNGNB_SCALE_REPORT=").map(|(_, value)| value))
            .expect("worker report");
        let v: Json = serde_json::from_str(report).unwrap();
        assert_eq!(v["fixture"], fixture);
        assert!(v["worker_peak_kib"].as_u64().unwrap() > 0);
        println!("LNGNB_SCALE_REPORT={report}");
    }
}
fn inspected(path: &Path, limits: Limits) -> RecordStore {
    let mut check = RecordInspection::open(path, limits).unwrap();
    for _ in 0..100 {
        if check
            .step(InspectionBudget {
                blob_files: 8,
                blob_bytes: 8 * 1024 * 1024,
                ..InspectionBudget::default()
            })
            .unwrap()
            .checks_complete
        {
            return check.into_store().unwrap();
        }
    }
    panic!("blob inspection did not complete");
}
fn review(store: RecordStore) -> EvidenceRecoveryReview {
    let generation = store.generation().unwrap();
    store
        .confirm_evidence_recovery(
            generation,
            "この試験が作った保持本文と台帳を再検査",
            "公開・実デバイス・電源断の検証は対象外",
            EvaluationLimits::default(),
        )
        .unwrap()
}
#[test]
fn body_volume_above_default_requires_explicit_scan_budget_before_local_resume() {
    let area = Area::new();
    let mib = 1024 * 1024;
    let limits = Limits {
        max_blob_bytes: mib,
        session_bytes: 80 * mib,
        ..Limits::default()
    };
    let mut writer = RecordStore::initialize(&area.data(), limits)
        .unwrap()
        .begin()
        .unwrap();
    for i in 0..65u8 {
        let body = vec![i; mib as usize];
        writer
            .put_blob(id::blob_id(&body), Cursor::new(body))
            .unwrap();
    }
    // 異常終了の印を残す。実際のprocess kill/電源断試験とはしない。
    drop(writer);
    assert!(matches!(
        RecordStore::open(&area.data(), Limits::default()),
        Err(StorageError::BudgetExceeded)
    ));
    let before = Instant::now();
    let store = inspected(&area.data(), Limits::default());
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    let scan_ms = before.elapsed().as_secs_f64() * 1000.0;
    let confirmation = review(store);
    let store = inspected(&area.data(), Limits::default());
    // 起動再検査自体も世代を進めるため、古い確認を再開資格として使わない。
    assert!(matches!(
        store.resume_local_writes(confirmation, "ローカル再開", EvaluationLimits::default()),
        Err(StorageError::StaleRecoveryReview)
    ));
    let store = inspected(&area.data(), Limits::default());
    let generation = store.generation().unwrap();
    let confirmation = store
        .confirm_evidence_recovery(
            generation,
            "全保持本文を確認",
            "正式環境の試験ではない",
            EvaluationLimits::default(),
        )
        .unwrap();
    // 確認後の通常openは全量64 MiBで拒否される。再検査後に同じ確認は使わない。
    assert!(matches!(
        RecordStore::open(&area.data(), Limits::default()),
        Err(StorageError::BudgetExceeded)
    ));
    let adjusted = Limits {
        scan_blob_bytes: 65 * mib,
        ..Limits::default()
    };
    let store = RecordStore::open(&area.data(), adjusted).unwrap();
    // read-only診断と全量起動検査は履歴世代を変えず、同じ確認を照合できる。
    let before = Instant::now();
    store
        .resume_local_writes(
            confirmation,
            "未確定制限を確認、残る保存障害なし。ローカルのみ再開",
            EvaluationLimits::default(),
        )
        .unwrap()
        .finish()
        .unwrap();
    let resume_ms = before.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(
        RecordStore::open(&area.data(), adjusted)
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::Clean
    );
    println!(
        "LNGNB_SCALE_REPORT={}",
        json!({"scope":"blob_volume_preliminary","blob_files":65,"bytes":65*mib,"inspection_step_bytes":8*mib,"default_scan_bytes":Limits::default().scan_blob_bytes,"adjusted_scan_bytes":adjusted.scan_blob_bytes,"split_inspection_ms":scan_ms,"explicit_resume_ms":resume_ms})
    );
}

#[test]
fn ledger_scale_probe() {
    let sizes = std::env::var("LNGNB_LEDGER_PROBE_HOLDS").unwrap_or_else(|_| "64,256".into());
    let sizes: Vec<u32> = sizes.split(',').map(|s| s.parse().unwrap()).collect();
    assert!(
        !sizes.is_empty() && sizes.len() <= 3 && sizes.iter().all(|n| (1..=100_000).contains(n))
    );
    for n in sizes {
        let area = Area::new();
        let mut writer = RecordStore::initialize(&area.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        let blob = id::blob_id(b"scale ledger payload");
        writer
            .put_blob(blob, Cursor::new(b"scale ledger payload"))
            .unwrap();
        // 新規の試験領域だけに、実装の台帳形式と整合する履歴を一括生成する。
        // 受付/保存処理の性能・耐久性の測定には使わず、照合SQLの入力規模を固定する。
        let mut c = rusqlite::Connection::open(area.data().join("database.sqlite")).unwrap();
        assert_eq!(
            c.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        let tx = c.transaction().unwrap();
        let generation: i64 = tx
            .query_row("SELECT generation FROM storage_state", [], |r| r.get(0))
            .unwrap();
        let mut digest = Sha256::new();
        {
            let mut holds=tx.prepare("INSERT INTO temporary_blob_holds(hold_id,blob_id,created_at,expires_at,generation) VALUES(?1,?2,?3,?4,?5)").unwrap();
            let mut history=tx.prepare("INSERT INTO history(generation,namespace,target,old_state,new_state,actor,reason,rules,at) SELECT ?1,namespace,?2,'blob_recorded','blob_staged_local_only','test_fixture',?3,'lngnb-validation-1','2026-10-23T00:00:00.000Z' FROM storage_state WHERE singleton=1").unwrap();
            for i in 0..n {
                let mut hold = [0x53u8; 32];
                hold[..4].copy_from_slice(&i.to_be_bytes());
                let g = generation + i64::from(i) + 1;
                let reason = format!(
                    "temporary_local_blob_promise:{}:0:253402300799",
                    data_encoding::HEXLOWER.encode(&hold)
                );
                holds
                    .execute(rusqlite::params![&hold, &blob.bytes, 0, 253402300799i64, g])
                    .unwrap();
                history
                    .execute(rusqlite::params![g, &blob.bytes, reason])
                    .unwrap();
                digest.update(hold);
            }
        }
        tx.execute(
            "UPDATE storage_state SET generation=?1 WHERE singleton=1",
            [generation + i64::from(n)],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(c);
        writer.finish().unwrap();
        let before = state(&area.data());
        let sql_low = Limits {
            sql_inspection: SqlInspectionBudget {
                callbacks: 1,
                ..SqlInspectionBudget::default()
            },
            ..Limits::default()
        };
        assert!(matches!(
            RecordStore::open(&area.data(), sql_low),
            Err(StorageError::BudgetExceeded)
        ));
        assert_eq!(state(&area.data()), before);
        let timer = Instant::now();
        let store = RecordStore::open(&area.data(), Limits::default()).unwrap();
        let open_ms = timer.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
        let timer = Instant::now();
        let protection = store.blob_protection(ProtectionBudget::default()).unwrap();
        let protection_ms = timer.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(protection.blobs.len(), 1);
        assert_eq!(protection.blobs[0].temporary_holds.len() as u32, n);
        assert!(protection.blobs[0].manual_retention_recorded);
        assert_eq!(state(&area.data()), before);
        let c = rusqlite::Connection::open_with_flags(
            area.data().join("database.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let history: i64 = c
            .query_row("SELECT count(*) FROM history", [], |r| r.get(0))
            .unwrap();
        println!(
            "LNGNB_SCALE_REPORT={}",
            json!({"scope":"synthetic_ledger_read_preliminary","holds":n,"history_rows":history,"hold_id_digest":data_encoding::HEXLOWER.encode(&digest.finalize()),"open_ms":open_ms,"protection_ms":protection_ms,"default_sql_callbacks":Limits::default().sql_inspection.callbacks,"policy_retry":true})
        );
    }
}
