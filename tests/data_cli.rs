//! R01/R24/R28/R30: 実CLIの初期化・管理診断と保全。A13公開fixtureのみ。
#![cfg(target_os = "linux")]
use lngnb::{
    id::{self, Id},
    record::LocalRecord,
    storage::{Limits, RecordInspection, RecordStore},
};
use rusqlite::Connection;
use std::{
    fs,
    io::Cursor,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "lngnb-data-cli-{}",
            Id::random_knowledge().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
    fn data(&self) -> PathBuf {
        self.0.join("data")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn cli(action: &str, path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["data", action, "--data-dir"])
        .arg(path)
        .output()
        .unwrap()
}
fn success(out: Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
    String::from_utf8(out.stdout).unwrap()
}
fn reject(out: Output, code: i32) {
    assert_eq!(out.status.code(), Some(code));
    assert!(out.stdout.is_empty());
}
fn snapshot(path: &Path) -> Vec<(String, Vec<String>)> {
    let c = Connection::open(path.join("database.sqlite")).unwrap();
    let names = c
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut s = c
                .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
                .unwrap();
            let cols = s.column_count();
            let rows = s
                .query_map([], |r| {
                    (0..cols)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .map(|r| format!("{:?}", r.unwrap()))
                .collect();
            (name, rows)
        })
        .collect()
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(
        include_str!("../docs/specification-v1.0.0.md")
            .split("## 付録A13 ")
            .nth(1)
            .unwrap()
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap(),
    )
    .unwrap()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn record(name: &str) -> LocalRecord {
    LocalRecord::check(
        &unhex(fixture()[name]["envelope_cbor_hex"].as_str().unwrap()),
        None,
    )
    .unwrap()
}

#[test]
fn explicit_initialization_and_status_do_not_overwrite_or_change_healthy_state() {
    let t = Temp::new();
    success(cli("init", &t.data()));
    assert_eq!(fs::metadata(t.data()).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(
        fs::metadata(t.data().join("database.sqlite"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    let before = snapshot(&t.data());
    let text = success(cli("status", &t.data()));
    for field in [
        "startup_state: clean\n",
        "records: 0\n",
        "diagnostic_valid: 0\n",
        "payload_missing: 0\n",
    ] {
        assert!(text.contains(field));
    }
    assert_eq!(snapshot(&t.data()), before);
    reject(cli("init", &t.data()), 1);
    assert_eq!(snapshot(&t.data()), before);
    let empty = t.0.join("empty");
    fs::create_dir(&empty).unwrap();
    reject(cli("init", &empty), 1);
    assert_eq!(fs::read_dir(empty).unwrap().count(), 0);
    let partial = t.0.join("partial");
    fs::create_dir(&partial).unwrap();
    fs::write(partial.join("database.sqlite"), b"incomplete public test").unwrap();
    reject(cli("init", &partial), 1);
    reject(cli("status", &partial), 1);
    assert_eq!(
        fs::read(partial.join("database.sqlite")).unwrap(),
        b"incomplete public test"
    );
}

#[test]
fn diagnoses_missing_dependencies_and_inspection_without_clearing_manual_wait() {
    let t = Temp::new();
    success(cli("init", &t.data()));
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    w.insert(&record("revision")).unwrap();
    w.finish().unwrap();
    let before = snapshot(&t.data());
    let text = success(cli("status", &t.data()));
    assert!(text.contains("diagnostic_pending: 1\n") && text.contains("payload_missing: 1\n"));
    assert_eq!(snapshot(&t.data()), before);
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    w.insert(&record("genesis")).unwrap();
    drop(w);
    let before = snapshot(&t.data());
    let text = success(cli("status", &t.data()));
    assert!(
        text.contains("startup_state: manual_review_required\n")
            && text.contains("diagnostic_valid: 2\n")
    );
    assert_eq!(snapshot(&t.data()), before);
    let t2 = Temp::new();
    success(cli("init", &t2.data()));
    RecordInspection::open(&t2.data(), Limits::default())
        .unwrap()
        .pause()
        .unwrap();
    let before = snapshot(&t2.data());
    let text = success(cli("status", &t2.data()));
    assert!(text.contains("startup_state: inspection_pending\n"));
    assert_eq!(snapshot(&t2.data()), before);
    // A13公開試験seedのみ。真正な共有本文と異なる宣言長を独立に診断する。
    let t3 = Temp::new();
    success(cli("init", &t3.data()));
    let f = fixture();
    let body = unhex(f["blob_hex"].as_str().unwrap());
    let key = ed25519_dalek::SigningKey::from_bytes(
        &unhex(f["seed_hex"].as_str().unwrap()).try_into().unwrap(),
    );
    let mut bad = record("revision").body().clone();
    if let lngnb::cbor::Value::Map(fields) = &mut bad {
        let (_, lngnb::cbor::Value::Map(p)) =
            fields.iter_mut().find(|(k, _)| k == "payload").unwrap()
        else {
            panic!()
        };
        p.iter_mut().find(|(k, _)| k == "byte_length").unwrap().1 =
            lngnb::cbor::Value::Int(body.len() as i64 + 1);
    }
    let mut w = RecordStore::open(&t3.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    w.insert(&record("genesis")).unwrap();
    w.insert(&record("revision")).unwrap();
    w.insert(&LocalRecord::sign(bad, &key).unwrap()).unwrap();
    w.put_blob(id::blob_id(&body), Cursor::new(&body)).unwrap();
    w.finish().unwrap();
    let before = snapshot(&t3.data());
    let text = success(cli("status", &t3.data()));
    for field in [
        "diagnostic_valid: 2\n",
        "diagnostic_invalid: 1\n",
        "payload_verified: 1\n",
        "payload_unavailable: 1\n",
    ] {
        assert!(text.contains(field));
    }
    assert_eq!(snapshot(&t3.data()), before); // 不正診断を既知不正へ永続確定したとはしない。
}

#[test]
fn newly_missing_retained_blob_records_stop_and_never_repairs_or_resumes() {
    let t = Temp::new();
    success(cli("init", &t.data()));
    let body = b"public retained test";
    let id = id::blob_id(body);
    let mut w = RecordStore::open(&t.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    w.put_blob(id, Cursor::new(body)).unwrap();
    w.finish().unwrap();
    let raw = fs::read(
        t.data()
            .join("blobs")
            .join(data_encoding::HEXLOWER.encode(&id.bytes)),
    )
    .unwrap();
    fs::remove_file(
        t.data()
            .join("blobs")
            .join(data_encoding::HEXLOWER.encode(&id.bytes)),
    )
    .unwrap();
    let text = success(cli("status", &t.data()));
    assert!(
        text.contains("startup_state: manual_review_required\n")
            && text.contains("missing_retained_blobs: 1\n")
    );
    let before = snapshot(&t.data());
    success(cli("status", &t.data()));
    assert_eq!(snapshot(&t.data()), before);
    fs::write(
        t.data()
            .join("blobs")
            .join(data_encoding::HEXLOWER.encode(&id.bytes)),
        raw,
    )
    .unwrap();
    fs::set_permissions(
        t.data()
            .join("blobs")
            .join(data_encoding::HEXLOWER.encode(&id.bytes)),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let text = success(cli("status", &t.data()));
    assert!(
        text.contains("startup_state: manual_review_required\n")
            && text.contains("missing_retained_blobs: 0\n")
    );
    assert!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .begin()
            .is_err()
    );
}

#[test]
fn missing_unsafe_busy_and_unsupported_inputs_never_become_initialization() {
    let t = Temp::new();
    reject(cli("status", &t.data()), 1);
    assert!(!t.data().exists());
    let bad = t.0.join("absent-parent/data");
    reject(cli("init", &bad), 3);
    assert!(!bad.exists());
    success(cli("init", &t.data()));
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    reject(cli("status", &t.data()), 1);
    drop(store);
    let link = t.0.join("link");
    symlink(t.data(), &link).unwrap();
    reject(cli("status", &link), 1);
    reject(cli("init", &link), 1);
    Connection::open(t.data().join("database.sqlite"))
        .unwrap()
        .pragma_update(None, "user_version", 10)
        .unwrap();
    let bytes = fs::read(t.data().join("database.sqlite")).unwrap();
    reject(cli("status", &t.data()), 1);
    assert_eq!(fs::read(t.data().join("database.sqlite")).unwrap(), bytes);
    reject(cli("init", &t.data()), 1);
    assert_eq!(fs::read(t.data().join("database.sqlite")).unwrap(), bytes);
}

#[test]
fn concurrent_initialization_and_output_failures_preserve_confirmed_data() {
    let t = Temp::new();
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
            Command::new(env!("CARGO_BIN_EXE_lngnb"))
                .args(["data", "init", "--data-dir"])
                .arg(t.data())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    assert_eq!(outputs.iter().filter(|o| o.status.success()).count(), 1);
    assert_eq!(
        outputs
            .iter()
            .filter(|o| o.status.code() == Some(1))
            .count(),
        1
    );
    success(cli("status", &t.data()));
    let t2 = Temp::new();
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["data", "init", "--data-dir"])
        .arg(t2.data())
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("初期化は完了")
    );
    success(cli("status", &t2.data()));
    let before = snapshot(&t2.data());
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["data", "status", "--data-dir"])
        .arg(t2.data())
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(snapshot(&t2.data()), before);
}
