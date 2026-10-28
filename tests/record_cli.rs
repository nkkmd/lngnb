//! 完成署名Recordを実IPCへ送るCLI結合。A13公開fixtureのみ。
#![cfg(target_os = "linux")]
use lngnb::{
    record::LocalRecord,
    storage::{Limits, RecordStore, admin_transport::Listener},
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::Duration,
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lngnb-record-cli-{}",
            lngnb::id::Id::random_knowledge().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn data(&self) -> PathBuf {
        self.0.join("data")
    }
    fn input(&self) -> PathBuf {
        self.0.join("record.cbor")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> LocalRecord {
    let spec = include_str!("../docs/specification-v1.0.0.md");
    let json = spec
        .split("## 付録A13 Record・IDの固定計算例")
        .nth(1)
        .unwrap()
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    let f: serde_json::Value = serde_json::from_str(json).unwrap();
    let hex = f["genesis"]["envelope_cbor_hex"].as_str().unwrap();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    LocalRecord::check(&bytes, None).unwrap()
}
fn cli(data: &Path, record: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["record", "submit", "--data-dir"])
        .arg(data)
        .arg("--record")
        .arg(record)
        .output()
        .unwrap()
}
#[test]
fn submit_cli_preserves_inputs_verifies_commits_and_handles_same_record_again() {
    let temp = Temp::new();
    let record = fixture();
    fs::write(temp.input(), record.bytes()).unwrap();
    let before = fs::read(temp.input()).unwrap();
    let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
    let mut listener = Listener::bind_writer(
        store.begin().unwrap(),
        lngnb::cbor::MAX_RECORD,
        Duration::from_secs(5),
    )
    .unwrap();
    let worker = thread::spawn(move || {
        for _ in 0..2 {
            listener.accept().unwrap().store_record().unwrap();
        }
        listener.close_writer().unwrap().finish().unwrap();
    });
    for inserted in [true, false] {
        let out = cli(&temp.data(), &temp.input());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.contains(&record.id().to_string()));
        assert!(text.contains(&format!("inserted: {inserted}")));
        assert!(text.contains("公開・正常停止・復旧完了の判定ではありません"));
    }
    worker.join().unwrap();
    assert_eq!(fs::read(temp.input()).unwrap(), before);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
}

#[test]
fn invalid_unsafe_and_oversized_files_never_create_storage_or_echo_contents() {
    let temp = Temp::new();
    for bytes in [
        b"private test input".to_vec(),
        vec![0; lngnb::cbor::MAX_RECORD + 1],
    ] {
        fs::write(temp.input(), &bytes).unwrap();
        let out = cli(&temp.data(), &temp.input());
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("private test input"));
        assert_eq!(fs::read(temp.input()).unwrap(), bytes);
        assert!(!temp.data().exists());
    }
    fs::write(temp.input(), fixture().bytes()).unwrap();
    let link = temp.0.join("link");
    symlink(temp.input(), &link).unwrap();
    assert_eq!(cli(&temp.data(), &link).status.code(), Some(1));
    let hard = temp.0.join("hard");
    fs::hard_link(temp.input(), &hard).unwrap();
    assert_eq!(cli(&temp.data(), &temp.input()).status.code(), Some(1));
    fs::remove_file(&hard).unwrap();
    let out = cli(&temp.data(), &temp.input());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!temp.data().exists());
}

#[test]
fn malformed_reply_returns_unknown_outcome_without_direct_storage_fallback() {
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
        os::unix::net::UnixListener,
    };
    let temp = Temp::new();
    let record = fixture();
    fs::write(temp.input(), record.bytes()).unwrap();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let endpoint = temp.data().join("admin.sock");
    let dir = fs::File::open(temp.data()).unwrap();
    let anchored = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join("admin.sock");
    let listener = UnixListener::bind(&anchored).unwrap();
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut header = [0; 8];
        stream.read_exact(&mut header).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(header[4..].try_into().unwrap()) as usize];
        stream.read_exact(&mut bytes).unwrap();
        stream
            .write_all(&[b'L', b'N', b'A', 1, 255, 255, 255, 255])
            .unwrap();
    });
    let out = cli(&temp.data(), &temp.input());
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("保存済みの可能性"));
    worker.join().unwrap();
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert!(store.record(record.id()).unwrap().is_none());
    assert_eq!(fs::read(temp.input()).unwrap(), record.bytes());
}

fn probe_cli(data: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "probe", "--data-dir"])
        .arg(data)
        .output()
        .unwrap()
}

#[test]
fn probe_cli_sends_no_request_and_preserves_manual_wait() {
    let temp = Temp::new();
    let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
    drop(store.begin().unwrap());
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    let before = store.startup_state().unwrap();
    let mut listener =
        Listener::bind(store, lngnb::cbor::MAX_RECORD, Duration::from_secs(5)).unwrap();
    let out = probe_cli(&temp.data());
    assert!(out.status.success(), "{:?}", out.stderr);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("保存要求は送っていません"));
    assert!(text.contains("受理準備・プロトコル対応・保存状態"));
    let mut connection = listener.accept().unwrap();
    assert!(connection.receive().is_err());
    assert_eq!(connection.store().startup_state().unwrap(), before);
    drop(connection);
    let store = listener.close().unwrap();
    assert_eq!(store.startup_state().unwrap(), before);
    assert!(store.record(fixture().id()).unwrap().is_none());
}

#[test]
fn probe_cli_missing_and_unsafe_targets_are_preserved_without_fallback() {
    let temp = Temp::new();
    let out = probe_cli(&temp.data());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!temp.data().exists());
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let path = temp.data().join("admin.sock");
    fs::write(&path, b"preserve").unwrap();
    let out = probe_cli(&temp.data());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read(path).unwrap(), b"preserve");
}
