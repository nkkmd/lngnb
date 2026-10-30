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
    named_fixture("genesis")
}
fn fixture_data() -> serde_json::Value {
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
    serde_json::from_str(json).unwrap()
}
fn named_fixture(kind: &str) -> LocalRecord {
    let f = fixture_data();
    let hex = f[kind]["envelope_cbor_hex"].as_str().unwrap();
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

struct Server {
    child: std::process::Child,
    log: PathBuf,
    errors: PathBuf,
}
impl Server {
    fn start(temp: &Temp) -> Self {
        Self::configured(temp, &[])
    }
    fn configured(temp: &Temp, options: &[&str]) -> Self {
        let log = temp.0.join("server-output");
        let errors = temp.0.join("server-errors");
        let child = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data())
            .args(options)
            .stdout(fs::File::create(&log).unwrap())
            .stderr(fs::File::create(&errors).unwrap())
            .spawn()
            .unwrap();
        let mut server = Self { child, log, errors };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if fs::read_to_string(&server.log).unwrap().contains('\n') {
                return server;
            }
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "{:?}",
                fs::read_to_string(&server.errors)
            );
            assert!(
                std::time::Instant::now() < deadline,
                "server did not become ready"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn signal(&mut self, signal: &str) {
        assert!(
            Command::new("kill")
                .arg(signal)
                .arg(self.child.id().to_string())
                .status()
                .unwrap()
                .success()
        );
    }
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(std::time::Instant::now() < deadline, "server did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn send_raw(data: &Path, bytes: &[u8]) -> std::os::unix::net::UnixStream {
    use std::{io::Write, os::fd::AsRawFd, os::unix::net::UnixStream};
    let dir = fs::File::open(data).unwrap();
    let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join("admin.sock");
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(bytes).unwrap();
    stream
}
fn raw_record() -> Vec<u8> {
    let record = fixture();
    let mut bytes = b"LNA\x01".to_vec();
    bytes.extend_from_slice(&(record.bytes().len() as u32).to_be_bytes());
    bytes.extend_from_slice(record.bytes());
    bytes
}
fn assert_review(temp: &Temp, stored: bool) {
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::NeedsReview
    );
    assert_eq!(store.record(fixture().id()).unwrap().is_some(), stored);
}

#[test]
fn foreground_server_probes_submits_stops_and_restarts_without_losing_records() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    fs::write(temp.input(), fixture().bytes()).unwrap();
    let mut server = Server::start(&temp);
    assert!(probe_cli(&temp.data()).status.success());
    for _ in 0..2 {
        assert!(cli(&temp.data(), &temp.input()).status.success());
    }
    assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
    server.signal("-TERM");
    assert!(server.wait().success());
    assert!(
        fs::read_to_string(&server.log)
            .unwrap()
            .contains("正常終了しました")
    );
    assert!(!temp.data().join("admin.sock").exists());
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
    assert!(store.record(fixture().id()).unwrap().is_some());
    drop(store);
    let mut server = Server::start(&temp);
    server.signal("-INT");
    assert!(server.wait().success());
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
    assert!(store.record(fixture().id()).unwrap().is_some());
}

#[test]
fn foreground_server_refuses_missing_manual_wait_and_existing_endpoint() {
    for mode in 0..3 {
        let temp = Temp::new();
        if mode > 0 {
            let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
            if mode == 1 {
                drop(store.begin().unwrap());
            } else {
                drop(store);
                fs::write(temp.data().join("admin.sock"), b"preserve").unwrap();
            }
        }
        let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stdout.is_empty());
        if mode == 0 {
            assert!(!temp.data().exists());
        } else {
            assert_review(&temp, false);
            if mode == 2 {
                assert_eq!(
                    fs::read(temp.data().join("admin.sock")).unwrap(),
                    b"preserve"
                );
            }
        }
    }
}

#[test]
fn stop_during_partial_request_does_not_finish_and_restart_cannot_clear_review() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    // Linuxの送信queueが空になるまで待ち、最初のbyte消費後に停止を要求する。
    // 固定sleepでaccept/停止の順序を推測しない。公開試験入力だけを使う。
    let script = r#"import fcntl,os,signal,socket,struct,sys,termios,time
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect('/proc/self/fd/'+str(fd)+'/admin.sock')
s.sendall(b'L')
deadline=time.monotonic()+5
while struct.unpack('i',fcntl.ioctl(s,termios.TIOCOUTQ,struct.pack('i',0)))[0]:
 if time.monotonic()>deadline: raise RuntimeError('first byte not consumed')
 time.sleep(0.01)
os.kill(int(sys.argv[2]),signal.SIGTERM)
s.close()
os.close(fd)
"#;
    let status = Command::new(std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap())
        .args(["-c", script])
        .arg(temp.data())
        .arg(server.child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(server.wait().code(), Some(3));
    assert_review(&temp, false);
    assert!(temp.data().join("admin.sock").exists());
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_review(&temp, false);
}

#[test]
fn lost_response_keeps_committed_record_and_forbids_normal_shutdown() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    use std::io::Write;
    let mut stream = send_raw(&temp.data(), b"");
    // 送信前に受信側を閉じ、commit後の応答を確実に失敗させる。
    stream.shutdown(std::net::Shutdown::Read).unwrap();
    stream.write_all(&raw_record()).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(server.wait().code(), Some(3));
    drop(stream);
    assert_review(&temp, true);
    assert!(temp.data().join("admin.sock").exists());
    assert!(
        !fs::read_to_string(&server.log)
            .unwrap()
            .contains("正常終了しました")
    );
}

#[test]
fn storage_failure_and_replaced_socket_never_become_clean_on_stop() {
    for sql in [true, false] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        let mut server = Server::start(&temp);
        if sql {
            let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
            conn.execute_batch("CREATE TRIGGER fail_admin BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
            drop(conn);
            drop(send_raw(&temp.data(), &raw_record()));
        } else {
            fs::remove_file(temp.data().join("admin.sock")).unwrap();
            fs::write(temp.data().join("admin.sock"), b"replacement").unwrap();
            server.signal("-TERM");
        }
        assert_eq!(server.wait().code(), Some(3));
        assert_review(&temp, false);
        if !sql {
            assert_eq!(
                fs::read(temp.data().join("admin.sock")).unwrap(),
                b"replacement"
            );
        }
    }
}

#[test]
fn killed_server_leaves_running_mark_and_socket() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    server.child.kill().unwrap();
    assert!(!server.wait().success());
    assert_review(&temp, false);
    assert!(temp.data().join("admin.sock").exists());
}

#[test]
fn ready_output_failure_preserves_unclean_state_and_endpoint() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_review(&temp, false);
    assert!(temp.data().join("admin.sock").exists());
}

#[test]
fn shutdown_output_failure_is_distinct_from_uncertain_storage() {
    use std::io::{BufRead, BufReader};
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut child = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("管理socketを開きました"));
    drop(reader); // 正常停止後の出力だけを失敗させる。
    let mut server = Server {
        child,
        log: temp.0.join("unused-output"),
        errors: temp.0.join("unused-errors"),
    };
    server.signal("-TERM");
    assert_eq!(server.wait().code(), Some(1));
    assert!(!temp.data().join("admin.sock").exists());
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
}

#[test]
fn failed_final_clean_commit_is_not_reported_as_normal_shutdown() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_finish BEFORE UPDATE ON storage_state WHEN NEW.state='clean' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    drop(conn);
    server.signal("-TERM");
    assert_eq!(server.wait().code(), Some(3));
    assert!(!temp.data().join("admin.sock").exists());
    assert_review(&temp, false);
    assert!(
        !fs::read_to_string(&server.log)
            .unwrap()
            .contains("正常終了しました")
    );
}

#[test]
fn invalid_runtime_options_fail_before_creating_or_changing_data() {
    let temp = Temp::new();
    for initialized in [false, true] {
        if initialized {
            drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        }
        for args in [
            vec!["--request-timeout-ms", "0"],
            vec!["--request-timeout-ms", "30001"],
            vec!["--max-new-records", "10001"],
            vec!["--max-diagnostic-records", "0"],
            vec!["--startup-records-per-step", "0"],
            vec!["--startup-record-bytes-per-step", "0"],
            vec!["--startup-blob-bytes-per-step", "0"],
            vec!["--startup-blob-targets-per-step", "0"],
            vec!["--startup-record-edges-per-step", "0"],
            vec!["--startup-evaluation-records-per-step", "0"],
            vec!["--startup-record-input-timeout-ms", "0"],
            vec!["--startup-record-input-timeout-ms", "60001"],
            vec!["--startup-record-input-timeout-ms", "private"],
            vec!["--startup-record-input-timeout-ms", "01"],
            vec![
                "--startup-record-input-timeout-ms",
                "1",
                "--startup-record-input-timeout-ms",
                "2",
            ],
            vec!["--startup-blob-input-timeout-ms", "0"],
            vec!["--startup-blob-input-timeout-ms", "60001"],
            vec!["--startup-blob-input-timeout-ms", "private"],
            vec!["--startup-blob-input-timeout-ms", "01"],
            vec![
                "--startup-blob-input-timeout-ms",
                "1",
                "--startup-blob-input-timeout-ms",
                "2",
            ],
            vec!["--startup-evaluation-timeout-ms", "0"],
            vec!["--startup-evaluation-timeout-ms", "60001"],
            vec!["--startup-evaluation-timeout-ms", "private"],
            vec!["--startup-evaluation-timeout-ms", "01"],
            vec![
                "--startup-evaluation-timeout-ms",
                "1",
                "--startup-evaluation-timeout-ms",
                "2",
            ],
            vec!["--startup-inspection-timeout-ms", "0"],
            vec!["--startup-inspection-timeout-ms", "60001"],
            vec!["--startup-inspection-timeout-ms", "private"],
            vec!["--startup-inspection-timeout-ms", "01"],
            vec![
                "--startup-inspection-timeout-ms",
                "1",
                "--startup-inspection-timeout-ms",
                "2",
            ],
            vec!["--sql-inspection-timeout-ms", "0"],
            vec!["--sql-inspection-timeout-ms", "60001"],
            vec!["--sql-inspection-timeout-ms", "private"],
            vec!["--sql-inspection-timeout-ms", "01"],
            vec![
                "--sql-inspection-timeout-ms",
                "1",
                "--sql-inspection-timeout-ms",
                "2",
            ],
            vec!["--sql-inspection-callbacks", "0"],
            vec!["--sql-inspection-callbacks", "100001"],
            vec!["--sql-inspection-callbacks", "private"],
            vec!["--sql-inspection-callbacks", "01"],
            vec![
                "--sql-inspection-callbacks",
                "1",
                "--sql-inspection-callbacks",
                "2",
            ],
            vec!["--startup-evaluation-records-per-step", "33"],
            vec!["--startup-evaluation-records-per-step", "private"],
            vec!["--startup-evaluation-records-per-step", "01"],
            vec![
                "--startup-evaluation-records-per-step",
                "1",
                "--startup-evaluation-records-per-step",
                "2",
            ],
            vec!["--startup-record-edges-per-step", "100001"],
            vec!["--startup-record-edges-per-step", "private"],
            vec!["--startup-record-edges-per-step", "01"],
            vec![
                "--startup-record-edges-per-step",
                "1",
                "--startup-record-edges-per-step",
                "2",
            ],
            vec!["--startup-blob-targets-per-step", "10001"],
            vec!["--startup-blob-targets-per-step", "private"],
            vec!["--startup-blob-targets-per-step", "01"],
            vec![
                "--startup-blob-targets-per-step",
                "1",
                "--startup-blob-targets-per-step",
                "2",
            ],
            vec!["--startup-blob-bytes-per-step", "67108865"],
            vec!["--startup-blob-bytes-per-step", "private"],
            vec!["--startup-blob-bytes-per-step", "01"],
            vec![
                "--startup-blob-bytes-per-step",
                "1",
                "--startup-blob-bytes-per-step",
                "2",
            ],
            vec!["--startup-record-bytes-per-step", "67108865"],
            vec!["--startup-record-bytes-per-step", "private"],
            vec!["--startup-record-bytes-per-step", "01"],
            vec![
                "--startup-record-bytes-per-step",
                "1",
                "--startup-record-bytes-per-step",
                "2",
            ],
            vec!["--startup-records-per-step", "10001"],
            vec!["--startup-records-per-step", "private"],
            vec![
                "--startup-records-per-step",
                "1",
                "--startup-records-per-step",
                "2",
            ],
            vec!["--max-diagnostic-records", "10001"],
            vec!["--max-diagnostic-records", "private"],
            vec![
                "--max-diagnostic-records",
                "1",
                "--max-diagnostic-records",
                "2",
            ],
            vec!["--max-new-records", "private"],
            vec!["--max-new-records", "1", "--max-new-records", "2"],
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
                .args(["admin", "serve", "--data-dir"])
                .arg(temp.data())
                .args(args)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2));
            assert!(out.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&out.stderr).contains("private"));
            assert!(!temp.data().join("admin.sock").exists());
            if initialized {
                let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
                assert_eq!(
                    store.startup_state().unwrap(),
                    lngnb::storage::StartupState::Clean
                );
                assert_eq!(store.generation().unwrap(), 0);
            } else {
                assert!(!temp.data().exists());
            }
        }
    }
}

#[test]
fn explicit_new_record_budget_preserves_duplicates_and_resets_on_normal_restart() {
    for exhaust in [false, true] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        fs::write(temp.input(), fixture().bytes()).unwrap();
        let mut server = Server::configured(&temp, &["--max-new-records", "1"]);
        for _ in 0..2 {
            assert!(cli(&temp.data(), &temp.input()).status.success());
        }
        let revision = named_fixture("revision");
        fs::write(temp.input(), revision.bytes()).unwrap();
        if exhaust {
            assert_eq!(cli(&temp.data(), &temp.input()).status.code(), Some(3));
            assert_eq!(server.wait().code(), Some(3));
            assert_review(&temp, true);
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert!(store.record(revision.id()).unwrap().is_none());
        } else {
            server.signal("-TERM");
            assert!(server.wait().success());
            let log = fs::read_to_string(&server.log).unwrap();
            assert!(log.contains("request_timeout_ms: 30000\nmax_new_records: 1\n"));
            let mut restarted = Server::start(&temp);
            assert!(cli(&temp.data(), &temp.input()).status.success());
            restarted.signal("-TERM");
            assert!(restarted.wait().success());
            let log = fs::read_to_string(&restarted.log).unwrap();
            assert!(log.contains("request_timeout_ms: 30000\nmax_new_records: 10000\n"));
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert!(store.record(revision.id()).unwrap().is_some());
            assert_eq!(
                store.startup_state().unwrap(),
                lngnb::storage::StartupState::Clean
            );
        }
    }
}

#[test]
fn explicit_request_deadline_is_applied_and_timeout_never_becomes_clean() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::configured(&temp, &["--request-timeout-ms", "500"]);
    let stream = send_raw(&temp.data(), b"L");
    // 既定30秒ならwaitの10秒上限を超える。相手は閉じずに期限切れを待つ。
    assert_eq!(server.wait().code(), Some(3));
    drop(stream);
    assert_review(&temp, false);
    let log = fs::read_to_string(&server.log).unwrap();
    assert!(log.contains("request_timeout_ms: 500\nmax_new_records: 10000\n"));
    assert!(!log.contains("正常終了しました"));
    assert!(temp.data().join("admin.sock").exists());
}

fn status_cli(data: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "status", "--data-dir"])
        .arg(data)
        .output()
        .unwrap()
}
fn diagnostic_field(output: &Output, name: &str) -> u64 {
    let text = std::str::from_utf8(&output.stdout).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .unwrap()
        .parse()
        .unwrap()
}
#[test]
fn active_runtime_status_is_read_only_reports_limits_and_excludes_duplicate_insertions() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::configured(
        &temp,
        &["--request-timeout-ms", "5000", "--max-new-records", "2"],
    );
    let first = status_cli(&temp.data());
    assert!(first.status.success(), "{:?}", first.stderr);
    assert_eq!(diagnostic_field(&first, "session_new_records"), 0);
    assert_eq!(diagnostic_field(&first, "max_new_records"), 2);
    assert_eq!(diagnostic_field(&first, "request_timeout_ms"), 5000);
    let again = status_cli(&temp.data());
    assert!(again.status.success());
    assert_eq!(
        diagnostic_field(&first, "generation"),
        diagnostic_field(&again, "generation")
    );
    fs::write(temp.input(), fixture().bytes()).unwrap();
    for _ in 0..2 {
        assert!(cli(&temp.data(), &temp.input()).status.success());
    }
    let second = status_cli(&temp.data());
    assert!(second.status.success());
    assert_eq!(diagnostic_field(&second, "session_new_records"), 1);
    assert_eq!(
        diagnostic_field(&second, "session_stored_bytes"),
        fixture().bytes().len() as u64
    );
    assert!(diagnostic_field(&second, "generation") > diagnostic_field(&first, "generation"));
    assert!(
        String::from_utf8(second.stdout)
            .unwrap()
            .contains("保存済み総件数ではありません")
    );
    server.signal("-TERM");
    assert!(server.wait().success());
    assert!(!temp.data().join("admin-status.sock").exists());
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
    assert!(store.record(fixture().id()).unwrap().is_some());
}
#[test]
fn unavailable_status_never_initializes_or_falls_back_to_old_record_listener() {
    let temp = Temp::new();
    assert_eq!(status_cli(&temp.data()).status.code(), Some(1));
    assert!(!temp.data().exists());
    let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
    let mut old = Listener::bind_writer(
        store.begin().unwrap(),
        lngnb::cbor::MAX_RECORD,
        Duration::from_millis(100),
    )
    .unwrap();
    assert_eq!(status_cli(&temp.data()).status.code(), Some(1));
    assert!(matches!(
        old.accept(),
        Err(lngnb::storage::admin_transport::Error::Timeout)
    ));
    fs::hard_link(
        temp.data().join("admin.sock"),
        temp.data().join("admin-status.sock"),
    )
    .unwrap();
    assert_eq!(status_cli(&temp.data()).status.code(), Some(1));
    assert!(matches!(
        old.accept(),
        Err(lngnb::storage::admin_transport::Error::Timeout)
    ));
    fs::remove_file(temp.data().join("admin-status.sock")).unwrap();
    old.close_writer().unwrap().finish().unwrap();
}
#[test]
fn status_socket_residue_and_replacement_prevent_normal_shutdown_without_deletion() {
    for replace in [false, true] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        let path = temp.data().join("admin-status.sock");
        if replace {
            let mut server = Server::start(&temp);
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"preserve").unwrap();
            server.signal("-TERM");
            assert_eq!(server.wait().code(), Some(3));
        } else {
            fs::write(&path, b"preserve").unwrap();
            let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
                .args(["admin", "serve", "--data-dir"])
                .arg(temp.data())
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(3));
            assert!(out.stdout.is_empty());
        }
        assert_eq!(fs::read(&path).unwrap(), b"preserve");
        assert!(temp.data().join("admin.sock").exists());
        assert_review(&temp, false);
    }
}
#[test]
fn malformed_status_reply_is_diagnostic_failure_and_sends_no_request() {
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
        os::unix::net::UnixListener,
    };
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let dir = fs::File::open(temp.data()).unwrap();
    let anchored =
        PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join("admin-status.sock");
    let socket = UnixListener::bind(anchored).unwrap();
    fs::set_permissions(
        temp.data().join("admin-status.sock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(temp.data().join("admin.sock"), b"preserve").unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        stream.write_all(b"LNI\x02\x00\x00\x00\x3e").unwrap();
        let mut byte = [0; 1];
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    let out = status_cli(&temp.data());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    worker.join().unwrap();
    assert_eq!(
        fs::read(temp.data().join("admin.sock")).unwrap(),
        b"preserve"
    );
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(store.generation().unwrap(), 0);
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
}

fn evaluate_cli(data: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "evaluate", "--data-dir"])
        .arg(data)
        .output()
        .unwrap()
}
#[test]
fn live_evaluation_matches_stopped_diagnostic_and_preserves_dependencies() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    let empty = evaluate_cli(&temp.data());
    assert!(empty.status.success(), "{:?}", empty.stderr);
    assert_eq!(diagnostic_field(&empty, "records"), 0);
    fs::write(temp.input(), named_fixture("revision").bytes()).unwrap();
    assert!(cli(&temp.data(), &temp.input()).status.success());
    let pending = evaluate_cli(&temp.data());
    assert!(pending.status.success());
    assert_eq!(diagnostic_field(&pending, "diagnostic_pending"), 1);
    assert_eq!(diagnostic_field(&pending, "payload_missing"), 1);
    fs::write(temp.input(), fixture().bytes()).unwrap();
    assert!(cli(&temp.data(), &temp.input()).status.success());
    let valid = evaluate_cli(&temp.data());
    assert!(valid.status.success());
    assert_eq!(diagnostic_field(&valid, "diagnostic_valid"), 2);
    assert_eq!(diagnostic_field(&valid, "payload_missing"), 1);
    let again = evaluate_cli(&temp.data());
    assert!(again.status.success());
    assert_eq!(
        diagnostic_field(&valid, "diagnostic_generation"),
        diagnostic_field(&again, "diagnostic_generation")
    );
    server.signal("-TERM");
    assert!(server.wait().success());
    assert!(!temp.data().join("admin-evaluate.sock").exists());
    let stopped = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["data", "status", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert!(stopped.status.success());
    for name in [
        "records",
        "diagnostic_valid",
        "diagnostic_pending",
        "diagnostic_invalid",
        "payload_missing",
    ] {
        assert_eq!(
            diagnostic_field(&valid, name),
            diagnostic_field(&stopped, name)
        );
    }
}
#[test]
fn live_evaluation_detects_new_retained_loss_and_prevents_clean_shutdown() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    let body = b"public live retained fixture";
    let id = lngnb::id::blob_id(body);
    writer.put_blob(id, std::io::Cursor::new(body)).unwrap();
    writer.finish().unwrap();
    let mut server = Server::start(&temp);
    fs::remove_file(
        temp.data()
            .join("blobs")
            .join(data_encoding::HEXLOWER.encode(&id.bytes)),
    )
    .unwrap();
    let out = evaluate_cli(&temp.data());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(server.wait().code(), Some(3));
    assert!(temp.data().join("admin-evaluate.sock").exists());
    assert_eq!(
        RecordStore::open(&temp.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        lngnb::storage::StartupState::NeedsReview
    );
}
#[test]
fn evaluation_requires_its_own_safe_endpoint_and_preserves_existing_name() {
    let temp = Temp::new();
    assert_eq!(evaluate_cli(&temp.data()).status.code(), Some(1));
    assert!(!temp.data().exists());
    let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
    let mut listener = Listener::bind_writer(
        store.begin().unwrap(),
        lngnb::cbor::MAX_RECORD,
        Duration::from_millis(20),
    )
    .unwrap();
    listener.enable_status().unwrap();
    assert_eq!(evaluate_cli(&temp.data()).status.code(), Some(1));
    assert!(matches!(
        listener.accept(),
        Err(lngnb::storage::admin_transport::Error::Timeout)
    ));
    listener.close_writer().unwrap().finish().unwrap();
    let path = temp.data().join("admin-evaluate.sock");
    fs::write(&path, b"preserve").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(fs::read(path).unwrap(), b"preserve");
}

#[test]
fn explicit_diagnostic_limit_does_not_change_storage_and_resets_on_clean_restart() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::configured(&temp, &["--max-diagnostic-records", "1"]);
    fs::write(temp.input(), fixture().bytes()).unwrap();
    assert!(cli(&temp.data(), &temp.input()).status.success());
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 1);
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "max_new_records"), 10_000);
    server.signal("-TERM");
    assert!(server.wait().success());
    assert!(
        fs::read_to_string(&server.log)
            .unwrap()
            .contains("max_diagnostic_records: 1\n")
    );
    let mut restarted = Server::start(&temp);
    fs::write(temp.input(), named_fixture("revision").bytes()).unwrap();
    assert!(cli(&temp.data(), &temp.input()).status.success());
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 2);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("max_diagnostic_records: 10000\n")
    );
}

#[test]
fn diagnostic_limit_does_not_reduce_startup_inspection_or_clear_review_after_failure() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    writer.insert(&named_fixture("revision")).unwrap();
    writer.finish().unwrap();
    let mut server = Server::configured(&temp, &["--max-diagnostic-records", "1"]);
    let out = evaluate_cli(&temp.data());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(server.wait().code(), Some(3));
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::NeedsReview
    );
    assert!(store.record(fixture().id()).unwrap().is_some());
    assert!(
        store
            .record(named_fixture("revision").id())
            .unwrap()
            .is_some()
    );
    drop(store);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert!(temp.data().join("admin-evaluate.sock").exists());
}

#[test]
fn startup_step_budget_splits_both_record_checks_without_limiting_the_collection() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    writer.insert(&named_fixture("revision")).unwrap();
    writer.finish().unwrap();
    let mut server = Server::configured(&temp, &["--startup-records-per-step", "1"]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 2);
    assert_eq!(diagnostic_field(&diagnostic, "diagnostic_valid"), 2);
    server.signal("-TERM");
    assert!(server.wait().success());
    assert!(
        fs::read_to_string(&server.log)
            .unwrap()
            .contains("startup_records_per_step: 1\n")
    );
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'records:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_input_pending' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_records_per_step: 10000\n")
    );
}

#[test]
fn invalid_later_startup_record_never_opens_socket_or_clears_manual_review() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    let record = fixture();
    writer.insert(&record).unwrap();
    writer.finish().unwrap();
    // 新規試験領域だけに、正常Recordの後に並ぶID不一致の保存破損を注入する。
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO records(id,bytes) VALUES(?1,?2)",
        rusqlite::params![&[255u8; 32][..], record.bytes()],
    )
    .unwrap();
    drop(conn);
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args(["--startup-records-per-step", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let checked: i64 = conn
        .query_row("SELECT checked_records FROM record_inspection", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(checked, 1);
    let state: String = conn
        .query_row("SELECT state FROM storage_state", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "running");
    let count: i64 = conn
        .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
    drop(conn);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert!(!temp.data().join("admin.sock").exists());
}

fn config_save_command(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
    command
        .args(["admin", "config-save", "--data-dir"])
        .arg(data)
        .args([
            "--request-timeout-ms",
            "500",
            "--max-new-records",
            "7",
            "--max-diagnostic-records",
            "8",
            "--startup-records-per-step",
            "1",
        ]);
    command
}
fn saved_config_row(data: &Path) -> (i64, i64, i64, i64) {
    rusqlite::Connection::open(data.join("database.sqlite")).unwrap().query_row(
        "SELECT request_timeout_ms,max_new_records,max_diagnostic_records,startup_records_per_step FROM admin_config WHERE singleton=1",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap()
}
#[test]
fn config_save_persists_explicit_values_and_serve_loads_them() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    writer.finish().unwrap();
    for _ in 0..2 {
        let output = config_save_command(&temp.data()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("保存値は起動へ適用していません"));
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store.startup_state().unwrap(),
            lngnb::storage::StartupState::Clean
        );
        assert_eq!(
            store.record(fixture().id()).unwrap().unwrap().bytes(),
            fixture().bytes()
        );
    }
    let candidate = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["config", "show", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert!(candidate.status.success());
    assert!(String::from_utf8_lossy(&candidate.stdout).contains("未保存・未適用"));
    let mut server = Server::start(&temp);
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "max_new_records"), 7);
    assert_eq!(diagnostic_field(&runtime, "request_timeout_ms"), 500);
    server.signal("-TERM");
    assert!(server.wait().success());
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
}
#[test]
fn config_save_invalid_or_incomplete_arguments_never_touch_the_area() {
    let temp = Temp::new();
    for initialized in [false, true] {
        if initialized {
            drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        }
        for arguments in [
            vec![],
            vec!["--request-timeout-ms", "500"],
            vec!["--request-timeout-ms", "private"],
            vec!["--request-timeout-ms", "500", "--request-timeout-ms", "500"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
                .args(["admin", "config-save", "--data-dir"])
                .arg(temp.data())
                .args(arguments)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains("private"));
            if initialized {
                let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
                assert_eq!(store.generation().unwrap(), 0);
                assert_eq!(store.saved_admin_config().unwrap(), None);
            } else {
                assert!(!temp.data().exists());
            }
        }
    }
}
#[test]
fn config_save_rejects_active_lock_and_manual_review_without_changing_values() {
    let temp = Temp::new();
    let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
    let output = config_save_command(&temp.data()).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(store.saved_admin_config().unwrap(), None);
    let mut writer = store.begin().unwrap();
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 700,
            max_new_records: 9,
            max_diagnostic_records: 10,
            startup_records_per_step: 2,
        })
        .unwrap();
    drop(writer);
    let output = config_save_command(&temp.data()).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(saved_config_row(&temp.data()), (700, 9, 10, 2));
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::NeedsReview
    );
    assert!(!temp.data().join("admin.sock").exists());
}
#[test]
fn config_save_failure_preserves_old_or_committed_new_values_and_blocks_restart() {
    for failure in ["setting", "history", "finish"] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
        let sql = match failure {
            "setting" => {
                "CREATE TRIGGER deny_settings BEFORE UPDATE ON admin_config BEGIN SELECT RAISE(ABORT,'test'); END;"
            }
            "history" => {
                "CREATE TRIGGER deny_settings BEFORE INSERT ON history WHEN NEW.new_state='admin_config_saved_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;"
            }
            _ => {
                "CREATE TRIGGER deny_settings BEFORE UPDATE ON storage_state WHEN OLD.state='running' AND NEW.state='clean' BEGIN SELECT RAISE(ABORT,'test'); END;"
            }
        };
        conn.execute_batch(sql).unwrap();
        drop(conn);
        let output = config_save_command(&temp.data()).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store.saved_admin_config().unwrap().is_some(),
            failure == "finish"
        );
        assert_eq!(
            store.startup_state().unwrap(),
            lngnb::storage::StartupState::NeedsReview
        );
        drop(store);
        let retry = config_save_command(&temp.data()).output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(!temp.data().join("admin.sock").exists());
    }
}
#[test]
fn config_save_output_failure_does_not_undo_confirmed_settings() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let output = config_save_command(&temp.data())
        .stdout(fs::File::options().write(true).open("/dev/full").unwrap())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("正常終了後"));
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
}

#[test]
fn config_save_never_repairs_corrupt_old_or_missing_storage() {
    for damaged in ["missing", "old", "config"] {
        let temp = Temp::new();
        if damaged != "missing" {
            drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
            let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
            if damaged == "old" {
                conn.pragma_update(None, "user_version", 11).unwrap();
            } else {
                conn.execute("DELETE FROM admin_config", []).unwrap();
            }
        }
        let before = fs::read(temp.data().join("database.sqlite")).ok();
        let output = config_save_command(&temp.data()).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read(temp.data().join("database.sqlite")).ok(), before);
        assert!(!temp.data().join("admin.sock").exists());
    }
}

#[test]
fn saved_startup_overrides_are_per_field_and_never_saved() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    assert!(
        config_save_command(&temp.data())
            .output()
            .unwrap()
            .status
            .success()
    );
    let options = [
        "--request-timeout-ms",
        "30000",
        "--max-new-records",
        "10000",
    ];
    let mut server = Server::configured(&temp, &options);
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "request_timeout_ms"), 30_000);
    assert_eq!(diagnostic_field(&runtime, "max_new_records"), 10_000);
    let text = fs::read_to_string(&server.log).unwrap();
    assert!(text.contains("max_diagnostic_records: 8\n"));
    assert!(text.contains("startup_records_per_step: 1\n"));
    server.signal("-TERM");
    assert!(server.wait().success());
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
    let mut restarted = Server::start(&temp);
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "request_timeout_ms"), 500);
    assert_eq!(diagnostic_field(&runtime, "max_new_records"), 7);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
}

#[test]
fn saved_startup_corruption_cannot_be_hidden_by_all_explicit_options() {
    for damage in ["missing", "value", "history"] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        assert!(
            config_save_command(&temp.data())
                .output()
                .unwrap()
                .status
                .success()
        );
        let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
        match damage {
            "missing" => {
                conn.execute("DELETE FROM admin_config", []).unwrap();
            }
            "value" => {
                conn.execute("UPDATE admin_config SET request_timeout_ms=501", [])
                    .unwrap();
            }
            _ => {
                conn.execute("UPDATE history SET reason='changed' WHERE new_state='admin_config_saved_local_only'", []).unwrap();
            }
        }
        drop(conn);
        let before = fs::read(temp.data().join("database.sqlite")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data())
            .args([
                "--request-timeout-ms",
                "30000",
                "--max-new-records",
                "10000",
                "--max-diagnostic-records",
                "10000",
                "--startup-records-per-step",
                "10000",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        assert_eq!(
            fs::read(temp.data().join("database.sqlite")).unwrap(),
            before
        );
        for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
            assert!(!temp.data().join(name).exists());
        }
    }
}

#[test]
fn saved_startup_split_and_diagnostic_budget_preserve_manual_wait_after_failure() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    writer.insert(&named_fixture("revision")).unwrap();
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 7,
            max_diagnostic_records: 1,
            startup_records_per_step: 1,
        })
        .unwrap();
    writer.finish().unwrap();
    let mut server = Server::start(&temp);
    let output = evaluate_cli(&temp.data());
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(server.wait().code(), Some(3));
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 1, 1));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'records:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_input_pending' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    assert_review(&temp, true);
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--max-diagnostic-records", "10000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 1, 1));
    }
}

fn config_show_cli(data: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "config-show", "--data-dir"])
        .arg(data)
        .output()
        .unwrap()
}
#[test]
fn config_show_saved_unsaved_and_manual_wait_do_not_change_database() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let before = fs::read(temp.data().join("database.sqlite")).unwrap();
    let output = config_show_cli(&temp.data());
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("saved: false\n"));
    assert!(!text.contains("request_timeout_ms:"));
    assert_eq!(
        fs::read(temp.data().join("database.sqlite")).unwrap(),
        before
    );
    assert!(
        config_save_command(&temp.data())
            .output()
            .unwrap()
            .status
            .success()
    );
    for review in [false, true] {
        if review {
            drop(
                RecordStore::open(&temp.data(), Limits::default())
                    .unwrap()
                    .begin()
                    .unwrap(),
            );
        }
        let before = fs::read(temp.data().join("database.sqlite")).unwrap();
        let output = config_show_cli(&temp.data());
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("saved: true\n"));
        assert!(text.contains("request_timeout_ms: 500\nmax_new_records: 7\nmax_diagnostic_records: 8\nstartup_records_per_step: 1\n"));
        assert!(text.contains("現在の起動時適用値ではありません"));
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
        assert_eq!(
            fs::read(temp.data().join("database.sqlite")).unwrap(),
            before
        );
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        let expected = if review {
            lngnb::storage::StartupState::NeedsReview
        } else {
            lngnb::storage::StartupState::Clean
        };
        assert_eq!(store.startup_state().unwrap(), expected);
        assert!(!temp.data().join("admin.sock").exists());
    }
}
#[test]
fn config_show_rejects_missing_unsafe_old_and_corrupt_storage_without_repair() {
    for damage in [
        "missing", "old", "config", "value", "history", "lock", "unsafe", "symlink", "journal",
    ] {
        let temp = Temp::new();
        if damage != "missing" {
            drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
            assert!(
                config_save_command(&temp.data())
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
            match damage {
                "old" => {
                    conn.pragma_update(None, "user_version", 11).unwrap();
                }
                "config" => {
                    conn.execute("DELETE FROM admin_config", []).unwrap();
                }
                "value" => {
                    conn.execute("UPDATE admin_config SET max_new_records=8", [])
                        .unwrap();
                }
                "history" => {
                    conn.execute("UPDATE history SET reason='changed' WHERE new_state='admin_config_saved_local_only'", []).unwrap();
                }
                "journal" => {
                    conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
                }
                _ => {}
            }
            drop(conn);
            if damage == "lock" {
                fs::remove_file(temp.data().join("lock")).unwrap();
            }
            if damage == "unsafe" {
                fs::set_permissions(temp.data(), fs::Permissions::from_mode(0o755)).unwrap();
            }
            if damage == "symlink" {
                fs::rename(
                    temp.data().join("database.sqlite"),
                    temp.0.join("preserved.sqlite"),
                )
                .unwrap();
                symlink(
                    temp.0.join("preserved.sqlite"),
                    temp.data().join("database.sqlite"),
                )
                .unwrap();
            }
        }
        let before = fs::read(temp.data().join("database.sqlite")).ok();
        let output = config_show_cli(&temp.data());
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read(temp.data().join("database.sqlite")).ok(), before);
        if damage == "missing" {
            assert!(!temp.data().exists());
        }
        if damage == "lock" {
            assert!(!temp.data().join("lock").exists());
        }
        assert!(!temp.data().join("admin.sock").exists());
    }
}
#[test]
fn config_show_invalid_arguments_and_active_server_never_fall_back_to_ipc() {
    let temp = Temp::new();
    for arguments in [
        vec!["--max-new-records", "1"],
        vec!["--data-dir", "private"],
        vec!["--unknown", "private"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["admin", "config-show", "--data-dir"])
            .arg(temp.data())
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private"));
        assert!(!temp.data().exists());
    }
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    let before = status_cli(&temp.data());
    let output = config_show_cli(&temp.data());
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let after = status_cli(&temp.data());
    assert!(before.status.success() && after.status.success());
    for field in [
        "generation",
        "session_new_records",
        "max_new_records",
        "request_timeout_ms",
    ] {
        assert_eq!(
            diagnostic_field(&before, field),
            diagnostic_field(&after, field)
        );
    }
    server.signal("-TERM");
    assert!(server.wait().success());
}
#[test]
fn config_show_reads_committed_wal_and_output_failure_leaves_manual_wait() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    // SQLite接続だけを保持してWALを残す。製品のlockは保持しない試験用接続。
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    conn.execute_batch("PRAGMA wal_autocheckpoint=0; SELECT * FROM storage_state;")
        .unwrap();
    let mut writer = RecordStore::open(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 700,
            max_new_records: 9,
            max_diagnostic_records: 10,
            startup_records_per_step: 2,
        })
        .unwrap();
    drop(writer);
    assert!(
        fs::metadata(temp.data().join("database.sqlite-wal"))
            .unwrap()
            .len()
            > 0
    );
    let output = config_show_cli(&temp.data());
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("request_timeout_ms: 700\nmax_new_records: 9\nmax_diagnostic_records: 10\nstartup_records_per_step: 2\n"));
    let generation: i64 = conn
        .query_row("SELECT generation FROM storage_state", [], |r| r.get(0))
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "config-show", "--data-dir"])
        .arg(temp.data())
        .stdout(fs::File::options().write(true).open("/dev/full").unwrap())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("結果出力に失敗"));
    let unchanged: (i64, String) = conn
        .query_row("SELECT generation,state FROM storage_state", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(unchanged, (generation, "running".to_owned()));
    assert_eq!(saved_config_row(&temp.data()), (700, 9, 10, 2));
}

#[test]
fn startup_byte_budget_splits_both_record_stages_and_returns_to_default() {
    let temp = Temp::new();
    let genesis = fixture();
    let revision = named_fixture("revision");
    let bytes = genesis.bytes().len().max(revision.bytes().len());
    assert!(bytes < genesis.bytes().len() + revision.bytes().len());
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&genesis).unwrap();
    writer.insert(&revision).unwrap();
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 7,
            max_diagnostic_records: 8,
            startup_records_per_step: 10_000,
        })
        .unwrap();
    writer.finish().unwrap();
    let value = bytes.to_string();
    let mut server = Server::configured(&temp, &["--startup-record-bytes-per-step", &value]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 2);
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "max_new_records"), 7);
    server.signal("-TERM");
    assert!(server.wait().success());
    let text = fs::read_to_string(&server.log).unwrap();
    assert!(text.contains(&format!("startup_record_bytes_per_step: {bytes}\n")));
    assert!(text.contains("startup_records_per_step: 10000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'records:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_input_pending' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_record_bytes_per_step: 67108864\n")
    );
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}

#[test]
fn startup_byte_budget_cannot_skip_one_record_or_clear_manual_wait_on_retry() {
    let temp = Temp::new();
    let record = fixture();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&record).unwrap();
    writer.finish().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args([
            "--startup-record-bytes-per-step",
            &(record.bytes().len() - 1).to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("署名不正"));
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let checked: i64 = conn
        .query_row("SELECT checked_records FROM record_inspection", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(checked, 0);
    let cursor: Option<Vec<u8>> = conn
        .query_row("SELECT cursor FROM record_inspection", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cursor, None);
    let state: String = conn
        .query_row("SELECT state FROM storage_state", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "running");
    drop(conn);
    assert_review(&temp, true);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert_review(&temp, true);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(store.saved_admin_config().unwrap(), None);
    assert_eq!(
        store.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
}

// A13の公開試験鍵によるfixture署名。実運用禁止。
fn fixture_sign(body: lngnb::cbor::Value) -> LocalRecord {
    let data = fixture_data();
    let hex = data["seed_hex"].as_str().unwrap();
    let seed: [u8; 32] = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let record = LocalRecord::sign(body, &ed25519_dalek::SigningKey::from_bytes(&seed)).unwrap();
    record.check_genesis(&fixture()).unwrap();
    record
}
fn blob_revision(payload: &[u8]) -> LocalRecord {
    use lngnb::cbor::Value;
    let mut body = named_fixture("revision").body().clone();
    let Value::Map(fields) = &mut body else {
        panic!("body map")
    };
    let Value::Map(fields) = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1 else {
        panic!("payload map")
    };
    fields.iter_mut().find(|(k, _)| k == "blob_id").unwrap().1 =
        Value::Bytes(lngnb::id::blob_id(payload).bytes.to_vec());
    fields
        .iter_mut()
        .find(|(k, _)| k == "byte_length")
        .unwrap()
        .1 = Value::Int(payload.len() as i64);
    fixture_sign(body)
}
fn startup_blobs(temp: &Temp) -> Vec<Vec<u8>> {
    let payloads = vec![
        b"first startup blob".to_vec(),
        b"second startup blob".to_vec(),
    ];
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    for payload in &payloads {
        writer.insert(&blob_revision(payload)).unwrap();
        writer
            .put_blob(lngnb::id::blob_id(payload), std::io::Cursor::new(payload))
            .unwrap();
    }
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 7,
            max_diagnostic_records: 8,
            startup_records_per_step: 10_000,
        })
        .unwrap();
    writer.finish().unwrap();
    payloads
}
fn startup_blob_path(temp: &Temp, payload: &[u8]) -> PathBuf {
    let id = lngnb::id::blob_id(payload);
    temp.data()
        .join("blobs")
        .join(data_encoding::HEXLOWER.encode(&id.bytes))
}
#[test]
fn startup_blob_byte_budget_splits_physical_and_evaluation_scans_and_is_not_saved() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let bytes = payloads.iter().map(Vec::len).max().unwrap();
    let value = bytes.to_string();
    let mut server = Server::configured(&temp, &["--startup-blob-bytes-per-step", &value]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let text = fs::read_to_string(&server.log).unwrap();
    assert!(text.contains(&format!("startup_blob_bytes_per_step: {bytes}\n")));
    assert!(text.contains("startup_record_bytes_per_step: 67108864\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'blobs:epoch=%' AND new_state='record_inspection_pending'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_blob_pending' AND reason LIKE 'evaluation_blob_checkpoint:records=%:payloads=%:checked=1:total=2:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let verified: i64 = conn
        .query_row(
            "SELECT count(*) FROM blob_inspection_files WHERE result='verified'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(verified, 2);
    drop(conn);
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_blob_bytes_per_step: 67108864\n")
    );
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}
#[test]
fn startup_blob_byte_budget_below_one_file_preserves_bytes_without_calling_them_corrupt() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args(["--startup-blob-bytes-per-step", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let corrupt: i64 = conn
        .query_row(
            "SELECT count(*) FROM blob_inspection_files WHERE result='corrupt'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(corrupt, 0);
    drop(conn);
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    assert_review(&temp, true);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert_review(&temp, true);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}
#[test]
fn startup_blob_byte_budget_detects_later_corruption_before_opening_any_socket() {
    let temp = Temp::new();
    let mut payloads = startup_blobs(&temp);
    payloads.sort_by_key(|payload| lngnb::id::blob_id(payload).bytes);
    let damaged = payloads.last().unwrap();
    fs::write(startup_blob_path(&temp, damaged), vec![0; damaged.len()]).unwrap();
    let value = payloads.iter().map(Vec::len).max().unwrap().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args(["--startup-blob-bytes-per-step", &value])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    for result in ["verified", "corrupt"] {
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM blob_inspection_files WHERE result=?1",
                [result],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
    drop(conn);
    assert_eq!(
        fs::read(startup_blob_path(&temp, damaged)).unwrap(),
        vec![0; damaged.len()]
    );
    fs::write(startup_blob_path(&temp, damaged), damaged).unwrap();
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert_review(&temp, true);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}

#[test]
fn startup_blob_target_budget_splits_both_stages_without_tightening_bytes_or_saving() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let mut server = Server::configured(&temp, &["--startup-blob-targets-per-step", "1"]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let text = fs::read_to_string(&server.log).unwrap();
    assert!(text.contains("startup_blob_targets_per_step: 1\n"));
    assert!(text.contains("startup_blob_bytes_per_step: 67108864\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'blobs:epoch=%' AND new_state='record_inspection_pending'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_blob_pending' AND reason LIKE 'evaluation_blob_checkpoint:records=%:payloads=%:checked=1:total=2:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_blob_targets_per_step: 10000\n")
    );
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}
#[test]
fn startup_blob_target_budget_counts_unheld_payloads_even_with_zero_hash_bytes() {
    let temp = Temp::new();
    let payloads = [
        b"first unheld blob".to_vec(),
        b"second unheld blob".to_vec(),
    ];
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    for payload in &payloads {
        writer.insert(&blob_revision(payload)).unwrap();
    }
    writer.finish().unwrap();
    let mut server = Server::configured(&temp, &["--startup-blob-targets-per-step", "1"]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 2);
    server.signal("-TERM");
    assert!(server.wait().success());
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_blob_pending' AND reason LIKE 'evaluation_blob_checkpoint:records=%:payloads=%:checked=1:total=2:bytes=0:digest=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let files: i64 = conn
        .query_row("SELECT count(*) FROM blob_inspection_files", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(files, 0);
    let checked: (i64, i64) = conn
        .query_row(
            "SELECT count(*),sum(examined_bytes) FROM evaluation_blob_facts WHERE state='missing'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(checked, (2, 0));
    drop(conn);
    for payload in &payloads {
        assert!(!startup_blob_path(&temp, payload).exists());
    }
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
    assert_eq!(store.saved_admin_config().unwrap(), None);
}

fn parent_revision(parents: &[lngnb::id::Id], payload: &[u8]) -> LocalRecord {
    use lngnb::cbor::Value;
    let mut body = blob_revision(payload).body().clone();
    let mut ids = parents.iter().map(|id| id.bytes).collect::<Vec<_>>();
    ids.sort();
    let Value::Map(fields) = &mut body else {
        panic!("body map")
    };
    fields
        .iter_mut()
        .find(|(key, _)| key == "parents")
        .unwrap()
        .1 = Value::Array(
        ids.into_iter()
            .map(|id| Value::Bytes(id.to_vec()))
            .collect(),
    );
    fixture_sign(body)
}
fn startup_edge_records(temp: &Temp, wide: bool) -> Vec<LocalRecord> {
    let root = blob_revision(b"edge root");
    let left = if wide {
        blob_revision(b"edge second root")
    } else {
        parent_revision(&[root.id()], b"edge left")
    };
    let leaf = if wide {
        parent_revision(&[root.id(), left.id()], b"edge merge")
    } else {
        parent_revision(&[root.id()], b"edge right")
    };
    let records = vec![fixture(), root, left, leaf];
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    for record in &records {
        writer.insert(record).unwrap();
    }
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 7,
            max_diagnostic_records: 8,
            startup_records_per_step: 10_000,
        })
        .unwrap();
    writer.finish().unwrap();
    records
}
#[test]
fn startup_edge_budget_splits_dependency_input_without_reducing_total_graph_or_saving() {
    let temp = Temp::new();
    let records = startup_edge_records(&temp, false);
    let mut server = Server::configured(&temp, &["--startup-record-edges-per-step", "1"]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 4);
    assert_eq!(diagnostic_field(&diagnostic, "diagnostic_invalid"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let text = fs::read_to_string(&server.log).unwrap();
    assert!(text.contains("startup_record_edges_per_step: 1\n"));
    assert!(text.contains("startup_records_per_step: 10000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_input_pending' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=%:bytes=%:edges=1:digest=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    for record in &records {
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_record_edges_per_step: 100000\n")
    );
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}
#[test]
fn startup_edge_budget_below_one_revision_preserves_records_without_invalidating_them() {
    let temp = Temp::new();
    let records = startup_edge_records(&temp, true);
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args(["--startup-record-edges-per-step", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("署名不正"));
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let invalid: i64 = conn
        .query_row("SELECT count(*) FROM known_invalid", [], |r| r.get(0))
        .unwrap();
    assert_eq!(invalid, 0);
    drop(conn);
    assert_review(&temp, true);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert_review(&temp, true);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    for record in &records {
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}

#[test]
fn startup_evaluation_budget_splits_new_assessments_and_returns_to_default_without_saving() {
    let temp = Temp::new();
    let records = startup_edge_records(&temp, false);
    let mut server = Server::configured(&temp, &["--startup-evaluation-records-per-step", "1"]);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 4);
    assert_eq!(diagnostic_field(&diagnostic, "diagnostic_invalid"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let text = fs::read_to_string(&server.log).unwrap();
    assert!(text.contains("startup_evaluation_records_per_step: 1\n"));
    assert!(text.contains("startup_records_per_step: 10000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    for count in [1, 2, 3] {
        let pattern = format!("evaluation_queue_checkpoint:input=%:digest=%:count={count}:total=4");
        let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_job_pending' AND reason LIKE ?1",[pattern],|r|r.get(0)).unwrap();
        assert_eq!(split, 1);
    }
    let result: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM evaluation_work),complete FROM evaluation_job",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(result, (4, 1));
    drop(conn);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    for record in &records {
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_evaluation_records_per_step: 32\n")
    );
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}
#[test]
fn startup_evaluation_budget_keeps_first_checkpoint_and_manual_wait_when_next_save_fails() {
    let temp = Temp::new();
    let records = startup_edge_records(&temp, false);
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER deny_later_evaluation BEFORE INSERT ON evaluation_work WHEN (SELECT count(*) FROM evaluation_work)>=1 BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    drop(conn);
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args(["--startup-evaluation-records-per-step", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let result: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM evaluation_work),complete FROM evaluation_job",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(result, (1, 0));
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_job_pending' AND reason LIKE 'evaluation_queue_checkpoint:input=%:digest=%:count=1:total=4'",[],|r|r.get(0)).unwrap();
    assert_eq!(split, 1);
    conn.execute_batch("DROP TRIGGER deny_later_evaluation;")
        .unwrap();
    drop(conn);
    assert_review(&temp, true);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(3));
    assert!(retry.stdout.is_empty());
    assert_review(&temp, true);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    for record in &records {
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}

#[test]
fn sql_callback_budget_accepts_runtime_records_and_returns_to_default_without_saving() {
    let temp = Temp::new();
    startup_edge_records(&temp, false);
    let record = blob_revision(b"SQL budget runtime record");
    fs::write(temp.input(), record.bytes()).unwrap();
    let mut server = Server::configured(&temp, &["--sql-inspection-callbacks", "50000"]);
    let submitted = cli(&temp.data(), &temp.input());
    assert!(submitted.status.success());
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "session_new_records"), 1);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 5);
    server.signal("-TERM");
    assert!(server.wait().success());
    assert!(
        fs::read_to_string(&server.log)
            .unwrap()
            .contains("sql_inspection_callbacks: 50000\n")
    );
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("sql_inspection_callbacks: 100000\n")
    );
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    drop(store);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
}
#[test]
fn sql_callback_budget_stops_large_ledger_before_running_without_repairing_or_clearing_manual_wait()
{
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default())
        .unwrap()
        .begin()
        .unwrap();
    writer.insert(&fixture()).unwrap();
    for _ in 0..48 {
        writer
            .stage_blob(
                lngnb::id::blob_id(b"bounded SQL callback ledger"),
                std::io::Cursor::new(b"bounded SQL callback ledger"),
                86400,
                lngnb::storage::TemporaryLimits::default(),
            )
            .unwrap();
    }
    writer
        .save_admin_config(lngnb::storage::AdminConfig {
            request_timeout_ms: 500,
            max_new_records: 7,
            max_diagnostic_records: 8,
            startup_records_per_step: 10_000,
        })
        .unwrap();
    writer.finish().unwrap();
    let before = fs::read(temp.data().join("database.sqlite")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"])
        .arg(temp.data())
        .args(["--sql-inspection-callbacks", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("署名不正"));
    assert_eq!(
        fs::read(temp.data().join("database.sqlite")).unwrap(),
        before
    );
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock"] {
        assert!(!temp.data().join(name).exists());
    }
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.startup_state().unwrap(),
        lngnb::storage::StartupState::Clean
    );
    drop(store);
    let mut server = Server::start(&temp);
    server.signal("-TERM");
    assert!(server.wait().success());
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let holds: i64 = conn
        .query_row("SELECT count(*) FROM temporary_blob_holds", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(holds, 48);
    drop(conn);
    drop(
        RecordStore::open(&temp.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap(),
    );
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--sql-inspection-callbacks", "100000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    }
}

#[test]
fn sql_time_budget_is_used_for_runtime_without_saving_or_clearing_manual_wait() {
    let temp = Temp::new();
    startup_edge_records(&temp, false);
    let record = blob_revision(b"SQL time budget runtime record");
    fs::write(temp.input(), record.bytes()).unwrap();
    let mut server = Server::configured(
        &temp,
        &[
            "--sql-inspection-timeout-ms",
            "30000",
            "--sql-inspection-callbacks",
            "50000",
        ],
    );
    assert!(cli(&temp.data(), &temp.input()).status.success());
    let runtime = status_cli(&temp.data());
    assert!(runtime.status.success());
    assert_eq!(diagnostic_field(&runtime, "session_new_records"), 1);
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 5);
    server.signal("-TERM");
    assert!(server.wait().success());
    let ready = fs::read_to_string(&server.log).unwrap();
    assert!(ready.contains("sql_inspection_timeout_ms: 30000\n"));
    assert!(ready.contains("sql_inspection_callbacks: 50000\n"));
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    let ready = fs::read_to_string(&restarted.log).unwrap();
    assert!(ready.contains("sql_inspection_timeout_ms: 60000\n"));
    assert!(ready.contains("sql_inspection_callbacks: 100000\n"));
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(record.id()).unwrap().unwrap().bytes(),
        record.bytes()
    );
    drop(store.begin().unwrap());
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--sql-inspection-timeout-ms", "30000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    }
}

#[test]
fn startup_inspection_time_budget_completes_split_checks_without_saving_or_clearing_manual_wait() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let mut server = Server::configured(
        &temp,
        &[
            "--startup-inspection-timeout-ms",
            "30000",
            "--startup-records-per-step",
            "1",
            "--startup-blob-targets-per-step",
            "1",
        ],
    );
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let ready = fs::read_to_string(&server.log).unwrap();
    assert!(ready.contains("startup_inspection_timeout_ms: 30000\n"));
    assert!(ready.contains("sql_inspection_timeout_ms: 60000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let progress: (String, i64, i64) = conn
        .query_row(
            "SELECT phase,checked_records,checked_blob_files FROM record_inspection",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(progress, ("complete".into(), 3, 2));
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'records:epoch=%:records=1:bytes=%'", [], |r| r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'blobs:epoch=%' AND new_state='record_inspection_pending'", [], |r| r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_inspection_timeout_ms: 60000\n")
    );
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(fixture().id()).unwrap().unwrap().bytes(),
        fixture().bytes()
    );
    for payload in &payloads {
        let record = blob_revision(payload);
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store.begin().unwrap());
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--startup-inspection-timeout-ms", "30000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    }
}

#[test]
fn startup_record_input_time_budget_completes_collection_without_saving_or_clearing_manual_wait() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let mut server = Server::configured(
        &temp,
        &[
            "--startup-record-input-timeout-ms",
            "30000",
            "--startup-records-per-step",
            "1",
            "--startup-blob-targets-per-step",
            "1",
        ],
    );
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let ready = fs::read_to_string(&server.log).unwrap();
    assert!(ready.contains("startup_record_input_timeout_ms: 30000\n"));
    assert!(ready.contains("sql_inspection_timeout_ms: 60000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let collected: (i64, i64) = conn
        .query_row("SELECT records,complete FROM evaluation_input", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(collected, (3, 1));
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason LIKE 'evaluation_input_checkpoint:%:records=1:%' AND new_state='evaluation_input_pending'", [], |r| r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_record_input_timeout_ms: 60000\n")
    );
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(fixture().id()).unwrap().unwrap().bytes(),
        fixture().bytes()
    );
    for payload in &payloads {
        let record = blob_revision(payload);
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store.begin().unwrap());
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--startup-record-input-timeout-ms", "30000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    }
}

#[test]
fn startup_blob_input_time_budget_completes_preparation_without_saving_or_clearing_manual_wait() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let mut server = Server::configured(
        &temp,
        &[
            "--startup-blob-input-timeout-ms",
            "30000",
            "--startup-records-per-step",
            "1",
            "--startup-blob-targets-per-step",
            "1",
        ],
    );
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let ready = fs::read_to_string(&server.log).unwrap();
    assert!(ready.contains("startup_blob_input_timeout_ms: 30000\n"));
    assert!(ready.contains("sql_inspection_timeout_ms: 60000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let prepared: (i64, i64) = conn
        .query_row(
            "SELECT total,complete FROM evaluation_blob_input",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(prepared, (2, 1));
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason LIKE 'evaluation_blob_checkpoint:%:checked=1:%' AND new_state='evaluation_blob_pending'", [], |r| r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_blob_input_timeout_ms: 60000\n")
    );
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(fixture().id()).unwrap().unwrap().bytes(),
        fixture().bytes()
    );
    for payload in &payloads {
        let record = blob_revision(payload);
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store.begin().unwrap());
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--startup-blob-input-timeout-ms", "30000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    }
}

#[test]
fn startup_parent_time_budget_completes_evaluation_without_saving_or_clearing_manual_wait() {
    let temp = Temp::new();
    let payloads = startup_blobs(&temp);
    let mut server = Server::configured(
        &temp,
        &[
            "--startup-evaluation-timeout-ms",
            "30000",
            "--startup-records-per-step",
            "1",
            "--startup-evaluation-records-per-step",
            "1",
        ],
    );
    let diagnostic = evaluate_cli(&temp.data());
    assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic, "records"), 3);
    assert_eq!(diagnostic_field(&diagnostic, "payload_missing"), 0);
    server.signal("-TERM");
    assert!(server.wait().success());
    let ready = fs::read_to_string(&server.log).unwrap();
    assert!(ready.contains("startup_evaluation_timeout_ms: 30000\n"));
    assert!(ready.contains("sql_inspection_timeout_ms: 60000\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let evaluated: (i64, i64) = conn
        .query_row("SELECT total,complete FROM evaluation_job", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(evaluated, (3, 1));
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason LIKE 'evaluation_queue_checkpoint:%:count=1:%' AND new_state='evaluation_job_pending'", [], |r| r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    let mut restarted = Server::start(&temp);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert!(
        fs::read_to_string(&restarted.log)
            .unwrap()
            .contains("startup_evaluation_timeout_ms: 60000\n")
    );
    for payload in &payloads {
        assert_eq!(
            fs::read(startup_blob_path(&temp, payload)).unwrap(),
            *payload
        );
    }
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(
        store.record(fixture().id()).unwrap().unwrap().bytes(),
        fixture().bytes()
    );
    for payload in &payloads {
        let record = blob_revision(payload);
        assert_eq!(
            store.record(record.id()).unwrap().unwrap().bytes(),
            record.bytes()
        );
    }
    drop(store.begin().unwrap());
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
        command
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data());
        if explicit {
            command.args(["--startup-evaluation-timeout-ms", "30000"]);
        }
        let retry = command.output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert!(retry.stdout.is_empty());
        assert_review(&temp, true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 10_000));
    }
}

fn config_change_command(data: &Path, records: &str, diagnostics: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lngnb"));
    command
        .args(["admin", "config-change", "--data-dir"])
        .arg(data)
        .args([
            "--request-timeout-ms", "5000",
            "--max-new-records", records,
            "--max-diagnostic-records", diagnostics,
            "--startup-records-per-step", "1",
        ]);
    command
}
fn config_frame(records: u64) -> Vec<u8> {
    let mut bytes = b"LNC\x01\0\0\0\x20".to_vec();
    for value in [5000u64, records, 8, 1] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}
fn config_stream(data: &Path) -> std::os::unix::net::UnixStream {
    use std::{os::fd::AsRawFd, os::unix::net::UnixStream};
    let dir = fs::File::open(data).unwrap();
    let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join("admin-config.sock");
    UnixStream::connect(path).unwrap()
}
fn assert_four_sockets(data: &Path, present: bool) {
    for name in ["admin.sock", "admin-status.sock", "admin-evaluate.sock", "admin-config.sock"] {
        assert_eq!(data.join(name).exists(), present, "{name}");
    }
}

// R24/R27/R28/R30: 実CLIの保存/反映・counter非reset・次回起動の分割。
#[test]
fn config_change_saves_applies_preserves_counters_and_uses_next_startup_setting() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    fs::write(temp.input(), fixture().bytes()).unwrap();
    let mut server = Server::configured(&temp, &["--sql-inspection-callbacks", "50000"]);
    assert_four_sockets(&temp.data(), true);
    assert!(cli(&temp.data(), &temp.input()).status.success());
    let before = status_cli(&temp.data());
    let changed = config_change_command(&temp.data(), "2", "2").output().unwrap();
    assert!(changed.status.success(), "{:?}", changed);
    assert!(String::from_utf8_lossy(&changed.stdout).contains("起動分割件数は次回起動用"));
    let after = status_cli(&temp.data());
    for field in ["session_new_records", "session_stored_bytes", "max_stored_bytes"] {
        assert_eq!(diagnostic_field(&before, field), diagnostic_field(&after, field));
    }
    assert!(diagnostic_field(&after, "generation") > diagnostic_field(&before, "generation"));
    assert_eq!(diagnostic_field(&after, "request_timeout_ms"), 5000);
    assert_eq!(diagnostic_field(&after, "max_new_records"), 2);
    assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
    // 停止中操作はIPCへ自動切替しない。
    assert_eq!(config_save_command(&temp.data()).output().unwrap().status.code(), Some(3));
    assert!(cli(&temp.data(), &temp.input()).status.success());
    fs::write(temp.input(), named_fixture("revision").bytes()).unwrap();
    assert!(cli(&temp.data(), &temp.input()).status.success());
    assert_eq!(diagnostic_field(&status_cli(&temp.data()), "session_new_records"), 2);
    assert!(evaluate_cli(&temp.data()).status.success());
    server.signal("-TERM");
    assert!(server.wait().success());
    assert_four_sockets(&temp.data(), false);
    assert_eq!(saved_config_row(&temp.data()), (5000, 2, 2, 1));
    let mut restarted = Server::start(&temp);
    let text = fs::read_to_string(&restarted.log).unwrap();
    assert!(text.contains("startup_records_per_step: 1\n"));
    assert!(text.contains("sql_inspection_callbacks: 100000\n"));
    assert_eq!(diagnostic_field(&status_cli(&temp.data()), "session_new_records"), 0);
    assert!(evaluate_cli(&temp.data()).status.success());
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
    assert_four_sockets(&temp.data(), false);
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_input_pending' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=1:bytes=%'", [], |r| r.get(0)).unwrap();
    assert!(split > 0);
    drop(conn);
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    for kind in ["genesis", "revision"] {
        let record = named_fixture(kind);
        assert_eq!(store.record(record.id()).unwrap().unwrap().bytes(), record.bytes());
    }
}

#[test]
fn config_change_rejection_or_sql_failure_preserves_settings_records_and_manual_wait() {
    for sql_failure in [false, true] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        assert!(config_save_command(&temp.data()).output().unwrap().status.success());
        let mut server = Server::start(&temp);
        for kind in ["genesis", "revision"] {
            fs::write(temp.input(), named_fixture(kind).bytes()).unwrap();
            assert!(cli(&temp.data(), &temp.input()).status.success());
        }
        if sql_failure {
            let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
            conn.execute_batch("CREATE TRIGGER deny_live_config BEFORE INSERT ON history WHEN NEW.new_state='admin_config_saved_local_only' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        }
        let output = config_change_command(&temp.data(), if sql_failure { "7" } else { "1" }, "8")
            .output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        assert_eq!(server.wait().code(), Some(3));
        assert_four_sockets(&temp.data(), true);
        assert_eq!(saved_config_row(&temp.data()), (500, 7, 8, 1));
        assert_review(&temp, true);
        let retry = config_save_command(&temp.data()).output().unwrap();
        assert_eq!(retry.status.code(), Some(3));
        assert_review(&temp, true);
    }
}

#[test]
fn config_change_bad_frame_and_response_loss_preserve_unclean_state() {
    use std::{io::Write, net::Shutdown};
    for lost in [false, true] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        let mut server = Server::start(&temp);
        let mut stream = config_stream(&temp.data());
        if lost {
            // 応答を確実に受け取れなくしてから要求する。速度/短いtimeoutに依存しない。
            stream.shutdown(Shutdown::Read).unwrap();
            stream.write_all(&config_frame(7)).unwrap();
        } else {
            stream.write_all(b"LNC\x02\0\0\0\x20").unwrap();
        }
        assert_eq!(server.wait().code(), Some(3));
        assert_four_sockets(&temp.data(), true);
        let errors = fs::read_to_string(&server.errors).unwrap();
        if lost {
            assert!(errors.contains("保存・次操作への適用後、応答に失敗"));
            assert_eq!(saved_config_row(&temp.data()), (5000, 7, 8, 1));
        } else {
            assert!(RecordStore::open(&temp.data(), Limits::default()).unwrap()
                .saved_admin_config().unwrap().is_none());
        }
        assert_review(&temp, false);
    }
}

#[test]
fn config_change_unavailable_old_or_replaced_endpoint_never_falls_back_or_cleans() {
    let temp = Temp::new();
    assert_eq!(config_change_command(&temp.data(), "7", "8").output().unwrap().status.code(), Some(1));
    assert!(!temp.data().exists());
    let store = RecordStore::initialize(&temp.data(), Limits::default()).unwrap();
    let mut listener = Listener::bind_writer(store.begin().unwrap(), lngnb::cbor::MAX_RECORD, Duration::from_millis(20)).unwrap();
    listener.enable_status().unwrap();
    listener.enable_evaluation().unwrap();
    assert_eq!(config_change_command(&temp.data(), "7", "8").output().unwrap().status.code(), Some(1));
    assert!(matches!(listener.accept(), Err(lngnb::storage::admin_transport::Error::Timeout)));
    listener.close_writer().unwrap().finish().unwrap();
    let path = temp.data().join("admin-config.sock");
    fs::write(&path, b"preserve").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(["admin", "serve", "--data-dir"]).arg(temp.data()).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&path).unwrap(), b"preserve");
    assert_review(&temp, false);
    // 別の正常領域で、ready後の専用名差替えも保全する。
    let other = Temp::new();
    drop(RecordStore::initialize(&other.data(), Limits::default()).unwrap());
    let mut server = Server::start(&other);
    let path = other.data().join("admin-config.sock");
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement").unwrap();
    server.signal("-TERM");
    assert_eq!(server.wait().code(), Some(3));
    assert_eq!(fs::read(path).unwrap(), b"replacement");
    assert_review(&other, false);
}

#[test]
fn config_change_invalid_arguments_never_touch_data_and_output_failure_is_confirmed() {
    let temp = Temp::new();
    for initialized in [false, true] {
        if initialized {
            drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        }
        let output = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["admin", "config-change", "--data-dir"]).arg(temp.data())
            .args(["--request-timeout-ms", "private"]).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private"));
        if initialized {
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.generation().unwrap(), 0);
            assert!(store.saved_admin_config().unwrap().is_none());
        } else {
            assert!(!temp.data().exists());
        }
    }
    let mut server = Server::start(&temp);
    let output = config_change_command(&temp.data(), "7", "8")
        .stdout(fs::File::options().write(true).open("/dev/full").unwrap()).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("保存・次操作への適用を確認後"));
    assert_eq!(diagnostic_field(&status_cli(&temp.data()), "request_timeout_ms"), 5000);
    server.signal("-TERM");
    assert!(server.wait().success());
    assert_eq!(saved_config_row(&temp.data()), (5000, 7, 8, 1));
    assert_four_sockets(&temp.data(), false);
}

#[test]
fn config_change_client_rejects_bad_mismatched_or_lost_reply_without_database_access() {
    use std::{io::{Read, Write}, os::fd::AsRawFd, os::unix::net::UnixListener};
    for mode in ["version", "length", "scope", "value", "lost"] {
        let temp = Temp::new();
        drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
        let dir = fs::File::open(temp.data()).unwrap();
        let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join("admin-config.sock");
        let listener = UnixListener::bind(path).unwrap();
        fs::set_permissions(temp.data().join("admin-config.sock"), fs::Permissions::from_mode(0o600)).unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 40];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request.to_vec(), config_frame(7));
            if mode == "lost" { return; }
            let mut reply = b"LNC\x01\0\0\0\x21".to_vec();
            reply.push(3);
            reply.extend_from_slice(&request[8..]);
            match mode {
                "version" => reply[3] = 2,
                "length" => reply[7] = 255,
                "scope" => reply[8] = 1,
                "value" => reply[16] ^= 1,
                _ => unreachable!(),
            }
            let _ = stream.write_all(&reply);
        });
        // 同じ排他を保持中でもclientはDBを直接開かない。
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        let output = config_change_command(&temp.data(), "7", "8").output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("確定不明"));
        worker.join().unwrap();
        assert!(store.saved_admin_config().unwrap().is_none());
        assert_eq!(store.generation().unwrap(), 0);
    }
}

#[test]
fn config_change_applies_diagnostic_limit_without_reducing_startup_or_clearing_review() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(), Limits::default()).unwrap().begin().unwrap();
    writer.insert(&fixture()).unwrap();
    writer.insert(&named_fixture("revision")).unwrap();
    writer.finish().unwrap();
    let mut server = Server::start(&temp);
    assert!(config_change_command(&temp.data(), "7", "1").output().unwrap().status.success());
    assert_eq!(evaluate_cli(&temp.data()).status.code(), Some(1));
    assert_eq!(server.wait().code(), Some(3));
    assert_eq!(saved_config_row(&temp.data()), (5000, 7, 1, 1));
    assert_review(&temp, true);
    assert_eq!(config_change_command(&temp.data(), "7", "8").output().unwrap().status.code(), Some(1));
    assert_review(&temp, true);
}

#[test]
fn config_change_stop_during_partial_frame_never_finishes_or_removes_sockets() {
    let temp = Temp::new();
    drop(RecordStore::initialize(&temp.data(), Limits::default()).unwrap());
    let mut server = Server::start(&temp);
    let script = r#"import fcntl,os,signal,socket,struct,sys,termios,time
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect('/proc/self/fd/'+str(fd)+'/admin-config.sock')
s.sendall(b'L')
deadline=time.monotonic()+5
while struct.unpack('i',fcntl.ioctl(s,termios.TIOCOUTQ,struct.pack('i',0)))[0]:
 if time.monotonic()>deadline: raise RuntimeError('first byte not consumed')
 time.sleep(0.01)
os.kill(int(sys.argv[2]),signal.SIGTERM)
s.close()
os.close(fd)
"#;
    let status = Command::new(std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap())
        .args(["-c", script])
        .arg(temp.data())
        .arg(server.child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(server.wait().code(), Some(3));
    assert_four_sockets(&temp.data(), true);
    assert_review(&temp, false);
}
