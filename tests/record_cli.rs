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

struct Server {
    child: std::process::Child,
    log: PathBuf,
    errors: PathBuf,
}
impl Server {
    fn start(temp: &Temp) -> Self {
        let log = temp.0.join("server-output");
        let errors = temp.0.join("server-errors");
        let child = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["admin", "serve", "--data-dir"])
            .arg(temp.data())
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
