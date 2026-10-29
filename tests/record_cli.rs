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
fn named_fixture(kind: &str) -> LocalRecord {
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
            vec!["--startup-records-per-step", "10001"],
            vec!["--startup-records-per-step", "private"],
            vec!["--startup-records-per-step", "1", "--startup-records-per-step", "2"],
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
    let mut writer = RecordStore::initialize(&temp.data(),Limits::default()).unwrap().begin().unwrap();
    writer.insert(&fixture()).unwrap(); writer.insert(&named_fixture("revision")).unwrap(); writer.finish().unwrap();
    let mut server = Server::configured(&temp,&["--startup-records-per-step","1"]);
    let diagnostic = evaluate_cli(&temp.data()); assert!(diagnostic.status.success());
    assert_eq!(diagnostic_field(&diagnostic,"records"),2);
    assert_eq!(diagnostic_field(&diagnostic,"diagnostic_valid"),2);
    server.signal("-TERM"); assert!(server.wait().success());
    assert!(fs::read_to_string(&server.log).unwrap().contains("startup_records_per_step: 1\n"));
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE reason='record_inspection_checkpoint' AND old_state LIKE 'records:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0);
    let split: i64 = conn.query_row("SELECT count(*) FROM history WHERE new_state='evaluation_input_pending' AND reason LIKE 'evaluation_input_checkpoint:epoch=%:records=1:bytes=%'",[],|r|r.get(0)).unwrap();
    assert!(split > 0); drop(conn);
    let mut restarted = Server::start(&temp); restarted.signal("-TERM"); assert!(restarted.wait().success());
    assert!(fs::read_to_string(&restarted.log).unwrap().contains("startup_records_per_step: 10000\n"));
}

#[test]
fn invalid_later_startup_record_never_opens_socket_or_clears_manual_review() {
    let temp = Temp::new();
    let mut writer = RecordStore::initialize(&temp.data(),Limits::default()).unwrap().begin().unwrap();
    let record = fixture(); writer.insert(&record).unwrap(); writer.finish().unwrap();
    // 新規試験領域だけに、正常Recordの後に並ぶID不一致の保存破損を注入する。
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    conn.execute("INSERT INTO records(id,bytes) VALUES(?1,?2)",rusqlite::params![&[255u8;32][..],record.bytes()]).unwrap(); drop(conn);
    let out = Command::new(env!("CARGO_BIN_EXE_lngnb")).args(["admin","serve","--data-dir"]).arg(temp.data()).args(["--startup-records-per-step","1"]).output().unwrap();
    assert_eq!(out.status.code(),Some(3)); assert!(out.stdout.is_empty());
    for name in ["admin.sock","admin-status.sock","admin-evaluate.sock"] { assert!(!temp.data().join(name).exists()); }
    let conn = rusqlite::Connection::open(temp.data().join("database.sqlite")).unwrap();
    let checked: i64 = conn.query_row("SELECT checked_records FROM record_inspection",[],|r|r.get(0)).unwrap();
    assert_eq!(checked,1);
    let state: String = conn.query_row("SELECT state FROM storage_state",[],|r|r.get(0)).unwrap(); assert_eq!(state,"running");
    let count: i64 = conn.query_row("SELECT count(*) FROM records",[],|r|r.get(0)).unwrap(); assert_eq!(count,2); drop(conn);
    let retry = Command::new(env!("CARGO_BIN_EXE_lngnb")).args(["admin","serve","--data-dir"]).arg(temp.data()).output().unwrap();
    assert_eq!(retry.status.code(),Some(3)); assert!(retry.stdout.is_empty());
    assert!(!temp.data().join("admin.sock").exists());
}
