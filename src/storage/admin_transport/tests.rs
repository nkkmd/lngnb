use super::*;
use crate::storage::{Limits, StartupState, StorageError};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Area(PathBuf);
impl Area {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lngnb-admin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn store(&self) -> RecordStore {
        RecordStore::initialize(&self.0.join("data"), Limits::default()).unwrap()
    }
    fn endpoint(&self) -> PathBuf {
        self.0.join("data").join(NAME)
    }
    fn listener(&self, limit: usize) -> Listener {
        Listener::bind(self.store(), limit, Duration::from_millis(100)).unwrap()
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

#[test]
fn owner_credentials_private_endpoint_and_exclusive_storage_lifetime() {
    let area = Area::new();
    let mut server = area.listener(16);
    let meta = fs::symlink_metadata(area.endpoint()).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
    assert!(matches!(
        RecordStore::open(&area.0.join("data"), Limits::default()),
        Err(StorageError::Busy)
    ));
    let mut client = UnixStream::connect(area.endpoint()).unwrap();
    client.write_all(&frame(b"inspect")).unwrap();
    let mut connection = server.accept().unwrap();
    assert_eq!(connection.peer_uid(), rustix::process::geteuid().as_raw());
    assert_eq!(
        connection.store().startup_state().unwrap(),
        StartupState::Clean
    );
    assert_eq!(connection.send(b"early"), Err(Error::InvalidFrame));
    assert_eq!(connection.receive().unwrap(), b"inspect");
    assert_eq!(connection.receive(), Err(Error::InvalidFrame));
    connection.send(b"diagnostic").unwrap();
    assert_eq!(connection.send(b"again"), Err(Error::InvalidFrame));
    let mut expected = vec![0; 18];
    client.read_exact(&mut expected).unwrap();
    assert_eq!(expected, frame(b"diagnostic"));
    drop(connection);
    let store = server.close().unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert!(!area.endpoint().exists());
    assert!(matches!(
        RecordStore::open(&area.0.join("data"), Limits::default()),
        Err(StorageError::Busy)
    ));
    drop(store);
    assert_eq!(
        RecordStore::open(&area.0.join("data"), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::Clean
    );
    for owner in [0, 1000, u32::MAX - 1] {
        assert!(authorized(owner, owner));
        assert!(authorized(owner, 0));
        assert!(!authorized(owner, 1001));
    }
}

#[test]
fn existing_files_symlinks_and_abandoned_sockets_are_never_adopted_or_deleted() {
    for kind in 0..3 {
        let area = Area::new();
        let store = area.store();
        let target = area.0.join("preserved");
        fs::write(&target, b"preserved").unwrap();
        match kind {
            0 => fs::write(area.endpoint(), b"existing").unwrap(),
            1 => symlink(&target, area.endpoint()).unwrap(),
            _ => {
                drop(UnixListener::bind(area.endpoint()).unwrap());
            }
        }
        let before = fs::symlink_metadata(area.endpoint()).unwrap();
        assert!(matches!(
            Listener::bind(store, 16, Duration::from_millis(100)),
            Err(Error::EndpointExists)
        ));
        let after = fs::symlink_metadata(area.endpoint()).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        assert_eq!(fs::read(target).unwrap(), b"preserved");
    }
    let area = Area::new();
    let server = area.listener(16);
    drop(server); // 異常終了相当: 自動unlinkしない。
    let store = RecordStore::open(&area.0.join("data"), Limits::default()).unwrap();
    assert!(matches!(
        Listener::bind(store, 16, Duration::from_millis(100)),
        Err(Error::EndpointExists)
    ));
}

#[test]
fn unsafe_permissions_and_replaced_endpoint_fail_without_removing_replacement() {
    for mutation in 0..4 {
        let area = Area::new();
        let mut server = area.listener(16);
        match mutation {
            0 => fs::set_permissions(area.endpoint(), fs::Permissions::from_mode(0o666)).unwrap(),
            1 => {
                fs::set_permissions(area.0.join("data"), fs::Permissions::from_mode(0o755)).unwrap()
            }
            2 => {
                fs::remove_file(area.endpoint()).unwrap();
                fs::write(area.endpoint(), b"replacement").unwrap();
            }
            _ => {
                fs::remove_file(area.endpoint()).unwrap();
                symlink(area.0.join("target"), area.endpoint()).unwrap();
            }
        }
        assert!(matches!(server.accept(), Err(Error::UnsafeEndpoint)));
        assert!(matches!(server.close(), Err(Error::UnsafeEndpoint)));
        assert!(fs::symlink_metadata(area.endpoint()).is_ok());
        if mutation == 2 {
            assert_eq!(fs::read(area.endpoint()).unwrap(), b"replacement");
        }
    }
}

#[test]
fn bounded_framing_rejects_unknown_version_empty_large_truncated_and_second_requests() {
    let area = Area::new();
    let mut server = area.listener(4);
    let mut unknown = frame(b"x");
    unknown[3] = 2;
    for bytes in [
        unknown,
        frame(b""),
        frame(b"12345"),
        frame(b"x")[..5].to_vec(),
        frame(b"123")[..9].to_vec(),
    ] {
        let mut client = UnixStream::connect(area.endpoint()).unwrap();
        client.write_all(&bytes).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut connection = server.accept().unwrap();
        assert_eq!(connection.receive(), Err(Error::InvalidFrame));
        assert_eq!(connection.receive(), Err(Error::InvalidFrame));
        assert_eq!(connection.send(b"ok"), Err(Error::InvalidFrame));
    }
    let mut client = UnixStream::connect(area.endpoint()).unwrap();
    let mut concatenated = frame(b"1234");
    concatenated.extend(frame(b"next"));
    client.write_all(&concatenated).unwrap();
    let mut connection = server.accept().unwrap();
    assert_eq!(connection.receive().unwrap(), b"1234");
    assert_eq!(connection.receive(), Err(Error::InvalidFrame));
    assert_eq!(connection.send(b"12345"), Err(Error::InvalidFrame));
    connection.send(b"1234").unwrap();
    drop(connection);
    drop(server.close().unwrap());
}

#[test]
fn idle_and_partial_peers_obey_deadline_and_cannot_restart_failed_receive() {
    let area = Area::new();
    let mut server = area.listener(16);
    let start = Instant::now();
    assert!(matches!(server.accept(), Err(Error::Timeout)));
    assert!(start.elapsed() < Duration::from_secs(3));
    for partial in [vec![], MAGIC.to_vec(), frame(b"partial")[..9].to_vec()] {
        let mut client = UnixStream::connect(area.endpoint()).unwrap();
        client.write_all(&partial).unwrap();
        let mut connection = server.accept().unwrap();
        let start = Instant::now();
        assert_eq!(connection.receive(), Err(Error::Timeout));
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(connection.receive(), Err(Error::InvalidFrame));
        assert_eq!(connection.send(b"ok"), Err(Error::InvalidFrame));
    }
    drop(server.close().unwrap());
}

#[test]
fn closing_transport_never_clears_manual_review_and_policy_failure_creates_no_socket() {
    let area = Area::new();
    drop(area.store().begin().unwrap());
    let store = RecordStore::open(&area.0.join("data"), Limits::default()).unwrap();
    let server = Listener::bind(store, 16, Duration::from_millis(100)).unwrap();
    let store = server.close().unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    drop(store);
    for (limit, timeout) in [
        (0, Duration::from_secs(1)),
        (MAX_FRAME + 1, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (1, MAX_TIMEOUT + Duration::from_secs(1)),
    ] {
        let store = RecordStore::open(&area.0.join("data"), Limits::default()).unwrap();
        assert!(matches!(
            Listener::bind(store, limit, timeout),
            Err(Error::Policy)
        ));
        assert!(!area.endpoint().exists());
    }
    for e in [
        Error::Policy,
        Error::UnsafeEndpoint,
        Error::EndpointExists,
        Error::Unauthorized,
        Error::Timeout,
        Error::InvalidFrame,
        Error::Io,
    ] {
        assert!(std::error::Error::source(&e).is_none());
        assert!(e.to_string().starts_with("admin_ipc_"));
    }
}

#[test]
fn kernel_credentials_reject_a_real_other_uid_without_reading_self_claimed_identity() {
    // 認証関数の試験専用socket。製品の0700境界を緩めない。
    let area = Area::new();
    fs::set_permissions(&area.0, fs::Permissions::from_mode(0o755)).unwrap();
    let path = area.0.join("credential-test.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let current = rustix::process::geteuid().as_raw();
    let expected_owner = if current == 0 { 0 } else { current + 1 };
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap_or("python3".into());
    let mut child = std::process::Command::new(python).args(["-c", "import os,socket,sys\nif os.geteuid()==0:\n os.setgroups([]); os.setgid(65534); os.setuid(65534)\ns=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b'uid=0'); s.close()"])
        .arg(&path).spawn().unwrap();
    ready(
        &listener,
        PollFlags::IN,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let (stream, _) = listener.accept().unwrap();
    assert_eq!(
        authenticate(&stream, expected_owner),
        Err(Error::Unauthorized)
    );
    // 要求内のroot自己申告が残っている: 認証は要求本文を読んでいない。
    assert!(child.wait().unwrap().success());
    let mut stream = stream;
    let mut bytes = [0; 5];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"uid=0");
}

#[test]
fn slow_trickle_and_response_backpressure_share_one_deadline_per_frame() {
    let area = Area::new();
    let mut server = area.listener(MAX_FRAME);
    let client = UnixStream::connect(area.endpoint()).unwrap();
    let sender = std::thread::spawn(move || {
        let mut client = client;
        for byte in frame(b"slow message") {
            if client.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    });
    let mut connection = server.accept().unwrap();
    let start = Instant::now();
    assert_eq!(connection.receive(), Err(Error::Timeout));
    assert!(start.elapsed() < Duration::from_secs(3));
    drop(connection);
    sender.join().unwrap();

    let mut client = UnixStream::connect(area.endpoint()).unwrap();
    client.write_all(&frame(b"request")).unwrap();
    let mut connection = server.accept().unwrap();
    assert_eq!(connection.receive().unwrap(), b"request");
    rustix::net::sockopt::set_socket_send_buffer_size(&connection.stream, 4096).unwrap();
    let start = Instant::now();
    assert_eq!(connection.send(&vec![1; MAX_FRAME]), Err(Error::Timeout));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(connection.send(b"retry"), Err(Error::InvalidFrame));
    drop(connection);
    drop(server.close().unwrap());
}

fn initialized_writer(area: &Area) -> crate::storage::RecordWriter {
    drop(area.store());
    let mut startup =
        crate::storage::LocalStartup::open(&area.0.join("data"), Limits::default()).unwrap();
    assert!(!startup.needs_review());
    while !startup
        .step(
            crate::storage::EvaluationLimits::default(),
            crate::storage::LocalStartupBudget::default(),
        )
        .unwrap()
        .checks_complete()
    {}
    startup.into_writer().unwrap()
}

#[test]
fn authenticated_record_commit_reply_duplicate_and_close_preserve_one_writer_lock() {
    let area = Area::new();
    let writer = initialized_writer(&area);
    let mut server = Listener::bind_writer(writer, MAX_FRAME, Duration::from_millis(100)).unwrap();
    let record = crate::storage::tests::fixture(); // A13公開fixture
    for inserted in [true, false] {
        let mut client = UnixStream::connect(area.endpoint()).unwrap();
        client.write_all(&frame(record.bytes())).unwrap();
        let mut connection = server.accept().unwrap();
        let receipt = connection.store_record().unwrap();
        assert_eq!(receipt.record_id, record.id());
        assert_eq!(receipt.inserted, inserted);
        assert!(matches!(
            connection.store_record(),
            Err(RecordError::Transport(Error::InvalidFrame))
        ));
        assert!(connection.store().record(record.id()).unwrap().is_some());
        let mut expected = vec![0; 42];
        client.read_exact(&mut expected).unwrap();
        assert_eq!(expected, frame(&receipt.bytes()));
        assert!(matches!(
            RecordStore::open(&area.0.join("data"), Limits::default()),
            Err(StorageError::Busy)
        ));
    }
    let writer = server.close_writer().unwrap();
    assert!(!area.endpoint().exists());
    assert!(matches!(
        RecordStore::open(&area.0.join("data"), Limits::default()),
        Err(StorageError::Busy)
    ));
    writer.finish().unwrap();
    assert_eq!(
        RecordStore::open(&area.0.join("data"), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::Clean
    );
}

#[test]
fn record_storage_failure_never_acknowledges_and_blocks_normal_finish() {
    let area = Area::new();
    let writer = initialized_writer(&area);
    writer.store.conn.execute_batch("CREATE TRIGGER deny_record BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    let mut server = Listener::bind_writer(writer, MAX_FRAME, Duration::from_millis(100)).unwrap();
    let record = crate::storage::tests::fixture();
    let mut client = UnixStream::connect(area.endpoint()).unwrap();
    client.write_all(&frame(record.bytes())).unwrap();
    let mut connection = server.accept().unwrap();
    assert!(matches!(
        connection.store_record(),
        Err(RecordError::Storage(_))
    ));
    assert!(connection.store().record(record.id()).unwrap().is_none());
    drop(connection);
    let writer = server.close_writer().unwrap();
    assert!(matches!(
        writer.finish(),
        Err(StorageError::UnresolvedFailure)
    ));
    assert_eq!(
        RecordStore::open(&area.0.join("data"), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
}

#[test]
fn lost_commit_response_retains_receipt_and_record_without_repeating_insertion() {
    let area = Area::new();
    let mut server = Listener::bind_writer(
        initialized_writer(&area),
        MAX_FRAME,
        Duration::from_millis(100),
    )
    .unwrap();
    let record = crate::storage::tests::fixture();
    let mut client = UnixStream::connect(area.endpoint()).unwrap();
    client.write_all(&frame(record.bytes())).unwrap();
    client.shutdown(std::net::Shutdown::Read).unwrap();
    let mut connection = server.accept().unwrap();
    let Err(RecordError::ResponseLost(receipt)) = connection.store_record() else {
        panic!("commit and response failure must be distinguished");
    };
    assert_eq!(receipt.record_id, record.id());
    assert!(receipt.inserted);
    assert!(connection.store().record(record.id()).unwrap().is_some());
    drop(connection);
    let mut retry = UnixStream::connect(area.endpoint()).unwrap();
    retry.write_all(&frame(record.bytes())).unwrap();
    let mut connection = server.accept().unwrap();
    assert!(!connection.store_record().unwrap().inserted);
    drop(connection);
    server.close_writer().unwrap().finish().unwrap();
}

#[test]
fn inspection_mode_and_invalid_requests_never_become_writes_or_clear_review() {
    let area = Area::new();
    drop(area.store().begin().unwrap());
    let store = RecordStore::open(&area.0.join("data"), Limits::default()).unwrap();
    let before = crate::storage::tests::logical_snapshot(&store.conn);
    let mut server = Listener::bind(store, MAX_FRAME, Duration::from_millis(100)).unwrap();
    let record = crate::storage::tests::fixture();
    let mut client = UnixStream::connect(area.endpoint()).unwrap();
    client.write_all(&frame(record.bytes())).unwrap();
    let mut connection = server.accept().unwrap();
    assert!(matches!(
        connection.store_record(),
        Err(RecordError::ReadOnly)
    ));
    assert_eq!(
        crate::storage::tests::logical_snapshot(&connection.store().conn),
        before
    );
    drop(connection);
    assert_eq!(
        server.close().unwrap().startup_state().unwrap(),
        StartupState::NeedsReview
    );

    let other = Area::new();
    let mut server = Listener::bind_writer(
        initialized_writer(&other),
        MAX_FRAME,
        Duration::from_millis(100),
    )
    .unwrap();
    let mut client = UnixStream::connect(other.endpoint()).unwrap();
    client.write_all(&frame(b"not a signed Record")).unwrap();
    let mut connection = server.accept().unwrap();
    let before = crate::storage::tests::logical_snapshot(&connection.store().conn);
    let error = connection.store_record().unwrap_err();
    assert!(matches!(error, RecordError::Invalid(_)));
    assert_eq!(error.to_string(), "admin_record_rejected");
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(
        crate::storage::tests::logical_snapshot(&connection.store().conn),
        before
    );
    drop(connection);
    server.close_writer().unwrap().finish().unwrap();
}
