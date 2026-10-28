//! A13公開試験fixtureのみ。秘密鍵をネットワークへ送らない。
use super::*;
use crate::storage::{
    Limits, RecordStore, StartupState,
    admin_transport::Listener,
    tests::{Temp, fixture},
};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
    sync::mpsc,
    thread,
};

#[test]
fn authenticated_client_matches_commit_ids_and_idempotent_receipts_under_one_lock() {
    let temp = Temp::new();
    let record = fixture();
    let mut server = Listener::bind_writer(
        temp.store().begin().unwrap(),
        crate::cbor::MAX_RECORD,
        Duration::from_secs(2),
    )
    .unwrap();
    let worker = thread::spawn(move || {
        for _ in 0..2 {
            server.accept().unwrap().store_record().unwrap();
        }
        server.close_writer().unwrap().finish().unwrap();
    });
    assert!(
        submit(&temp.data(), &record, Duration::from_secs(2))
            .unwrap()
            .inserted
    );
    assert!(
        !submit(&temp.data(), &record, Duration::from_secs(2))
            .unwrap()
            .inserted
    );
    worker.join().unwrap();
    let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
    assert!(store.record(record.id()).unwrap().is_some());
}

#[test]
fn malformed_truncated_wrong_id_and_closed_responses_never_confirm_storage() {
    let record = fixture();
    let mut good = vec![1, 1];
    good.extend_from_slice(&record.id().bytes);
    let mut wrong_id = good.clone();
    wrong_id[2] ^= 1;
    let mut wrong_flag = good.clone();
    wrong_flag[1] = 2;
    for body in [vec![], good[..10].to_vec(), wrong_id, wrong_flag] {
        let temp = Temp::new();
        drop(temp.store());
        let socket = temp.data().join("admin.sock");
        let server = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut header = [0; 8];
            stream.read_exact(&mut header).unwrap();
            let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            if !body.is_empty() {
                stream
                    .write_all(&[b'L', b'N', b'A', 1, 0, 0, 0, 34])
                    .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        assert_eq!(
            submit(&temp.data(), &record, Duration::from_secs(2)),
            Err(Error::OutcomeUnknown)
        );
        worker.join().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert!(store.record(record.id()).unwrap().is_none()); // 直接保存へ降格しない。
    }
}

#[test]
fn oversized_unknown_frame_and_idle_peer_obey_one_deadline_without_retry() {
    for response in [
        vec![b'L', b'N', b'A', 1, 255, 255, 255, 255],
        vec![b'L', b'N', b'A', 2, 0, 0, 0, 34],
        vec![],
    ] {
        let temp = Temp::new();
        drop(temp.store());
        let socket = temp.data().join("admin.sock");
        let server = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut header = [0; 8];
            stream.read_exact(&mut header).unwrap();
            let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).unwrap();
            if !response.is_empty() {
                stream.write_all(&response).unwrap();
            }
            done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            server.set_nonblocking(true).unwrap();
            assert!(matches!(server.accept(), Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        });
        let start = Instant::now();
        assert_eq!(
            submit(&temp.data(), &fixture(), Duration::from_millis(150)),
            Err(Error::OutcomeUnknown)
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        done_tx.send(()).unwrap();
        worker.join().unwrap();
    }
}

#[test]
fn missing_unsafe_symlink_stale_endpoints_and_invalid_policy_are_not_sent() {
    let temp = Temp::new();
    drop(temp.store());
    let record = fixture();
    assert_eq!(
        submit(&temp.data(), &record, Duration::ZERO),
        Err(Error::Policy)
    );
    assert_eq!(
        submit(&temp.data(), &record, Duration::from_secs(31)),
        Err(Error::Policy)
    );
    assert_eq!(
        submit(&temp.data(), &record, Duration::from_secs(1)),
        Err(Error::Endpoint)
    );
    let path = temp.data().join("admin.sock");
    std::fs::write(&path, b"preserve").unwrap();
    assert_eq!(
        submit(&temp.data(), &record, Duration::from_secs(1)),
        Err(Error::Endpoint)
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve");
    std::fs::remove_file(&path).unwrap();
    symlink(temp.data().join("absent"), &path).unwrap();
    assert_eq!(
        submit(&temp.data(), &record, Duration::from_secs(1)),
        Err(Error::Endpoint)
    );
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    std::fs::remove_file(&path).unwrap();
    let server = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        submit(&temp.data(), &record, Duration::from_secs(1)),
        Err(Error::Endpoint)
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(server);
    assert_eq!(
        submit(&temp.data(), &record, Duration::from_secs(1)),
        Err(Error::Connect)
    );
}

#[test]
fn server_authentication_rejects_real_other_uid_before_reading_self_claims() {
    // client認証関数の試験専用socket。製品の0700/0600条件は変更しない。
    let temp = Temp::new();
    std::fs::set_permissions(&temp.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = temp.root.join("auth.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let current = rustix::process::geteuid().as_raw();
    let owner = if current == 0 { 0 } else { current + 1 };
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap_or("python3".into());
    let mut child = std::process::Command::new(python).args(["-c", "import os,socket,sys\nif os.geteuid()==0:\n os.setgroups([]); os.setgid(65534); os.setuid(65534)\ns=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b'root'); s.close()"])
        .arg(&path).spawn().unwrap();
    ready(
        &listener,
        PollFlags::IN,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    assert_eq!(
        authenticate_server(&stream, owner),
        Err(Error::Unauthorized)
    );
    assert!(child.wait().unwrap().success());
    let mut untouched = [0; 4];
    stream.read_exact(&mut untouched).unwrap();
    assert_eq!(&untouched, b"root");
}
