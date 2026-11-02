use super::*;
use crate::storage::{
    Limits, StartupState,
    tests::{Temp, logical_snapshot},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
const ELAPSED: Duration = Duration::from_secs(30);
fn decode(bytes: &[u8], port: u32, sent: &[u8; 40]) -> OriginResult<SocketPresence> {
    super::decode(bytes, port, sent, (13, 17))
}
fn received(
    bytes: &[u8],
    flags: MsgFlags,
    sender: Option<NetlinkAddr>,
    port: u32,
    sent: &[u8; 40],
) -> OriginResult<SocketPresence> {
    super::received(bytes, flags, sender, port, sent, (13, 17))
}

fn response(port: u32, sent: &[u8; 40]) -> Vec<u8> {
    let mut bytes = vec![0; 44];
    bytes[..4].copy_from_slice(&44u32.to_ne_bytes());
    bytes[4..6].copy_from_slice(&20u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    bytes[12..16].copy_from_slice(&port.to_ne_bytes());
    bytes[16..20].copy_from_slice(&[1, 1, 10, 0]);
    bytes[20..24].copy_from_slice(&sent[24..28]);
    bytes[24..32].copy_from_slice(&sent[32..40]);
    bytes[32..36].copy_from_slice(&[12, 0, 1, 0]);
    bytes[36..40].copy_from_slice(&13u32.to_ne_bytes());
    bytes[40..44].copy_from_slice(&17u32.to_ne_bytes());
    bytes
}
fn error(port: u32, sent: &[u8; 40], errno: i32) -> Vec<u8> {
    let mut bytes = vec![0; 60];
    bytes[..4].copy_from_slice(&60u32.to_ne_bytes());
    bytes[4..6].copy_from_slice(&2u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    bytes[12..16].copy_from_slice(&port.to_ne_bytes());
    bytes[16..20].copy_from_slice(&errno.to_ne_bytes());
    bytes[20..].copy_from_slice(sent);
    bytes
}

#[test]
fn contract_matches_independent_python_uapi_and_rejects_malformed_responses() {
    let sent = request(7, 9).unwrap();
    let good = response(19, &sent);
    // 独立Pythonのstruct形式で要求とfixture応答を構築/解釈する。
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap_or("python3".into());
    let output = std::process::Command::new(python).arg("-c").arg(
        "import struct,sys,json; from pathlib import Path; sys.path.insert(0,str(Path(sys.argv[1])/'tests')); import socket_identity_reference as r; x=json.loads(sys.argv[2]); s=bytes(x['sent']); g=bytes(x['good']); assert s==r.request(7,9,1); assert r.decode(g,0,(0,0),19,s,7,9)==(10,(13,17)); print('query_contract_passed')"
    ).arg(env!("CARGO_MANIFEST_DIR"))
        .arg(serde_json::json!({"sent":sent.as_slice(), "good":good}).to_string())
        .output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, b"query_contract_passed\n");
    assert_eq!(
        decode(&good, 19, &sent),
        Ok(SocketPresence::Present { state: 10 })
    );
    assert_eq!(
        received(
            &good,
            MsgFlags::empty(),
            Some(NetlinkAddr::new(0, 0)),
            19,
            &sent
        ),
        Ok(SocketPresence::Present { state: 10 })
    );
    for flags in [MsgFlags::MSG_TRUNC, MsgFlags::MSG_CTRUNC] {
        assert_eq!(
            received(&good, flags, Some(NetlinkAddr::new(0, 0)), 19, &sent),
            Err(SocketOriginError::InvalidResponse)
        );
    }
    for sender in [
        None,
        Some(NetlinkAddr::new(1, 0)),
        Some(NetlinkAddr::new(0, 1)),
    ] {
        assert_eq!(
            received(&good, MsgFlags::empty(), sender, 19, &sent),
            Err(SocketOriginError::InvalidResponse)
        );
    }
    assert_eq!(
        decode(&error(19, &sent, -2), 19, &sent),
        Ok(SocketPresence::Missing)
    );
    assert_eq!(
        decode(&error(19, &sent, -116), 19, &sent),
        Ok(SocketPresence::CookieMismatch)
    );
    for e in [-1, -5, -22] {
        assert_eq!(
            decode(&error(19, &sent, e), 19, &sent),
            Err(SocketOriginError::Unavailable)
        );
    }
    for e in [0, 2] {
        assert!(decode(&error(19, &sent, e), 19, &sent).is_err());
    }
    for n in 0..good.len() {
        assert!(decode(&good[..n], 19, &sent).is_err());
    }
    for (pos, value) in [
        (4, 3),
        (6, 2),
        (8, 2),
        (12, 20),
        (16, 2),
        (17, 2),
        (18, 0),
        (19, 1),
        (20, 8),
        (24, 10),
        (32, 3),
        (34, 2),
        (36, 14),
        (40, 18),
    ] {
        let mut bad = good.clone();
        bad[pos] = value;
        assert!(decode(&bad, 19, &sent).is_err(), "offset {pos}");
    }
    for suffix in [&[0u8][..], &good[32..][..]] {
        let mut bad = good.clone();
        bad.extend_from_slice(suffix);
        let len = bad.len() as u32;
        bad[..4].copy_from_slice(&len.to_ne_bytes());
        assert!(decode(&bad, 19, &sent).is_err());
    }
    let mut bad = error(19, &sent, -2);
    bad[44] ^= 1;
    assert!(decode(&bad, 19, &sent).is_err());
    assert!(decode(&vec![0; LIMIT + 1], 19, &sent).is_err());
    assert!(request(0, 9).is_err());
    assert!(request(7, 0).is_err());
    assert!(request(7, u64::MAX).is_err());
}

#[test]
fn live_duplicated_and_closed_socket_results_preserve_path_store_and_manual_hold() {
    let t = Temp::new();
    drop(t.store().begin().unwrap());
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    let before = logical_snapshot(&store.conn);
    let (listener, origin) =
        Listener::bind_with_origin(store, MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let store = listener.access.store();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED).unwrap(),
        SocketPresence::Present { state: 10 }
    );
    super::super::tests::independent(&origin, &t, Some(&listener));
    assert!(matches!(listener.socket.accept(), Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
    let held = listener.socket.try_clone().unwrap();
    drop(listener);
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED).unwrap(),
        SocketPresence::Present { state: 10 }
    );
    assert!(matches!(held.accept(), Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
    // exec子だけが保持するfdも、PID/排他の推測ではなく同じ個別照会で確認。
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap_or("python3".into());
    let fd: std::os::fd::OwnedFd = held.try_clone().unwrap().into();
    let child=std::process::Command::new(python).arg("-c").arg(
        "import signal,socket,sys; signal.alarm(30); s=socket.socket(fileno=2); print('ready',flush=True); assert sys.stdin.buffer.read(1)==b'x'; s.close()"
    ).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::from(fd)).spawn().unwrap();
    struct Guard(std::process::Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Guard(child);
    let out = child.0.stdout.as_mut().unwrap();
    ready(out, PollFlags::IN, Instant::now() + ELAPSED).unwrap();
    let mut marker = [0; 6];
    out.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"ready\n");
    drop(held);
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED).unwrap(),
        SocketPresence::Present { state: 10 }
    );
    child.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    assert!(child.0.wait().unwrap().success());
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED).unwrap(),
        SocketPresence::Missing
    );
    super::super::tests::independent(&origin, &t, None);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(logical_snapshot(&store.conn), before);
    assert_eq!(
        store.admin_socket_inventory(ELAPSED).unwrap().entries[0].observed,
        Some(origin.identity.path)
    );
    assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
    assert_eq!(
        fs::symlink_metadata(t.data().join(NAME)).unwrap().mode() & 0o7777,
        0o600
    );
}

#[test]
fn query_uses_original_directory_fd_and_refuses_absent_or_hardlinked_path() {
    let t = Temp::new();
    let (listener, origin) =
        Listener::bind_with_origin(t.store(), MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    drop(listener);
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    let moved = t.root.join("moved");
    fs::rename(t.data(), &moved).unwrap();
    fs::create_dir(t.data()).unwrap();
    fs::write(t.data().join(NAME), b"KEEP").unwrap();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED).unwrap(),
        SocketPresence::Missing
    );
    assert_eq!(fs::read(t.data().join(NAME)).unwrap(), b"KEEP");
    let path = moved.join(NAME);
    let saved = t.root.join("saved.sock");
    fs::rename(&path, &saved).unwrap();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    fs::hard_link(&saved, &path).unwrap();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(fs::symlink_metadata(path).unwrap().nlink(), 2);
    assert_eq!(fs::read(t.data().join(NAME)).unwrap(), b"KEEP");
}

#[test]
fn wrong_cookie_is_distinct_and_context_directory_path_or_budget_never_bypassed() {
    let t = Temp::new();
    let (listener, mut origin) =
        Listener::bind_with_origin(t.store(), MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let store = listener.access.store();
    let before = logical_snapshot(&store.conn);
    let cookie = origin.identity.socket_cookie;
    origin.identity.socket_cookie = if cookie == 1 { 2 } else { cookie - 1 };
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED).unwrap(),
        SocketPresence::CookieMismatch
    );
    origin.identity.socket_cookie = cookie;
    assert_eq!(
        store.socket_origin_presence(&origin, Duration::ZERO),
        Err(SocketOriginError::BudgetExceeded)
    );
    let other = Temp::new();
    assert_eq!(
        other.store().socket_origin_presence(&origin, ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    origin.identity.namespace_inode ^= 1;
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    origin.identity.namespace_inode ^= 1;
    let path = t.data().join(NAME);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o660);
    let saved = t.root.join("saved.sock");
    fs::rename(&path, &saved).unwrap();
    symlink(&saved, &path).unwrap();
    assert_eq!(
        store.socket_origin_presence(&origin, ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(logical_snapshot(&store.conn), before);
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);
}

#[test]
fn post_query_changes_or_failure_never_return_partial_diagnosis_or_repair() {
    let t = Temp::new();
    drop(t.store().begin().unwrap());
    let (listener, origin) = Listener::bind_with_origin(
        RecordStore::open(&t.data(), Limits::default()).unwrap(),
        MAX_FRAME,
        MAX_TIMEOUT,
        ELAPSED,
    )
    .unwrap();
    let store = listener.access.store();
    let before = logical_snapshot(&store.conn);
    assert_eq!(
        store.origin_presence_inner(&origin, ELAPSED, || Err(SocketOriginError::Unavailable)),
        Err(SocketOriginError::Unavailable)
    );
    let path = t.data().join(NAME);
    assert_eq!(
        store.origin_presence_inner(&origin, ELAPSED, || {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            Ok(())
        }),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o400);
    assert_eq!(logical_snapshot(&store.conn), before);
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
}
