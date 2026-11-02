use super::*;
use crate::storage::{
    Limits, StartupState,
    tests::{Temp, logical_snapshot},
};
use std::{
    fs,
    os::{fd::OwnedFd, unix::fs::{PermissionsExt, symlink}},
    process::{Command, Stdio},
};
const ELAPSED: Duration = Duration::from_secs(60);

fn independent(origin: &SocketOrigin, t: &Temp, listener: Option<&Listener>) {
    let i = origin.identity();
    let p = i.path;
    let expected = serde_json::json!({
        "boot_id": i.boot_id,
        "namespace": [i.namespace_device, i.namespace_inode],
        "directory": [i.directory_device, i.directory_inode, i.owner_uid as u64],
        "directory_path": t.data(),
        "name": i.name,
        "socket_device": i.socket_device,
        "socket_inode": i.socket_inode,
        "socket_cookie": i.socket_cookie,
        "path": [p.device as i128, p.inode as i128, p.owner_uid as i128,
                 p.owner_gid as i128, p.mode as i128, p.links as i128,
                 p.byte_length as i128, p.modified_seconds as i128,
                 p.modified_nanoseconds as i128, p.changed_seconds as i128,
                 p.changed_nanoseconds as i128],
    });
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap_or("python3".into());
    let mut child = Command::new(python);
    child.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/socket_identity_reference.py"));
    if let Some(listener) = listener {
        child.arg("--check-origin");
        let fd: OwnedFd = listener.socket.try_clone().unwrap().into();
        child.stdin(Stdio::from(fd));
    } else {
        child.arg("--check-closed-origin").stdin(Stdio::null());
    }
    let output = child.arg(expected.to_string()).output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, b"socket_origin_reference_passed\n");
}

#[test]
fn tracked_bind_matches_independent_kernel_identity_and_receipt_keeps_no_listener() {
    let t = Temp::new();
    drop(t.store().begin().unwrap());
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    let before = logical_snapshot(&store.conn);
    let (listener, origin) = Listener::bind_with_origin(store, MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    listener.verify_socket_origin(&origin, ELAPSED).unwrap();
    independent(&origin, &t, Some(&listener));
    assert_eq!(origin.identity().path.links, 1);
    assert_eq!(origin.identity().name, NAME);
    assert_eq!(logical_snapshot(&listener.access.store().conn), before);
    assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
    // 返した記述値を変更しても、保持された根拠には影響しない。
    let mut copy = origin.identity().clone();
    copy.socket_cookie ^= 1;
    assert_ne!(&copy, origin.identity());
    listener.verify_socket_origin(&origin, ELAPSED).unwrap();
    drop(listener);
    independent(&origin, &t, None);
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert_eq!(logical_snapshot(&store.conn), before);
    assert_eq!(store.admin_socket_inventory(ELAPSED).unwrap().entries[0].observed,
               Some(origin.identity().path));
}

#[test]
fn other_receipt_context_or_budget_mismatch_never_changes_store_or_socket() {
    let t = Temp::new();
    let other = Temp::new();
    let (listener, mut origin) = Listener::bind_with_origin(t.store(), MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let (second, other_origin) = Listener::bind_with_origin(other.store(), MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let before = logical_snapshot(&listener.access.store().conn);
    assert_eq!(listener.verify_socket_origin(&other_origin, ELAPSED), Err(SocketOriginError::Mismatch));
    assert_eq!(second.verify_socket_origin(&origin, ELAPSED), Err(SocketOriginError::Mismatch));
    assert_eq!(listener.verify_socket_origin(&origin, Duration::ZERO), Err(SocketOriginError::BudgetExceeded));
    let original = origin.identity.clone();
    origin.identity.boot_id = "00000000-0000-0000-0000-000000000000".into();
    assert_eq!(listener.verify_socket_origin(&origin, ELAPSED), Err(SocketOriginError::Mismatch));
    origin.identity = original.clone();
    origin.identity.namespace_inode ^= 1;
    assert_eq!(listener.verify_socket_origin(&origin, ELAPSED), Err(SocketOriginError::Mismatch));
    origin.identity = original;
    listener.verify_socket_origin(&origin, ELAPSED).unwrap();
    assert_eq!(logical_snapshot(&listener.access.store().conn), before);
    assert_eq!(listener.access.store().startup_state().unwrap(), StartupState::Clean);
    let path = anchored(&listener.access.store().dir, NAME);
    assert_eq!(SocketPathMetadata::from_metadata(&fs::symlink_metadata(&path).unwrap()), origin.identity().path);
}

#[test]
fn path_mode_link_and_between_observation_changes_are_rejected_without_repair() {
    let t = Temp::new();
    let (listener, origin) = Listener::bind_with_origin(t.store(), MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let path = anchored(&listener.access.store().dir, NAME);
    let before = logical_snapshot(&listener.access.store().conn);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(listener.verify_socket_origin(&origin, ELAPSED), Err(SocketOriginError::Mismatch));
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o660);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    // ctimeの変化も元の取得値へ自動追従しない。新規bindで別fixtureを使う。
    let alias = t.root.join("alias.sock");
    fs::hard_link(&path, &alias).unwrap();
    assert_eq!(listener.verify_socket_origin(&origin, ELAPSED), Err(SocketOriginError::Mismatch));
    assert_eq!(fs::symlink_metadata(&path).unwrap().nlink(), 2);
    let saved = t.root.join("original.sock");
    fs::rename(&path, &saved).unwrap();
    symlink(&saved, &path).unwrap();
    assert_eq!(listener.verify_socket_origin(&origin, ELAPSED), Err(SocketOriginError::Mismatch));
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    assert_eq!(logical_snapshot(&listener.access.store().conn), before);

    let t2 = Temp::new();
    let (listener2, origin2) = Listener::bind_with_origin(t2.store(), MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let path2 = anchored(&listener2.access.store().dir, NAME);
    let result = listener2.verify_origin_inner(&origin2, ELAPSED, || {
        fs::set_permissions(&path2, fs::Permissions::from_mode(0o400)).unwrap();
        Ok(())
    });
    assert_eq!(result, Err(SocketOriginError::Mismatch));
    assert_eq!(fs::symlink_metadata(path2).unwrap().mode() & 0o7777, 0o400);
}

#[test]
fn failed_capture_leaves_created_socket_and_writer_failure_boundaries_intact() {
    let t = Temp::new();
    let store = t.store();
    let before = logical_snapshot(&store.conn);
    assert!(matches!(Listener::bind_with_origin(store, MAX_FRAME, MAX_TIMEOUT, Duration::ZERO),
                     Err(SocketOriginError::BudgetExceeded)));
    assert!(!t.data().join(NAME).exists());
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(logical_snapshot(&store.conn), before);
    fs::write(t.data().join(NAME), b"KEEP").unwrap();
    assert!(matches!(Listener::bind_with_origin(store, MAX_FRAME, MAX_TIMEOUT, ELAPSED),
                     Err(SocketOriginError::Bind(Error::EndpointExists))));
    assert_eq!(fs::read(t.data().join(NAME)).unwrap(), b"KEEP");

    let fresh = Temp::new();
    let writer = fresh.store().begin().unwrap();
    let result = Listener::bind_origin_inner(|| Listener::bind_writer(writer, MAX_FRAME, MAX_TIMEOUT),
                                           ELAPSED, |_| Err(SocketOriginError::Unavailable));
    assert!(matches!(result, Err(SocketOriginError::Unavailable)));
    assert!(fs::symlink_metadata(fresh.data().join(NAME)).unwrap().file_type().is_socket());
    let store = RecordStore::open(&fresh.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    assert!(store.begin().is_err());
}

#[test]
fn tracked_writer_and_fd_anchoring_preserve_explicit_close_and_finish_separation() {
    let t = Temp::new();
    let (listener, origin) = Listener::bind_writer_with_origin(t.store().begin().unwrap(), MAX_FRAME,
                                                             MAX_TIMEOUT, ELAPSED).unwrap();
    listener.verify_socket_origin(&origin, ELAPSED).unwrap();
    let writer = listener.close_writer().unwrap();
    assert!(!t.data().join(NAME).exists());
    assert_eq!(writer.store.startup_state().unwrap(), StartupState::NeedsReview);
    writer.finish().unwrap();
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    assert_eq!(store.startup_state().unwrap(), StartupState::Clean);

    let moved_area = Temp::new();
    let (reader, observed) = Listener::bind_with_origin(moved_area.store(), MAX_FRAME,
                                                       MAX_TIMEOUT, ELAPSED).unwrap();
    let moved = moved_area.root.join("moved-data");
    fs::rename(moved_area.data(), &moved).unwrap();
    fs::create_dir(moved_area.data()).unwrap();
    fs::write(moved_area.data().join(NAME), b"OTHER AREA").unwrap();
    reader.verify_socket_origin(&observed, ELAPSED).unwrap();
    drop(reader);
    assert!(moved.join(NAME).exists());
    assert_eq!(fs::read(moved_area.data().join(NAME)).unwrap(), b"OTHER AREA");
}

#[test]
fn boot_context_input_is_bounded_and_canonical() {
    let valid = b"01234567-89ab-cdef-0123-456789abcdef\n";
    assert_eq!(boot_id(valid).unwrap(), "01234567-89ab-cdef-0123-456789abcdef");
    for n in 0..valid.len() {
        assert_eq!(boot_id(&valid[..n]), Err(SocketOriginError::Unavailable));
    }
    let mut extra = valid.to_vec();
    extra.push(b'\n');
    assert_eq!(boot_id(&extra), Err(SocketOriginError::Unavailable));
    for index in 0..valid.len() {
        let mut invalid = *valid;
        invalid[index] = if index == 8 { b'0' } else { b'Z' };
        assert_eq!(boot_id(&invalid), Err(SocketOriginError::Unavailable));
    }
    assert_eq!(SocketOriginError::Unavailable.to_string(), "admin_socket_origin_unavailable");
}
