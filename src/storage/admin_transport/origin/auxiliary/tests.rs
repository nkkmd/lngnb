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
const NAMES: [&str; 4] = [NAME, status::NAME, evaluation::NAME, configuration::NAME];

fn all(t: &Temp) -> (Listener, Vec<SocketOrigin>) {
    let (listener, main) = Listener::bind_writer_with_origin(
        t.store().begin().unwrap(),
        MAX_FRAME,
        MAX_TIMEOUT,
        ELAPSED,
    )
    .unwrap();
    let (listener, status) = listener.enable_status_with_origin(ELAPSED).unwrap();
    let (listener, evaluation) = listener.enable_evaluation_with_origin(17, ELAPSED).unwrap();
    let (listener, configuration) = listener.enable_configuration_with_origin(ELAPSED).unwrap();
    (listener, vec![main, status, evaluation, configuration])
}
fn independent(origin: &SocketOrigin, t: &Temp, fd: Option<&UnixListener>) {
    super::super::tests::independent_socket(origin, t, fd);
}

#[test]
fn four_tracked_names_match_independent_kernel_and_keep_explicit_close_finish() {
    let t = Temp::new();
    let writer = t.store().begin().unwrap();
    let before = logical_snapshot(&writer.store.conn);
    let (listener, main) =
        Listener::bind_writer_with_origin(writer, MAX_FRAME, MAX_TIMEOUT, ELAPSED).unwrap();
    let (listener, status) = listener.enable_status_with_origin(ELAPSED).unwrap();
    let (listener, evaluation) = listener.enable_evaluation_with_origin(17, ELAPSED).unwrap();
    let (listener, configuration) = listener.enable_configuration_with_origin(ELAPSED).unwrap();
    let origins = [main, status, evaluation, configuration];
    assert_eq!(listener.evaluation_records, 17);
    assert_eq!(listener.timeout, MAX_TIMEOUT);
    for (name, origin) in NAMES.into_iter().zip(&origins) {
        assert_eq!(origin.identity.name, name);
        listener.verify_socket_origin(origin, ELAPSED).unwrap();
        let (socket, _) = listener.origin_socket(name).unwrap();
        independent(origin, &t, Some(socket));
        assert!(matches!(socket.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        assert_eq!(
            listener
                .access
                .store()
                .socket_origin_presence(origin, ELAPSED)
                .unwrap(),
            SocketPresence::Present { state: 10 }
        );
    }
    assert!(RecordStore::open(&t.data(), Limits::default()).is_err());
    assert_eq!(logical_snapshot(&listener.access.store().conn), before);
    let writer = listener.close_writer().unwrap();
    for name in NAMES {
        assert!(!t.data().join(name).exists());
    }
    assert_eq!(
        writer.store.startup_state().unwrap(),
        StartupState::NeedsReview
    );
    writer.finish().unwrap();
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::Clean
    );
    for target in [
        Auxiliary::Status,
        Auxiliary::Evaluation(17),
        Auxiliary::Configuration,
    ] {
        let t = Temp::new();
        let mut listener =
            Listener::bind_writer(t.store().begin().unwrap(), MAX_FRAME, MAX_TIMEOUT).unwrap();
        let Access::Write(writer) = &mut listener.access else {
            panic!("writer expected");
        };
        writer.failed = true;
        assert!(matches!(
            listener.enable_auxiliary_origin(target, ELAPSED, |_| Ok(())),
            Err(SocketOriginError::Bind(Error::SessionFailed))
        ));
        for name in &NAMES[1..] {
            assert!(!t.data().join(name).exists());
        }
        assert_eq!(
            RecordStore::open(&t.data(), Limits::default())
                .unwrap()
                .startup_state()
                .unwrap(),
            StartupState::NeedsReview
        );
    }
}

#[test]
fn only_held_auxiliary_is_present_after_listener_drop_without_extending_fd_lifetime() {
    for (selected, name) in NAMES.into_iter().enumerate().skip(1) {
        let t = Temp::new();
        let (listener, origins) = all(&t);
        let before = logical_snapshot(&listener.access.store().conn);
        let held = listener
            .origin_socket(name)
            .unwrap()
            .0
            .try_clone()
            .unwrap();
        drop(listener);
        let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
        for (index, origin) in origins.iter().enumerate() {
            if index == selected {
                assert_eq!(
                    store.socket_origin_presence(origin, ELAPSED).unwrap(),
                    SocketPresence::Present { state: 10 }
                );
                independent(origin, &t, Some(&held));
            } else {
                assert_eq!(
                    store.socket_origin_presence(origin, ELAPSED),
                    Err(SocketOriginError::Unavailable)
                );
                independent(origin, &t, None);
            }
        }
        assert!(matches!(held.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        drop(held);
        for origin in &origins {
            assert_eq!(
                store.socket_origin_presence(origin, ELAPSED),
                Err(SocketOriginError::Unavailable)
            );
            assert_eq!(
                SocketPathMetadata::from_metadata(
                    &fs::symlink_metadata(t.data().join(origin.identity.name)).unwrap()
                ),
                origin.identity.path
            );
        }
        assert_eq!(logical_snapshot(&store.conn), before);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn auxiliary_references_reject_other_area_name_and_attribute_changes_without_repair() {
    let t = Temp::new();
    let other = Temp::new();
    let (listener, mut origins) = all(&t);
    let (second, _) = all(&other);
    let before = logical_snapshot(&listener.access.store().conn);
    for origin in &origins[1..] {
        assert_eq!(
            second.verify_socket_origin(origin, ELAPSED),
            Err(SocketOriginError::Mismatch)
        );
        assert_eq!(
            listener.verify_socket_origin(origin, Duration::ZERO),
            Err(SocketOriginError::BudgetExceeded)
        );
    }
    let original = origins[1].identity.name;
    origins[1].identity.name = configuration::NAME;
    assert_eq!(
        listener.verify_socket_origin(&origins[1], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    origins[1].identity.name = original;
    let path = t.data().join(status::NAME);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        listener.verify_socket_origin(&origins[1], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o660);
    let eval = t.data().join(evaluation::NAME);
    let alias = t.root.join("alias.sock");
    fs::hard_link(&eval, &alias).unwrap();
    assert_eq!(
        listener.verify_socket_origin(&origins[2], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(fs::symlink_metadata(eval).unwrap().nlink(), 2);
    let config = t.data().join(configuration::NAME);
    let saved = t.root.join("saved.sock");
    fs::rename(&config, &saved).unwrap();
    symlink(&saved, &config).unwrap();
    assert_eq!(
        listener.verify_socket_origin(&origins[3], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert!(
        fs::symlink_metadata(config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(logical_snapshot(&listener.access.store().conn), before);
}

#[test]
fn rejected_creation_and_capture_leave_names_data_and_manual_wait_without_adoption() {
    for case in 0..6 {
        let t = Temp::new();
        let writer = t.store().begin().unwrap();
        let before = logical_snapshot(&writer.store.conn);
        let listener = Listener::bind_writer(writer, MAX_FRAME, MAX_TIMEOUT).unwrap();
        let result = match case {
            0 => listener.enable_status_with_origin(Duration::ZERO),
            1 => listener.enable_evaluation_with_origin(0, ELAPSED),
            2 => listener.enable_evaluation_with_origin(10_001, ELAPSED),
            3 => listener.enable_configuration_with_origin(ELAPSED),
            4 => {
                fs::write(t.data().join(status::NAME), b"KEEP").unwrap();
                listener.enable_status_with_origin(ELAPSED)
            }
            _ => {
                let mut listener = listener;
                listener.enable_status().unwrap();
                listener.enable_status_with_origin(ELAPSED)
            }
        };
        let expected = match case {
            0 => SocketOriginError::BudgetExceeded,
            1 | 2 => SocketOriginError::Bind(Error::Policy),
            3 => SocketOriginError::Bind(Error::WrongMode),
            _ => SocketOriginError::Bind(Error::EndpointExists),
        };
        assert!(matches!(result,Err(e) if e==expected));
        assert!(t.data().join(NAME).exists());
        assert!(!t.data().join(evaluation::NAME).exists());
        assert!(!t.data().join(configuration::NAME).exists());
        if case == 4 {
            assert_eq!(fs::read(t.data().join(status::NAME)).unwrap(), b"KEEP");
        }
        if case < 4 {
            assert!(!t.data().join(status::NAME).exists());
        }
        let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(logical_snapshot(&store.conn), before);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        assert!(store.begin().is_err());
    }
    for stage in 0..3 {
        let t = Temp::new();
        let (mut listener, _) = Listener::bind_writer_with_origin(
            t.store().begin().unwrap(),
            MAX_FRAME,
            MAX_TIMEOUT,
            ELAPSED,
        )
        .unwrap();
        if stage > 0 {
            listener.enable_status().unwrap();
        }
        if stage > 1 {
            listener.enable_evaluation().unwrap();
        }
        let before = logical_snapshot(&listener.access.store().conn);
        let target = match stage {
            0 => Auxiliary::Status,
            1 => Auxiliary::Evaluation(17),
            _ => Auxiliary::Configuration,
        };
        let name = target.name();
        let result = listener
            .enable_auxiliary_origin(target, ELAPSED, |_| Err(SocketOriginError::Unavailable));
        assert!(matches!(result, Err(SocketOriginError::Unavailable)));
        assert!(
            fs::symlink_metadata(t.data().join(name))
                .unwrap()
                .file_type()
                .is_socket()
        );
        let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
        assert_eq!(logical_snapshot(&store.conn), before);
        assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
    }
}

#[test]
fn absent_endpoint_invalid_receipt_and_observation_change_do_not_clear_or_repair() {
    let t = Temp::new();
    let (listener, mut origins) = all(&t);
    let original = origins[1].identity.name;
    origins[1].identity.name = "../outside";
    assert_eq!(
        listener.verify_socket_origin(&origins[1], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(
        listener
            .access
            .store()
            .socket_origin_presence(&origins[1], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    origins[1].identity.name = original;
    let path = t.data().join(configuration::NAME);
    let before = logical_snapshot(&listener.access.store().conn);
    assert_eq!(
        listener.verify_origin_inner(&origins[3], ELAPSED, || {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            Ok(())
        }),
        Err(SocketOriginError::Mismatch)
    );
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o400);
    assert_eq!(logical_snapshot(&listener.access.store().conn), before);
    let mut listener = listener;
    drop(listener.status.take());
    assert_eq!(
        listener.verify_socket_origin(&origins[1], ELAPSED),
        Err(SocketOriginError::Mismatch)
    );
    assert!(t.data().join(status::NAME).exists());
    drop(listener);
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::NeedsReview
    );
    let t = Temp::new();
    let listener = Listener::bind(t.store(), MAX_FRAME, MAX_TIMEOUT).unwrap();
    assert!(matches!(
        listener.enable_status_with_origin(ELAPSED),
        Err(SocketOriginError::Bind(Error::WrongMode))
    ));
    assert_eq!(
        RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .startup_state()
            .unwrap(),
        StartupState::Clean
    );
}

#[test]
fn auxiliary_query_stays_bound_to_original_directory_and_ignores_unrelated_names() {
    let t = Temp::new();
    let (listener, origins) = all(&t);
    drop(listener);
    let store = RecordStore::open(&t.data(), Limits::default()).unwrap();
    let moved = t.root.join("moved");
    fs::rename(t.data(), &moved).unwrap();
    fs::create_dir(t.data()).unwrap();
    for name in NAMES {
        fs::write(t.data().join(name), b"OTHER").unwrap();
    }
    for origin in &origins[1..] {
        assert_eq!(
            store.socket_origin_presence(origin, ELAPSED),
            Err(SocketOriginError::Unavailable)
        );
        assert_eq!(
            SocketPathMetadata::from_metadata(
                &fs::symlink_metadata(moved.join(origin.identity.name)).unwrap()
            ),
            origin.identity.path
        );
    }
    for name in NAMES {
        assert_eq!(fs::read(t.data().join(name)).unwrap(), b"OTHER");
    }
}
