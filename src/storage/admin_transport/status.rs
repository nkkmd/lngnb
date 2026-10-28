//! 要求bytesを受け取らない管理診断専用endpoint。Record受理とは分離する。
use super::*;

pub(super) const NAME: &str = "admin-status.sock";
pub(super) const MAGIC: [u8; 4] = *b"LNI\x01";
pub(super) const SIZE: usize = 62;

/// その時点の実行時情報だけ。全資料検査・公開・正常停止・復旧の証明ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u64,
    pub new_records: u64,
    pub stored_bytes: u64,
    pub max_new_records: u64,
    pub max_stored_bytes: u64,
    pub available_bytes: u64,
    pub reserved_floor_bytes: u64,
    pub request_timeout_ms: u32,
    pub capacity_warning: bool,
}
impl Snapshot {
    fn bytes(self) -> [u8; SIZE] {
        let mut bytes = [0; SIZE];
        bytes[0] = 1; // local runtime scope
        for (i, value) in [
            self.generation,
            self.new_records,
            self.stored_bytes,
            self.max_new_records,
            self.max_stored_bytes,
            self.available_bytes,
            self.reserved_floor_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[1 + i * 8..9 + i * 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[57..61].copy_from_slice(&self.request_timeout_ms.to_be_bytes());
        bytes[61] = u8::from(self.capacity_warning);
        bytes
    }
    pub(super) fn check(bytes: &[u8; SIZE]) -> Option<Self> {
        let number = |i: usize| u64::from_be_bytes(bytes[1 + i * 8..9 + i * 8].try_into().unwrap());
        let snapshot = Self {
            generation: number(0),
            new_records: number(1),
            stored_bytes: number(2),
            max_new_records: number(3),
            max_stored_bytes: number(4),
            available_bytes: number(5),
            reserved_floor_bytes: number(6),
            request_timeout_ms: u32::from_be_bytes(bytes[57..61].try_into().unwrap()),
            capacity_warning: bytes[61] == 1,
        };
        if bytes[0] != 1
            || bytes[61] > 1
            || snapshot.generation > i64::MAX as u64
            || snapshot.max_new_records == 0
            || snapshot.max_stored_bytes == 0
            || snapshot.new_records > snapshot.max_new_records
            || snapshot.stored_bytes > snapshot.max_stored_bytes
            || snapshot.request_timeout_ms == 0
            || snapshot.request_timeout_ms > 30_000
        {
            return None;
        }
        Some(snapshot)
    }
}

pub(super) struct Endpoint {
    socket: UnixListener,
    identity: (u64, u64),
    name: &'static str,
}
impl Endpoint {
    pub(super) fn bind(store: &RecordStore, owner: u32, name: &'static str) -> Result<Self> {
        check_area(&store.dir).map_err(|_| Error::UnsafeEndpoint)?;
        let path = anchored(&store.dir, name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(Error::EndpointExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error::Io),
        }
        let socket = UnixListener::bind(&path).map_err(|_| Error::Io)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|_| Error::Io)?;
        if !meta.file_type().is_socket() {
            return Err(Error::UnsafeEndpoint);
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Io)?;
        if meta.uid() != owner {
            std::os::unix::fs::chown(&path, Some(owner), None).map_err(|_| Error::Io)?;
        }
        socket.set_nonblocking(true).map_err(|_| Error::Io)?;
        let endpoint = Self {
            socket,
            identity: (meta.dev(), meta.ino()),
            name,
        };
        endpoint.check(store, owner)?;
        Ok(endpoint)
    }
    pub(super) fn accept(&self) -> Result<Option<UnixStream>> {
        match self.socket.accept() {
            Ok((stream, _)) => Ok(Some(stream)),
            Err(e) if retry(&e) => Ok(None),
            Err(_) => Err(Error::Io),
        }
    }
    pub(super) fn check(&self, store: &RecordStore, owner: u32) -> Result<()> {
        check_area(&store.dir).map_err(|_| Error::UnsafeEndpoint)?;
        let parent = std::fs::metadata(anchored(&store.dir, ".")).map_err(|_| Error::Io)?;
        let meta = std::fs::symlink_metadata(anchored(&store.dir, self.name))
            .map_err(|_| Error::UnsafeEndpoint)?;
        if parent.uid() != owner
            || meta.uid() != owner
            || !meta.file_type().is_socket()
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
            || (meta.dev(), meta.ino()) != self.identity
        {
            return Err(Error::UnsafeEndpoint);
        }
        Ok(())
    }
    pub(super) fn close(self, store: &RecordStore, owner: u32) -> Result<()> {
        self.check(store, owner)?;
        drop(self.socket);
        rustix::fs::unlinkat(&store.dir, self.name, rustix::fs::AtFlags::empty()).map_err(|_| Error::Io)
    }
}
impl Listener {
    /// 同じ排他を保持するwriterに診断endpointを追加する。既存名は採用・削除しない。
    pub fn enable_status(&mut self) -> Result<()> {
        self.check_endpoint()?;
        match &self.access {
            Access::Write(writer) if writer.failed => return Err(Error::SessionFailed),
            Access::Write(_) => (),
            _ => return Err(Error::WrongMode),
        }
        if self.timeout.as_millis() == 0
            || self.timeout != Duration::from_millis(self.timeout.as_millis() as u64)
        {
            return Err(Error::Policy);
        }
        if self.status.is_some() {
            return Err(Error::EndpointExists);
        }
        self.status = Some(Endpoint::bind(self.access.store(), self.owner, NAME)?);
        Ok(())
    }
    /// 一回に一接続だけ。未接続なら即座にfalseを返し、Record受付と直列化する。
    /// 診断は読取りだけで、応答成功もwriter.finishや復旧確認にはならない。
    pub fn serve_status_if_pending(&mut self) -> Result<bool> {
        self.check_endpoint()?;
        let endpoint = self.status.as_ref().ok_or(Error::WrongMode)?;
        endpoint.check(self.access.store(), self.owner)?;
        let (mut stream, _) = match endpoint.socket.accept() {
            Ok(pair) => pair,
            Err(e) if retry(&e) => return Ok(false),
            Err(_) => return Err(Error::Io),
        };
        authenticate(&stream, self.owner)?;
        self.check_endpoint()?;
        endpoint.check(self.access.store(), self.owner)?;
        stream.set_nonblocking(true).map_err(|_| Error::Io)?;
        let Access::Write(writer) = &self.access else {
            return Err(Error::WrongMode);
        };
        if writer.failed {
            return Err(Error::SessionFailed);
        }
        let generation = writer
            .store
            .generation()
            .map_err(|_| Error::SessionFailed)?;
        let capacity = writer.store.capacity().map_err(|_| Error::SessionFailed)?;
        let snapshot = Snapshot {
            generation: generation.try_into().map_err(|_| Error::SessionFailed)?,
            new_records: writer.records,
            stored_bytes: writer.bytes,
            max_new_records: writer.store.limits.session_records,
            max_stored_bytes: writer.store.limits.session_bytes,
            available_bytes: capacity.available,
            reserved_floor_bytes: capacity.reserved_floor,
            request_timeout_ms: self
                .timeout
                .as_millis()
                .try_into()
                .map_err(|_| Error::Policy)?,
            capacity_warning: capacity.warning,
        };
        let bytes = snapshot.bytes();
        let deadline = Instant::now() + self.timeout;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&(SIZE as u32).to_be_bytes());
        send_all(&mut stream, &header, deadline)?;
        send_all(&mut stream, &bytes, deadline)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        Limits, StartupState,
        tests::{Temp, fixture, logical_snapshot},
    };
    use std::{thread, time::Instant};

    fn serve(listener: &mut Listener) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if listener.serve_status_if_pending().unwrap() {
                break;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
    }
    fn query(temp: &Temp, listener: &mut Listener) -> Snapshot {
        let path = temp.data();
        let worker = thread::spawn(move || client::status(&path, Duration::from_secs(2)).unwrap());
        serve(listener);
        worker.join().unwrap()
    }
    #[test]
    fn fixed_status_bytes_and_invalid_fields_are_independently_checked() {
        let expected = "0100000000000000010000000000000002000000000000000300000000000000040000000000000005000000000000000600000000000000070000000801";
        let bytes: Vec<u8> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();
        let snapshot = Snapshot {
            generation: 1,
            new_records: 2,
            stored_bytes: 3,
            max_new_records: 4,
            max_stored_bytes: 5,
            available_bytes: 6,
            reserved_floor_bytes: 7,
            request_timeout_ms: 8,
            capacity_warning: true,
        };
        assert_eq!(snapshot.bytes().as_slice(), bytes);
        let valid = snapshot.bytes();
        assert_eq!(Snapshot::check(&valid), Some(snapshot));
        for (offset, value) in [(0, 0), (61, 2), (1, 255), (16, 255), (24, 255)] {
            let mut bad = valid;
            bad[offset] = value;
            assert!(Snapshot::check(&bad).is_none());
        }
        for range in [25..33, 33..41, 57..61] {
            let mut bad = valid;
            bad[range].fill(0);
            assert!(Snapshot::check(&bad).is_none());
        }
        let mut bad = valid;
        bad[57..61].copy_from_slice(&30_001u32.to_be_bytes());
        assert!(Snapshot::check(&bad).is_none());
    }
    #[test]
    fn runtime_status_is_read_only_counts_new_records_and_keeps_one_lock() {
        let temp = Temp::new();
        let mut listener = Listener::bind_writer(
            temp.store().begin().unwrap(),
            MAX_FRAME,
            Duration::from_secs(1),
        )
        .unwrap();
        listener.enable_status().unwrap();
        assert_eq!(listener.enable_status(), Err(Error::EndpointExists));
        let before = logical_snapshot(&listener.access.store().conn);
        let first = query(&temp, &mut listener);
        assert_eq!(first.new_records, 0);
        assert_eq!(first.stored_bytes, 0);
        assert_eq!(first.request_timeout_ms, 1000);
        assert_eq!(before, logical_snapshot(&listener.access.store().conn));
        assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
        for _ in 0..2 {
            let path = temp.data();
            let worker = thread::spawn(move || {
                client::submit(&path, &fixture(), Duration::from_secs(2)).unwrap()
            });
            listener.accept().unwrap().store_record().unwrap();
            worker.join().unwrap();
        }
        let before = logical_snapshot(&listener.access.store().conn);
        let second = query(&temp, &mut listener);
        assert_eq!(second.new_records, 1);
        assert_eq!(second.stored_bytes, fixture().bytes().len() as u64);
        assert!(second.generation > first.generation);
        assert_eq!(before, logical_snapshot(&listener.access.store().conn));
        listener.close_writer().unwrap().finish().unwrap();
        assert!(!temp.data().join(NAME).exists());
        assert!(!temp.data().join(super::super::NAME).exists());
        assert_eq!(
            RecordStore::open(&temp.data(), Limits::default())
                .unwrap()
                .startup_state()
                .unwrap(),
            StartupState::Clean
        );
    }
    #[test]
    fn status_residue_and_replacement_are_never_adopted_or_removed() {
        let inspect = Temp::new();
        let mut readonly =
            Listener::bind(inspect.store(), MAX_FRAME, Duration::from_secs(1)).unwrap();
        assert_eq!(readonly.enable_status(), Err(Error::WrongMode));
        readonly.close().unwrap();
        let fractional = Temp::new();
        let mut listener = Listener::bind_writer(
            fractional.store().begin().unwrap(),
            MAX_FRAME,
            Duration::from_micros(500),
        )
        .unwrap();
        assert_eq!(listener.enable_status(), Err(Error::Policy));
        drop(listener);
        for replace in [false, true] {
            let temp = Temp::new();
            let mut listener = Listener::bind_writer(
                temp.store().begin().unwrap(),
                MAX_FRAME,
                Duration::from_secs(1),
            )
            .unwrap();
            let path = temp.data().join(NAME);
            if replace {
                listener.enable_status().unwrap();
                std::fs::remove_file(&path).unwrap();
            }
            std::fs::write(&path, b"preserve").unwrap();
            if replace {
                assert!(matches!(
                    listener.close_writer(),
                    Err(Error::UnsafeEndpoint)
                ));
            } else {
                assert_eq!(listener.enable_status(), Err(Error::EndpointExists));
                drop(listener);
            }
            assert_eq!(std::fs::read(&path).unwrap(), b"preserve");
            assert!(temp.data().join(super::super::NAME).exists());
            assert_eq!(
                RecordStore::open(&temp.data(), Limits::default())
                    .unwrap()
                    .startup_state()
                    .unwrap(),
                StartupState::NeedsReview
            );
        }
    }
    #[test]
    fn diagnostic_response_loss_does_not_mutate_db_or_confirm_normal_finish() {
        let temp = Temp::new();
        let mut listener = Listener::bind_writer(
            temp.store().begin().unwrap(),
            MAX_FRAME,
            Duration::from_secs(1),
        )
        .unwrap();
        listener.enable_status().unwrap();
        let before = logical_snapshot(&listener.access.store().conn);
        let dir = super::super::super::directory(&temp.data()).unwrap();
        let stream = UnixStream::connect(anchored(&dir, NAME)).unwrap();
        stream.shutdown(std::net::Shutdown::Read).unwrap();
        assert!(listener.serve_status_if_pending().is_err());
        assert_eq!(before, logical_snapshot(&listener.access.store().conn));
        drop(listener);
        assert_eq!(
            RecordStore::open(&temp.data(), Limits::default())
                .unwrap()
                .startup_state()
                .unwrap(),
            StartupState::NeedsReview
        );
        assert!(temp.data().join(NAME).exists());
    }
}
