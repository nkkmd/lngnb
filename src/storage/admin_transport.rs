//! Linux管理IPCの内部受理境界。管理コマンド/公開リレーの起動・終了ではない。
//!
//! 保存排他を所有し、所有者/rootの接続だけを受理する。メッセージは不透明な
//! bytesであり、呼出し側で操作・完成署名Recordを検査する。秘密鍵を渡してはならない。
//! 同じUID/rootによる意図的な置換や、接続後のfd譲渡は防御範囲外。
use super::{
    RecordStore, RecordWriter, StorageError, anchored, check_area,
    management::{Receipt, RecordRequest},
};
use rustix::event::{self, PollFd, PollFlags};
use std::{
    fmt,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    time::{Duration, Instant},
};

const NAME: &str = "admin.sock";
const MAGIC: [u8; 4] = *b"LNA\x01";
const MAX_FRAME: usize = crate::cbor::MAX_RECORD;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

pub mod client;
mod configuration;
mod evaluation;
mod inventory;
mod status;
pub use configuration::ConfigError;
pub use evaluation::Snapshot as EvaluationStatus;
pub use inventory::{AdminSocketPathEntry, AdminSocketPathInventory, SocketPathKind, SocketPathMetadata};
pub use status::Snapshot as RuntimeStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Policy,
    UnsafeEndpoint,
    EndpointExists,
    Unauthorized,
    Timeout,
    InvalidFrame,
    Io,
    WrongMode,
    SessionFailed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Policy => "admin_ipc_policy",
            Self::UnsafeEndpoint => "admin_ipc_unsafe_endpoint",
            Self::EndpointExists => "admin_ipc_endpoint_exists",
            Self::Unauthorized => "admin_ipc_unauthorized",
            Self::Timeout => "admin_ipc_timeout",
            Self::InvalidFrame => "admin_ipc_invalid_frame",
            Self::Io => "admin_ipc_io",
            Self::WrongMode => "admin_ipc_wrong_mode",
            Self::SessionFailed => "admin_ipc_session_failed",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// 一度に一接続だけを貸し出す内部サーバー境界。保持中は保存領域のflockを失わない。
/// Drop/失敗ではsocket名を残す。既存名を自動削除・採用せず管理者の確認を要求する。
pub struct Listener {
    socket: UnixListener,
    status: Option<status::Endpoint>,
    evaluation: Option<status::Endpoint>,
    configuration: Option<status::Endpoint>,
    evaluation_records: u64,
    access: Access,
    identity: (u64, u64),
    owner: u32,
    max_frame: usize,
    timeout: Duration,
}
enum Access {
    Inspect(RecordStore),
    Write(RecordWriter),
}
impl Access {
    fn store(&self) -> &RecordStore {
        match self {
            Self::Inspect(s) => s,
            Self::Write(w) => &w.store,
        }
    }
}
impl Listener {
    /// 既に検査・排他取得済みの保存領域へbindする。起動印・評価・履歴は変更しない。
    /// 失敗時も作成途中のsocket名を消さず、保存領域を再初期化しない。
    pub fn bind(store: RecordStore, max_frame: usize, timeout: Duration) -> Result<Self> {
        Self::bind_access(Access::Inspect(store), max_frame, timeout)
    }
    /// 起動検査等を終えた既存writerを使い、同じ排他・稼働中印を保持する。
    /// 既に失敗したwriterを復旧させず、bind失敗/dropでも正常停止を記録しない。
    pub fn bind_writer(writer: RecordWriter, max_frame: usize, timeout: Duration) -> Result<Self> {
        if writer.failed {
            return Err(Error::SessionFailed);
        }
        Self::bind_access(Access::Write(writer), max_frame, timeout)
    }
    fn bind_access(access: Access, max_frame: usize, timeout: Duration) -> Result<Self> {
        let store = access.store();
        if max_frame == 0 || max_frame > MAX_FRAME || timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(Error::Policy);
        }
        check_area(&store.dir).map_err(|_| Error::UnsafeEndpoint)?;
        let parent = std::fs::metadata(anchored(&store.dir, ".")).map_err(|_| Error::Io)?;
        let path = anchored(&store.dir, NAME);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(Error::EndpointExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error::Io),
        }
        // 親が所有者専用なので、bind→0600の間にも別UIDは到達できない。
        let socket = UnixListener::bind(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                Error::EndpointExists
            } else {
                Error::Io
            }
        })?;
        let created = std::fs::symlink_metadata(&path).map_err(|_| Error::Io)?;
        if !created.file_type().is_socket() {
            return Err(Error::UnsafeEndpoint);
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Io)?;
        // rootが所有者の領域を管理する場合も、領域所有者から接続可能にする。
        if created.uid() != parent.uid() {
            std::os::unix::fs::chown(&path, Some(parent.uid()), None).map_err(|_| Error::Io)?;
        }
        socket.set_nonblocking(true).map_err(|_| Error::Io)?;
        let listener = Self {
            socket,
            status: None,
            evaluation: None,
            configuration: None,
            evaluation_records: 10_000,
            access,
            identity: (created.dev(), created.ino()),
            owner: parent.uid(),
            max_frame,
            timeout,
        };
        listener.check_endpoint()?;
        Ok(listener)
    }
    fn check_endpoint(&self) -> Result<()> {
        check_area(&self.access.store().dir).map_err(|_| Error::UnsafeEndpoint)?;
        let parent =
            std::fs::metadata(anchored(&self.access.store().dir, ".")).map_err(|_| Error::Io)?;
        let meta = std::fs::symlink_metadata(anchored(&self.access.store().dir, NAME))
            .map_err(|_| Error::UnsafeEndpoint)?;
        if parent.uid() != self.owner
            || !meta.file_type().is_socket()
            || meta.uid() != self.owner
            || meta.mode() & 0o7777 != 0o600
            || (meta.dev(), meta.ino()) != self.identity
        {
            return Err(Error::UnsafeEndpoint);
        }
        Ok(())
    }
    /// kernelのSO_PEERCREDを、要求bytesを読む前に検査する。UID自己申告は利用しない。
    /// &mut借用により二つの管理接続を同時に処理させない。
    pub fn accept(&mut self) -> Result<Connection<'_>> {
        self.accept_for(self.timeout)
    }
    /// 受付待ちだけの期限を短くできる。要求/応答の既存timeoutは変更しない。
    /// Timeoutは接続受理前だけ。呼出し側は停止要求を確認して再待機できる。
    pub fn accept_for(&mut self, wait: Duration) -> Result<Connection<'_>> {
        if wait.is_zero() || wait > MAX_TIMEOUT {
            return Err(Error::Policy);
        }
        self.check_endpoint()?;
        let deadline = Instant::now() + wait;
        let stream = loop {
            ready(&self.socket, PollFlags::IN, deadline)?;
            match self.socket.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if retry(&e) => continue,
                Err(_) => return Err(Error::Io),
            }
        };
        let uid = authenticate(&stream, self.owner)?;
        self.check_endpoint()?;
        stream.set_nonblocking(true).map_err(|_| Error::Io)?;
        Ok(Connection {
            stream,
            listener: self,
            uid,
            received: false,
            complete: false,
            sent: false,
        })
    }
    /// 通信受付だけを閉じて、自分のsocket名だけを除く。正常停止印は記録しない。
    /// 残存物・置換・削除/fsync失敗は成功にせず、再bindで上書きもしない。
    pub fn close(self) -> Result<RecordStore> {
        if !matches!(self.access, Access::Inspect(_)) {
            return Err(Error::WrongMode);
        }
        match self.close_access()? {
            Access::Inspect(s) => Ok(s),
            _ => unreachable!(),
        }
    }
    /// 受付停止/socket整理後にwriterを返す。finishは未確定障害を確認した呼出し側の別操作。
    pub fn close_writer(self) -> Result<RecordWriter> {
        if !matches!(self.access, Access::Write(_)) {
            return Err(Error::WrongMode);
        }
        match self.close_access()? {
            Access::Write(w) => Ok(w),
            _ => unreachable!(),
        }
    }
    fn close_access(self) -> Result<Access> {
        self.check_endpoint()?;
        if let Some(status) = &self.status {
            status.check(self.access.store(), self.owner)?;
        }
        if let Some(endpoint) = &self.evaluation {
            endpoint.check(self.access.store(), self.owner)?;
        }
        if let Some(endpoint) = &self.configuration {
            endpoint.check(self.access.store(), self.owner)?;
        }
        let Self {
            socket,
            status,
            evaluation,
            configuration,
            access,
            owner,
            ..
        } = self;
        drop(socket);
        let store = access.store();
        if let Some(endpoint) = configuration {
            endpoint.close(store, owner)?;
        }
        if let Some(endpoint) = evaluation {
            endpoint.close(store, owner)?;
        }
        if let Some(status) = status {
            status.close(store, owner)?;
        }
        rustix::fs::unlinkat(&store.dir, NAME, rustix::fs::AtFlags::empty())
            .map_err(|_| Error::Io)?;
        rustix::fs::fsync(&store.dir).map_err(|_| Error::Io)?;
        Ok(access)
    }
}
fn authorized(owner: u32, peer: u32) -> bool {
    peer == owner || peer == 0
}
fn authenticate(stream: &UnixStream, owner: u32) -> Result<u32> {
    let uid = rustix::net::sockopt::get_socket_peercred(stream)
        .map_err(|_| Error::Io)?
        .uid
        .as_raw();
    if authorized(owner, uid) {
        Ok(uid)
    } else {
        Err(Error::Unauthorized)
    }
}

/// 認証済み・保存排他の存続中だけ有効。一接続は要求一つ・応答一つ。
/// bytes自体は未検証であり、受信完了は管理操作の受理・永続化成功を意味しない。
pub struct Connection<'a> {
    stream: UnixStream,
    listener: &'a mut Listener,
    uid: u32,
    received: bool,
    complete: bool,
    sent: bool,
}
impl Connection<'_> {
    pub fn peer_uid(&self) -> u32 {
        self.uid
    }
    pub fn store(&self) -> &RecordStore {
        self.listener.access.store()
    }
    /// 認証済み接続から完成Recordだけを読み、共通処理で一件commit後にlocal-only応答。
    /// 応答失敗でもcommit済みRecordを削除せず、receiptを付けて確定済みと区別する。
    pub fn store_record(&mut self) -> std::result::Result<Receipt, RecordError> {
        if !matches!(self.listener.access, Access::Write(_)) {
            return Err(RecordError::ReadOnly);
        }
        let bytes = self.receive().map_err(RecordError::Transport)?;
        self.commit_record(&bytes)
    }
    /// 要求の最初のbyte前に閉じた接続だけは診断用の無操作として区別する。
    /// 部分frame・不正Record・保存/応答失敗は成功へ読み替えない。
    pub fn store_record_or_probe(&mut self) -> std::result::Result<Option<Receipt>, RecordError> {
        if !matches!(self.listener.access, Access::Write(_)) {
            return Err(RecordError::ReadOnly);
        }
        let Some(bytes) = self.receive_optional().map_err(RecordError::Transport)? else {
            return Ok(None);
        };
        self.commit_record(&bytes).map(Some)
    }
    fn commit_record(&mut self, bytes: &[u8]) -> std::result::Result<Receipt, RecordError> {
        let request = RecordRequest::check(bytes).map_err(RecordError::Invalid)?;
        let receipt = match &mut self.listener.access {
            Access::Write(writer) => request.submit(writer).map_err(RecordError::Storage)?,
            _ => return Err(RecordError::ReadOnly),
        };
        self.send(&receipt.bytes())
            .map_err(|_| RecordError::ResponseLost(receipt))?;
        Ok(receipt)
    }
    pub fn receive(&mut self) -> Result<Vec<u8>> {
        self.receive_optional()?.ok_or(Error::InvalidFrame)
    }
    fn receive_optional(&mut self) -> Result<Option<Vec<u8>>> {
        if self.received {
            return Err(Error::InvalidFrame);
        }
        // 途中失敗後の再解釈・deadlineリセットによる無制限延長を許さない。
        self.received = true;
        let deadline = Instant::now() + self.listener.timeout;
        let mut header = [0; 8];
        loop {
            ready(&self.stream, PollFlags::IN, deadline)?;
            match self.stream.read(&mut header[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(e) if retry(&e) => (),
                Err(_) => return Err(Error::Io),
            }
        }
        transfer(&mut self.stream, &mut header[1..], deadline)?;
        let length =
            u32::from_be_bytes(header[4..].try_into().map_err(|_| Error::InvalidFrame)?) as usize;
        if header[..4] != MAGIC || length == 0 || length > self.listener.max_frame {
            return Err(Error::InvalidFrame);
        }
        let mut bytes = vec![0; length];
        transfer(&mut self.stream, &mut bytes, deadline)?;
        self.complete = true;
        Ok(Some(bytes))
    }
    /// 応答内容の検査・永続化成否の判定は呼出し側で済ませる。
    pub fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if !self.complete || self.sent || bytes.is_empty() || bytes.len() > self.listener.max_frame
        {
            return Err(Error::InvalidFrame);
        }
        self.sent = true;
        let deadline = Instant::now() + self.listener.timeout;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        send_all(&mut self.stream, &header, deadline)?;
        send_all(&mut self.stream, bytes, deadline)
    }
}
/// 下位source/入力値を展開しない。ResponseLostだけは一件commit確認済み。
#[derive(Debug)]
pub enum RecordError {
    Transport(Error),
    Invalid(crate::Error),
    ReadOnly,
    Storage(StorageError),
    ResponseLost(Receipt),
}
impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport(_) => "admin_record_transport_failed",
            Self::Invalid(_) => "admin_record_rejected",
            Self::ReadOnly => "admin_record_read_only",
            Self::Storage(_) => "admin_record_storage_unconfirmed",
            Self::ResponseLost(_) => "admin_record_committed_response_failed",
        })
    }
}
impl std::error::Error for RecordError {}
fn retry(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}
fn ready(fd: &impl std::os::fd::AsFd, flags: PollFlags, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Timeout)?;
        let ms = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut fds = [PollFd::new(fd, flags)];
        match event::poll(&mut fds, ms) {
            Ok(0) => return Err(Error::Timeout),
            Ok(_) => return Ok(()), // HUP/ERRも実際のread/writeで失敗として扱う。
            Err(rustix::io::Errno::INTR) => (),
            Err(_) => return Err(Error::Io),
        }
    }
}
fn transfer(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(stream, PollFlags::IN, deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(Error::InvalidFrame),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if retry(&e) => (),
            Err(_) => return Err(Error::Io),
        }
    }
    Ok(())
}
fn send_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(stream, PollFlags::OUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::Io),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if retry(&e) => (),
            Err(_) => return Err(Error::Io),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
