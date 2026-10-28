//! 同一データ領域の管理socketへ完成Record一件だけを送る内部クライアント。
//! DB/lockは開かず、応答不明時の自動再送・ローカル保存への降格をしない。
use super::{MAGIC, MAX_TIMEOUT, PollFlags, Receipt, authorized, ready, send_all, transfer};
use crate::{
    record::LocalRecord,
    storage::{anchored, check_area, directory},
};
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use std::{
    fmt,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Policy,
    Endpoint,
    Connect,
    Unauthorized,
    OutcomeUnknown,
    StatusUnavailable,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Policy => "admin_client_policy",
            Self::Endpoint => "admin_client_unsafe_endpoint",
            Self::Connect => "admin_client_connect_failed",
            Self::Unauthorized => "admin_client_server_unauthorized",
            Self::StatusUnavailable => "admin_client_status_unavailable",
            Self::OutcomeUnknown => "admin_client_commit_unknown",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

fn authenticate_server(fd: &impl std::os::fd::AsFd, owner: u32) -> Result<()> {
    let peer = net::sockopt::get_socket_peercred(fd).map_err(|_| Error::Unauthorized)?;
    if !authorized(owner, peer.uid.as_raw()) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn endpoint(dir: &rustix::fd::OwnedFd, owner: u32, name: &str) -> Result<(u64, u64)> {
    check_area(dir).map_err(|_| Error::Endpoint)?;
    let parent = std::fs::metadata(anchored(dir, ".")).map_err(|_| Error::Endpoint)?;
    let meta =
        std::fs::symlink_metadata(anchored(dir, name)).map_err(|_| Error::Endpoint)?;
    if parent.uid() != owner
        || !meta.file_type().is_socket()
        || meta.uid() != owner
        || meta.mode() & 0o7777 != 0o600
        || (name == super::status::NAME && meta.nlink() != 1)
    {
        return Err(Error::Endpoint);
    }
    Ok((meta.dev(), meta.ino()))
}

/// socketの権限・同一性と接続先kernel UIDだけを検査する。要求bytesは送らない。
/// 相手の受理準備・プロトコル対応・保存状態を確認するものではない。
/// DB/lockを開かず、失敗時も再送・初期化・残存socket削除をしない。
pub fn probe(path: &Path, timeout: Duration) -> Result<()> {
    let (stream, _) = connect(path, timeout)?;
    drop(stream);
    Ok(())
}

fn connect(path: &Path, timeout: Duration) -> Result<(UnixStream, Instant)> {
    connect_to(path, super::NAME, timeout)
}
fn connect_to(path: &Path, name: &str, timeout: Duration) -> Result<(UnixStream, Instant)> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(Error::Policy);
    }
    let deadline = Instant::now() + timeout;
    let dir = directory(path).map_err(|_| Error::Endpoint)?;
    let owner = std::fs::metadata(anchored(&dir, "."))
        .map_err(|_| Error::Endpoint)?
        .uid();
    let identity = endpoint(&dir, owner, name)?;
    let address = SocketAddrUnix::new(anchored(&dir, name)).map_err(|_| Error::Endpoint)?;
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::Connect)?;
    match net::connect_unix(&fd, &address) {
        Ok(()) => (),
        Err(rustix::io::Errno::INPROGRESS) => {
            ready(&fd, PollFlags::OUT, deadline).map_err(|_| Error::Connect)?;
            net::sockopt::get_socket_error(&fd)
                .map_err(|_| Error::Connect)?
                .map_err(|_| Error::Connect)?;
        }
        // UDS backlog満杯のEAGAIN等は待ち続けず、未送信として拒否する。
        Err(_) => return Err(Error::Connect),
    }
    authenticate_server(&fd, owner)?;
    if endpoint(&dir, owner, name)? != identity {
        return Err(Error::Endpoint);
    }
    Ok((UnixStream::from(fd), deadline))
}

/// 診断専用socketだけへ接続し、要求bytesを送らず固定応答を照合する。
/// 古い受理側で診断endpointがない場合もRecord endpointへ降格しない。
pub fn status(path: &Path, timeout: Duration) -> Result<super::RuntimeStatus> {
    let (mut stream, deadline) = connect_to(path, super::status::NAME, timeout)?;
    let mut header = [0; 8];
    transfer(&mut stream, &mut header, deadline).map_err(|_| Error::StatusUnavailable)?;
    if header[..4] != super::status::MAGIC || header[4..] != (super::status::SIZE as u32).to_be_bytes() {
        return Err(Error::StatusUnavailable);
    }
    let mut bytes = [0; super::status::SIZE];
    transfer(&mut stream, &mut bytes, deadline).map_err(|_| Error::StatusUnavailable)?;
    super::RuntimeStatus::check(&bytes).ok_or(Error::StatusUnavailable)
}

/// 接続先のkernel UIDが領域所有者/rootであることを、送信前に照合する。
/// timeoutは接続から応答全体まで一つの単調deadline（最大30秒）。
/// 書込み開始後の失敗・不正応答・ID不一致は保守的にcommit不明として返す。
pub fn submit(path: &Path, record: &LocalRecord, timeout: Duration) -> Result<Receipt> {
    let (mut stream, deadline) = connect(path, timeout)?;
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(&(record.bytes().len() as u32).to_be_bytes());
    send_all(&mut stream, &header, deadline).map_err(|_| Error::OutcomeUnknown)?;
    send_all(&mut stream, record.bytes(), deadline).map_err(|_| Error::OutcomeUnknown)?;
    let mut reply_header = [0; 8];
    transfer(&mut stream, &mut reply_header, deadline).map_err(|_| Error::OutcomeUnknown)?;
    // 応答は固定34 bytes。相手指定長で確保せず、未知版/過大/短長を拒否する。
    if reply_header[..4] != MAGIC || reply_header[4..] != 34u32.to_be_bytes() {
        return Err(Error::OutcomeUnknown);
    }
    let mut reply = [0; 34];
    transfer(&mut stream, &mut reply, deadline).map_err(|_| Error::OutcomeUnknown)?;
    if reply[0] != 1 || reply[1] > 1 || reply[2..] != record.id().bytes {
        return Err(Error::OutcomeUnknown);
    }
    Ok(Receipt {
        record_id: record.id(),
        inserted: reply[1] == 1,
    })
}

#[cfg(test)]
mod tests;
