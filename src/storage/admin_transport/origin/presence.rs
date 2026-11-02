//! 元namespace・作成根拠に束縛した、一要求だけの非破壊kernel照会。
use super::*;
use nix::sys::socket::{
    self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use std::{io::IoSliceMut, os::fd::AsRawFd};

const LIMIT: usize = 4096;
const SEQUENCE: u32 = 1; // 毎回新しい専用socket。一度だけ送信する。

/// 指定した元socketに対する、その照会時点だけの診断。整理資格ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPresence {
    Present { state: u8 },
    CookieMismatch,
}

impl RecordStore {
    /// 同じ領域の排他を保持し、非永続根拠・現在path/contextを照会前後に照合。
    /// 受付fdを別processが保持する場合も元namespaceの個別照会を使う。
    /// 停止状態/復旧/整理の資格は判定せず、SQL・履歴・unlink・接続は行わない。
    pub fn socket_origin_presence(
        &self,
        origin: &SocketOrigin,
        elapsed: Duration,
    ) -> OriginResult<SocketPresence> {
        self.origin_presence_inner(origin, elapsed, || Ok(()))
    }

    fn origin_presence_inner(
        &self,
        origin: &SocketOrigin,
        elapsed: Duration,
        after_query: impl FnOnce() -> OriginResult<()>,
    ) -> OriginResult<SocketPresence> {
        let budget = Budget {
            start: Instant::now(),
            elapsed,
        };
        origin.check_current(self, &budget)?;
        let result = query(&origin.identity, &budget)?;
        after_query()?;
        origin.check_current(self, &budget)?;
        Ok(result)
    }
}

impl SocketOrigin {
    fn check_current(&self, store: &RecordStore, budget: &Budget) -> OriginResult<()> {
        budget.check()?;
        let i = &self.identity;
        let ns = self
            .namespace
            .metadata()
            .map_err(|_| SocketOriginError::Unavailable)?;
        let context = Context::read()?;
        if context.identity.boot != i.boot_id
            || context.identity.device != i.namespace_device
            || context.identity.inode != i.namespace_inode
            || (ns.dev(), ns.ino()) != (i.namespace_device, i.namespace_inode)
        {
            return Err(SocketOriginError::Mismatch);
        }
        budget.check()?;
        check_area(&store.dir).map_err(|_| SocketOriginError::Mismatch)?;
        let directory = std::fs::metadata(anchored(&store.dir, "."))
            .map_err(|_| SocketOriginError::Unavailable)?;
        let path = SocketPathMetadata::from_metadata(
            &std::fs::symlink_metadata(anchored(&store.dir, NAME))
                .map_err(|_| SocketOriginError::Mismatch)?,
        );
        if i.name != NAME
            || (directory.dev(), directory.ino(), directory.uid())
                != (i.directory_device, i.directory_inode, i.owner_uid)
            || path != i.path
            || path.kind != SocketPathKind::Socket
            || path.owner_uid != i.owner_uid
            || path.mode != 0o600
            || path.links != 1
        {
            return Err(SocketOriginError::Mismatch);
        }
        budget.check()
    }
}

fn request(inode: u32, cookie: u64) -> OriginResult<[u8; 40]> {
    if inode == 0 || cookie == 0 || cookie == u64::MAX {
        return Err(SocketOriginError::Mismatch);
    }
    let mut bytes = [0; 40];
    bytes[..4].copy_from_slice(&40u32.to_ne_bytes());
    bytes[4..6].copy_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    bytes[6..8].copy_from_slice(&1u16.to_ne_bytes()); // REQUEST、dump/ACKなし
    bytes[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    bytes[16] = 1; // AF_UNIX
    bytes[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // 全state、全socket dumpではない
    bytes[24..28].copy_from_slice(&inode.to_ne_bytes());
    bytes[28..32].copy_from_slice(&2u32.to_ne_bytes()); // UDIAG_SHOW_VFS
    bytes[32..36].copy_from_slice(&(cookie as u32).to_ne_bytes());
    bytes[36..40].copy_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
    Ok(bytes)
}

fn word(bytes: &[u8], at: usize) -> OriginResult<u32> {
    let value = bytes
        .get(at..at + 4)
        .ok_or(SocketOriginError::InvalidResponse)?;
    Ok(u32::from_ne_bytes(
        value
            .try_into()
            .map_err(|_| SocketOriginError::InvalidResponse)?,
    ))
}
fn short(bytes: &[u8], at: usize) -> OriginResult<u16> {
    let value = bytes
        .get(at..at + 2)
        .ok_or(SocketOriginError::InvalidResponse)?;
    Ok(u16::from_ne_bytes(
        value
            .try_into()
            .map_err(|_| SocketOriginError::InvalidResponse)?,
    ))
}

fn decode(
    bytes: &[u8],
    port: u32,
    sent: &[u8; 40],
    expected_vfs: (u32, u32),
) -> OriginResult<SocketPresence> {
    let bad = SocketOriginError::InvalidResponse;
    if !(16..=LIMIT).contains(&bytes.len())
        || word(bytes, 0)? as usize != bytes.len()
        || short(bytes, 6)? != 0
        || word(bytes, 8)? != SEQUENCE
        || word(bytes, 12)? != port
    {
        return Err(bad);
    }
    let body = &bytes[16..];
    if short(bytes, 4)? == 2 {
        // NLMSG_ERROR。元要求も完全一致を必須とする。
        if body.len() != 44 || body[4..] != sent[..] {
            return Err(bad);
        }
        return match word(body, 0)? as i32 {
            // ENOENTは診断handler未提供とも区別不能。
            -2 => Err(SocketOriginError::Unavailable),
            -116 => Ok(SocketPresence::CookieMismatch), // Linux ESTALE
            0 => Err(bad),                              // ACKを不在へ変換しない
            value if value < 0 => Err(SocketOriginError::Unavailable),
            _ => Err(bad),
        };
    }
    if short(bytes, 4)? != 20
        || body.len() < 16
        || body[0] != 1
        || body[1] != 1
        || !(1..=12).contains(&body[2])
        || body[3] != 0
        || word(body, 4)? != word(sent, 24)?
        || word(body, 8)? != word(sent, 32)?
        || word(body, 12)? != word(sent, 36)?
    {
        return Err(bad);
    }
    let mut seen = Vec::new(); // 入力4096 bytes以下、最大1020属性だけ。
    let mut pos = 16;
    let mut vfs = false;
    while pos < body.len() {
        let size = short(body, pos)? as usize;
        let tag = short(body, pos + 2)?;
        let end = pos + size;
        let aligned = pos + ((size + 3) & !3);
        if size < 4 || end > body.len() || aligned > body.len() || seen.contains(&tag) {
            return Err(bad);
        }
        if tag == 1 {
            if size != 12 || (word(body, pos + 4)?, word(body, pos + 8)?) != expected_vfs {
                return Err(bad);
            }
            vfs = true;
        }
        seen.push(tag);
        pos = aligned;
    }
    if !vfs {
        return Err(bad);
    }
    // VFS inodeはu32。完全path identityの証明へ流用せず、pathは別途完全照合する。
    Ok(SocketPresence::Present { state: body[2] })
}

fn received(
    bytes: &[u8],
    flags: MsgFlags,
    sender: Option<NetlinkAddr>,
    port: u32,
    sent: &[u8; 40],
    expected_vfs: (u32, u32),
) -> OriginResult<SocketPresence> {
    if !flags.is_empty() || sender != Some(NetlinkAddr::new(0, 0)) {
        return Err(SocketOriginError::InvalidResponse);
    }
    decode(bytes, port, sent, expected_vfs)
}

fn query(identity: &SocketOriginIdentity, budget: &Budget) -> OriginResult<SocketPresence> {
    let sent = request(identity.socket_inode, identity.socket_cookie)?;
    let major = rustix::fs::major(identity.path.device);
    let minor = rustix::fs::minor(identity.path.device);
    if major >= (1 << 12) || minor >= (1 << 20) {
        return Err(SocketOriginError::Unavailable);
    }
    // kernel UAPIのVFS補助属性だけに用いる低32bit。完全path inodeは前後に別照合。
    let vfs = (identity.path.inode as u32, (major << 20) | minor);
    budget.check()?;
    let fd = socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::NetlinkSockDiag,
    )
    .map_err(|_| SocketOriginError::Unavailable)?;
    socket::bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))
        .map_err(|_| SocketOriginError::Unavailable)?;
    let local: NetlinkAddr =
        socket::getsockname(fd.as_raw_fd()).map_err(|_| SocketOriginError::Unavailable)?;
    if local.pid() == 0 || local.groups() != 0 {
        return Err(SocketOriginError::Unavailable);
    }
    budget.check()?;
    // 同一同期呼出しthreadで作成前後のcontextを囲む。setnsしない。
    let context = Context::read()?;
    if context.identity.boot != identity.boot_id
        || (context.identity.device, context.identity.inode)
            != (identity.namespace_device, identity.namespace_inode)
    {
        return Err(SocketOriginError::Mismatch);
    }
    budget.check()?;
    let kernel = NetlinkAddr::new(0, 0);
    let count = socket::sendto(fd.as_raw_fd(), &sent, &kernel, MsgFlags::MSG_DONTWAIT)
        .map_err(|_| SocketOriginError::Unavailable)?;
    if count != sent.len() {
        return Err(SocketOriginError::Unavailable);
    }
    budget.check()?;
    let remaining = budget
        .elapsed
        .checked_sub(budget.start.elapsed())
        .ok_or(SocketOriginError::BudgetExceeded)?;
    let ms = remaining
        .as_millis()
        .saturating_add(1)
        .min(i32::MAX as u128) as i32;
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    let ready = event::poll(&mut fds, ms).map_err(|_| SocketOriginError::Unavailable)?;
    budget.check()?;
    if ready == 0 {
        return Err(SocketOriginError::BudgetExceeded);
    }
    let mut bytes = [0; LIMIT];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let msg = socket::recvmsg::<NetlinkAddr>(
        fd.as_raw_fd(),
        &mut iov,
        None,
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
    )
    .map_err(|_| SocketOriginError::Unavailable)?;
    if msg.bytes > LIMIT {
        return Err(SocketOriginError::InvalidResponse);
    }
    let count = msg.bytes;
    let flags = msg.flags;
    let sender = msg.address;
    budget.check()?;
    received(&bytes[..count], flags, sender, local.pid(), &sent, vfs)
}

#[cfg(test)]
mod tests;
