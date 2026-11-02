//! 明示した新規bindに限る、非永続の作成時根拠。削除/不使用の資格ではない。
use super::*;
use std::fs::File;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketOriginError {
    BudgetExceeded,
    Unavailable,
    Mismatch,
    Bind(Error),
}
impl fmt::Display for SocketOriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BudgetExceeded => "admin_socket_origin_budget_exceeded",
            Self::Unavailable => "admin_socket_origin_unavailable",
            Self::Mismatch => "admin_socket_origin_mismatch",
            Self::Bind(_) => "admin_socket_origin_bind_failed",
        })
    }
}
impl std::error::Error for SocketOriginError {}
type OriginResult<T> = std::result::Result<T, SocketOriginError>;

/// ローカルな記述値。変更したcopyを作ってもSocketOriginの根拠へ戻せない。
/// 交換/保存形式、原子的snapshot、後の同一性・不使用の保証ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOriginIdentity {
    pub boot_id: String,
    pub namespace_device: u64,
    pub namespace_inode: u64,
    pub directory_device: u64,
    pub directory_inode: u64,
    pub owner_uid: u32,
    pub name: &'static str,
    /// fdのsockfs identity。pathのfilesystem identityとは別。
    pub socket_device: u64,
    pub socket_inode: u32,
    pub socket_cookie: u64,
    pub path: SocketPathMetadata,
}
/// 同じブートの元namespaceを保持する非永続の根拠。受付fd/Storeは保持しない。
/// 任意の観測値から構築/復元するAPI、Clone、可変getterは提供しない。
#[derive(Debug)]
pub struct SocketOrigin {
    identity: SocketOriginIdentity,
    namespace: File,
}
impl SocketOrigin {
    pub fn identity(&self) -> &SocketOriginIdentity {
        &self.identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextIdentity {
    boot: String,
    device: u64,
    inode: u64,
}
struct Context {
    identity: ContextIdentity,
    namespace: File,
}
fn boot_id(bytes: &[u8]) -> OriginResult<String> {
    if bytes.len() != 37 || bytes[36] != b'\n' {
        return Err(SocketOriginError::Unavailable);
    }
    for (i, b) in bytes[..36].iter().enumerate() {
        let valid = match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        };
        if !valid {
            return Err(SocketOriginError::Unavailable);
        }
    }
    String::from_utf8(bytes[..36].to_vec()).map_err(|_| SocketOriginError::Unavailable)
}
impl Context {
    fn read() -> OriginResult<Self> {
        // 固定kernel proc入口だけ。namespace handleは意図したproc magic linkを辿る。
        // データ領域のNOFOLLOW規則を、任意pathで迂回する入口にはしない。
        let mut bytes = Vec::with_capacity(38);
        File::open("/proc/sys/kernel/random/boot_id")
            .map_err(|_| SocketOriginError::Unavailable)?
            .take(38)
            .read_to_end(&mut bytes)
            .map_err(|_| SocketOriginError::Unavailable)?;
        let boot = boot_id(&bytes)?;
        let namespace = File::open("/proc/thread-self/ns/net")
            .map_err(|_| SocketOriginError::Unavailable)?;
        let meta = namespace.metadata().map_err(|_| SocketOriginError::Unavailable)?;
        Ok(Self {
            identity: ContextIdentity { boot, device: meta.dev(), inode: meta.ino() },
            namespace,
        })
    }
}
struct Budget {
    start: Instant,
    elapsed: Duration,
}
impl Budget {
    fn check(&self) -> OriginResult<()> {
        if self.start.elapsed() >= self.elapsed {
            Err(SocketOriginError::BudgetExceeded)
        } else {
            Ok(())
        }
    }
}
impl Listener {
    /// 主socketを新規bindし、同じ排他のまま作成前後を照合して根拠を返す。
    /// 失敗時は作成済みsocketが残る可能性があり、削除/再bind/finishは行わない。
    /// elapsedは処理境界の予算。OS I/O/bind等の強制中断保証ではない。
    pub fn bind_with_origin(
        store: RecordStore,
        max_frame: usize,
        timeout: Duration,
        elapsed: Duration,
    ) -> OriginResult<(Self, SocketOrigin)> {
        Self::bind_origin_inner(|| Self::bind(store, max_frame, timeout), elapsed, |_| Ok(()))
    }
    /// 明示起動検査済みwriterの既存資格を引き継ぐ。根拠取得は保存/finishではない。
    pub fn bind_writer_with_origin(
        writer: RecordWriter,
        max_frame: usize,
        timeout: Duration,
        elapsed: Duration,
    ) -> OriginResult<(Self, SocketOrigin)> {
        Self::bind_origin_inner(|| Self::bind_writer(writer, max_frame, timeout), elapsed, |_| Ok(()))
    }
    fn bind_origin_inner(
        bind: impl FnOnce() -> Result<Self>,
        elapsed: Duration,
        after_bind: impl FnOnce(&Self) -> OriginResult<()>,
    ) -> OriginResult<(Self, SocketOrigin)> {
        let budget = Budget { start: Instant::now(), elapsed };
        budget.check()?;
        let context = Context::read()?;
        budget.check()?;
        let listener = bind().map_err(SocketOriginError::Bind)?;
        after_bind(&listener)?;
        let identity = listener.observe_origin(&context.identity, &budget, || Ok(()))?;
        let origin = SocketOrigin { identity, namespace: context.namespace };
        Ok((listener, origin))
    }
    /// 現在保持する主受付fd/領域/path/contextと、取得済み根拠の一致だけを確認。
    /// 不使用診断・永続作成来歴・再開/整理資格へ変換せず、他のendpointは検査しない。
    pub fn verify_socket_origin(&self, origin: &SocketOrigin, elapsed: Duration) -> OriginResult<()> {
        self.verify_origin_inner(origin, elapsed, || Ok(()))
    }
    fn verify_origin_inner(
        &self,
        origin: &SocketOrigin,
        elapsed: Duration,
        between: impl FnOnce() -> OriginResult<()>,
    ) -> OriginResult<()> {
        let budget = Budget { start: Instant::now(), elapsed };
        budget.check()?;
        let ns = origin.namespace.metadata().map_err(|_| SocketOriginError::Unavailable)?;
        let expected = ContextIdentity {
            boot: origin.identity.boot_id.clone(),
            device: ns.dev(),
            inode: ns.ino(),
        };
        if expected.device != origin.identity.namespace_device
            || expected.inode != origin.identity.namespace_inode {
            return Err(SocketOriginError::Mismatch);
        }
        let current = self.observe_origin(&expected, &budget, between)?;
        if current != origin.identity {
            return Err(SocketOriginError::Mismatch);
        }
        Ok(())
    }
    fn observe_origin(
        &self,
        expected: &ContextIdentity,
        budget: &Budget,
        between: impl FnOnce() -> OriginResult<()>,
    ) -> OriginResult<SocketOriginIdentity> {
        let observe = || -> OriginResult<SocketOriginIdentity> {
            budget.check()?;
            let context = Context::read()?;
            if &context.identity != expected {
                return Err(SocketOriginError::Mismatch);
            }
            budget.check()?;
            self.check_endpoint().map_err(|_| SocketOriginError::Mismatch)?;
            let directory = std::fs::metadata(anchored(&self.access.store().dir, "."))
                .map_err(|_| SocketOriginError::Unavailable)?;
            let path = SocketPathMetadata::from_metadata(
                &std::fs::symlink_metadata(anchored(&self.access.store().dir, NAME))
                    .map_err(|_| SocketOriginError::Mismatch)?);
            if path.kind != SocketPathKind::Socket || path.mode != 0o600
                || path.owner_uid != self.owner || path.links != 1
                || (path.device, path.inode) != self.identity {
                return Err(SocketOriginError::Mismatch);
            }
            budget.check()?;
            let fd = rustix::fs::fstat(&self.socket).map_err(|_| SocketOriginError::Unavailable)?;
            let inode = u32::try_from(fd.st_ino).map_err(|_| SocketOriginError::Unavailable)?;
            let cookie = rustix::net::sockopt::get_socket_cookie(&self.socket)
                .map_err(|_| SocketOriginError::Unavailable)?;
            if inode == 0 || cookie == 0 || cookie == u64::MAX {
                return Err(SocketOriginError::Unavailable);
            }
            budget.check()?;
            Ok(SocketOriginIdentity {
                boot_id: context.identity.boot,
                namespace_device: context.identity.device,
                namespace_inode: context.identity.inode,
                directory_device: directory.dev(),
                directory_inode: directory.ino(),
                owner_uid: directory.uid(),
                name: NAME,
                socket_device: fd.st_dev,
                socket_inode: inode,
                socket_cookie: cookie,
                path,
            })
        };
        let first = observe()?;
        between()?;
        let second = observe()?;
        budget.check()?;
        if first != second {
            return Err(SocketOriginError::Mismatch);
        }
        Ok(second)
    }
}

#[cfg(test)]
mod tests;
