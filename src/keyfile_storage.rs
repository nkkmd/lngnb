//! A11/R34: Linuxの所有者専用ディレクトリ内での鍵ファイル操作。
//! ファイルは暗号化bytesだけ。DB・HTTP・IPC・端末操作には接続しない。
use super::{KeyError, MAX_KEYFILE_BYTES, UnlockedKey, generate, unlock};
use rustix::fs::{self, AtFlags, CWD, FlockOperation, Mode, OFlags, RenameFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
};

type Result<T> = std::result::Result<T, KeyFileError>;
const PREFIX: &str = ".lngnb-key-";
const SCAN_LIMIT: usize = 10_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    UnsafePath,
    Busy,
    Exists,
    Missing,
    Io,
    PendingRecovery,
    ScanLimit,
    /// 診断中にディレクトリ一覧または対象暗号文の変化を検出した。
    RecoveryChanged,
    /// 保全先の永続化確認済みだが、最後の保全元照合等が未完了/不一致。
    PreservationReviewRequired,
    /// 復元先の永続化確認済みだが、残存元の最終照合等が未完了/不一致。
    RestorationReviewRequired,
    /// 呼出し元が明示した公開鍵と認証復号した鍵が一致しない。
    UnexpectedPublicKey,
    /// 交換/配置済みだがdirectory fsync成功を確認できない。成功/rollbackを断定しない。
    CommitUncertain,
    /// 新鍵の永続化確認済み。旧暗号文の整理だけが未完了/不確実。
    CleanupUncertain,
    Key(KeyError),
}
impl From<KeyError> for KeyFileError {
    fn from(e: KeyError) -> Self {
        Self::Key(e)
    }
}
impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsafePath => "unsafe_key_path",
            Self::Busy => "key_directory_busy",
            Self::Exists => "key_file_exists",
            Self::Missing => "key_file_missing",
            Self::Io => "key_file_io_failed",
            Self::PendingRecovery => "key_recovery_required",
            Self::ScanLimit => "key_directory_scan_limit",
            Self::RecoveryChanged => "key_recovery_input_changed",
            Self::PreservationReviewRequired => "key_preservation_committed_review_required",
            Self::RestorationReviewRequired => "key_restoration_committed_review_required",
            Self::UnexpectedPublicKey => "key_unexpected_public_key",
            Self::CommitUncertain => "key_commit_uncertain",
            Self::CleanupUncertain => "key_committed_cleanup_uncertain",
            Self::Key(e) => return e.fmt(f),
        })
    }
}
impl std::error::Error for KeyFileError {}
fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|_| KeyFileError::Io)
}
fn os<T>(r: rustix::io::Result<T>) -> Result<T> {
    r.map_err(|_| KeyFileError::Io)
}
fn name(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 128
        || s == "."
        || s == ".."
        || s.starts_with(PREFIX)
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(KeyFileError::UnsafePath);
    }
    Ok(())
}
fn directory(path: &Path) -> Result<File> {
    if path.as_os_str().is_empty() {
        return Err(KeyFileError::UnsafePath);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = os(fs::openat(CWD, ".", flags, Mode::empty()))?;
    for c in path.components() {
        fd = match c {
            Component::RootDir => os(fs::openat(CWD, "/", flags, Mode::empty()))?,
            Component::CurDir => continue,
            Component::Normal(n) => {
                fs::openat(&fd, n, flags, Mode::empty()).map_err(|_| KeyFileError::UnsafePath)?
            }
            _ => return Err(KeyFileError::UnsafePath),
        };
    }
    let f = File::from(fd);
    let m = io(f.metadata())?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
        return Err(KeyFileError::UnsafePath);
    }
    Ok(f)
}
/// 専用0700ディレクトリを開く。作成・権限修正・他者所有/root特例は行わない。
/// directory inodeを寿命中flockし、&mut selfで同じハンドルの操作も直列化する。
/// 所有者/rootが悪意を持ってファイルを差し替える攻撃への保証は追加しない。
pub struct KeyDirectory {
    dir: File,
}
/// 現在観測した残存名と上限付き読取りの結果。形式・認証・復旧の成功ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecoveryEntry {
    pub name: String,
    pub read_error: Option<KeyFileError>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecoveryInventory {
    pub entries: Vec<KeyRecoveryEntry>,
    /// 予約prefixだが生成名の形式に一致しないentry数。危険な生の名前は返さない。
    pub unrecognized_entries: usize,
}
impl KeyRecoveryInventory {
    pub fn has_residues(&self) -> bool {
        !self.entries.is_empty() || self.unrecognized_entries != 0
    }
}
fn recovery_name(n: &str) -> bool {
    n.strip_prefix(PREFIX).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl Drop for KeyDirectory {
    fn drop(&mut self) {
        let _ = fs::flock(&self.dir, FlockOperation::Unlock);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    TempCreated,
    Written,
    FileSynced,
    Validated,
    BeforeInstall,
    Installed,
    DirectorySynced,
    BeforeCleanup,
    Removed,
}
// 復元は既存targetとの交換を許さず、配置直前に同じ領域の残存元を再照合する。
enum InstallInput<'a> {
    New,
    Replace(&'a [u8]),
    Recovery { name: &'a str, bytes: &'a [u8] },
}
impl KeyDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        let dir = directory(path)?;
        match fs::flock(&dir, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { dir }),
            Err(rustix::io::Errno::WOULDBLOCK) => Err(KeyFileError::Busy),
            Err(_) => Err(KeyFileError::Io),
        }
    }
    fn secure(&self) -> Result<()> {
        let m = io(self.dir.metadata())?;
        if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
            return Err(KeyFileError::UnsafePath);
        }
        Ok(())
    }
    fn read(&self, n: &str) -> Result<Vec<u8>> {
        self.secure()?;
        let fd = fs::openat(
            &self.dir,
            n,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                KeyFileError::Missing
            } else {
                KeyFileError::UnsafePath
            }
        })?;
        let mut f = File::from(fd);
        let before = io(f.metadata())?;
        private_file(&before, rustix::process::geteuid().as_raw())?;
        if before.len() > MAX_KEYFILE_BYTES as u64 {
            return Err(KeyError::InvalidFormat.into());
        }
        let mut b = Vec::new();
        io((&mut f)
            .take(MAX_KEYFILE_BYTES as u64 + 1)
            .read_to_end(&mut b))?;
        let after = io(f.metadata())?;
        if b.len() > MAX_KEYFILE_BYTES {
            return Err(KeyError::InvalidFormat.into());
        }
        if before.len() != b.len() as u64 || fingerprint(&before) != fingerprint(&after) {
            return Err(KeyFileError::UnsafePath);
        }
        Ok(b)
    }
    pub fn load(&mut self, n: &str, passphrase: &str) -> Result<UnlockedKey> {
        name(n)?;
        Ok(unlock(&self.read(n)?, passphrase)?)
    }
    /// 書換え・fsync・採用・削除をせず一覧を診断する。既存の排他とI/O上限を共有。
    /// 読取り成功は形式/AEAD未検査。全体の未完了を部分成功として返さない。
    /// 各fileは個別読取り時点の観測であり、集合全体の内容snapshotではない。
    pub fn recovery_inventory(&mut self) -> Result<KeyRecoveryInventory> {
        self.recovery_inventory_with(&mut || Ok(()))
    }
    fn recovery_inventory_with(
        &mut self,
        hook: &mut impl FnMut() -> Result<()>,
    ) -> Result<KeyRecoveryInventory> {
        self.secure()?;
        let before = fingerprint(&io(self.dir.metadata())?);
        let entries = io(std::fs::read_dir(format!(
            "/proc/self/fd/{}",
            self.dir.as_raw_fd()
        )))?;
        let mut result = KeyRecoveryInventory {
            entries: Vec::new(),
            unrecognized_entries: 0,
        };
        for (i, entry) in entries.enumerate() {
            if i >= SCAN_LIMIT {
                return Err(KeyFileError::ScanLimit);
            }
            let entry = io(entry)?;
            let n = entry.file_name();
            if !n.as_encoded_bytes().starts_with(PREFIX.as_bytes()) {
                continue;
            }
            if let Some(n) = n.to_str().filter(|n| recovery_name(n)) {
                result.entries.push(KeyRecoveryEntry {
                    name: n.into(),
                    read_error: self.read(n).err(),
                });
            } else {
                result.unrecognized_entries += 1;
            }
        }
        hook()?;
        self.secure()?;
        if before != fingerprint(&io(self.dir.metadata())?) {
            return Err(KeyFileError::RecoveryChanged);
        }
        result.entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }
    /// 指定した生成形式の残存名だけを認証復号し、公開鍵だけを返す。
    /// 元の操作/対象名/新旧/保存確定・採用/削除資格は推測しない。
    pub fn check_recovery_file(&mut self, n: &str, passphrase: &str) -> Result<[u8; 32]> {
        self.check_recovery_file_with(n, passphrase, &mut || Ok(()))
    }
    fn check_recovery_file_with(
        &mut self,
        n: &str,
        passphrase: &str,
        hook: &mut impl FnMut() -> Result<()>,
    ) -> Result<[u8; 32]> {
        if !recovery_name(n) {
            return Err(KeyFileError::UnsafePath);
        }
        let input = self.read(n)?;
        let key = unlock(&input, passphrase)?;
        hook()?;
        if self.read(n).map_err(|_| KeyFileError::RecoveryChanged)? != input {
            return Err(KeyFileError::RecoveryChanged);
        }
        Ok(key.public_key())
    }
    /// 明示指定した残存暗号文を認証し、別の専用領域の新しい通常名へ同じbytesを保全。
    /// 元の領域は書換え/採用/削除せず、過去の更新結果や新旧も推測しない。
    /// 両領域の排他を保持する。別ハンドルで同じinodeを開くと非待機lockで拒否される。
    pub fn preserve_recovery_file(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
    ) -> Result<[u8; 32]> {
        self.preserve_recovery_file_with(residue, passphrase, backup, backup_name, &mut |_| Ok(()))
    }
    fn preserve_recovery_file_with(
        &mut self,
        residue: &str,
        passphrase: &str,
        backup: &mut KeyDirectory,
        backup_name: &str,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<[u8; 32]> {
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(backup_name)?;
        backup.pending()?;
        match fs::statat(&backup.dir, backup_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(KeyFileError::Exists),
            Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err(KeyFileError::Io),
        }
        let input = self.read(residue)?;
        let public = unlock(&input, passphrase)?.public_key();
        if self
            .read(residue)
            .map_err(|_| KeyFileError::RecoveryChanged)?
            != input
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        // 作成と同じ検査・file fsync・読戻し/認証・NOREPLACE・dir fsyncを共有する。
        // 再暗号化ではなく同一暗号文の保全であり、新たなseed/salt/nonceは生成しない。
        let copied = backup
            .install(backup_name, &input, passphrase, None, &mut |stage| {
                hook(stage)?;
                if stage == Stage::BeforeInstall
                    && self
                        .read(residue)
                        .map_err(|_| KeyFileError::RecoveryChanged)?
                        != input
                {
                    return Err(KeyFileError::RecoveryChanged);
                }
                Ok(())
            })
            .map_err(|e| {
                if e == KeyFileError::CleanupUncertain {
                    // 新規コピーには旧暗号文のunlinkがない。directory fsync後の未完了を区別。
                    KeyFileError::PreservationReviewRequired
                } else {
                    e
                }
            })?;
        if copied != public || self.read(residue).ok().as_deref() != Some(input.as_slice()) {
            return Err(KeyFileError::PreservationReviewRequired);
        }
        Ok(public)
    }
    /// 選択した残存暗号文を、同じ領域の存在しない通常名へ明示復元する。
    /// 認証した公開鍵と呼出し元が別途指定した期待公開鍵の一致を必須とする。
    /// 元名/新旧/過去の更新結果は推測しない。全残存物を保持し、PendingRecoveryも解除しない。
    /// CLIへの接続・既存鍵の置換・残存物の整理はこのAPIの範囲外。
    pub fn restore_recovery_file(
        &mut self,
        residue: &str,
        passphrase: &str,
        target: &str,
        expected_public_key: &[u8; 32],
    ) -> Result<[u8; 32]> {
        self.restore_recovery_file_with(
            residue,
            passphrase,
            target,
            expected_public_key,
            &mut |_| Ok(()),
        )
    }
    fn restore_recovery_file_with(
        &mut self,
        residue: &str,
        passphrase: &str,
        target: &str,
        expected_public_key: &[u8; 32],
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<[u8; 32]> {
        if !recovery_name(residue) {
            return Err(KeyFileError::UnsafePath);
        }
        name(target)?;
        self.secure()?;
        match fs::statat(&self.dir, target, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(KeyFileError::Exists),
            Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err(KeyFileError::Io),
        }
        let input = self.read(residue)?;
        let public = unlock(&input, passphrase)?.public_key();
        if &public != expected_public_key {
            return Err(KeyFileError::UnexpectedPublicKey);
        }
        let restored = self
            .install_input(
                target,
                &input,
                passphrase,
                InstallInput::Recovery {
                    name: residue,
                    bytes: &input,
                },
                hook,
            )
            .map_err(|e| {
                if e == KeyFileError::CleanupUncertain {
                    KeyFileError::RestorationReviewRequired
                } else {
                    e
                }
            })?;
        if restored != public || self.read(residue).ok().as_deref() != Some(input.as_slice()) {
            return Err(KeyFileError::RestorationReviewRequired);
        }
        Ok(public)
    }
    fn pending(&self) -> Result<()> {
        self.secure()?;
        // /proc経路はNOFOLLOWで開いたdirectory fdへ固定し、利用者パスを再解決しない。
        let entries = io(std::fs::read_dir(format!(
            "/proc/self/fd/{}",
            self.dir.as_raw_fd()
        )))?;
        for (i, entry) in entries.enumerate() {
            if i >= SCAN_LIMIT {
                return Err(KeyFileError::ScanLimit);
            }
            if io(entry)?
                .file_name()
                .as_encoded_bytes()
                .starts_with(PREFIX.as_bytes())
            {
                return Err(KeyFileError::PendingRecovery);
            }
        }
        Ok(())
    }
    pub fn create(&mut self, n: &str, passphrase: &str) -> Result<[u8; 32]> {
        self.create_with(n, passphrase, &mut |_| Ok(()))
    }
    fn create_with(
        &mut self,
        n: &str,
        p: &str,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<[u8; 32]> {
        name(n)?;
        self.pending()?;
        match fs::statat(&self.dir, n, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(KeyFileError::Exists),
            Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err(KeyFileError::Io),
        }
        let encrypted = generate(p)?;
        self.install(n, &encrypted, p, None, hook)
    }
    pub fn change_passphrase(&mut self, n: &str, old: &str, new: &str) -> Result<[u8; 32]> {
        self.change_with(n, old, new, &mut |_| Ok(()))
    }
    fn change_with(
        &mut self,
        n: &str,
        old: &str,
        new: &str,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<[u8; 32]> {
        name(n)?;
        self.pending()?;
        let original = self.read(n)?;
        let key = unlock(&original, old)?;
        let encrypted = key.encrypt(new)?;
        self.install(n, &encrypted, new, Some(&original), hook)
    }
    fn install(
        &mut self,
        n: &str,
        encrypted: &[u8],
        p: &str,
        original: Option<&[u8]>,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<[u8; 32]> {
        self.install_input(
            n,
            encrypted,
            p,
            match original {
                Some(bytes) => InstallInput::Replace(bytes),
                None => InstallInput::New,
            },
            hook,
        )
    }
    fn install_input(
        &mut self,
        n: &str,
        encrypted: &[u8],
        p: &str,
        input: InstallInput<'_>,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<[u8; 32]> {
        let mut random = [0; 32];
        super::random(&mut random)?;
        let temp = format!("{PREFIX}{}", data_encoding::HEXLOWER.encode(&random));
        let fd = os(fs::openat(
            &self.dir,
            &temp,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ))?;
        let mut f = File::from(fd);
        // 呼出し元のumaskが0600を狭めても、作成したinodeだけを0600へ確定する。
        os(fs::fchmod(&f, Mode::RUSR | Mode::WUSR))?;
        hook(Stage::TempCreated)?;
        io(f.write_all(encrypted))?;
        hook(Stage::Written)?;
        io(f.sync_all())?;
        hook(Stage::FileSynced)?;
        let readback = self.read(&temp)?;
        if readback != encrypted {
            return Err(KeyFileError::Io);
        }
        let public = unlock(&readback, p)?.public_key();
        hook(Stage::Validated)?;
        hook(Stage::BeforeInstall)?;
        self.secure()?;
        if let InstallInput::Recovery { name, bytes } = input {
            if self.read(name).map_err(|_| KeyFileError::RecoveryChanged)? != bytes {
                return Err(KeyFileError::RecoveryChanged);
            }
        }
        if let InstallInput::Replace(old) = input {
            if self.read(n)? != old {
                return Err(KeyFileError::UnsafePath);
            }
        }
        let flag = if matches!(input, InstallInput::Replace(_)) {
            RenameFlags::EXCHANGE
        } else {
            RenameFlags::NOREPLACE
        };
        fs::renameat_with(&self.dir, &temp, &self.dir, n, flag).map_err(|e| {
            if e == rustix::io::Errno::EXIST {
                KeyFileError::Exists
            } else {
                KeyFileError::Io
            }
        })?;
        // ここから元へ戻ったと推測しない。EXCHANGEなら旧暗号文はtempへ残っている。
        hook(Stage::Installed).map_err(|_| KeyFileError::CommitUncertain)?;
        if self.read(n).map_err(|_| KeyFileError::CommitUncertain)? != encrypted {
            return Err(KeyFileError::CommitUncertain);
        }
        io(self.dir.sync_all()).map_err(|_| KeyFileError::CommitUncertain)?;
        hook(Stage::DirectorySynced).map_err(|_| KeyFileError::CleanupUncertain)?;
        if let InstallInput::Replace(old) = input {
            hook(Stage::BeforeCleanup).map_err(|_| KeyFileError::CleanupUncertain)?;
            if self
                .read(&temp)
                .map_err(|_| KeyFileError::CleanupUncertain)?
                != old
            {
                return Err(KeyFileError::CleanupUncertain);
            }
            os(fs::unlinkat(&self.dir, &temp, AtFlags::empty()))
                .map_err(|_| KeyFileError::CleanupUncertain)?;
            hook(Stage::Removed).map_err(|_| KeyFileError::CleanupUncertain)?;
            io(self.dir.sync_all()).map_err(|_| KeyFileError::CleanupUncertain)?;
        }
        Ok(public)
    }
}
fn private_file(m: &std::fs::Metadata, uid: u32) -> Result<()> {
    if !m.is_file() || m.nlink() != 1 || m.uid() != uid || m.mode() & 0o7777 != 0o600 {
        return Err(KeyFileError::UnsafePath);
    }
    Ok(())
}
fn fingerprint(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.uid(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
#[cfg(test)]
#[path = "keyfile_storage_tests.rs"]
mod tests;
