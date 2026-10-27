//! A11/R34: 制御端末だけから読む秘密入力。製品CLI・鍵ファイル操作への接続は後続。
use rustix::{
    fs::{self, CWD, Mode, OFlags},
    termios::{self, LocalModes, OptionalActions, QueueSelector, Termios},
};
use std::{
    fs::File,
    io::{Read, Write},
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;
const MAX_BYTES: usize = 1024;
static TERMINAL: Mutex<()> = Mutex::new(());
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretInputError {
    NoTerminal,
    NotForeground,
    Busy,
    Io,
    Cancelled,
    InvalidInput,
    ConfirmationMismatch,
    RestoreFailed,
}
impl std::fmt::Display for SecretInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoTerminal => "secret_input_requires_controlling_terminal",
            Self::NotForeground => "secret_input_requires_foreground_terminal",
            Self::Busy => "secret_terminal_busy",
            Self::Io => "secret_terminal_io_failed",
            Self::Cancelled => "secret_input_cancelled",
            Self::InvalidInput => "invalid_passphrase_input",
            Self::ConfirmationMismatch => "passphrase_confirmation_mismatch",
            Self::RestoreFailed => "secret_terminal_restore_failed",
        })
    }
}
impl std::error::Error for SecretInputError {}
type Result<T> = std::result::Result<T, SecretInputError>;
/// 操作終了時に消去する秘密値。Debug/Clone/Deref/Displayを提供しない。
pub struct Passphrase(Zeroizing<String>);
impl Passphrase {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// stdin/環境変数/CLI引数から代替入力せず、同一プロセスの端末操作を直列化する。
/// SIGKILL等のプロセス外からの終了ではDropを保証できない。
pub struct SecretTerminal {
    tty: File,
    _lock: MutexGuard<'static, ()>,
}
impl SecretTerminal {
    pub fn open() -> Result<Self> {
        let lock = TERMINAL.try_lock().map_err(|_| SecretInputError::Busy)?;
        let fd = fs::openat(
            CWD,
            "/dev/tty",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SecretInputError::NoTerminal)?;
        let tty = File::from(fd);
        termios::tcgetattr(&tty).map_err(|_| SecretInputError::NoTerminal)?;
        foreground(&tty)?;
        Ok(Self { tty, _lock: lock })
    }
    pub fn current_passphrase(&mut self) -> Result<Passphrase> {
        self.read("現在のパスフレーズ: ")
    }
    pub fn new_passphrase(&mut self) -> Result<Passphrase> {
        let first = self.read("新しいパスフレーズ: ")?;
        let second = self.read("確認のパスフレーズ: ")?;
        if first.as_str() != second.as_str() {
            return Err(SecretInputError::ConfirmationMismatch);
        }
        Ok(first)
    }
    fn read(&mut self, prompt: &'static str) -> Result<Passphrase> {
        let mut guard = RawTerminal::enter(&self.tty)?;
        let result = (|| {
            let mut tty = &self.tty;
            tty.write_all(prompt.as_bytes())
                .and_then(|()| tty.flush())
                .map_err(|_| SecretInputError::Io)?;
            let result = read_line(&mut tty);
            tty.write_all(b"\r\n")
                .and_then(|()| tty.flush())
                .map_err(|_| SecretInputError::Io)?;
            result
        })();
        // 復元と残存入力破棄の成功を確認するまでは秘密を呼出し元へ返さない。
        guard.restore()?;
        result.map(Passphrase)
    }
}
fn foreground(tty: &File) -> Result<()> {
    let group = termios::tcgetpgrp(tty).map_err(|_| SecretInputError::NoTerminal)?;
    if group != rustix::process::getpgrp() {
        return Err(SecretInputError::NotForeground);
    }
    Ok(())
}
struct RawTerminal<'a> {
    tty: &'a File,
    original: Termios,
    active: bool,
}
impl<'a> RawTerminal<'a> {
    fn enter(tty: &'a File) -> Result<Self> {
        foreground(tty)?;
        let original = termios::tcgetattr(tty).map_err(|_| SecretInputError::Io)?;
        let mut raw = original.clone();
        raw.make_raw();
        // ECHONLはcfmakerawだけでは明示解除されない実装もあるため、別に落とす。
        raw.local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL);
        let mut guard = Self {
            tty,
            original,
            active: true,
        };
        if termios::tcsetattr(tty, OptionalActions::Now, &raw).is_err() {
            guard.restore()?;
            return Err(SecretInputError::Io);
        }
        let ready = termios::tcgetattr(tty)
            .map(|t| {
                !t.local_modes.intersects(
                    LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG,
                )
            })
            .unwrap_or(false)
            && termios::tcflush(tty, QueueSelector::IFlush).is_ok();
        if !ready {
            guard.restore()?;
            return Err(SecretInputError::Io);
        }
        Ok(guard)
    }
    fn restore(&mut self) -> Result<()> {
        let tty = self.tty;
        self.restore_with_flush(|| termios::tcflush(tty, QueueSelector::IFlush).is_ok())
    }
    fn restore_with_flush(&mut self, flush: impl FnOnce() -> bool) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        // 貼付け余剰や超過入力を、echoを戻した後のシェル等へ渡さない。
        // 破棄に失敗しても元設定の復元・読戻しを独立して試みる。
        let flushed = flush();
        let restored = termios::tcsetattr(self.tty, OptionalActions::Now, &self.original).is_ok();
        let checked = termios::tcgetattr(self.tty)
            .map(|t| same_settings(&t, &self.original))
            .unwrap_or(false);
        if !flushed || !restored || !checked {
            return Err(SecretInputError::RestoreFailed);
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for RawTerminal<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
fn same_settings(a: &Termios, b: &Termios) -> bool {
    a.input_modes == b.input_modes
        && a.output_modes == b.output_modes
        && a.control_modes == b.control_modes
        && a.local_modes == b.local_modes
        && a.line_discipline == b.line_discipline
        && {
            use termios::SpecialCodeIndex as C;
            [
                C::VINTR,
                C::VQUIT,
                C::VERASE,
                C::VKILL,
                C::VEOF,
                C::VTIME,
                C::VMIN,
                C::VSWTC,
                C::VSTART,
                C::VSTOP,
                C::VSUSP,
                C::VEOL,
                C::VREPRINT,
                C::VDISCARD,
                C::VWERASE,
                C::VLNEXT,
                C::VEOL2,
            ]
            .into_iter()
            .all(|i| a.special_codes[i] == b.special_codes[i])
        }
        && a.input_speed() == b.input_speed()
        && a.output_speed() == b.output_speed()
}
fn read_line(reader: &mut impl Read) -> Result<Zeroizing<String>> {
    // 再確保で古い秘密が解放領域へ残らないよう、初めから最大長を確保する。
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_BYTES));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        let n = match reader.read(&mut *byte) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SecretInputError::Io),
        };
        if n == 0 {
            return Err(SecretInputError::Cancelled);
        }
        match byte[0] {
            b'\r' | b'\n' => break,
            3 | 4 | 26 | 28 => return Err(SecretInputError::Cancelled), // Ctrl-C/D/Z/\を通常の中断として扱う。
            8 | 127 => erase_last(&mut input),
            21 => {
                input.fill(0);
                input.clear();
            } // Ctrl-U
            b => {
                if input.len() == MAX_BYTES {
                    return Err(SecretInputError::InvalidInput);
                }
                input.push(b);
            }
        }
    }
    if input.is_empty() {
        return Err(SecretInputError::InvalidInput);
    }
    let text = std::str::from_utf8(&input).map_err(|_| SecretInputError::InvalidInput)?;
    Ok(Zeroizing::new(text.to_owned()))
}
fn erase_last(input: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    let mut start = input.len() - 1;
    while start > 0 && input[start] & 0xc0 == 0x80 {
        start -= 1;
    }
    input[start..].fill(0);
    input.truncate(start);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flush_failure_still_restores_terminal_and_retains_retry() {
        if std::env::var("LNGNB_PUBLIC_TERMINAL_CASE").as_deref() == Ok("flush-failure") {
            let terminal = SecretTerminal::open().unwrap();
            let mut guard = RawTerminal::enter(&terminal.tty).unwrap();
            (&terminal.tty).write_all(b"Public test prompt: ").unwrap();
            // 公開試験値だけを入力。失敗時の結果は秘密を持たない固定エラー。
            let input = read_line(&mut &terminal.tty).unwrap();
            assert!(input.as_str() == "public discarded input");
            assert_eq!(
                guard.restore_with_flush(|| false),
                Err(SecretInputError::RestoreFailed)
            );
            assert!(same_settings(
                &termios::tcgetattr(&terminal.tty).unwrap(),
                &guard.original
            ));
            assert!(guard.active); // 失敗を完了扱いせず、明示/Drop再試行を維持。
            guard.restore().unwrap();
            assert!(!guard.active);
            drop(input);
            println!("TERMINAL_CHECK_OK");
            return;
        }
        let output = std::process::Command::new("python3")
            .arg("tests/terminal_reference.py")
            .arg(std::env::current_exe().unwrap())
            .arg("secret_terminal::tests::flush_failure_still_restores_terminal_and_retains_retry")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "PTY restore checker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "PTY_CASES_OK=1"
        );
    }
    #[test]
    fn byte_limits_utf8_and_editing_do_not_normalize_input() {
        for text in [
            " x ",
            "e\u{301}",
            "é",
            "あ".repeat(341).as_str(),
            "x".repeat(1024).as_str(),
        ] {
            let mut b = text.as_bytes().to_vec();
            b.push(b'\n');
            assert!(read_line(&mut &b[..]).unwrap().as_str() == text);
        }
        for mut b in [vec![b'x'; 1025], vec![0xff], Vec::new()] {
            b.push(b'\n');
            assert_eq!(
                read_line(&mut &b[..]).unwrap_err(),
                SecretInputError::InvalidInput
            );
        }
        assert!(
            read_line(&mut &b"remove\x15e\xcc\x81\x7fx\n"[..])
                .unwrap()
                .as_str()
                == "ex"
        );
        for c in [3, 4, 26, 28] {
            assert_eq!(
                read_line(&mut &[c][..]).unwrap_err(),
                SecretInputError::Cancelled
            );
        }
    }
    #[test]
    fn eof_io_and_errors_do_not_disclose_input() {
        assert_eq!(
            read_line(&mut &b"public unfinished test"[..]).unwrap_err(),
            SecretInputError::Cancelled
        );
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("public error marker"))
            }
        }
        let e = read_line(&mut Broken).unwrap_err();
        assert_eq!(e, SecretInputError::Io);
        assert!(!format!("{e:?} {e}").contains("public error marker"));
        assert!(std::error::Error::source(&e).is_none());
    }
}
