//! R34/A11: Pythonの独立したPTYドライバで制御端末・非表示・復元を確認。入力は公開試験値だけ。
#![cfg(target_os = "linux")]
use lngnb::secret_terminal::{Passphrase, SecretInputError as E, SecretTerminal, TerminalSignals};
use std::io::Write;
use std::process::Command;

fn error(result: Result<Passphrase, E>, expected: E) {
    match result {
        Err(e) => assert_eq!(e, expected),
        Ok(_) => panic!("unexpected passphrase"),
    }
}
#[test]
fn controlling_terminal_input_is_private_and_restored() {
    if let Ok(mode) = std::env::var("LNGNB_PUBLIC_TERMINAL_CASE") {
        if mode == "no-terminal" || mode == "signal-no-terminal" {
            if mode == "signal-no-terminal" {
                assert!(matches!(
                    SecretTerminal::open_interruptible(TerminalSignals::install().unwrap()),
                    Err(E::NoTerminal)
                ));
            } else {
                assert!(matches!(SecretTerminal::open(), Err(E::NoTerminal)));
            }
            println!("TERMINAL_CHECK_OK");
            return;
        }
        if mode == "background" {
            assert!(matches!(SecretTerminal::open(), Err(E::NotForeground)));
            println!("TERMINAL_CHECK_OK");
            return;
        }
        let signals = (mode.starts_with("signal-") || mode.starts_with("interruptible-"))
            .then(|| TerminalSignals::install().unwrap());
        let mut terminal = match signals {
            Some(signals) => SecretTerminal::open_interruptible(signals).unwrap(),
            None => SecretTerminal::open().unwrap(),
        };
        assert!(matches!(TerminalSignals::install(), Err(E::Busy)));
        if mode.starts_with("interruptible-") {
            if mode == "interruptible-hangup" {
                error(terminal.current_passphrase(), E::RestoreFailed);
            } else if mode == "interruptible-confirm" {
                assert!(terminal.new_passphrase().unwrap().as_str() == "public confirmation test");
            } else {
                assert!(
                    terminal.current_passphrase().unwrap().as_str() == " public e\u{301} é あ "
                );
            }
            if mode != "interruptible-hangup" {
                assert_eq!(signals.unwrap().check_cancelled(), Ok(()));
            }
            println!("TERMINAL_CHECK_OK");
            return;
        }
        if mode == "signal-idle" || mode == "signal-idle-after" {
            if mode == "signal-idle-after" {
                assert!(
                    terminal.current_passphrase().unwrap().as_str() == "public completed input"
                );
            }
            drop(terminal);
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/tty")
                .unwrap()
                .write_all(b"Idle test: ")
                .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(10));
            panic!("idle signal failed to terminate process");
        }
        assert!(matches!(SecretTerminal::open(), Err(E::Busy)));
        if let Some(signals) = signals {
            if mode == "signal-confirm" {
                error(terminal.new_passphrase(), E::Cancelled);
            } else {
                error(terminal.current_passphrase(), E::Cancelled);
            }
            assert_eq!(signals.check_cancelled(), Err(E::Cancelled));
            error(terminal.current_passphrase(), E::Cancelled);
            drop(terminal);
            assert_eq!(
                TerminalSignals::install().unwrap().check_cancelled(),
                Err(E::Cancelled)
            );
            assert!(matches!(
                SecretTerminal::open_interruptible(signals),
                Err(E::Cancelled)
            ));
            println!("TERMINAL_CHECK_OK");
            return;
        }
        match mode.as_str() {
            "unicode" => {
                assert!(terminal.current_passphrase().unwrap().as_str() == " public e\u{301} é あ ")
            }
            "editing" => assert!(terminal.current_passphrase().unwrap().as_str() == "ex"),
            "boundary" => {
                assert!(terminal.current_passphrase().unwrap().as_str() == "あ".repeat(341) + "x")
            }
            "confirm" => {
                assert!(terminal.new_passphrase().unwrap().as_str() == "public confirmation test")
            }
            "mismatch" => error(terminal.new_passphrase(), E::ConfirmationMismatch),
            "cancel" | "eof-key" => error(terminal.current_passphrase(), E::Cancelled),
            "empty" | "invalid-utf8" | "overflow" => {
                error(terminal.current_passphrase(), E::InvalidInput)
            }
            "hangup" => error(terminal.current_passphrase(), E::RestoreFailed),
            _ => panic!("unknown public terminal case"),
        }
        drop(terminal);
        if mode != "hangup" {
            assert!(SecretTerminal::open().is_ok());
        }
        println!("TERMINAL_CHECK_OK");
        return;
    }
    let output = Command::new("python3")
        .arg("tests/terminal_reference.py")
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PTY checker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "PTY_CASES_OK=26"
    );
}
