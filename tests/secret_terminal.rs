//! R34/A11: Pythonの独立したPTYドライバで制御端末・非表示・復元を確認。入力は公開試験値だけ。
#![cfg(target_os = "linux")]
use lngnb::secret_terminal::{Passphrase, SecretInputError as E, SecretTerminal};
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
        if mode == "no-terminal" {
            assert!(matches!(SecretTerminal::open(), Err(E::NoTerminal)));
            println!("TERMINAL_CHECK_OK");
            return;
        }
        if mode == "background" {
            assert!(matches!(SecretTerminal::open(), Err(E::NotForeground)));
            println!("TERMINAL_CHECK_OK");
            return;
        }
        let mut terminal = SecretTerminal::open().unwrap();
        assert!(matches!(SecretTerminal::open(), Err(E::Busy)));
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
        "PTY_CASES_OK=13"
    );
}
