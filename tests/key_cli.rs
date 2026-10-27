//! R34/A11: 製品バイナリと独立PTY・暗号検査器の接続。公開試験入力だけ。
#![cfg(target_os = "linux")]
use std::process::Command;

#[test]
fn key_cli_preserves_files_and_terminal_across_success_failure_and_cancellation() {
    let python = std::env::var("LNGNB_REFERENCE_PYTHON")
        .unwrap_or_else(|_| "/tmp/lngnb-reference/bin/python".into());
    let output = Command::new(python)
        .arg("tests/key_cli_reference.py")
        .arg(env!("CARGO_BIN_EXE_lngnb"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "key CLI checker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "KEY_CLI_CASES_OK"
    );
}
