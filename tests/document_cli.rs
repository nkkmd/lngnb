//! R01/R24/R30/R34: 作成CLIと実保存・独立Python照合。公開試験鍵のみ。
#![cfg(target_os = "linux")]
use lngnb::id::Id;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    process::Command,
};

#[test]
fn creation_cli_preserves_inputs_and_storage_across_failure_cancellation_and_restart() {
    let root = std::env::temp_dir().join(format!(
        "lngnb-document-test-{}",
        Id::random_knowledge().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    struct Clean(std::path::PathBuf);
    impl Drop for Clean {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _clean = Clean(root.clone());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("keys"))
        .unwrap();
    let spec = include_str!("../docs/specification-v1.0.0.md");
    let a14: serde_json::Value = serde_json::from_str(
        spec.split("## 付録A14 ")
            .nth(1)
            .unwrap()
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap(),
    )
    .unwrap();
    let hex = a14["keyfile_cbor_hex"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let key = root.join("keys/publisher");
    fs::write(&key, bytes).unwrap();
    fs::set_permissions(key, fs::Permissions::from_mode(0o600)).unwrap();
    for name in [
        "ok",
        "empty",
        "binary",
        "wrong",
        "wrong-id",
        "bad-meta",
        "bad-media",
        "no-tty",
        "residue",
        "limit",
        "link",
        "blocked",
        "busy",
        "sql",
        "blob-sql",
        "genesis-sql",
        "finish",
        "output",
        "kill",
        "cancel0",
        "cancel1",
        "cancel2",
        "cancel3",
        "cancel4",
    ] {
        let initialized = Command::new(env!("CARGO_BIN_EXE_lngnb"))
            .args(["data", "init", "--data-dir"])
            .arg(root.join(name))
            .output()
            .unwrap();
        assert!(
            initialized.status.success(),
            "CLI fixture initialization failed"
        );
    }
    let out = Command::new(
        std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
    )
    .arg("tests/document_cli_reference.py")
    .arg(env!("CARGO_BIN_EXE_lngnb"))
    .arg(&root)
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "document CLI checker failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        "DOCUMENT_CLI_CASES_OK"
    );
}
