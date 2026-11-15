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

#[test]
fn history_key_cli_updates_and_recovers_with_a_real_terminal() {
    use lngnb::keyfile::{
        KeyDirectory, KeyDirectoryIdentity, KeyFileIdentity, KeyRecoveryHold, KeyResumeExpected,
    };
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).unwrap();
    let root = Scratch(std::env::temp_dir().join(format!(
        "lngnb-history-cli-{}",
        data_encoding::HEXLOWER.encode(&nonce)
    )));
    let mkdir = |path: &std::path::Path| fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    mkdir(&root.0);
    // 公開試験専用。実運用に流用しない。
    let old = "public CLI old example only";
    for scenario in ["normal", "cancel", "output"] {
        let path = root.0.join(scenario);
        let copy = root.0.join(format!("{scenario}-backup"));
        mkdir(&path);
        mkdir(&copy);
        let mut source = KeyDirectory::open(&path).unwrap();
        let public_key = source.create("publisher", old).unwrap();
        let key = fs::read(path.join("publisher")).unwrap();
        fs::copy(path.join("publisher"), copy.join("saved")).unwrap();
        let mut backups = [KeyDirectory::open(&copy).unwrap()];
        let KeyRecoveryHold::Held { area_id } = source.initialize_recovery_hold().unwrap() else {
            panic!("expected a new recovery hold");
        };
        source.initialize_key_state(&area_id).unwrap();
        let identity = |path| KeyFileIdentity::from_metadata(&fs::metadata(path).unwrap());
        let expected = KeyResumeExpected {
            state: source.key_state_history(&area_id).unwrap(),
            current: identity(path.join("publisher")),
            ciphertext_sha256: Sha256::digest(&key).into(),
            public_key,
            preserved_directory: KeyDirectoryIdentity::from_metadata(&fs::metadata(&copy).unwrap()),
            preserved: identity(copy.join("saved")),
            guard: identity(path.join(".lngnb-key-hold")),
        };
        let prepared = source
            .prepare_key_resume("publisher", old, &mut backups, 0, "saved", &[], &expected)
            .unwrap();
        let resume = prepared.intent();
        prepared.record().unwrap();
        source
            .recover_key_resume_release(
                "publisher",
                old,
                &mut backups,
                0,
                "saved",
                &[],
                &expected,
                &resume,
            )
            .unwrap();
        resume
            .write_receipt(
                &mut fs::File::create(root.0.join(format!("{scenario}-receipt"))).unwrap(),
            )
            .unwrap();
    }
    let python = std::env::var("LNGNB_REFERENCE_PYTHON")
        .unwrap_or_else(|_| "/tmp/lngnb-reference/bin/python".into());
    let output = Command::new(python)
        .arg("tests/key_cli_reference.py")
        .arg(env!("CARGO_BIN_EXE_lngnb"))
        .arg(&root.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "history CLI checker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"HISTORY_KEY_CLI_CASES_OK\n");
}
