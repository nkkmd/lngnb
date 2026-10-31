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
    inspection_fixture(&root, spec);
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

// 公開A13試験seed専用。実運用へ流用しない。本文/Genesis/親/由来を保持しない正常fixture。
fn inspection_fixture(root: &std::path::Path, spec: &str) {
    use lngnb::{cbor::{self, Value}, record::LocalRecord, storage::{Limits, RecordStore}};
    let a13: serde_json::Value = serde_json::from_str(spec.split("## 付録A13 ").nth(1).unwrap().split("```json\n").nth(1).unwrap().split("\n```").next().unwrap()).unwrap();
    let unhex = |s: &str| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect::<Vec<_>>();
    let key = ed25519_dalek::SigningKey::from_bytes(&unhex(a13["seed_hex"].as_str().unwrap()).try_into().unwrap());
    let source = LocalRecord::check(&unhex(a13["revision"]["envelope_cbor_hex"].as_str().unwrap()), None).unwrap();
    let Value::Map(mut body) = source.body().clone() else { unreachable!() };
    let parents = (0..256u32).map(|n| { let mut id = vec![0; 32]; id[28..].copy_from_slice(&n.to_be_bytes()); Value::Bytes(id) }).collect();
    *body.iter_mut().find(|(k, _)| k == "parents").unwrap() = ("parents".into(), Value::Array(parents));
    let one = vec![("knowledge_id".into(), Value::Bytes(vec![0; 32]))];
    let mut two = one.clone(); two.push(("genesis_record_id".into(), Value::Bytes(vec![8; 32])));
    let mut three = two.clone(); three.push(("revision_record_id".into(), Value::Bytes(vec![9; 32])));
    let mut origins = vec![Value::Map(one), Value::Map(two), Value::Map(three)];
    origins.extend((1..126u8).map(|n| Value::Map(vec![("knowledge_id".into(), Value::Bytes(vec![n; 32]))])));
    origins.sort_by_key(|v| cbor::encode(v).unwrap());
    body.push(("origins".into(), Value::Array(origins)));
    let (_, Value::Map(metadata)) = body.iter_mut().find(|(k, _)| k == "metadata").unwrap() else { unreachable!() };
    metadata.retain(|(k, _)| k != "titles");
    metadata.push(("titles".into(), Value::Map(vec![("ja".into(), Value::Text("PRIVATE METADATA".into()))])));
    let maximum = LocalRecord::sign(Value::Map(body.clone()), &key).unwrap();
    for (k, v) in &mut body { if k == "parents" || k == "origins" { *v = Value::Array(vec![]); } }
    let empty = LocalRecord::sign(Value::Map(body), &key).unwrap();
    let mut writer = RecordStore::initialize(&root.join("inspect-declarations"), Limits::default()).unwrap().begin().unwrap();
    writer.insert(&maximum).unwrap(); writer.insert(&empty).unwrap(); writer.finish().unwrap();
}
