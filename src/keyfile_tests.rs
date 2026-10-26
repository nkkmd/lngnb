//! R05/R06/R34、A11/A14/K01〜03。公開試験seedのみ。実運用への流用禁止。
use super::*;
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write;
        write!(out, "{b:02x}").unwrap();
        out
    })
}
fn fixture(section: &str) -> serde_json::Value {
    let spec = include_str!("../docs/specification-v1.0.0.md");
    let json = spec
        .split(section)
        .nth(1)
        .unwrap()
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    serde_json::from_str(json).unwrap()
}
fn a14() -> serde_json::Value {
    fixture("## 付録A14 暗号化鍵ファイルの固定計算例")
}
fn a13() -> serde_json::Value {
    fixture("## 付録A13 Record・IDの固定計算例")
}
fn original() -> Vec<u8> {
    unhex(a14()["keyfile_cbor_hex"].as_str().unwrap())
}
fn passphrase() -> String {
    String::from_utf8(unhex(a14()["passphrase_utf8_hex"].as_str().unwrap())).unwrap()
}
fn test_key() -> UnlockedKey {
    UnlockedKey(SigningKey::from_bytes(
        &unhex(a13()["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    ))
}
fn replace(v: &mut Value, path: &[&str], new: Value) {
    if let Value::Map(m) = v {
        let target = &mut m.iter_mut().find(|(k, _)| k == path[0]).unwrap().1;
        if path.len() == 1 {
            *target = new;
        } else {
            replace(target, &path[1..], new);
        }
    } else {
        panic!("test path");
    }
}
fn assert_error(input: &[u8], pass: &str, want: KeyError) {
    match unlock(input, pass) {
        Err(e) => assert_eq!(e, want),
        Ok(_) => panic!("unexpected unlocked key"),
    }
}
#[test]
fn fixed_a14_bytes_kdf_aad_and_signature_match() {
    let f = a14();
    let salt = unhex(f["salt_hex"].as_str().unwrap()).try_into().unwrap();
    let nonce = unhex(f["nonce_hex"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(
        hex(&*derive(&passphrase(), &salt).unwrap()),
        f["argon2id_output_hex"]
    );
    let h = header(test_key().public_key(), salt, nonce);
    assert_eq!(hex(&encode(&h).unwrap()), f["header_cbor_hex"]);
    assert_eq!(hex(&aad(&h).unwrap()), f["aad_hex"]);
    assert_eq!(
        encrypt_with(&test_key(), &passphrase(), salt, nonce).unwrap(),
        original()
    );
    let key = unlock(&original(), &passphrase()).unwrap();
    let record = unhex(a13()["genesis"]["envelope_cbor_hex"].as_str().unwrap());
    let local = LocalRecord::check(&record, None).unwrap();
    assert_eq!(
        key.sign_record(local.body().clone()).unwrap().bytes(),
        record
    );
}
#[test]
fn authentication_failures_never_return_a_signing_key() {
    assert_error(
        &original(),
        "wrong public test password",
        KeyError::AuthenticationFailed,
    );
    for path in [
        &["ciphertext"][..],
        &["kdf", "salt"],
        &["cipher", "nonce"],
        &["public_key"],
    ] {
        let mut v = cbor::decode(&original()).unwrap();
        let mut target = &v;
        for part in path {
            target = get(target, part).unwrap();
        }
        let mut b = if let Value::Bytes(b) = target {
            b.clone()
        } else {
            unreachable!()
        };
        b[0] ^= 1;
        replace(&mut v, path, Value::Bytes(b));
        assert_error(
            &encode(&v).unwrap(),
            &passphrase(),
            KeyError::AuthenticationFailed,
        );
    }
    let mut v = cbor::decode(&original()).unwrap();
    let mut b: [u8; 48] = bytes(get(&v, "ciphertext").unwrap()).unwrap();
    b[47] ^= 1;
    replace(&mut v, &["ciphertext"], Value::Bytes(b.to_vec()));
    assert_error(
        &encode(&v).unwrap(),
        &passphrase(),
        KeyError::AuthenticationFailed,
    );
}
#[test]
fn authenticated_seed_must_match_public_key() {
    let salt = [42; 16];
    let nonce = [43; 12];
    let mut h = header([1; 32], salt, nonce);
    let derived = derive(&passphrase(), &salt).unwrap();
    let mut seed = Zeroizing::new(test_key().0.to_bytes());
    let tag = ChaCha20Poly1305::new((&*derived).into())
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad(&h).unwrap(), &mut *seed)
        .unwrap();
    let mut ciphertext = seed.to_vec();
    ciphertext.extend_from_slice(&tag);
    if let Value::Map(ref mut m) = h {
        m.push(("ciphertext".into(), Value::Bytes(ciphertext)));
    }
    assert_error(
        &encode(&h).unwrap(),
        &passphrase(),
        KeyError::AuthenticationFailed,
    );
}
#[test]
fn fixed_schema_rejects_hostile_settings_before_kdf() {
    for (path, new) in [
        (vec!["format"], text("lngnb-keyfile-2")),
        (vec!["kdf", "name"], text("argon2i")),
        (vec!["kdf", "version"], Value::Int(16)),
        (vec!["kdf", "memory_kib"], Value::Int(i64::MAX)),
        (vec!["kdf", "iterations"], Value::Int(i64::MAX)),
        (vec!["kdf", "parallelism"], Value::Int(2)),
        (vec!["kdf", "iterations"], Value::Bool(true)),
        (vec!["cipher", "name"], text("aes")),
    ] {
        let mut v = cbor::decode(&original()).unwrap();
        replace(&mut v, &path, new);
        assert_error(&encode(&v).unwrap(), &passphrase(), KeyError::InvalidFormat);
    }
    for path in [
        &["public_key"][..],
        &["kdf", "salt"],
        &["cipher", "nonce"],
        &["ciphertext"],
    ] {
        let v = cbor::decode(&original()).unwrap();
        let mut b = &v;
        for p in path {
            b = get(b, p).unwrap();
        }
        let size = if let Value::Bytes(b) = b {
            b.len()
        } else {
            unreachable!()
        };
        for wrong in [size - 1, size + 1] {
            let mut altered = v.clone();
            replace(&mut altered, path, Value::Bytes(vec![0; wrong]));
            assert_error(
                &encode(&altered).unwrap(),
                &passphrase(),
                KeyError::InvalidFormat,
            );
        }
    }
}
#[test]
fn missing_extra_and_noncanonical_data_are_not_repaired() {
    for path in [&[][..], &["kdf"], &["cipher"]] {
        let mut v = cbor::decode(&original()).unwrap();
        let mut target = &mut v;
        for p in path {
            if let Value::Map(m) = target {
                target = &mut m.iter_mut().find(|(k, _)| k == p).unwrap().1;
            }
        }
        if let Value::Map(m) = target {
            m.push(("extra".into(), Value::Null));
        }
        assert_error(&encode(&v).unwrap(), &passphrase(), KeyError::InvalidFormat);
    }
    let v = cbor::decode(&original()).unwrap();
    if let Value::Map(m) = &v {
        for (name, _) in m {
            let mut missing = v.clone();
            if let Value::Map(m) = &mut missing {
                m.retain(|(k, _)| k != name);
            }
            assert_error(
                &encode(&missing).unwrap(),
                &passphrase(),
                KeyError::InvalidFormat,
            );
        }
    }
    let b = original();
    for length in [0, 1, b.len() - 1] {
        assert_error(&b[..length], &passphrase(), KeyError::InvalidFormat);
    }
    let mut trailing = b.clone();
    trailing.push(0);
    assert_error(&trailing, &passphrase(), KeyError::InvalidFormat);
    let mut nonminimal = vec![0xb8, 0x05];
    nonminimal.extend_from_slice(&b[1..]);
    assert_error(&nonminimal, &passphrase(), KeyError::InvalidFormat);
    for n in [4095, 4096, 4097] {
        assert_error(&vec![0; n], &passphrase(), KeyError::InvalidFormat);
    }
}
#[test]
fn passphrase_byte_boundaries_and_exact_unicode_are_preserved() {
    for p in [String::new(), "a".repeat(1025), "あ".repeat(342)] {
        assert_eq!(generate(&p).unwrap_err(), KeyError::InvalidPassphrase);
        assert_error(&original(), &p, KeyError::InvalidPassphrase);
    }
    for p in ["x".to_owned(), "é".repeat(512), " e\u{301}\n ".to_owned()] {
        let b = test_key().encrypt(&p).unwrap();
        assert_eq!(
            unlock(&b, &p).unwrap().public_key(),
            test_key().public_key()
        );
    }
    let b = test_key().encrypt(" e\u{301}\n ").unwrap();
    for p in [" é\n ", "e\u{301}\n", " e\u{301} "] {
        assert_error(&b, p, KeyError::AuthenticationFailed);
    }
}
#[test]
fn generation_and_reencryption_use_fresh_randomness() {
    let a = generate("public test passphrase").unwrap();
    let b = generate("public test passphrase").unwrap();
    let ka = unlock(&a, "public test passphrase").unwrap();
    let kb = unlock(&b, "public test passphrase").unwrap();
    assert_ne!(ka.public_key(), kb.public_key());
    let changed = ka.encrypt("new public test passphrase").unwrap();
    assert_eq!(
        unlock(&changed, "new public test passphrase")
            .unwrap()
            .public_key(),
        ka.public_key()
    );
    let va = cbor::decode(&a).unwrap();
    let vb = cbor::decode(&changed).unwrap();
    assert_ne!(
        get(get(&va, "kdf").unwrap(), "salt").unwrap(),
        get(get(&vb, "kdf").unwrap(), "salt").unwrap()
    );
    assert_ne!(
        get(get(&va, "cipher").unwrap(), "nonce").unwrap(),
        get(get(&vb, "cipher").unwrap(), "nonce").unwrap()
    );
    assert_error(
        &changed,
        "public test passphrase",
        KeyError::AuthenticationFailed,
    );
    assert!(unlock(&a, "public test passphrase").is_ok());
}
#[test]
fn independent_openssl_keyfile_and_signature_check() {
    // 下位検査器へ渡すのは公開試験seedと既知の試験用passphraseだけ。
    let mut cases = Vec::new();
    for pass in [passphrase(), " 空白 e\u{301}\n ".to_owned()] {
        let encrypted = test_key().encrypt(&pass).unwrap();
        let genesis = LocalRecord::check(
            &unhex(a13()["genesis"]["envelope_cbor_hex"].as_str().unwrap()),
            None,
        )
        .unwrap();
        let record = unlock(&encrypted, &pass)
            .unwrap()
            .sign_record(genesis.body().clone())
            .unwrap();
        cases.push(serde_json::json!({"encrypted":hex(&encrypted),"passphrase":pass,"record":hex(record.bytes())}));
    }
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required");
    let mut child = Command::new(python)
        .arg("tests/keyfile_reference.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "independent checker failed (details suppressed)"
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["checked"], 2);
    for bytes in result["reencrypted"].as_array().unwrap() {
        assert_eq!(
            unlock(
                &unhex(bytes.as_str().unwrap()),
                "independent public test passphrase"
            )
            .unwrap()
            .public_key(),
            test_key().public_key()
        );
    }
}

#[test]
fn invalid_signing_input_and_errors_do_not_expose_secrets() {
    match test_key().sign_record(Value::Null) {
        Err(e) => {
            assert_eq!(e, KeyError::InvalidRecord);
            assert_eq!(e.to_string(), "invalid_signing_record");
            assert!(std::error::Error::source(&e).is_none());
        }
        Ok(_) => panic!("unexpected signed record"),
    }
    let marker = "private input must not appear in errors";
    let e = match unlock(&original(), marker) {
        Err(e) => e,
        Ok(_) => panic!("unexpected unlocked key"),
    };
    assert_eq!(e.to_string(), "key_authentication_failed");
    assert!(!format!("{e:?}").contains(marker));
}
