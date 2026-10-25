//! R02〜R07/R10: 工程③の形式・局所署名検査。親解決/公開ゲートの合格ではない。
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    scalar::Scalar,
};
use ed25519_dalek::{Signer, SigningKey};
use lngnb::{
    Error,
    cbor::{self, Value},
    id::{self, Id, Kind},
    record::{LocalRecord, PROFILE, verify_signature},
};
use sha2::{Digest, Sha512};
use std::io::Write;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write;
        write!(out, "{b:02x}").unwrap();
        out
    })
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> serde_json::Value {
    let spec = include_str!("../docs/specification-v1.0.0.md");
    let section = spec
        .split("## 付録A13 Record・IDの固定計算例")
        .nth(1)
        .unwrap();
    let json = section
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    serde_json::from_str(json).unwrap()
}
fn key() -> SigningKey {
    SigningKey::from_bytes(
        &unhex(fixture()["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
}
fn original(name: &str) -> Vec<u8> {
    unhex(fixture()[name]["envelope_cbor_hex"].as_str().unwrap())
}
fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    if let Value::Map(m) = v {
        &m.iter().find(|(k, _)| k == key).unwrap().1
    } else {
        panic!("map expected")
    }
}
fn set(v: &mut Value, key: &str, value: Value) {
    if let Value::Map(m) = v {
        if let Some((_, v)) = m.iter_mut().find(|(k, _)| k == key) {
            *v = value;
        } else {
            m.push((key.into(), value));
        }
    } else {
        panic!("map expected")
    }
}
fn body(name: &str) -> Value {
    get(&cbor::decode(&original(name)).unwrap(), "body").clone()
}
fn txt(s: &str) -> Value {
    Value::Text(s.into())
}
fn raw_sign(body: Value, key: &SigningKey) -> Vec<u8> {
    let public = key.verifying_key().to_bytes();
    let mut message = b"lngnb:signature:library-core-1\0".to_vec();
    message.extend(cbor::encode(&body).unwrap());
    let sig = Value::Map(vec![
        (
            "key_id".into(),
            Value::Bytes(id::key_id(&public).bytes.to_vec()),
        ),
        ("algorithm".into(), txt("ed25519")),
        ("public_key_bytes".into(), Value::Bytes(public.to_vec())),
        (
            "signature_bytes".into(),
            Value::Bytes(key.sign(&message).to_bytes().to_vec()),
        ),
    ]);
    cbor::encode(&Value::Map(vec![
        ("body".into(), body),
        ("signature".into(), sig),
    ]))
    .unwrap()
}
fn err(bytes: &[u8], error: Error) {
    assert_eq!(LocalRecord::check(bytes, None).unwrap_err(), error);
}

#[test]
fn a13_bytes_signatures_and_ids_are_exact() {
    let f = fixture();
    for name in ["genesis", "revision"] {
        let input = original(name);
        let record = LocalRecord::check(&input, None).unwrap();
        assert_eq!(record.bytes(), input);
        assert_eq!(record.id().to_string(), f[name]["record_id"]);
        assert_eq!(
            LocalRecord::sign(body(name), &key()).unwrap().bytes(),
            input
        );
        assert_eq!(
            hex(&cbor::encode(record.body()).unwrap()),
            f[name]["body_cbor_hex"]
        );
    }
    LocalRecord::check(&original("revision"), None)
        .unwrap()
        .check_genesis(&LocalRecord::check(&original("genesis"), None).unwrap())
        .unwrap();
    let public = key().verifying_key().to_bytes();
    assert_eq!(id::key_id(&public).to_string(), f["key_id"]);
    assert_eq!(
        id::blob_id(&unhex(f["blob_hex"].as_str().unwrap())).to_string(),
        f["blob_id"]
    );
    assert_eq!(id::blob_id(b"").to_string(), f["empty_blob_id"]);
}

#[test]
fn c02_c06_cbor_rejects_noncanonical_and_forbidden_encodings() {
    for bytes in [
        "1817",
        "190018",
        "1a00000100",
        "1b0000000000010000",
        "a2616101616102",
        "a2616201616102",
        "f90000",
        "c000",
        "bfff",
        "61ff",
        "a10100",
        "f7",
        "f8ff",
        "1c",
        "5f40ff",
        "9f00ff",
        "00ff",
        "",
        "1b8000000000000000",
        "3b8000000000000000",
    ] {
        assert_eq!(
            cbor::decode(&unhex(bytes)),
            Err(Error::InvalidFormat),
            "{bytes}"
        );
    }
    let input = original("genesis");
    for end in 0..input.len() {
        assert!(cbor::decode(&input[..end]).is_err());
    }
    let mut extra = input;
    extra.push(0);
    err(&extra, Error::InvalidFormat);
}

#[test]
fn c07_general_boundaries_and_unicode_bytes() {
    for n in [
        i64::MIN,
        -65537,
        -256,
        -25,
        -24,
        -1,
        0,
        23,
        24,
        255,
        256,
        65535,
        65536,
        i64::MAX,
    ] {
        let v = Value::Int(n);
        assert_eq!(cbor::decode(&cbor::encode(&v).unwrap()).unwrap(), v);
    }
    for value in [
        Value::Null,
        Value::Bool(false),
        Value::Bool(true),
        txt("e\u{301}"),
        txt("é"),
    ] {
        assert_eq!(cbor::decode(&cbor::encode(&value).unwrap()).unwrap(), value);
    }
    assert_ne!(
        cbor::encode(&txt("e\u{301}")).unwrap(),
        cbor::encode(&txt("é")).unwrap()
    );
    for n in [1_048_575, 1_048_576, 1_048_577] {
        for value in [Value::Bytes(vec![0; n]), txt(&"a".repeat(n))] {
            assert_eq!(cbor::encode(&value).is_ok(), n <= 1_048_576);
        }
    }
    for n in [4095, 4096, 4097] {
        let value = Value::Array(vec![Value::Null; n]);
        assert_eq!(cbor::encode(&value).is_ok(), n <= 4096);
        let mut raw = vec![0x99];
        raw.extend_from_slice(&(n as u16).to_be_bytes());
        raw.extend(vec![0xf6; n]);
        assert_eq!(cbor::decode(&raw).is_ok(), n <= 4096);
    }
    for n in [1023, 1024, 1025] {
        let value = Value::Map((0..n).map(|i| (format!("k{i:04}"), Value::Null)).collect());
        assert_eq!(cbor::encode(&value).is_ok(), n <= 1024);
        let mut raw = vec![0xb9];
        raw.extend_from_slice(&(n as u16).to_be_bytes());
        for i in 0..n {
            raw.extend(cbor::encode(&txt(&format!("k{i:04}"))).unwrap());
            raw.push(0xf6);
        }
        assert_eq!(cbor::decode(&raw).is_ok(), n <= 1024);
    }
    for n in [15, 16, 17] {
        let mut value = Value::Null;
        for _ in 0..n {
            value = Value::Array(vec![value]);
        }
        assert_eq!(cbor::encode(&value).is_ok(), n <= 16);
        let mut raw = vec![0x81; n];
        raw.push(0xf6);
        assert_eq!(cbor::decode(&raw).is_ok(), n <= 16);
    }
    // MAX_RECORDの直前/一致/直後。最大byte string二つを小さく調整する。
    for n in [2_097_151, 2_097_152, 2_097_153] {
        let mut raw = vec![0x82, 0x5a, 0x00, 0x10, 0x00, 0x00];
        raw.extend(vec![0; 1_048_576]);
        let len = n - 1 - 5 - 1_048_576 - 5;
        raw.push(0x5a);
        raw.extend_from_slice(&(len as u32).to_be_bytes());
        raw.extend(vec![0; len]);
        assert_eq!(raw.len(), n);
        assert_eq!(cbor::decode(&raw).is_ok(), n <= 2_097_152);
    }
    assert!(cbor::decode(&unhex("5bffffffffffffffff")).is_err());
    assert!(
        cbor::encode(&Value::Map(vec![
            ("x".into(), Value::Null),
            ("x".into(), Value::Null)
        ]))
        .is_err()
    );
}

#[test]
fn c08_c09_strict_schemas_and_ordered_sets() {
    for (field, value) in [
        ("parents", Value::Array(vec![Value::Bytes(vec![1; 32]); 2])),
        (
            "parents",
            Value::Array(vec![Value::Bytes(vec![2; 32]), Value::Bytes(vec![1; 32])]),
        ),
        ("knowledge_id", txt("not bytes")),
        ("extra", Value::Null),
    ] {
        let mut b = body("revision");
        set(&mut b, field, value);
        err(&raw_sign(b, &key()), Error::InvalidFormat);
    }
    for name in ["genesis", "revision"] {
        let Value::Map(fields) = body(name) else {
            unreachable!()
        };
        for remove in 0..fields.len() {
            let mut b = fields.clone();
            b.remove(remove);
            err(&raw_sign(Value::Map(b), &key()), Error::InvalidFormat);
        }
    }
    for (field, value) in [
        ("tags", Value::Array(vec![txt("b"), txt("a")])),
        ("tags", Value::Array(vec![txt("a"); 2])),
        ("languages", Value::Array(vec![txt("JA")])),
        ("schema", Value::Map(vec![])),
        ("extensions", Value::Map(vec![("".into(), Value::Null)])),
        (
            "information_type",
            Value::Map(vec![
                ("namespace".into(), txt("lngnb")),
                ("code".into(), Value::Bool(true)),
            ]),
        ),
        ("resource_type", txt("lngnb:Name")),
        ("titles", Value::Map(vec![("en-US".into(), txt("title"))])),
    ] {
        let mut b = body("revision");
        let mut m = get(&b, "metadata").clone();
        set(&mut m, field, value);
        set(&mut b, "metadata", m);
        err(&raw_sign(b, &key()), Error::InvalidFormat);
    }
    for media in [
        "Text/plain",
        "text/plain;charset=utf-8",
        "text/*",
        " text/plain",
        "a/b/c",
    ] {
        let mut b = body("revision");
        let mut p = get(&b, "payload").clone();
        set(&mut p, "media_type", txt(media));
        set(&mut b, "payload", p);
        err(&raw_sign(b, &key()), Error::InvalidFormat);
    }
}

#[test]
fn a2_field_boundaries_are_enforced_without_extra_restrictions() {
    for (field, limit) in [("parents", 256), ("origins", 128)] {
        for n in [limit - 1, limit, limit + 1] {
            let values = (0..n)
                .map(|i| {
                    let mut id = vec![0; 32];
                    id[30..].copy_from_slice(&(i as u16).to_be_bytes());
                    if field == "parents" {
                        Value::Bytes(id)
                    } else {
                        Value::Map(vec![("knowledge_id".into(), Value::Bytes(id))])
                    }
                })
                .collect();
            let mut b = body("revision");
            set(&mut b, field, Value::Array(values));
            assert_eq!(
                LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
                n <= limit
            );
        }
    }
    for (field, count, size) in [
        ("tags", 128, 256),
        ("languages", 64, 64),
        ("titles", 64, 4096),
        ("summaries", 64, 65536),
    ] {
        for n in [count - 1, count, count + 1] {
            let value = if field == "titles" || field == "summaries" {
                Value::Map((0..n).map(|i| (format!("x{i:03}"), txt(""))).collect())
            } else {
                Value::Array((0..n).map(|i| txt(&format!("x{i:03}"))).collect())
            };
            let mut b = body("revision");
            let mut m = get(&b, "metadata").clone();
            set(&mut m, field, value);
            set(&mut b, "metadata", m);
            assert_eq!(
                LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
                n <= count,
                "{field} count {n}"
            );
        }
        for n in [size - 1, size, size + 1] {
            let s = if field == "languages" {
                // 構文も満たす64 bytes: 7組の8文字＋区切りと最後の1文字。
                let base = "abcdefgh-".repeat(7) + "a";
                base[..n.min(64)].to_owned() + if n > 64 { "a" } else { "" }
            } else {
                "a".repeat(n)
            };
            let syntax_valid = field != "languages"
                || (1..=64).contains(&n) && s.split('-').all(|p| !p.is_empty() && p.len() <= 8);
            let value = if field == "titles" || field == "summaries" {
                Value::Map(vec![("und".into(), txt(&s))])
            } else {
                Value::Array(vec![txt(&s)])
            };
            let mut b = body("revision");
            let mut m = get(&b, "metadata").clone();
            set(&mut m, field, value);
            set(&mut b, "metadata", m);
            assert_eq!(
                LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
                n <= size && syntax_valid,
                "{field} size {n}"
            );
        }
    }
    for n in [0, 1, 255, 256, 257] {
        let mut b = body("revision");
        let mut m = get(&b, "metadata").clone();
        set(
            &mut m,
            "extensions",
            Value::Map(vec![("a".repeat(n), Value::Null)]),
        );
        set(&mut b, "metadata", m);
        assert_eq!(
            LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
            (1..=256).contains(&n)
        );
    }
    // 未知型、最大u63、media/resource不一致、空本文と未指定mediaは適合。
    let mut b = body("revision");
    let mut m = get(&b, "metadata").clone();
    set(
        &mut m,
        "information_type",
        Value::Map(vec![
            ("namespace".into(), txt("custom")),
            ("code".into(), Value::Int(i64::MAX)),
        ]),
    );
    set(&mut m, "resource_type", txt("other:unknown"));
    set(&mut b, "metadata", m);
    let mut p = get(&b, "payload").clone();
    set(&mut p, "byte_length", Value::Int(0));
    set(&mut p, "media_type", txt(""));
    set(&mut b, "payload", p);
    assert!(LocalRecord::check(&raw_sign(b, &key()), None).is_ok());
}

#[test]
fn metadata_encoded_length_boundary_is_exact() {
    let b = body("revision");
    let mut m = get(&b, "metadata").clone();
    set(
        &mut m,
        "extensions",
        Value::Map(vec![("pad".into(), Value::Bytes(vec![]))]),
    );
    // byte stringが長さ65536以上になる際のheader増分4を含めて調整する。
    let overhead = cbor::encode(&m).unwrap().len() + 4;
    for n in [262143, 262144, 262145] {
        let mut m = m.clone();
        set(
            &mut m,
            "extensions",
            Value::Map(vec![("pad".into(), Value::Bytes(vec![0; n - overhead]))]),
        );
        assert_eq!(cbor::encode(&m).unwrap().len(), n);
        let mut b = b.clone();
        set(&mut b, "metadata", m);
        assert_eq!(
            LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
            n <= 262144
        );
    }
}

#[test]
fn c10_four_external_id_types_are_strict() {
    let f = fixture();
    for (kind, s) in [
        (Kind::Knowledge, f["knowledge_id"].as_str().unwrap()),
        (Kind::Record, f["genesis"]["record_id"].as_str().unwrap()),
        (Kind::Blob, f["blob_id"].as_str().unwrap()),
        (Kind::Key, f["key_id"].as_str().unwrap()),
    ] {
        assert_eq!(Id::parse(kind, s).unwrap().to_string(), s);
        for wrong in [
            s.to_uppercase(),
            format!("{s}="),
            format!(" {s}"),
            s[..55].into(),
            format!("zz1_{}", &s[4..]),
        ] {
            assert!(Id::parse(kind, &wrong).is_err());
        }
        let mut bad = s.as_bytes().to_vec();
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let last = alphabet.iter().position(|b| *b == bad[55]).unwrap();
        bad[55] = alphabet[last + 1];
        assert!(Id::parse(kind, std::str::from_utf8(&bad).unwrap()).is_err());
        for other in [Kind::Knowledge, Kind::Record, Kind::Blob, Kind::Key] {
            assert_eq!(Id::parse(other, s).is_ok(), other == kind);
        }
    }
    let a = Id::random_knowledge().unwrap();
    let b = Id::random_knowledge().unwrap();
    assert_eq!(a.kind, Kind::Knowledge);
    assert_ne!(a, b);
}

#[test]
fn s01_s03_s05_tampering_is_rejected() {
    let f = fixture();
    let public: [u8; 32] = key().verifying_key().to_bytes();
    let sig: [u8; 64] = unhex(f["revision"]["signature_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let msg = unhex(f["revision"]["signature_message_hex"].as_str().unwrap());
    assert!(verify_signature(&public, &sig, &msg).is_ok());
    let mut plus = sig;
    // Lの生bytesは規範から固定する。
    let order = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = plus[32 + i] as u16 + order[i] as u16 + carry;
        plus[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(
        verify_signature(&public, &plus, &msg),
        Err(Error::InvalidSignature)
    );
    let mut changed = msg.clone();
    changed[0] ^= 1;
    assert!(verify_signature(&public, &sig, &changed).is_err());
    let mut e = cbor::decode(&original("revision")).unwrap();
    let mut signature = get(&e, "signature").clone();
    set(&mut signature, "key_id", Value::Bytes(vec![0; 32]));
    set(&mut e, "signature", signature);
    err(&cbor::encode(&e).unwrap(), Error::InvalidSignature);
    let mut b = body("revision");
    let mut m = get(&b, "metadata").clone();
    set(
        &mut m,
        "titles",
        Value::Map(vec![("en".into(), txt("Jello"))]),
    );
    set(&mut b, "metadata", m);
    let mut e = cbor::decode(&original("revision")).unwrap();
    set(&mut e, "body", b);
    err(&cbor::encode(&e).unwrap(), Error::InvalidSignature);
}

#[test]
fn s02_rejects_noncanonical_identity_small_and_mixed_order_points() {
    let public = key().verifying_key().to_bytes();
    let sig = key().sign(b"message").to_bytes();
    for point in EIGHT_TORSION {
        for bytes in [
            point.compress().to_bytes(),
            (ED25519_BASEPOINT_POINT + point).compress().to_bytes(),
        ] {
            if bytes == ED25519_BASEPOINT_POINT.compress().to_bytes() {
                continue;
            }
            assert_eq!(
                verify_signature(&bytes, &sig, b"message"),
                Err(Error::InvalidSignature)
            );
            let mut s = sig;
            s[..32].copy_from_slice(&bytes);
            assert_eq!(
                verify_signature(&public, &s, b"message"),
                Err(Error::InvalidSignature)
            );
        }
    }
    for bytes in [
        unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        unhex("0100000000000000000000000000000000000000000000000000000000000080"),
    ] {
        let bytes: [u8; 32] = bytes.try_into().unwrap();
        assert!(verify_signature(&bytes, &sig, b"message").is_err());
        let mut changed = sig;
        changed[..32].copy_from_slice(&bytes);
        assert!(verify_signature(&public, &changed, b"message").is_err());
    }
    // cofactorを掛けない等式には適合する混合位数署名を作り、追加部分群検査で拒否する。
    let a = Scalar::from(7u64);
    let r = Scalar::from(11u64);
    let t = EIGHT_TORSION[1];
    let public = (a * ED25519_BASEPOINT_POINT + t).compress().to_bytes();
    let r_bytes = (r * ED25519_BASEPOINT_POINT + t).compress().to_bytes();
    for n in 0..10000u32 {
        let msg = n.to_le_bytes();
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(public);
        h.update(msg);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        if k.to_bytes()[0] % 8 != 7 {
            continue;
        }
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&(r + k * a).to_bytes());
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&public)
                .unwrap()
                .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
        );
        assert_eq!(
            verify_signature(&public, &sig, &msg),
            Err(Error::InvalidSignature)
        );
        return;
    }
    panic!("mixed-order test vector not found");
}

#[test]
fn s04_s06_s07_and_validation_priority() {
    let genesis = LocalRecord::check(&original("genesis"), None).unwrap();
    let other = SigningKey::from_bytes(&[1; 32]);
    let record = LocalRecord::check(&raw_sign(body("revision"), &other), None).unwrap();
    assert_eq!(record.check_genesis(&genesis), Err(Error::WrongPublisher));
    let mut wrong = body("revision");
    set(&mut wrong, "knowledge_id", Value::Bytes(vec![4; 32]));
    assert_eq!(
        LocalRecord::check(&raw_sign(wrong, &key()), None)
            .unwrap()
            .check_genesis(&genesis),
        Err(Error::GenesisMismatch)
    );
    let mut wrong = body("genesis");
    set(
        &mut wrong,
        "publisher_public_key",
        Value::Bytes(vec![3; 32]),
    );
    err(&raw_sign(wrong, &key()), Error::WrongPublisher);
    for (field, value, error) in [
        ("profile_id", "unknown-profile", Error::UnsupportedProfile),
        ("record_kind", "authority", Error::UnsupportedKind),
    ] {
        let mut b = body("revision");
        set(&mut b, field, txt(value));
        set(&mut b, "extra", Value::Null);
        err(&raw_sign(b, &key()), error);
    }
    let mut input = original("genesis");
    *input.last_mut().unwrap() ^= 1;
    assert_eq!(
        LocalRecord::check(
            &input,
            Some(Id {
                kind: Kind::Record,
                bytes: [0; 32]
            })
        )
        .unwrap_err(),
        Error::IdMismatch
    );
    let mut b = body("revision");
    set(&mut b, "profile_id", txt(PROFILE));
    assert!(LocalRecord::sign(b, &key()).is_ok());
}

#[test]
fn independent_python_cbor_hash_and_signature_comparison() {
    let mut cases = Vec::new();
    for name in ["genesis", "revision"] {
        cases.push(serde_json::json!({"seed":hex(&key().to_bytes()),"body":hex(&cbor::encode(&body(name)).unwrap()),"envelope":hex(&original(name))}));
    }
    for n in 0..16u8 {
        let k = SigningKey::from_bytes(&[n; 32]);
        let mut b = body("genesis");
        set(
            &mut b,
            "publisher_public_key",
            Value::Bytes(k.verifying_key().to_bytes().to_vec()),
        );
        set(&mut b, "knowledge_id", Value::Bytes(vec![n; 32]));
        let record = LocalRecord::sign(b, &k).unwrap();
        cases.push(serde_json::json!({"seed":hex(&k.to_bytes()),"body":hex(&cbor::encode(record.body()).unwrap()),"envelope":hex(record.bytes())}));
    }
    for n in 0..8u8 {
        let mut b = body("revision");
        let mut m = get(&b, "metadata").clone();
        set(
            &mut m,
            "titles",
            Value::Map(vec![("ja".into(), txt("図書館 e\u{301} é Ａ"))]),
        );
        set(
            &mut m,
            "extensions",
            Value::Map(vec![(
                "k".repeat(24 + n as usize),
                Value::Array(vec![
                    Value::Int(i64::MIN),
                    Value::Int(i64::MAX),
                    Value::Bool(true),
                    Value::Null,
                    Value::Bytes(vec![n; 256]),
                    Value::Map(vec![("長い鍵".into(), txt("改行\n"))]),
                ]),
            )]),
        );
        set(&mut b, "metadata", m);
        let record = LocalRecord::sign(b, &key()).unwrap();
        cases.push(serde_json::json!({"seed":hex(&key().to_bytes()),"body":hex(&cbor::encode(record.body()).unwrap()),"envelope":hex(record.bytes())}));
    }
    let python = std::env::var_os("LNGNB_REFERENCE_PYTHON").unwrap_or_else(|| "python3".into());
    let mut child = std::process::Command::new(python)
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference.py"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("独立照合用Python環境が必要");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "独立照合失敗");
    let reference: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reference.len(), cases.len());
    for (case, id) in cases.iter().zip(reference) {
        assert_eq!(
            LocalRecord::check(&unhex(case["envelope"].as_str().unwrap()), None)
                .unwrap()
                .id()
                .to_string(),
            id
        );
    }
}

#[test]
fn schema_reference_signature_and_scalar_boundaries() {
    for name in ["name", "version"] {
        for n in [0, 1, 255, 256, 257] {
            let mut b = body("revision");
            let mut m = get(&b, "metadata").clone();
            set(
                &mut m,
                "schema",
                Value::Map(vec![(name.into(), txt(&"x".repeat(n)))]),
            );
            set(&mut b, "metadata", m);
            assert_eq!(
                LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
                (1..=256).contains(&n)
            );
        }
    }
    for n in [0, 1, 63, 64, 65] {
        let mut b = body("revision");
        let mut m = get(&b, "metadata").clone();
        set(
            &mut m,
            "information_type",
            Value::Map(vec![
                ("namespace".into(), txt(&"a".repeat(n))),
                ("code".into(), Value::Int(10)),
            ]),
        );
        set(&mut b, "metadata", m);
        assert_eq!(
            LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
            (1..=64).contains(&n)
        );
    }
    for n in [254, 255, 256] {
        let mut b = body("revision");
        let mut p = get(&b, "payload").clone();
        set(
            &mut p,
            "media_type",
            txt(&("a/".to_owned() + &"b".repeat(n - 2))),
        );
        set(&mut b, "payload", p);
        assert_eq!(
            LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
            n <= 255
        );
    }
    let reference = Value::Map(vec![("knowledge_id".into(), Value::Bytes(vec![0; 32]))]);
    for addition in [
        None,
        Some(("genesis_record_id", Value::Bytes(vec![1; 32]))),
        Some(("revision_record_id", Value::Bytes(vec![2; 32]))),
    ] {
        let mut r = reference.clone();
        if let Some((k, v)) = addition.clone() {
            set(&mut r, k, v);
        }
        let mut b = body("revision");
        set(&mut b, "origins", Value::Array(vec![r]));
        assert_eq!(
            LocalRecord::check(&raw_sign(b, &key()), None).is_ok(),
            !matches!(addition, Some(("revision_record_id", _)))
        );
    }
    let mut envelope = cbor::decode(&original("revision")).unwrap();
    let sig = get(&envelope, "signature").clone();
    let Value::Map(fields) = sig.clone() else {
        unreachable!()
    };
    for index in 0..fields.len() {
        let mut missing = fields.clone();
        missing.remove(index);
        set(&mut envelope, "signature", Value::Map(missing));
        err(&cbor::encode(&envelope).unwrap(), Error::InvalidFormat);
    }
    for n in [0, 31, 32, 63, 65] {
        let mut wrong = sig.clone();
        set(&mut wrong, "signature_bytes", Value::Bytes(vec![0; n]));
        set(&mut envelope, "signature", wrong);
        err(&cbor::encode(&envelope).unwrap(), Error::InvalidFormat);
    }
    assert_ne!(
        id::record_id(&original("revision")),
        id::record_id(&original("genesis"))
    );
    let mut extra = original("revision");
    extra[0] ^= 1;
    assert_ne!(id::record_id(&original("revision")), id::record_id(&extra));
}

#[test]
fn malformed_byte_inputs_never_panic() {
    // 固定擬似乱数列は試験入力専用。製品のID生成には使わない。
    let mut x = 0x1234_5678u32;
    for len in 0..2048 {
        let mut input = Vec::new();
        for _ in 0..len % 257 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            input.push(x as u8);
        }
        let _ = LocalRecord::check(&input, None);
    }
}
