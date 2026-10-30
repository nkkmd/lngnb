//! A2/A3/A11: 新規資料と明示したGenesis・親からRevisionを署名する内部基盤。
//! 完成Recordだけを返す。CLI・本文I/O・永続保存・pin・公開には接続しない。
use crate::{
    cbor::{self, Value},
    id::{self, Id, Kind},
    keyfile::UnlockedKey,
    record::{LocalRecord, PROFILE},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationError {
    InvalidInput,
    PayloadLimit,
    RandomUnavailable,
    SigningFailed,
}
impl std::fmt::Display for CreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid_creation_input",
            Self::PayloadLimit => "creation_payload_limit",
            Self::RandomUnavailable => "creation_random_unavailable",
            Self::SigningFailed => "creation_signing_failed",
        })
    }
}
impl std::error::Error for CreationError {}
type Result<T> = std::result::Result<T, CreationError>;

/// ローカルの作成予算。Record形式の規範上限とは別。
#[derive(Debug, Clone, Copy)]
pub struct CreationBudget {
    pub max_payload_bytes: usize,
}
impl Default for CreationBudget {
    fn default() -> Self {
        Self {
            max_payload_bytes: 16 * 1024 * 1024,
        }
    }
}
/// 署名・局所検査と組内のGenesis照合を済ませた初版。
/// 本文保持、保存確定、record_validation=valid、pin、公開資格は表さない。
#[derive(Debug)]
pub struct InitialRecords {
    genesis: LocalRecord,
    revision: LocalRecord,
}
impl InitialRecords {
    pub fn genesis(&self) -> &LocalRecord {
        &self.genesis
    }
    pub fn revision(&self) -> &LocalRecord {
        &self.revision
    }
}
fn map(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

pub(crate) const MAX_METADATA_BYTES: usize = 262_144;
// 符号化/文字列複製の前に、encoded sizeの下限を割当てなしで走査する。
// 実際のCBOR長/重複key/規範は、後段の共通encoderとRecord検査で引き続き確認する。
fn metadata_preflight(value: &Value, depth: usize, remaining: &mut usize) -> Result<()> {
    fn charge(remaining: &mut usize, bytes: usize) -> Result<()> {
        *remaining = remaining
            .checked_sub(bytes)
            .ok_or(CreationError::InvalidInput)?;
        Ok(())
    }
    let depth = depth + usize::from(matches!(value, Value::Map(_) | Value::Array(_)));
    if depth > 16 {
        return Err(CreationError::InvalidInput);
    }
    charge(remaining, 1)?; // 全valueは少なくとも一byteのheadを必要とする。
    match value {
        Value::Text(s) => charge(remaining, s.len())?,
        Value::Bytes(b) => charge(remaining, b.len())?,
        Value::Map(fields) => {
            if fields.len() > 1024 {
                return Err(CreationError::InvalidInput);
            }
            for (key, child) in fields {
                charge(remaining, 1)?;
                charge(remaining, key.len())?;
                metadata_preflight(child, depth, remaining)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 4096 {
                return Err(CreationError::InvalidInput);
            }
            for child in values {
                metadata_preflight(child, depth, remaining)?;
            }
        }
        _ => (),
    }
    Ok(())
}

/// 新規入力だけを署名前に整える。署名済みRecordの書換えには使わない。
fn metadata(mut input: Value) -> Result<Value> {
    let mut remaining = MAX_METADATA_BYTES;
    metadata_preflight(&input, 0, &mut remaining)?;
    // 重複key・深さ・文字列等の上限を、変換/既定値挿入の前にも検査する。
    if cbor::encode(&input)
        .map_err(|_| CreationError::InvalidInput)?
        .len()
        > MAX_METADATA_BYTES
    {
        return Err(CreationError::InvalidInput);
    }
    let Value::Map(fields) = &mut input else {
        return Err(CreationError::InvalidInput);
    };
    for (name, value) in fields.iter_mut() {
        match name.as_str() {
            "titles" | "summaries" => {
                let Value::Map(labels) = value else {
                    return Err(CreationError::InvalidInput);
                };
                for (label, _) in labels.iter_mut() {
                    *label = label.to_ascii_lowercase();
                }
                labels.sort_by(|a, b| a.0.cmp(&b.0));
                if labels.windows(2).any(|w| w[0].0 == w[1].0) {
                    return Err(CreationError::InvalidInput);
                }
            }
            "tags" | "languages" => {
                let Value::Array(values) = value else {
                    return Err(CreationError::InvalidInput);
                };
                let mut strings = Vec::with_capacity(values.len());
                for v in values.iter() {
                    let Value::Text(s) = v else {
                        return Err(CreationError::InvalidInput);
                    };
                    strings.push(if name == "languages" {
                        s.to_ascii_lowercase()
                    } else {
                        s.clone()
                    });
                }
                strings.sort();
                if strings.windows(2).any(|w| w[0] == w[1]) {
                    return Err(CreationError::InvalidInput);
                }
                *values = strings.into_iter().map(Value::Text).collect();
            }
            _ => (),
        }
    }
    if !fields.iter().any(|(k, _)| k == "information_type") {
        fields.push((
            "information_type".into(),
            map(vec![("namespace", text("lngnb")), ("code", Value::Int(0))]),
        ));
    }
    if !fields.iter().any(|(k, _)| k == "resource_type") {
        fields.push(("resource_type".into(), text("lngnb:unspecified")));
    }
    Ok(input)
}

/// 呼出し元が保持する本文bytesからBlob ID/実長を計算し、新しいKnowledgeを作る。
/// Noneのmedia_typeは空文字。内容/拡張子から推測せず、明示値を黙って補正しない。
/// payloadの読込み/メモリ確保は呼出し側の責務。本関数は予算超過ならhash/署名前に拒否する。
/// 鍵を保存・export/cacheせず、返却値は完成署名Record二つだけ。途中結果を返さない。
pub fn create_initial(
    key: &UnlockedKey,
    payload: &[u8],
    metadata_input: Value,
    media_type: Option<&str>,
    budget: CreationBudget,
) -> Result<InitialRecords> {
    create_with(key, payload, metadata_input, media_type, budget, || {
        Id::random_knowledge().map_err(|_| CreationError::RandomUnavailable)
    })
}
fn create_with(
    key: &UnlockedKey,
    payload: &[u8],
    metadata_input: Value,
    media_type: Option<&str>,
    budget: CreationBudget,
    knowledge: impl FnOnce() -> Result<Id>,
) -> Result<InitialRecords> {
    if payload.len() > budget.max_payload_bytes {
        return Err(CreationError::PayloadLimit);
    }
    let media_type = media_type.unwrap_or("");
    if media_type.len() > 255 {
        return Err(CreationError::InvalidInput);
    }
    let length = i64::try_from(payload.len()).map_err(|_| CreationError::PayloadLimit)?;
    let metadata = metadata(metadata_input)?;
    let knowledge = knowledge()?;
    if knowledge.kind != Kind::Knowledge {
        return Err(CreationError::InvalidInput);
    }
    let genesis = key
        .sign_record(map(vec![
            ("profile_id", text(PROFILE)),
            ("record_kind", text("genesis")),
            ("knowledge_id", bytes(&knowledge.bytes)),
            ("publisher_public_key", bytes(&key.public_key())),
        ]))
        .map_err(|_| CreationError::SigningFailed)?;
    let revision = key
        .sign_record(map(vec![
            ("profile_id", text(PROFILE)),
            ("record_kind", text("revision")),
            ("knowledge_id", bytes(&knowledge.bytes)),
            ("genesis_record_id", bytes(&genesis.id().bytes)),
            ("parents", Value::Array(vec![])),
            (
                "payload",
                map(vec![
                    ("blob_id", bytes(&id::blob_id(payload).bytes)),
                    ("byte_length", Value::Int(length)),
                    ("media_type", text(media_type)),
                ]),
            ),
            ("metadata", metadata),
        ]))
        .map_err(|_| CreationError::InvalidInput)?;
    revision
        .check_genesis(&genesis)
        .map_err(|_| CreationError::SigningFailed)?;
    Ok(InitialRecords { genesis, revision })
}

/// 明示したGenesisの発行鍵で、指定した親集合を持つ新しいRevisionを作る。
/// 親は局所検査済みのRevisionを最大256件、重複なしで指定する。生ID順へ並べる。
/// 空集合は同じKnowledgeの別初版。先端選択・親/metadata/由来の暗黙継承は行わない。
/// 直接の親とGenesisの結合だけを照合し、祖先全体・本文・保存・pin・公開は検証しない。
/// 返却値は完成署名Recordだけであり、record_validation=validを表さない。
pub fn create_revision(
    key: &UnlockedKey,
    genesis: &LocalRecord,
    parents: &[&LocalRecord],
    payload: &[u8],
    metadata_input: Value,
    media_type: Option<&str>,
    budget: CreationBudget,
) -> Result<LocalRecord> {
    if genesis.kind() != crate::record::RecordKind::Genesis
        || key.public_key() != genesis.identity().public
        || parents.len() > 256
    {
        return Err(CreationError::InvalidInput);
    }
    if payload.len() > budget.max_payload_bytes {
        return Err(CreationError::PayloadLimit);
    }
    let media_type = media_type.unwrap_or("");
    if media_type.len() > 255 {
        return Err(CreationError::InvalidInput);
    }
    // 件数を検査してから確保。親の署名済みbytesやmetadataを複製しない。
    let mut ids = Vec::with_capacity(parents.len());
    for parent in parents {
        parent
            .check_genesis(genesis)
            .map_err(|_| CreationError::InvalidInput)?;
        ids.push(parent.id().bytes);
    }
    ids.sort_unstable();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(CreationError::InvalidInput);
    }
    let length = i64::try_from(payload.len()).map_err(|_| CreationError::PayloadLimit)?;
    let metadata = metadata(metadata_input)?;
    let revision = key
        .sign_record(map(vec![
            ("profile_id", text(PROFILE)),
            ("record_kind", text("revision")),
            ("knowledge_id", bytes(&genesis.identity().knowledge)),
            ("genesis_record_id", bytes(&genesis.id().bytes)),
            (
                "parents",
                Value::Array(ids.iter().map(|id| bytes(id)).collect()),
            ),
            (
                "payload",
                map(vec![
                    ("blob_id", bytes(&id::blob_id(payload).bytes)),
                    ("byte_length", Value::Int(length)),
                    ("media_type", text(media_type)),
                ]),
            ),
            ("metadata", metadata),
        ]))
        .map_err(|_| CreationError::InvalidInput)?;
    revision
        .check_genesis(genesis)
        .map_err(|_| CreationError::SigningFailed)?;
    if ids.contains(&revision.id().bytes) {
        return Err(CreationError::InvalidInput);
    }
    Ok(revision)
}

#[cfg(test)]
mod tests {
    // A13/A14の公開試験値だけを使う。実運用への流用禁止。
    use super::*;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    fn fixture(section: &str) -> serde_json::Value {
        let spec = include_str!("../docs/specification-v1.0.0.md");
        serde_json::from_str(
            spec.split(section)
                .nth(1)
                .unwrap()
                .split("```json\n")
                .nth(1)
                .unwrap()
                .split("\n```")
                .next()
                .unwrap(),
        )
        .unwrap()
    }
    fn a13() -> serde_json::Value {
        fixture("## 付録A13 Record・IDの固定計算例")
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        data_encoding::HEXLOWER.encode(b)
    }
    fn key() -> UnlockedKey {
        let f = fixture("## 付録A14 暗号化鍵ファイルの固定計算例");
        crate::keyfile::unlock(
            &unhex(f["keyfile_cbor_hex"].as_str().unwrap()),
            &String::from_utf8(unhex(f["passphrase_utf8_hex"].as_str().unwrap())).unwrap(),
        )
        .unwrap()
    }
    fn get<'a>(v: &'a Value, name: &str) -> &'a Value {
        let Value::Map(m) = v else {
            panic!("expected public fixture map");
        };
        &m.iter().find(|(k, _)| k == name).unwrap().1
    }
    fn contains(v: &Value, name: &str) -> bool {
        matches!(v, Value::Map(m) if m.iter().any(|(k,_)| k == name))
    }
    #[test]
    fn preflight_rejects_oversize_inputs_before_randomness_and_preserves_boundaries() {
        let key = key();
        let media = format!("a/{}", "b".repeat(253));
        let records = create_initial(
            &key,
            b"",
            Value::Map(vec![]),
            Some(&media),
            CreationBudget::default(),
        )
        .unwrap();
        assert_eq!(
            get(get(records.revision().body(), "payload"), "media_type"),
            &text(&media)
        );
        let longer = format!("{media}b");
        assert_eq!(
            create_with(
                &key,
                b"",
                Value::Map(vec![]),
                Some(&longer),
                CreationBudget::default(),
                || panic!("oversize media must fail before randomness")
            )
            .unwrap_err(),
            CreationError::InvalidInput
        );
        let keys = map(vec![
            (&"x".repeat(131_073), Value::Null),
            (&"y".repeat(131_073), Value::Null),
        ]);
        assert_eq!(
            create_with(&key, b"", keys, None, CreationBudget::default(), || panic!(
                "oversize metadata must fail before randomness"
            ))
            .unwrap_err(),
            CreationError::InvalidInput
        );
        // 下限検査だけで正規のCBOR長検査を代替しない。
        let small = map(vec![("x", text("abc"))]);
        let exact = cbor::encode(&small).unwrap().len();
        let mut remaining = exact;
        metadata_preflight(&small, 0, &mut remaining).unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(
            metadata_preflight(&small, 0, &mut (exact - 1)).unwrap_err(),
            CreationError::InvalidInput
        );
        let mut remaining = MAX_METADATA_BYTES;
        assert_eq!(
            metadata_preflight(&Value::Array(vec![Value::Null; 4097]), 0, &mut remaining)
                .unwrap_err(),
            CreationError::InvalidInput
        );
        let mut fields: Vec<_> = (0..1024).map(|i| (i.to_string(), Value::Null)).collect();
        let mut remaining = MAX_METADATA_BYTES;
        metadata_preflight(&Value::Map(fields.clone()), 0, &mut remaining).unwrap();
        fields.push(("one more".into(), Value::Null));
        let mut remaining = MAX_METADATA_BYTES;
        assert_eq!(
            metadata_preflight(&Value::Map(fields), 0, &mut remaining).unwrap_err(),
            CreationError::InvalidInput
        );
        let mut deep = Value::Null;
        for _ in 0..17 {
            deep = Value::Array(vec![deep]);
        }
        let mut remaining = MAX_METADATA_BYTES;
        assert_eq!(
            metadata_preflight(&deep, 0, &mut remaining).unwrap_err(),
            CreationError::InvalidInput
        );
    }
    #[test]
    fn fixed_initial_records_match_a13_exactly() {
        let f = a13();
        let original = LocalRecord::check(
            &unhex(f["revision"]["envelope_cbor_hex"].as_str().unwrap()),
            None,
        )
        .unwrap();
        let meta = get(original.body(), "metadata").clone();
        let payload = unhex(f["blob_hex"].as_str().unwrap());
        let records = create_with(
            &key(),
            &payload,
            meta,
            Some("text/plain"),
            CreationBudget::default(),
            || {
                Ok(Id {
                    kind: Kind::Knowledge,
                    bytes: unhex(f["knowledge_id_hex"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                })
            },
        )
        .unwrap();
        for (name, record) in [
            ("genesis", records.genesis()),
            ("revision", records.revision()),
        ] {
            assert_eq!(
                record.bytes(),
                unhex(f[name]["envelope_cbor_hex"].as_str().unwrap())
            );
            assert_eq!(
                record.id().to_string(),
                f[name]["record_id"].as_str().unwrap()
            );
        }
        assert_eq!(original.bytes(), records.revision().bytes());
        records.revision().check_genesis(records.genesis()).unwrap();
    }
    #[test]
    fn defaults_empty_payload_and_fresh_knowledge_are_explicit() {
        let key = key();
        let budget = CreationBudget {
            max_payload_bytes: 0,
        };
        let a = create_initial(&key, b"", Value::Map(vec![]), None, budget).unwrap();
        let b = create_initial(&key, b"", Value::Map(vec![]), None, budget).unwrap();
        assert_ne!(
            get(a.genesis().body(), "knowledge_id"),
            get(b.genesis().body(), "knowledge_id")
        );
        assert_eq!(
            get(a.genesis().body(), "publisher_public_key"),
            &bytes(&key.public_key())
        );
        let body = a.revision().body();
        assert_eq!(get(body, "parents"), &Value::Array(vec![]));
        assert!(!contains(body, "origins"));
        let p = get(body, "payload");
        assert_eq!(get(p, "media_type"), &text(""));
        assert_eq!(get(p, "byte_length"), &Value::Int(0));
        assert_eq!(get(p, "blob_id"), &bytes(&id::blob_id(b"").bytes));
        let m = get(body, "metadata");
        assert_eq!(get(m, "resource_type"), &text("lngnb:unspecified"));
        assert_eq!(get(get(m, "information_type"), "namespace"), &text("lngnb"));
        assert_eq!(get(get(m, "information_type"), "code"), &Value::Int(0));
        assert!(!contains(m, "languages") && !contains(m, "titles"));
        a.revision().check_genesis(a.genesis()).unwrap();
    }
    #[test]
    fn new_labels_and_sets_normalize_without_changing_unicode_values_or_extensions() {
        let meta = map(vec![
            (
                "titles",
                map(vec![("JA", text(" e\u{301} é あ ")), ("UND", text(""))]),
            ),
            ("summaries", map(vec![("EN-US", text("e\u{301}\n"))])),
            ("languages", Value::Array(vec![text("JA"), text("EN")])),
            ("tags", Value::Array(vec![text("ａ"), text("a"), text("A")])),
            (
                "information_type",
                map(vec![
                    ("namespace", text("example")),
                    ("code", Value::Int(9_000_000_000)),
                ]),
            ),
            ("resource_type", text("example:unknown")),
            (
                "extensions",
                map(vec![("Case", text("keep")), ("case", Value::Int(1))]),
            ),
        ]);
        let r = create_initial(
            &key(),
            b"\x00\xff\n",
            meta,
            Some("application/x-example"),
            CreationBudget::default(),
        )
        .unwrap();
        let m = get(r.revision().body(), "metadata");
        assert_eq!(get(get(m, "titles"), "ja"), &text(" e\u{301} é あ "));
        assert_eq!(get(get(m, "summaries"), "en-us"), &text("e\u{301}\n"));
        assert_eq!(
            get(m, "languages"),
            &Value::Array(vec![text("en"), text("ja")])
        );
        assert_eq!(
            get(m, "tags"),
            &Value::Array(vec![text("A"), text("a"), text("ａ")])
        );
        assert_eq!(
            get(get(m, "information_type"), "code"),
            &Value::Int(9_000_000_000)
        );
        assert_eq!(get(m, "resource_type"), &text("example:unknown"));
        assert_eq!(get(get(m, "extensions"), "Case"), &text("keep"));
        assert_eq!(get(get(m, "extensions"), "case"), &Value::Int(1));
    }
    #[test]
    fn invalid_inputs_limits_and_random_failure_return_no_partial_pair_or_input_details() {
        let key = key();
        for meta in [
            Value::Null,
            map(vec![(
                "titles",
                map(vec![("EN", text("a")), ("en", text("b"))]),
            )]),
            map(vec![(
                "languages",
                Value::Array(vec![text("EN"), text("en")]),
            )]),
            map(vec![(
                "tags",
                Value::Array(vec![text("same"), text("same")]),
            )]),
            map(vec![("information_type", Value::Null)]),
            map(vec![("private input marker", text("do not echo"))]),
            map(vec![(
                "titles",
                map(vec![("und", text(&"あ".repeat(1366)))]),
            )]),
            map(vec![(
                "extensions",
                map(vec![("oversize", text(&"x".repeat(262_144)))]),
            )]),
        ] {
            let e = create_initial(&key, b"", meta, None, CreationBudget::default()).unwrap_err();
            assert_eq!(e, CreationError::InvalidInput);
            assert_eq!(e.to_string(), "invalid_creation_input");
            assert!(std::error::Error::source(&e).is_none());
        }
        for media in [
            "Text/Plain",
            "text/plain; charset=utf-8",
            " text/plain",
            "text/*",
        ] {
            assert_eq!(
                create_initial(
                    &key,
                    b"",
                    Value::Map(vec![]),
                    Some(media),
                    CreationBudget::default()
                )
                .unwrap_err(),
                CreationError::InvalidInput
            );
        }
        let payload = vec![0; CreationBudget::default().max_payload_bytes + 1];
        assert_eq!(
            create_initial(
                &key,
                &payload,
                Value::Map(vec![]),
                None,
                CreationBudget::default()
            )
            .unwrap_err(),
            CreationError::PayloadLimit
        );
        let larger = CreationBudget {
            max_payload_bytes: payload.len(),
        };
        let r = create_initial(&key, &payload, Value::Map(vec![]), None, larger).unwrap();
        assert_eq!(
            get(get(r.revision().body(), "payload"), "byte_length"),
            &Value::Int(payload.len() as i64)
        );
        assert_eq!(
            create_with(
                &key,
                b"x",
                Value::Map(vec![]),
                None,
                CreationBudget {
                    max_payload_bytes: 0
                },
                || panic!("budget failure must precede randomness")
            )
            .unwrap_err(),
            CreationError::PayloadLimit
        );
        assert_eq!(
            create_with(&key, b"", Value::Map(vec![]), None, larger, || Err(
                CreationError::RandomUnavailable
            ))
            .unwrap_err(),
            CreationError::RandomUnavailable
        );
    }
    #[test]
    fn independent_python_checks_the_complete_initial_pair_and_payload_binding() {
        let payload = b"public new payload\x00\xff\n";
        let records = create_initial(
            &key(),
            payload,
            map(vec![("titles", map(vec![("JA", text("e\u{301} é"))]))]),
            None,
            CreationBudget::default(),
        )
        .unwrap();
        let cases: Vec<_> = [records.genesis(),records.revision()].iter().map(|r| serde_json::json!({
            "seed":a13()["seed_hex"],"body":hex(&cbor::encode(r.body()).unwrap()),"envelope":hex(r.bytes()),
            "initial_creation":{"payload":hex(payload),"genesis":hex(records.genesis().bytes())}
        })).collect();
        let mut child = Command::new(
            std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
        )
        .arg("tests/reference.py")
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
            "independent initial creation check failed (details suppressed)"
        );
        let ids: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            ids,
            vec![
                records.genesis().id().to_string(),
                records.revision().id().to_string()
            ]
        );
    }

    fn revise(
        key: &UnlockedKey,
        genesis: &LocalRecord,
        parents: &[&LocalRecord],
        payload: &[u8],
    ) -> LocalRecord {
        create_revision(
            key,
            genesis,
            parents,
            payload,
            Value::Map(vec![]),
            None,
            CreationBudget::default(),
        )
        .unwrap()
    }

    #[test]
    fn revision_empty_parents_reproduces_a13_without_changing_genesis() {
        let key = key();
        let f = a13();
        let genesis = LocalRecord::check(
            &unhex(f["genesis"]["envelope_cbor_hex"].as_str().unwrap()),
            None,
        )
        .unwrap();
        let expected = LocalRecord::check(
            &unhex(f["revision"]["envelope_cbor_hex"].as_str().unwrap()),
            None,
        )
        .unwrap();
        let original = genesis.bytes().to_vec();
        let payload = unhex(f["blob_hex"].as_str().unwrap());
        let result = create_revision(
            &key,
            &genesis,
            &[],
            &payload,
            get(expected.body(), "metadata").clone(),
            Some("text/plain"),
            CreationBudget::default(),
        )
        .unwrap();
        assert_eq!(result.bytes(), expected.bytes());
        assert_eq!(genesis.bytes(), original);
    }

    #[test]
    fn revision_chain_branch_and_merge_keep_inputs_and_canonical_parent_set() {
        let key = key();
        let initial = create_initial(
            &key,
            b"base",
            Value::Map(vec![]),
            None,
            CreationBudget::default(),
        )
        .unwrap();
        let original = initial.revision().bytes().to_vec();
        let a = revise(&key, initial.genesis(), &[initial.revision()], b"branch a");
        let b = revise(&key, initial.genesis(), &[initial.revision()], b"branch b");
        let merged = revise(&key, initial.genesis(), &[&b, &a], b"merged");
        let reordered = revise(&key, initial.genesis(), &[&a, &b], b"merged");
        assert_eq!(merged.bytes(), reordered.bytes());
        let mut expected = vec![a.id().bytes, b.id().bytes];
        expected.sort();
        assert_eq!(merged.parents().unwrap(), expected);
        assert_eq!(a.parents().unwrap(), vec![initial.revision().id().bytes]);
        assert_ne!(a.id(), b.id());
        assert_eq!(initial.revision().bytes(), original);
        // 同じ起点であっても、新しい親なし初版を旧先端へ自動接続しない。
        let independent = revise(&key, initial.genesis(), &[], b"another initial");
        assert!(independent.parents().unwrap().is_empty());
    }

    #[test]
    fn revision_rejects_wrong_key_or_genesis_duplicate_and_excessive_parents() {
        let key = key();
        let initial = create_initial(
            &key,
            b"base",
            Value::Map(vec![]),
            None,
            CreationBudget::default(),
        )
        .unwrap();
        let other = create_initial(
            &key,
            b"other",
            Value::Map(vec![]),
            None,
            CreationBudget::default(),
        )
        .unwrap();
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let wrong_publisher =
            LocalRecord::sign(initial.revision().body().clone(), &other_key).unwrap();
        let wrong_genesis = LocalRecord::sign(
            map(vec![
                ("profile_id", text(PROFILE)),
                ("record_kind", text("genesis")),
                (
                    "knowledge_id",
                    bytes(&initial.genesis().identity().knowledge),
                ),
                (
                    "publisher_public_key",
                    bytes(&other_key.verifying_key().to_bytes()),
                ),
            ]),
            &other_key,
        )
        .unwrap();
        for (genesis, parents) in [
            (initial.revision(), vec![]),
            (&wrong_genesis, vec![]),
            (initial.genesis(), vec![initial.genesis()]),
            (initial.genesis(), vec![other.revision()]),
            (initial.genesis(), vec![&wrong_publisher]),
            (
                initial.genesis(),
                vec![initial.revision(), initial.revision()],
            ),
            (initial.genesis(), vec![initial.revision(); 257]),
        ] {
            assert_eq!(
                create_revision(
                    &key,
                    genesis,
                    &parents,
                    b"",
                    Value::Map(vec![]),
                    None,
                    CreationBudget::default()
                )
                .unwrap_err(),
                CreationError::InvalidInput
            );
        }
        // 同じKnowledgeと鍵でも、別Genesisに属する親は受け入れない。
        let mut body = initial.revision().body().clone();
        let Value::Map(fields) = &mut body else {
            unreachable!()
        };
        fields
            .iter_mut()
            .find(|(k, _)| k == "genesis_record_id")
            .unwrap()
            .1 = bytes(&other.genesis().id().bytes);
        let changed = key.sign_record(body).unwrap();
        assert_eq!(
            create_revision(
                &key,
                initial.genesis(),
                &[&changed],
                b"",
                Value::Map(vec![]),
                None,
                CreationBudget::default()
            )
            .unwrap_err(),
            CreationError::InvalidInput
        );
    }

    #[test]
    fn revision_payload_metadata_and_parent_count_boundaries_are_checked() {
        let key = key();
        let initial = create_initial(
            &key,
            b"",
            Value::Map(vec![]),
            None,
            CreationBudget::default(),
        )
        .unwrap();
        let budget = CreationBudget {
            max_payload_bytes: 2,
        };
        for payload in [b"".as_slice(), b"a".as_slice(), b"ab".as_slice()] {
            create_revision(
                &key,
                initial.genesis(),
                &[],
                payload,
                Value::Map(vec![]),
                None,
                budget,
            )
            .unwrap();
        }
        assert_eq!(
            create_revision(
                &key,
                initial.genesis(),
                &[],
                b"abc",
                Value::Map(vec![]),
                None,
                budget
            )
            .unwrap_err(),
            CreationError::PayloadLimit
        );
        for metadata in [
            Value::Null,
            map(vec![(
                "titles",
                map(vec![("JA", text("a")), ("ja", text("b"))]),
            )]),
        ] {
            assert_eq!(
                create_revision(&key, initial.genesis(), &[], b"", metadata, None, budget)
                    .unwrap_err(),
                CreationError::InvalidInput
            );
        }
        assert_eq!(
            create_revision(
                &key,
                initial.genesis(),
                &[],
                b"",
                Value::Map(vec![]),
                Some(&"a".repeat(256)),
                budget
            )
            .unwrap_err(),
            CreationError::InvalidInput
        );
        let parents: Vec<_> = (0..256u32)
            .map(|n| revise(&key, initial.genesis(), &[], &n.to_be_bytes()))
            .collect();
        let refs: Vec<_> = parents.iter().collect();
        let merged = revise(&key, initial.genesis(), &refs, b"max parents");
        assert_eq!(merged.parents().unwrap().len(), 256);
    }

    #[test]
    fn independent_python_checks_revision_parent_bindings_and_payload() {
        let key = key();
        let initial = create_initial(
            &key,
            b"base",
            Value::Map(vec![]),
            None,
            CreationBudget::default(),
        )
        .unwrap();
        let a = revise(&key, initial.genesis(), &[initial.revision()], b"a");
        let b = revise(&key, initial.genesis(), &[initial.revision()], b"b");
        let payload = b"public revised payload\x00\xff\n";
        let merged = create_revision(
            &key,
            initial.genesis(),
            &[&b, &a],
            payload,
            map(vec![("titles", map(vec![("JA", text("e\u{301} é"))]))]),
            Some("application/octet-stream"),
            CreationBudget::default(),
        )
        .unwrap();
        let cases = vec![serde_json::json!({
            "seed": a13()["seed_hex"], "body": hex(&cbor::encode(merged.body()).unwrap()), "envelope": hex(merged.bytes()),
            "revision_creation": {"payload": hex(payload), "genesis": hex(initial.genesis().bytes()), "parents": [hex(b.bytes()), hex(a.bytes())]}
        })];
        let mut child = Command::new(
            std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
        )
        .arg("tests/reference.py")
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
            "independent revision check failed (details suppressed)"
        );
        let ids: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(ids, vec![merged.id().to_string()]);
    }
}
