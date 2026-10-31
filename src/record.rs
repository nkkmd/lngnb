//! A2/A3/A15.1: 局所検査とGenesisの発行鍵照合。
//! この型はrecord_validation=valid、pin、公開許可、親検査完了を表さない。
use crate::{
    Error, Result,
    cbor::{self, Value},
    id::{self, Id},
};
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const PROFILE: &str = "lngnb-library-core-1";
const DOMAIN: &[u8] = b"lngnb:signature:library-core-1\0";

fn invalid<T>() -> Result<T> {
    Err(Error::InvalidFormat)
}
fn map(v: &Value) -> Result<&[(String, Value)]> {
    if let Value::Map(m) = v {
        Ok(m)
    } else {
        invalid()
    }
}
fn text(v: &Value) -> Result<&str> {
    if let Value::Text(s) = v {
        Ok(s)
    } else {
        invalid()
    }
}
fn array(v: &Value) -> Result<&[Value]> {
    if let Value::Array(a) = v {
        Ok(a)
    } else {
        invalid()
    }
}
fn bytes<const N: usize>(v: &Value) -> Result<[u8; N]> {
    if let Value::Bytes(b) = v {
        b.as_slice().try_into().map_err(|_| Error::InvalidFormat)
    } else {
        invalid()
    }
}
fn u63(v: &Value) -> Result<u64> {
    if let Value::Int(n) = v {
        u64::try_from(*n).map_err(|_| Error::InvalidFormat)
    } else {
        invalid()
    }
}
fn get<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    opt(v, key)?.ok_or(Error::InvalidFormat)
}
fn opt<'a>(v: &'a Value, key: &str) -> Result<Option<&'a Value>> {
    Ok(map(v)?.iter().find(|(k, _)| k == key).map(|(_, v)| v))
}
fn fields(v: &Value, required: &[&str], optional: &[&str]) -> Result<()> {
    let m = map(v)?;
    if m.iter()
        .any(|(k, _)| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
        || required
            .iter()
            .any(|k| !m.iter().any(|(name, _)| name == k))
    {
        return invalid();
    }
    Ok(())
}
fn namespace(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn language(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.split('-').all(|p| {
            (1..=8).contains(&p.len())
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}
fn media(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let token = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
    };
    s.len() <= 255 && s.split_once('/').is_some_and(|(a, b)| token(a) && token(b))
}
fn reference(v: &Value) -> Result<()> {
    fields(
        v,
        &["knowledge_id"],
        &["genesis_record_id", "revision_record_id"],
    )?;
    bytes::<32>(get(v, "knowledge_id")?)?;
    for name in ["genesis_record_id", "revision_record_id"] {
        if let Some(b) = opt(v, name)? {
            bytes::<32>(b)?;
        }
    }
    if opt(v, "revision_record_id")?.is_some() && opt(v, "genesis_record_id")?.is_none() {
        return invalid();
    }
    Ok(())
}
fn free(v: &Value) -> Result<()> {
    match v {
        Value::Map(m) => {
            for (key, v) in m {
                if !(1..=256).contains(&key.len()) {
                    return invalid();
                }
                free(v)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                free(v)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn metadata(v: &Value) -> Result<()> {
    fields(
        v,
        &["information_type", "resource_type"],
        &[
            "titles",
            "summaries",
            "tags",
            "languages",
            "schema",
            "extensions",
        ],
    )?;
    if cbor::encode(v)?.len() > 262144 {
        return invalid();
    }
    let it = get(v, "information_type")?;
    fields(it, &["namespace", "code"], &[])?;
    if !namespace(text(get(it, "namespace")?)?) {
        return invalid();
    }
    u63(get(it, "code")?)?;
    if !text(get(v, "resource_type")?)?
        .split_once(':')
        .is_some_and(|(a, b)| namespace(a) && namespace(b))
    {
        return invalid();
    }
    for (name, max) in [("titles", 4096), ("summaries", 65536)] {
        if let Some(labels) = opt(v, name)? {
            let labels = map(labels)?;
            if labels.len() > 64 {
                return invalid();
            }
            for (label, value) in labels {
                if !language(label) || text(value)?.len() > max {
                    return invalid();
                }
            }
        }
    }
    for (name, limit, size) in [("tags", 128, 256), ("languages", 64, 64)] {
        if let Some(values) = opt(v, name)? {
            let values = array(values)?;
            if values.len() > limit {
                return invalid();
            }
            let mut previous: Option<&str> = None;
            for value in values {
                let s = text(value)?;
                if s.is_empty()
                    || s.len() > size
                    || previous.is_some_and(|p| p >= s)
                    || (name == "languages" && !language(s))
                {
                    return invalid();
                }
                previous = Some(s);
            }
        }
    }
    if let Some(schema) = opt(v, "schema")? {
        fields(schema, &[], &["name", "version", "reference"])?;
        if map(schema)?.is_empty() {
            return invalid();
        }
        for name in ["name", "version"] {
            if let Some(s) = opt(schema, name)? {
                if !(1..=256).contains(&text(s)?.len()) {
                    return invalid();
                }
            }
        }
        if let Some(r) = opt(schema, "reference")? {
            reference(r)?;
        }
    }
    if let Some(ext) = opt(v, "extensions")? {
        map(ext)?;
        free(ext)?;
    }
    Ok(())
}
fn schema(body: &Value, kind: RecordKind) -> Result<()> {
    let common = ["profile_id", "record_kind", "knowledge_id"];
    let mut required = common.to_vec();
    match kind {
        RecordKind::Genesis => {
            required.push("publisher_public_key");
            fields(body, &required, &[])?;
            bytes::<32>(get(body, "publisher_public_key")?)?;
        }
        RecordKind::Revision => {
            required.extend(["genesis_record_id", "parents", "payload", "metadata"]);
            fields(body, &required, &["origins"])?;
            bytes::<32>(get(body, "genesis_record_id")?)?;
            let parents = array(get(body, "parents")?)?;
            if parents.len() > 256 {
                return invalid();
            }
            let mut previous = None;
            for p in parents {
                let id = bytes::<32>(p)?;
                if previous.is_some_and(|p| p >= id) {
                    return invalid();
                }
                previous = Some(id);
            }
            let payload = get(body, "payload")?;
            fields(payload, &["blob_id", "byte_length", "media_type"], &[])?;
            bytes::<32>(get(payload, "blob_id")?)?;
            u63(get(payload, "byte_length")?)?;
            if !media(text(get(payload, "media_type")?)?) {
                return invalid();
            }
            metadata(get(body, "metadata")?)?;
            if let Some(origins) = opt(body, "origins")? {
                let origins = array(origins)?;
                if origins.len() > 128 {
                    return invalid();
                }
                let mut previous = None;
                for origin in origins {
                    reference(origin)?;
                    let encoded = cbor::encode(origin)?;
                    if previous.as_ref().is_some_and(|p| p >= &encoded) {
                        return invalid();
                    }
                    previous = Some(encoded);
                }
            }
        }
    }
    bytes::<32>(get(body, "knowledge_id")?)?;
    Ok(())
}

/// A3.1の追加条件を、verify_strictという名前だけに委ねない。
pub fn verify_signature(public: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Result<()> {
    for encoded in [
        public,
        signature[..32]
            .try_into()
            .map_err(|_| Error::InvalidSignature)?,
    ] {
        let point = CompressedEdwardsY(*encoded)
            .decompress()
            .ok_or(Error::InvalidSignature)?;
        if point.compress().as_bytes() != encoded || point.is_identity() || !point.is_torsion_free()
        {
            return Err(Error::InvalidSignature);
        }
    }
    // dalekはS<Lと、cofactorを掛けない検証式・Rの一致を検査する。
    VerifyingKey::from_bytes(public)
        .map_err(|_| Error::InvalidSignature)?
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::InvalidSignature)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Genesis,
    Revision,
}
/// 署名に含まれる由来参照。省略IDを補完せず、参照先の保持・承認を表さない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginReference {
    pub knowledge_id: Id,
    pub genesis_record_id: Option<Id>,
    pub revision_record_id: Option<Id>,
}
/// 局所検査済みRevisionの宣言値。Genesis/親/由来の外部照合・評価結果ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionReferences {
    pub knowledge_id: Id,
    pub genesis_record_id: Id,
    pub publisher_key_id: Id,
    pub parents: Vec<Id>,
    /// 未指定と明示した空集合を区別し、符号化済みの集合順を保つ。
    pub origins: Option<Vec<OriginReference>>,
}
#[derive(Debug, Clone)]
pub struct LocalRecord {
    bytes: Vec<u8>,
    body: Value,
    id: Id,
    kind: RecordKind,
    public: [u8; 32],
    knowledge: [u8; 32],
}
/// 局所検査済みRecordから抽出する依存照合用の識別情報。単独で署名証明にしない。
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordIdentity {
    pub(crate) id: Id,
    pub(crate) kind: RecordKind,
    pub(crate) public: [u8; 32],
    pub(crate) knowledge: [u8; 32],
}
impl RecordIdentity {
    pub(crate) fn check_genesis(&self, expected: [u8; 32], genesis: &Self) -> Result<()> {
        if self.kind != RecordKind::Revision
            || genesis.kind != RecordKind::Genesis
            || self.knowledge != genesis.knowledge
            || expected != genesis.id.bytes
        {
            return Err(Error::GenesisMismatch);
        }
        if self.public != genesis.public {
            return Err(Error::WrongPublisher);
        }
        Ok(())
    }
}
impl LocalRecord {
    /// 形式→対応版/種別→スキーマ→期待ID→署名→Genesis自己鍵の順に検査。
    /// RevisionのGenesis/親が未照合でも返る。validと解釈しないこと。
    pub fn check(input: &[u8], expected: Option<Id>) -> Result<Self> {
        let envelope = cbor::decode(input)?;
        let body = get(&envelope, "body")?;
        let profile = text(get(body, "profile_id")?)?;
        let kind_name = text(get(body, "record_kind")?)?;
        if profile != PROFILE {
            return Err(Error::UnsupportedProfile);
        }
        let kind = match kind_name {
            "genesis" => RecordKind::Genesis,
            "revision" => RecordKind::Revision,
            _ => return Err(Error::UnsupportedKind),
        };
        fields(&envelope, &["body", "signature"], &[])?;
        schema(body, kind)?;
        let sig = get(&envelope, "signature")?;
        fields(
            sig,
            &["key_id", "algorithm", "public_key_bytes", "signature_bytes"],
            &[],
        )?;
        if text(get(sig, "algorithm")?)? != "ed25519" {
            return invalid();
        }
        let public = bytes::<32>(get(sig, "public_key_bytes")?)?;
        let signature = bytes::<64>(get(sig, "signature_bytes")?)?;
        let key_id = bytes::<32>(get(sig, "key_id")?)?;
        let id = id::record_id(input);
        if expected.is_some_and(|e| e != id) {
            return Err(Error::IdMismatch);
        }
        if id::key_id(&public).bytes != key_id {
            return Err(Error::InvalidSignature);
        }
        let mut message = DOMAIN.to_vec();
        message.extend(cbor::encode(body)?);
        verify_signature(&public, &signature, &message)?;
        if kind == RecordKind::Genesis && bytes::<32>(get(body, "publisher_public_key")?)? != public
        {
            return Err(Error::WrongPublisher);
        }
        let knowledge = bytes::<32>(get(body, "knowledge_id")?)?;
        Ok(Self {
            bytes: input.to_vec(),
            body: body.clone(),
            id,
            kind,
            public,
            knowledge,
        })
    }
    /// 署名済み生成結果も受信側の厳格受理条件で確認する。鍵生成/保管は工程⑤。
    pub fn sign(body: Value, key: &SigningKey) -> Result<Self> {
        let public = key.verifying_key().to_bytes();
        let mut message = DOMAIN.to_vec();
        message.extend(cbor::encode(&body)?);
        let signature = key.sign(&message).to_bytes();
        let signature = Value::Map(vec![
            (
                "key_id".into(),
                Value::Bytes(id::key_id(&public).bytes.to_vec()),
            ),
            ("algorithm".into(), Value::Text("ed25519".into())),
            ("public_key_bytes".into(), Value::Bytes(public.to_vec())),
            ("signature_bytes".into(), Value::Bytes(signature.to_vec())),
        ]);
        let envelope = Value::Map(vec![("body".into(), body), ("signature".into(), signature)]);
        Self::check(&cbor::encode(&envelope)?, None)
    }
    pub fn check_genesis(&self, genesis: &Self) -> Result<()> {
        self.identity()
            .check_genesis(self.genesis()?, &genesis.identity())
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn body(&self) -> &Value {
        &self.body
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn kind(&self) -> RecordKind {
        self.kind
    }
    /// 元bytesを変えず、署名された直接参照だけを読み取る。Genesisでは失敗する。
    /// 祖先探索・不足IDの推測・参照取得・現在版選択・pin/公開判定は行わない。
    pub fn revision_references(&self) -> Result<RevisionReferences> {
        if self.kind != RecordKind::Revision {
            return invalid();
        }
        let record_id = |bytes| Id { kind: id::Kind::Record, bytes };
        let origins = opt(&self.body, "origins")?.map(|origins| {
            array(origins)?.iter().map(|origin| {
                Ok(OriginReference {
                    knowledge_id: Id { kind: id::Kind::Knowledge, bytes: bytes(get(origin, "knowledge_id")?)? },
                    genesis_record_id: opt(origin, "genesis_record_id")?.map(bytes).transpose()?.map(record_id),
                    revision_record_id: opt(origin, "revision_record_id")?.map(bytes).transpose()?.map(record_id),
                })
            }).collect::<Result<Vec<_>>>()
        }).transpose()?;
        Ok(RevisionReferences {
            knowledge_id: Id { kind: id::Kind::Knowledge, bytes: self.knowledge },
            genesis_record_id: record_id(self.genesis()?),
            publisher_key_id: id::key_id(&self.public),
            parents: self.parents()?.into_iter().map(record_id).collect(),
            origins,
        })
    }
    pub(crate) fn identity(&self) -> RecordIdentity {
        RecordIdentity {
            id: self.id,
            kind: self.kind,
            public: self.public,
            knowledge: self.knowledge,
        }
    }
    pub(crate) fn genesis(&self) -> Result<[u8; 32]> {
        match self.kind {
            RecordKind::Genesis => Ok(self.id.bytes),
            RecordKind::Revision => bytes(get(&self.body, "genesis_record_id")?),
        }
    }
    pub(crate) fn parents(&self) -> Result<Vec<[u8; 32]>> {
        if self.kind == RecordKind::Genesis {
            return Ok(Vec::new());
        }
        array(get(&self.body, "parents")?)?
            .iter()
            .map(bytes)
            .collect()
    }
    pub(crate) fn payload(&self) -> Result<Option<([u8; 32], u64)>> {
        if self.kind == RecordKind::Genesis {
            return Ok(None);
        }
        let payload = get(&self.body, "payload")?;
        Ok(Some((
            bytes(get(payload, "blob_id")?)?,
            u63(get(payload, "byte_length")?)?,
        )))
    }
}
