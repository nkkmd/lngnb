//! A4.2 固定Recordの開示用世代における管理用照会。
use super::*;

#[derive(Debug, PartialEq, Eq)]
pub struct EvaluationReference {
    namespace: [u8; 32],
    knowledge: Id,
    genesis: Id,
    public: bool,
    generation: i64,
}

impl EvaluationReference {
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.strip_prefix("lngnb-eval:1:")?.split(':');
        let ns = parts.next()?.strip_prefix("ns1_")?;
        if ns.len() != 52 {
            return None;
        }
        let codec = data_encoding::BASE32_NOPAD;
        let namespace: [u8; 32] = codec
            .decode(ns.to_ascii_uppercase().as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        if codec.encode(&namespace).to_ascii_lowercase() != ns {
            return None;
        }
        let knowledge = Id::parse(Kind::Knowledge, parts.next()?).ok()?;
        let public = match parts.next()? {
            "public" => true,
            "untrusted" => false,
            _ => return None,
        };
        let genesis = Id::parse(Kind::Record, parts.next()?).ok()?;
        let number = parts.next()?;
        let generation: i64 = number.parse().ok()?;
        if generation < 1 || generation.to_string() != number || parts.next().is_some() {
            return None;
        }
        Some(Self {
            namespace,
            knowledge,
            genesis,
            public,
            generation,
        })
    }

    /// 指定Recordの最後の状態変化を指定世代まで遡る。取消し後は過去の可視行を返さない。
    pub fn lookup(&self, store: &RecordStore, record: Id) -> Result<Option<serde_json::Value>> {
        if record.kind != Kind::Record {
            return Ok(None);
        }
        let scope: &[u8] = if self.public {
            &[]
        } else {
            &self.genesis.bytes
        };
        store.conn.query_row(
            "SELECT generation,payload,reason,rules FROM (
             SELECT h.* FROM disclosure_generations g JOIN disclosure_history h ON h.namespace=g.namespace
             WHERE g.namespace=?1 AND g.knowledge_id=?2 AND g.scope_genesis=?3 AND g.generation>=?4
             AND h.record_id=?5 AND h.generation<=?4 ORDER BY h.generation DESC LIMIT 1
             ) WHERE visible=1 AND genesis=?6",
            params![self.namespace,self.knowledge.bytes,scope,self.generation,record.bytes,self.genesis.bytes],
            |r| Ok(serde_json::json!({
                "record_id":record.to_string(), "knowledge_id":self.knowledge.to_string(),
                "genesis_record_id":self.genesis.to_string(), "scope":if self.public {"public"} else {"untrusted"},
                "requested_generation":self.generation.to_string(), "last_change_generation":r.get::<_,i64>(0)?.to_string(),
                "record_validation":"valid","payload_status":r.get::<_,Option<String>>(1)?,
                "reasons":r.get::<_,Option<String>>(2)?.into_iter().collect::<Vec<_>>(),
                "rules_version":r.get::<_,String>(3)?
            })),
        ).optional().map_err(Into::into)
    }
}
