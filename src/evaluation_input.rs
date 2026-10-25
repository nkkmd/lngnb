//! R20/R24/R27/R28/R30: Recordの局所検査と依存情報収集をID cursorで分割する。
//! 署名済み一次bytesはrecordsに保持する。要約を外部Recordや署名証明として扱わない。
use super::*;
use crate::cbor::{self, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationInputBudget {
    pub records: u64,
    pub bytes: u64,
    pub edges: u64,
    pub elapsed: Duration,
}
impl Default for EvaluationInputBudget {
    fn default() -> Self {
        Self {
            records: 10_000,
            bytes: 64 * 1024 * 1024,
            edges: 100_000,
            elapsed: Duration::from_secs(60),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationInputProgress {
    pub collected_records: u64,
    pub collected_bytes: u64,
    pub collected_edges: u64,
    /// Record収集だけの完了。親評価・本文整合・公開許可とは別。
    pub complete: bool,
}
struct Entry {
    length: i64,
    raw: Vec<u8>,
    node: Node,
}
struct Cache {
    epoch: i64,
    cursor: Option<Key>,
    bytes: i64,
    edges: i64,
    complete: bool,
    digest: Key,
    rows: BTreeMap<Key, Entry>,
}
impl Cache {
    fn progress(&self) -> EvaluationInputProgress {
        EvaluationInputProgress {
            collected_records: self.rows.len() as u64,
            collected_bytes: self.bytes as u64,
            collected_edges: self.edges as u64,
            complete: self.complete,
        }
    }
    fn label(&self) -> String {
        format!(
            "epoch={}:records={}:bytes={}:edges={}:digest={}",
            self.epoch,
            self.rows.len(),
            self.bytes,
            self.edges,
            data_encoding::HEXLOWER.encode(&self.digest)
        )
    }
}
fn key(v: &Value) -> Result<Key> {
    let Value::Bytes(b) = v else {
        return Err(StorageError::Corrupt);
    };
    b.as_slice().try_into().map_err(|_| StorageError::Corrupt)
}
fn encode(node: &Node) -> Result<Vec<u8>> {
    let payload = node
        .payload
        .map(|(id, n)| Value::Array(vec![Value::Bytes(id.to_vec()), Value::Int(n as i64)]))
        .unwrap_or(Value::Null);
    cbor::encode(&Value::Array(vec![
        Value::Int(if node.identity.kind == RecordKind::Genesis {
            0
        } else {
            1
        }),
        Value::Bytes(node.identity.knowledge.to_vec()),
        Value::Bytes(node.identity.public.to_vec()),
        Value::Bytes(node.genesis.to_vec()),
        Value::Array(
            node.parents
                .iter()
                .map(|p| Value::Bytes(p.to_vec()))
                .collect(),
        ),
        payload,
    ]))
    .map_err(|_| StorageError::Corrupt)
}
fn decode(raw: &[u8], id: Key) -> Result<Node> {
    let v = cbor::decode(raw).map_err(|_| StorageError::Corrupt)?;
    let Value::Array(a) = v else {
        return Err(StorageError::Corrupt);
    };
    let [
        Value::Int(kind),
        knowledge,
        public,
        genesis,
        Value::Array(parents),
        payload,
    ] = a.as_slice()
    else {
        return Err(StorageError::Corrupt);
    };
    let kind = match kind {
        0 => RecordKind::Genesis,
        1 => RecordKind::Revision,
        _ => return Err(StorageError::Corrupt),
    };
    let knowledge = key(knowledge)?;
    let public = key(public)?;
    let genesis = key(genesis)?;
    if parents.len() > 256 {
        return Err(StorageError::Corrupt);
    }
    let parents = parents.iter().map(key).collect::<Result<Vec<_>>>()?;
    if parents.windows(2).any(|p| p[0] >= p[1]) {
        return Err(StorageError::Corrupt);
    }
    let payload = match payload {
        Value::Null => None,
        Value::Array(p) => {
            let [blob, Value::Int(n)] = p.as_slice() else {
                return Err(StorageError::Corrupt);
            };
            if *n < 0 {
                return Err(StorageError::Corrupt);
            }
            Some((key(blob)?, *n as u64))
        }
        _ => return Err(StorageError::Corrupt),
    };
    if (kind == RecordKind::Genesis && (genesis != id || !parents.is_empty() || payload.is_some()))
        || (kind == RecordKind::Revision && payload.is_none())
    {
        return Err(StorageError::Corrupt);
    }
    Ok(Node {
        identity: RecordIdentity {
            id: record_id(id),
            kind,
            knowledge,
            public,
        },
        genesis,
        parents,
        payload,
    })
}
fn digest(cache: &Cache) -> Key {
    let mut h = Sha256::new();
    h.update(b"lngnb:evaluation-record-input:1\0lngnb-validation-1\0");
    h.update(cache.epoch.to_be_bytes());
    h.update((cache.rows.len() as u64).to_be_bytes());
    h.update(cache.bytes.to_be_bytes());
    h.update(cache.edges.to_be_bytes());
    h.update([u8::from(cache.complete)]);
    h.update([u8::from(cache.cursor.is_some())]);
    if let Some(cursor) = cache.cursor {
        h.update(cursor);
    }
    for (id, row) in &cache.rows {
        h.update(id);
        h.update(row.length.to_be_bytes());
        h.update((row.raw.len() as u64).to_be_bytes());
        h.update(&row.raw);
    }
    h.finalize().into()
}
pub(super) fn epoch(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT record_epoch FROM evaluation_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?)
}
type Header = (i64, Option<Vec<u8>>, i64, i64, i64, i64, Vec<u8>, i64);
fn load(store: &RecordStore, budget: &Budget) -> Result<Option<Cache>> {
    budget.check()?;
    let started: i64 = store.conn.query_row(
        "SELECT input_started FROM evaluation_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let header:Option<Header>=store.conn.query_row("SELECT epoch,cursor,records,bytes,edges,complete,digest,checkpoint_generation FROM evaluation_input WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    let mut rows = BTreeMap::new();
    let mut bytes = 0i64;
    let mut edges = 0i64;
    let mut stmt=store.conn.prepare("SELECT n.record_id,n.source_length,length(n.summary),n.summary,length(r.bytes) FROM evaluation_nodes n LEFT JOIN records r ON r.id=n.record_id ORDER BY n.record_id")?;
    let mut query = stmt.query([])?;
    while let Some(r) = query.next()? {
        budget.check()?;
        if rows.len() as u64 >= budget.limits.records {
            return Err(StorageError::BudgetExceeded);
        }
        let id: Vec<u8> = r.get(0)?;
        let id: Key = id.try_into().map_err(|_| StorageError::Corrupt)?;
        let length: i64 = r.get(1)?;
        let n: i64 = r.get(2)?;
        let current: Option<i64> = r.get(4)?;
        if !(1..=MAX_RECORD as i64).contains(&length)
            || !(1..=16384).contains(&n)
            || current != Some(length)
        {
            return Err(StorageError::Corrupt);
        }
        let raw: Vec<u8> = r.get(3)?;
        let node = decode(&raw, id)?;
        bytes = bytes.checked_add(length).ok_or(StorageError::Corrupt)?;
        edges = edges
            .checked_add(node.parents.len() as i64)
            .ok_or(StorageError::Corrupt)?;
        if bytes as u64 > budget.limits.record_bytes || edges as u64 > budget.limits.edges {
            return Err(StorageError::BudgetExceeded);
        }
        rows.insert(id, Entry { length, raw, node });
    }
    let Some((saved_epoch, cursor, count, saved_bytes, saved_edges, complete, hash, generation)) =
        header
    else {
        if started != 0 || !rows.is_empty() {
            return Err(StorageError::Corrupt);
        }
        return Ok(None);
    };
    let cursor = cursor
        .map(|v| v.try_into().map_err(|_| StorageError::Corrupt))
        .transpose()?;
    let hash: Key = hash.try_into().map_err(|_| StorageError::Corrupt)?;
    let cache = Cache {
        epoch: saved_epoch,
        cursor,
        bytes,
        edges,
        complete: complete == 1,
        digest: hash,
        rows,
    };
    if started != 1
        || saved_epoch < 0
        || saved_epoch > epoch(&store.conn)?
        || count != cache.rows.len() as i64
        || saved_bytes != bytes
        || saved_edges != edges
        || ![0, 1].contains(&complete)
        || cache.cursor != cache.rows.last_key_value().map(|(id, _)| *id)
        || digest(&cache) != hash
    {
        return Err(StorageError::Corrupt);
    }
    let (old, new, reason, rules, namespace, target): (
        String,
        String,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = store.conn.query_row(
        "SELECT old_state,new_state,reason,rules,namespace,target FROM history WHERE generation=?1",
        [generation],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )?;
    let current_namespace: Vec<u8> = store.conn.query_row(
        "SELECT namespace FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if generation < 0
        || generation > store.generation()?
        || target.is_some()
        || namespace != current_namespace
        || rules != "lngnb-validation-1"
        || reason != format!("evaluation_input_checkpoint:{}", cache.label())
        || new
            != if cache.complete {
                "evaluation_input_complete"
            } else {
                "evaluation_input_pending"
            }
        || (old != "input_not_started" && !old.starts_with("epoch="))
    {
        return Err(StorageError::Corrupt);
    }
    // epoch変更前のcache自体も先に照合する。新入力で破損を隠さない。
    if saved_epoch == epoch(&store.conn)? {
        let mut stmt = store
            .conn
            .prepare("SELECT id,length(bytes) FROM records WHERE id<=?1 ORDER BY id")?;
        let mut query = stmt.query([cache.cursor])?;
        let mut count = 0usize;
        while let Some(r) = query.next()? {
            budget.check()?;
            if count >= cache.rows.len() {
                return Err(StorageError::Corrupt);
            }
            let id: Vec<u8> = r.get(0)?;
            let length: i64 = r.get(1)?;
            if cache
                .rows
                .get(id.as_slice())
                .is_none_or(|row| row.length != length)
            {
                return Err(StorageError::Corrupt);
            }
            count += 1;
        }
        if count != cache.rows.len() {
            return Err(StorageError::Corrupt);
        }
        let more: bool = store.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE ?1 IS NULL OR id>?1)",
            [cache.cursor],
            |r| r.get(0),
        )?;
        if cache.complete == more {
            return Err(StorageError::Corrupt);
        }
    }
    budget.check()?;
    Ok(Some(cache))
}
pub(super) fn ready(
    store: &RecordStore,
    budget: &Budget,
) -> Result<Option<(i64, BTreeMap<Key, Node>)>> {
    let Some(cache) = load(store, budget)? else {
        return Ok(None);
    };
    if !cache.complete || cache.epoch != epoch(&store.conn)? {
        return Err(StorageError::EvaluationInputPending);
    }
    Ok(Some((
        cache.epoch,
        cache
            .rows
            .into_iter()
            .map(|(id, row)| (id, row.node))
            .collect(),
    )))
}
impl EvaluationJob {
    /// 局所検査したRecordだけを依存情報へ変換して保存する。収集途中はstepへ進めない。
    pub fn prepare(
        &mut self,
        limits: EvaluationLimits,
        work: EvaluationInputBudget,
    ) -> Result<EvaluationInputProgress> {
        if self.writer.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.prepare_inner(limits, work);
        if result
            .as_ref()
            .is_err_and(|e| !matches!(e, StorageError::BudgetExceeded | StorageError::Capacity))
        {
            self.writer.failed = true;
        }
        result
    }
    fn prepare_inner(
        &mut self,
        limits: EvaluationLimits,
        work: EvaluationInputBudget,
    ) -> Result<EvaluationInputProgress> {
        if work.records == 0 || work.bytes == 0 {
            return Err(StorageError::BudgetExceeded);
        }
        let budget = Budget {
            start: Instant::now(),
            limits: EvaluationLimits {
                elapsed: limits.elapsed.min(work.elapsed),
                ..limits
            },
        };
        let saved = load(&self.writer.store, &budget)?;
        let current_epoch = epoch(&self.writer.store.conn)?;
        if saved
            .as_ref()
            .is_some_and(|c| c.epoch == current_epoch && c.complete)
        {
            return Ok(saved.unwrap().progress());
        }
        let old = saved
            .as_ref()
            .map(Cache::label)
            .unwrap_or_else(|| "input_not_started".into());
        let old_size = saved
            .as_ref()
            .map(|c| (c.rows.len() as u64, c.edges as u64))
            .unwrap_or_default();
        let fresh = saved.as_ref().is_none_or(|c| c.epoch != current_epoch);
        let mut cache = if fresh {
            Cache {
                epoch: current_epoch,
                cursor: None,
                bytes: 0,
                edges: 0,
                complete: false,
                digest: [0; 32],
                rows: BTreeMap::new(),
            }
        } else {
            saved.unwrap()
        };
        let previous = cache.cursor;
        let mut used_records = 0u64;
        let mut used_bytes = 0u64;
        let mut used_edges = 0u64;
        let mut stmt = self.writer.store.conn.prepare(
            "SELECT id,length(bytes) FROM records WHERE ?1 IS NULL OR id>?1 ORDER BY id",
        )?;
        let mut query = stmt.query([cache.cursor])?;
        while let Some(r) = query.next()? {
            budget.check()?;
            if used_records >= work.records {
                break;
            }
            let id: Vec<u8> = r.get(0)?;
            let id: Key = id.try_into().map_err(|_| StorageError::Corrupt)?;
            let length: i64 = r.get(1)?;
            if !(1..=MAX_RECORD as i64).contains(&length) {
                return Err(StorageError::Corrupt);
            }
            if cache.rows.len() as u64 >= limits.records
                || (cache.bytes as u64)
                    .checked_add(length as u64)
                    .is_none_or(|n| n > limits.record_bytes)
            {
                return Err(StorageError::BudgetExceeded);
            }
            if used_bytes
                .checked_add(length as u64)
                .is_none_or(|n| n > work.bytes)
            {
                if cache.cursor == previous {
                    return Err(StorageError::BudgetExceeded);
                }
                break;
            }
            used_records += 1;
            used_bytes += length as u64;
            let record = self
                .writer
                .store
                .record(record_id(id))?
                .ok_or(StorageError::Corrupt)?;
            let node = Node::from_record(&record)?;
            let edges = node.parents.len() as u64;
            if (cache.edges as u64)
                .checked_add(edges)
                .is_none_or(|n| n > limits.edges)
            {
                return Err(StorageError::BudgetExceeded);
            }
            if used_edges.checked_add(edges).is_none_or(|n| n > work.edges) {
                if cache.cursor == previous {
                    return Err(StorageError::BudgetExceeded);
                }
                break;
            }
            used_edges += edges;
            cache.bytes += length;
            cache.edges += edges as i64;
            cache.cursor = Some(id);
            let raw = encode(&node)?;
            cache.rows.insert(id, Entry { length, raw, node });
        }
        drop(query);
        drop(stmt);
        cache.complete = !self.writer.store.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE ?1 IS NULL OR id>?1)",
            [cache.cursor],
            |r| r.get::<_, bool>(0),
        )?;
        cache.digest = digest(&cache);
        budget.check()?;
        let reserve = (old_size.0 + cache.rows.len() as u64)
            .checked_mul(4096)
            .and_then(|n| {
                (old_size.1 + cache.edges as u64)
                    .checked_mul(256)
                    .and_then(|e| n.checked_add(e))
            })
            .and_then(|n| n.checked_add(65536))
            .ok_or(StorageError::Capacity)?;
        let capacity = self.writer.store.capacity()?;
        if capacity.available <= capacity.reserved_floor.saturating_add(reserve) {
            return Err(StorageError::Capacity);
        }
        #[cfg(test)]
        if self.pause_at == Some("input_scanned") {
            queue::test_pause("input_scanned");
        }
        let tx = self.writer.store.conn.transaction()?;
        if epoch(&tx)? != current_epoch {
            return Err(StorageError::Corrupt);
        }
        tx.execute(
            "UPDATE evaluation_state SET dirty=1,input_started=1 WHERE singleton=1",
            [],
        )?;
        if fresh {
            tx.execute("DELETE FROM evaluation_nodes", [])?;
        }
        for (id, row) in &cache.rows {
            budget.check()?;
            if fresh || previous.is_none_or(|p| *id > p) {
                tx.execute(
                    "INSERT INTO evaluation_nodes VALUES(?1,?2,?3)",
                    params![id, row.length, row.raw],
                )?;
            }
        }
        advance(&tx)?;
        tx.execute("INSERT INTO evaluation_input SELECT 1,?1,?2,?3,?4,?5,?6,?7,generation FROM storage_state WHERE singleton=1 ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,cursor=excluded.cursor,records=excluded.records,bytes=excluded.bytes,edges=excluded.edges,complete=excluded.complete,digest=excluded.digest,checkpoint_generation=excluded.checkpoint_generation",params![cache.epoch,cache.cursor,cache.rows.len() as i64,cache.bytes,cache.edges,i64::from(cache.complete),cache.digest])?;
        audit(
            &tx,
            None,
            &old,
            if cache.complete {
                "evaluation_input_complete"
            } else {
                "evaluation_input_pending"
            },
            &format!("evaluation_input_checkpoint:{}", cache.label()),
        )?;
        #[cfg(test)]
        if self.pause_at == Some("input_before") {
            queue::test_pause("input_before");
        }
        if epoch(&tx)? != current_epoch {
            return Err(StorageError::Corrupt);
        }
        budget.check()?;
        tx.commit()?;
        #[cfg(test)]
        if self.pause_at == Some("input_after") {
            queue::test_pause("input_after");
        }
        Ok(cache.progress())
    }
}

#[cfg(test)]
#[path = "evaluation_input_tests.rs"]
mod tests;
