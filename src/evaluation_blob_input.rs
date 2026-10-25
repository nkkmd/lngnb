//! R08/R20/R24/R26/R27/R30: 親評価用Blobの全体hashをファイル単位で分割・再開する。
//! 保存した自己検査来歴と現在のメタデータを照合する。本文の取得資格は与えない。
use super::*;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationBlobBudget {
    /// 未保持/失敗観測だけのIDも一対象として数える。
    pub targets: u64,
    pub bytes: u64,
    pub elapsed: Duration,
}
impl Default for EvaluationBlobBudget {
    fn default() -> Self {
        Self {
            targets: 10_000,
            bytes: 64 * 1024 * 1024,
            elapsed: Duration::from_secs(60),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationBlobProgress {
    pub checked_targets: u64,
    pub total_targets: u64,
    pub hashed_bytes: u64,
    /// 対象一覧の検査終了。本文が全て存在することや親評価完了とは別。
    pub checks_complete: bool,
    /// この対象集合の保持本文に欠損/破損を検出。falseだけで検査完了とはしない。
    pub storage_fault: bool,
}
#[derive(Clone, PartialEq, Eq)]
struct Descriptor {
    length: Option<i64>,
    size: Option<i64>,
    stamp: Option<String>,
    failure: Option<PayloadReason>,
}
#[derive(Clone)]
struct Row {
    source: Descriptor,
    fact: Option<BlobFact>,
    examined: i64,
}
struct Cache {
    record_epoch: i64,
    payload_epoch: i64,
    directory: String,
    digest: Key,
    rows: BTreeMap<Key, Row>,
}
pub(super) struct Evidence {
    dir: OwnedFd,
    directory: String,
    files: BTreeMap<Key, Option<String>>,
    payload_epoch: i64,
}
pub(super) type Inputs = (BTreeMap<Key, BlobFact>, Evidence);
fn payload_epoch(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT payload_epoch FROM evaluation_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?)
}
fn failure(s: Option<String>) -> Result<Option<PayloadReason>> {
    match s.as_deref() {
        None => Ok(None),
        Some("transfer_hash_mismatch") => Ok(Some(PayloadReason::TransferHashMismatch)),
        Some("transfer_failed") => Ok(Some(PayloadReason::TransferFailed)),
        _ => Err(StorageError::Corrupt),
    }
}
fn observe(conn: &Connection, dir: &OwnedFd, id: Key) -> Result<Descriptor> {
    let length: Option<i64> = conn
        .query_row("SELECT byte_length FROM blobs WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(n) = length {
        if n < 0 {
            return Err(StorageError::Corrupt);
        }
        let (stamp, size) = match blobs::checked_file(dir, &blobs::hex(&id)) {
            Ok(file) => {
                let m = file.metadata()?;
                (
                    Some(fingerprint(&m)),
                    Some(i64::try_from(m.len()).map_err(|_| StorageError::Corrupt)?),
                )
            }
            Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(e) => return Err(e),
        };
        Ok(Descriptor {
            length,
            stamp,
            size,
            failure: None,
        })
    } else {
        let observed: Option<String> = conn
            .query_row("SELECT reason FROM blob_failures WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(Descriptor {
            length: None,
            size: None,
            stamp: None,
            failure: failure(observed)?,
        })
    }
}
impl Descriptor {
    fn hash_bytes(&self) -> u64 {
        if self.length.is_some() && self.size == self.length {
            self.length.unwrap() as u64
        } else {
            0
        }
    }
    fn inspect(&self, dir: &OwnedFd, id: Key) -> Result<(BlobFact, i64)> {
        let fact = match self.length {
            None => self
                .failure
                .map(BlobFact::TransferFailed)
                .unwrap_or(BlobFact::Missing),
            Some(n) if self.size != Some(n) => BlobFact::Unavailable,
            Some(n) => {
                #[cfg(test)]
                HASHES.with(|v| v.set(v.get() + 1));
                match blobs::verify_file(dir, blob_id(id), Some(n as u64), n as u64) {
                    Ok(_) => BlobFact::Verified(n as u64),
                    Err(StorageError::Corrupt) => BlobFact::Unavailable,
                    Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        BlobFact::Unavailable
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        if self.length.is_some() && blob_stamp(dir, id)? != self.stamp {
            return Err(StorageError::Corrupt);
        }
        Ok((fact, self.hash_bytes() as i64))
    }
}
impl Cache {
    fn progress(&self) -> EvaluationBlobProgress {
        EvaluationBlobProgress {
            checked_targets: self.rows.values().filter(|r| r.fact.is_some()).count() as u64,
            total_targets: self.rows.len() as u64,
            hashed_bytes: self.rows.values().map(|r| r.examined as u64).sum(),
            checks_complete: self.rows.values().all(|r| r.fact.is_some()),
            storage_fault: self.rows.values().any(|r| {
                r.fact == Some(BlobFact::Unavailable)
                    || (r.source.length.is_some() && r.source.size != r.source.length)
            }),
        }
    }
    fn label(&self) -> String {
        let p = self.progress();
        format!(
            "records={}:payloads={}:checked={}:total={}:bytes={}:digest={}",
            self.record_epoch,
            self.payload_epoch,
            p.checked_targets,
            p.total_targets,
            p.hashed_bytes,
            data_encoding::HEXLOWER.encode(&self.digest)
        )
    }
    fn inputs(&self, dir: OwnedFd) -> Result<Inputs> {
        let mut facts = BTreeMap::new();
        let mut files = BTreeMap::new();
        for (id, row) in &self.rows {
            facts.insert(*id, row.fact.ok_or(StorageError::EvaluationInputPending)?);
            if row.source.length.is_some() {
                files.insert(*id, row.source.stamp.clone());
            }
        }
        Ok((
            facts,
            Evidence {
                dir,
                directory: self.directory.clone(),
                files,
                payload_epoch: self.payload_epoch,
            },
        ))
    }
}
impl Evidence {
    pub(super) fn validate(
        &self,
        root: &OwnedFd,
        conn: &Connection,
        budget: &Budget,
    ) -> Result<()> {
        if payload_epoch(conn)? != self.payload_epoch {
            return Err(StorageError::Corrupt);
        }
        let current = blobs::blob_directory(root, "blobs")?;
        if fingerprint(&std::fs::metadata(anchored(&current, "."))?) != self.directory {
            return Err(StorageError::Corrupt);
        }
        for (id, stamp) in &self.files {
            budget.check()?;
            if blob_stamp(&self.dir, *id)? != *stamp {
                return Err(StorageError::Corrupt);
            }
        }
        budget.check()
    }
}
fn inventory(
    store: &RecordStore,
    nodes: &BTreeMap<Key, Node>,
    budget: &Budget,
    record_epoch: i64,
) -> Result<(Cache, OwnedFd)> {
    let payload_epoch = payload_epoch(&store.conn)?;
    let dir = blobs::blob_directory(&store.dir, "blobs")?;
    let directory = fingerprint(&std::fs::metadata(anchored(&dir, "."))?);
    let targets: BTreeSet<_> = nodes
        .values()
        .filter_map(|n| n.payload.map(|(id, _)| id))
        .collect();
    if targets.len() as u64 > budget.limits.records {
        return Err(StorageError::BudgetExceeded);
    }
    let mut total = 0u64;
    let mut rows = BTreeMap::new();
    for id in targets {
        budget.check()?;
        let source = observe(&store.conn, &dir, id)?;
        total = total
            .checked_add(source.length.unwrap_or(0) as u64)
            .ok_or(StorageError::BudgetExceeded)?;
        if total > budget.limits.blob_bytes {
            return Err(StorageError::BudgetExceeded);
        }
        rows.insert(
            id,
            Row {
                source,
                fact: None,
                examined: 0,
            },
        );
    }
    let cache = Cache {
        record_epoch,
        payload_epoch,
        directory,
        digest: [0; 32],
        rows,
    };
    validate(&cache, &dir, &store.dir, &store.conn, budget)?;
    Ok((cache, dir))
}
fn validate(
    cache: &Cache,
    dir: &OwnedFd,
    root: &OwnedFd,
    conn: &Connection,
    budget: &Budget,
) -> Result<()> {
    if preparation::epoch(conn)? != cache.record_epoch
        || payload_epoch(conn)? != cache.payload_epoch
    {
        return Err(StorageError::Corrupt);
    }
    let current = blobs::blob_directory(root, "blobs")?;
    if fingerprint(&std::fs::metadata(anchored(&current, "."))?) != cache.directory {
        return Err(StorageError::Corrupt);
    }
    for (id, row) in &cache.rows {
        budget.check()?;
        if observe(conn, dir, *id)? != row.source {
            return Err(StorageError::Corrupt);
        }
    }
    budget.check()
}
pub(super) fn fresh(
    store: &RecordStore,
    nodes: &BTreeMap<Key, Node>,
    budget: &Budget,
    record_epoch: i64,
) -> Result<Inputs> {
    let (mut cache, dir) = inventory(store, nodes, budget, record_epoch)?;
    for (id, row) in &mut cache.rows {
        budget.check()?;
        let (fact, n) = row.source.inspect(&dir, *id)?;
        row.fact = Some(fact);
        row.examined = n;
    }
    validate(&cache, &dir, &store.dir, &store.conn, budget)?;
    cache.inputs(dir)
}
fn state(fact: Option<BlobFact>) -> &'static str {
    match fact {
        None => "pending",
        Some(BlobFact::Verified(_)) => "verified",
        Some(BlobFact::Missing) => "missing",
        Some(BlobFact::TransferFailed(_)) => "failed",
        Some(BlobFact::Unavailable) => "unavailable",
    }
}
fn digest(cache: &Cache) -> Key {
    let mut h = Sha256::new();
    h.update(b"lngnb:evaluation-blob-input:1\0lngnb-validation-1\0");
    h.update(cache.record_epoch.to_be_bytes());
    h.update(cache.payload_epoch.to_be_bytes());
    h.update((cache.rows.len() as u64).to_be_bytes());
    h.update((cache.directory.len() as u64).to_be_bytes());
    h.update(cache.directory.as_bytes());
    for (id, row) in &cache.rows {
        h.update(id);
        h.update(row.source.length.unwrap_or(-1).to_be_bytes());
        h.update(row.source.size.unwrap_or(-1).to_be_bytes());
        for text in [
            row.source.stamp.as_deref().unwrap_or(""),
            row.source.failure.map(PayloadReason::code).unwrap_or(""),
            state(row.fact),
        ] {
            h.update((text.len() as u64).to_be_bytes());
            h.update(text.as_bytes());
        }
        h.update(row.examined.to_be_bytes());
    }
    h.finalize().into()
}
type Header = (i64, i64, String, Vec<u8>, i64, i64, i64);
fn load(store: &RecordStore, budget: &Budget) -> Result<Option<Cache>> {
    budget.check()?;
    let started: i64 = store.conn.query_row(
        "SELECT blob_input_started FROM evaluation_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let header:Option<Header>=store.conn.query_row("SELECT record_epoch,payload_epoch,directory,digest,total,complete,checkpoint_generation FROM evaluation_blob_input WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
    let mut rows = BTreeMap::new();
    let mut total = 0u64;
    let mut stmt=store.conn.prepare("SELECT blob_id,byte_length,size,fingerprint,transfer,state,examined_bytes FROM evaluation_blob_facts ORDER BY blob_id")?;
    let mut query = stmt.query([])?;
    while let Some(r) = query.next()? {
        budget.check()?;
        if rows.len() as u64 >= budget.limits.records {
            return Err(StorageError::BudgetExceeded);
        }
        let id: Vec<u8> = r.get(0)?;
        let id: Key = id.try_into().map_err(|_| StorageError::Corrupt)?;
        let source = Descriptor {
            length: r.get(1)?,
            size: r.get(2)?,
            stamp: r.get(3)?,
            failure: failure(r.get(4)?)?,
        };
        let text: String = r.get(5)?;
        let examined: i64 = r.get(6)?;
        if source.length.is_some_and(|n| n < 0)
            || source.size.is_some_and(|n| n < 0)
            || source.size.is_some() != source.stamp.is_some()
            || source
                .stamp
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 512)
            || source.length.is_none() && source.size.is_some()
            || source.length.is_some() && source.failure.is_some()
            || examined < 0
        {
            return Err(StorageError::Corrupt);
        }
        let fact = match text.as_str() {
            "pending" => None,
            "verified" => Some(BlobFact::Verified(
                source.length.ok_or(StorageError::Corrupt)? as u64,
            )),
            "missing" => Some(BlobFact::Missing),
            "failed" => Some(BlobFact::TransferFailed(
                source.failure.ok_or(StorageError::Corrupt)?,
            )),
            "unavailable" => Some(BlobFact::Unavailable),
            _ => return Err(StorageError::Corrupt),
        };
        if match fact {
            None => examined != 0,
            Some(BlobFact::Verified(_)) => {
                source.length.is_none()
                    || source.size != source.length
                    || examined != source.length.unwrap()
            }
            Some(BlobFact::Missing) => {
                source.length.is_some() || source.failure.is_some() || examined != 0
            }
            Some(BlobFact::TransferFailed(_)) => source.length.is_some() || examined != 0,
            Some(BlobFact::Unavailable) => {
                source.length.is_none() || examined != source.hash_bytes() as i64
            }
        } {
            return Err(StorageError::Corrupt);
        }
        total = total
            .checked_add(source.length.unwrap_or(0) as u64)
            .ok_or(StorageError::BudgetExceeded)?;
        if total > budget.limits.blob_bytes {
            return Err(StorageError::BudgetExceeded);
        }
        rows.insert(
            id,
            Row {
                source,
                fact,
                examined,
            },
        );
    }
    let Some((record_epoch, epoch, directory, hash, n, complete, generation)) = header else {
        if started != 0 || !rows.is_empty() {
            return Err(StorageError::Corrupt);
        }
        return Ok(None);
    };
    let hash: Key = hash.try_into().map_err(|_| StorageError::Corrupt)?;
    let cache = Cache {
        record_epoch,
        payload_epoch: epoch,
        directory,
        digest: hash,
        rows,
    };
    if started != 1
        || record_epoch < 0
        || epoch < 0
        || record_epoch > preparation::epoch(&store.conn)?
        || epoch > payload_epoch(&store.conn)?
        || n != cache.rows.len() as i64
        || ![0, 1].contains(&complete)
        || (complete == 1) != cache.progress().checks_complete
        || cache.directory.is_empty()
        || cache.directory.len() > 512
        || digest(&cache) != hash
    {
        return Err(StorageError::Corrupt);
    }
    let (target, old, new, reason, rules, namespace): (
        Option<Vec<u8>>,
        String,
        String,
        String,
        String,
        Vec<u8>,
    ) = store.conn.query_row(
        "SELECT target,old_state,new_state,reason,rules,namespace FROM history WHERE generation=?1",
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
    let current: Vec<u8> = store.conn.query_row(
        "SELECT namespace FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if generation < 0
        || generation > store.generation()?
        || target.is_some()
        || current != namespace
        || rules != "lngnb-validation-1"
        || reason != format!("evaluation_blob_checkpoint:{}", cache.label())
        || new
            != if complete == 1 {
                "evaluation_blob_complete"
            } else {
                "evaluation_blob_pending"
            }
        || (old != "blobs_not_started" && !old.starts_with("records="))
    {
        return Err(StorageError::Corrupt);
    }
    Ok(Some(cache))
}
fn same_sources(a: &Cache, b: &Cache) -> bool {
    a.record_epoch == b.record_epoch
        && a.payload_epoch == b.payload_epoch
        && a.directory == b.directory
        && a.rows.len() == b.rows.len()
        && a.rows
            .iter()
            .all(|(id, r)| b.rows.get(id).is_some_and(|s| s.source == r.source))
}
pub(super) fn ready(
    store: &RecordStore,
    nodes: &BTreeMap<Key, Node>,
    budget: &Budget,
    record_epoch: i64,
) -> Result<Option<Inputs>> {
    let Some(cache) = load(store, budget)? else {
        return Ok(None);
    };
    let (current, dir) = inventory(store, nodes, budget, record_epoch)?;
    if cache.record_epoch != current.record_epoch || cache.payload_epoch != current.payload_epoch {
        return Err(StorageError::EvaluationInputPending);
    }
    if !same_sources(&cache, &current) {
        return Err(StorageError::Corrupt);
    }
    if cache.progress().storage_fault {
        return Err(StorageError::Corrupt);
    }
    if !cache.progress().checks_complete {
        return Err(StorageError::EvaluationInputPending);
    }
    cache.inputs(dir).map(Some)
}
fn roots(
    cache: &Cache,
    nodes: &BTreeMap<Key, Node>,
    known: &BTreeMap<Key, (Key, u64)>,
    budget: &Budget,
) -> Result<BTreeMap<Key, (Key, u64)>> {
    let mut roots = BTreeMap::new();
    for (id, node) in nodes {
        budget.check()?;
        if let Some((blob, declared)) = node.payload {
            if let Some(BlobFact::Verified(n)) = cache.rows[&blob].fact {
                if known.get(id).is_some_and(|old| *old != (blob, n)) {
                    return Err(StorageError::Corrupt);
                }
                if n != declared {
                    roots.insert(*id, (blob, n));
                }
            }
        }
    }
    Ok(roots)
}
impl EvaluationJob {
    pub fn prepare_blobs(
        &mut self,
        limits: EvaluationLimits,
        work: EvaluationBlobBudget,
    ) -> Result<EvaluationBlobProgress> {
        if self.writer.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.prepare_blobs_inner(limits, work);
        if result.as_ref().is_err_and(|e| {
            !matches!(
                e,
                StorageError::BudgetExceeded
                    | StorageError::Capacity
                    | StorageError::EvaluationInputPending
            )
        }) {
            self.writer.failed = true;
        }
        result
    }
    fn prepare_blobs_inner(
        &mut self,
        limits: EvaluationLimits,
        work: EvaluationBlobBudget,
    ) -> Result<EvaluationBlobProgress> {
        if work.targets == 0 {
            return Err(StorageError::BudgetExceeded);
        }
        let budget = Budget {
            start: Instant::now(),
            limits: EvaluationLimits {
                elapsed: limits.elapsed.min(work.elapsed),
                ..limits
            },
        };
        let (record_epoch, nodes) = preparation::ready(&self.writer.store, &budget)?
            .ok_or(StorageError::EvaluationInputPending)?;
        let known = self.writer.store.load_known(&nodes, &budget)?;
        let saved = load(&self.writer.store, &budget)?;
        let (current, dir) = inventory(&self.writer.store, &nodes, &budget, record_epoch)?;
        if current.progress().storage_fault {
            self.started_clean = false;
        }
        let fresh = saved
            .as_ref()
            .is_none_or(|old| !same_sources(old, &current));
        if let Some(old) = &saved {
            let physical_change = old.rows.iter().any(|(id, row)| {
                row.source.length.is_some()
                    && current.rows.get(id).is_none_or(|r| {
                        r.source.stamp != row.source.stamp
                            || r.source.size != row.source.size
                            || r.source.length != row.source.length
                    })
            });
            if old.progress().storage_fault
                || physical_change
                || (old.record_epoch == current.record_epoch
                    && old.payload_epoch == current.payload_epoch
                    && old.directory != current.directory)
            {
                self.started_clean = false;
            }
            if !fresh && old.progress().checks_complete {
                roots(old, &nodes, &known, &budget)?;
                return Ok(old.progress());
            }
        }
        let old_label = saved
            .as_ref()
            .map(Cache::label)
            .unwrap_or_else(|| "blobs_not_started".into());
        let old_rows = saved.as_ref().map(|s| s.rows.len()).unwrap_or(0);
        let mut cache = if fresh { current } else { saved.unwrap() };
        let mut checked = 0u64;
        let mut bytes = 0u64;
        let mut changed = BTreeSet::new();
        for (id, row) in &mut cache.rows {
            if row.fact.is_some() {
                continue;
            }
            budget.check()?;
            if checked >= work.targets {
                break;
            }
            let n = row.source.hash_bytes();
            if bytes.checked_add(n).is_none_or(|b| b > work.bytes) {
                if checked == 0 {
                    return Err(StorageError::BudgetExceeded);
                }
                break;
            }
            let (fact, examined) = row.source.inspect(&dir, *id)?;
            if fact == BlobFact::Unavailable {
                self.started_clean = false;
            }
            row.fact = Some(fact);
            row.examined = examined;
            checked += 1;
            bytes += n;
            changed.insert(*id);
        }
        validate(
            &cache,
            &dir,
            &self.writer.store.dir,
            &self.writer.store.conn,
            &budget,
        )?;
        cache.digest = digest(&cache);
        let reserve = ((old_rows + cache.rows.len()) as u64)
            .checked_mul(4096)
            .and_then(|n| n.checked_add(65536))
            .ok_or(StorageError::Capacity)?;
        let capacity = self.writer.store.capacity()?;
        if capacity.available <= capacity.reserved_floor.saturating_add(reserve) {
            return Err(StorageError::Capacity);
        }
        let roots = roots(&cache, &nodes, &known, &budget)?;
        #[cfg(test)]
        if self.pause_at == Some("blob_scanned") {
            queue::test_pause("blob_scanned");
        }
        let tx = self.writer.store.conn.transaction()?;
        tx.execute(
            "UPDATE evaluation_state SET dirty=1,blob_input_started=1 WHERE singleton=1",
            [],
        )?;
        if fresh {
            tx.execute("DELETE FROM evaluation_blob_facts", [])?;
        }
        for (id, row) in &cache.rows {
            budget.check()?;
            if fresh || changed.contains(id) {
                tx.execute("INSERT INTO evaluation_blob_facts VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(blob_id) DO UPDATE SET state=excluded.state,examined_bytes=excluded.examined_bytes",params![id,row.source.length,row.source.size,row.source.stamp,row.source.failure.map(PayloadReason::code),state(row.fact),row.examined])?;
            }
        }
        advance(&tx)?;
        for (id, (blob, n)) in roots {
            budget.check()?;
            tx.execute("INSERT INTO known_invalid(record_id,reason,blob_id,actual_length,rules,generation,at) SELECT ?1,'declared_length_mismatch',?2,?3,'lngnb-validation-1',generation,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM storage_state WHERE singleton=1 ON CONFLICT(record_id) DO NOTHING",params![id,blob,n as i64])?;
        }
        tx.execute("INSERT INTO evaluation_blob_input SELECT 1,?1,?2,?3,?4,?5,?6,generation FROM storage_state WHERE singleton=1 ON CONFLICT(singleton) DO UPDATE SET record_epoch=excluded.record_epoch,payload_epoch=excluded.payload_epoch,directory=excluded.directory,digest=excluded.digest,total=excluded.total,complete=excluded.complete,checkpoint_generation=excluded.checkpoint_generation",params![cache.record_epoch,cache.payload_epoch,cache.directory,cache.digest,cache.rows.len() as i64,i64::from(cache.progress().checks_complete)])?;
        audit(
            &tx,
            None,
            &old_label,
            if cache.progress().checks_complete {
                "evaluation_blob_complete"
            } else {
                "evaluation_blob_pending"
            },
            &format!("evaluation_blob_checkpoint:{}", cache.label()),
        )?;
        #[cfg(test)]
        if self.pause_at == Some("blob_before") {
            queue::test_pause("blob_before");
        }
        validate(&cache, &dir, &self.writer.store.dir, &tx, &budget)?;
        tx.commit()?;
        #[cfg(test)]
        if self.pause_at == Some("blob_after") {
            queue::test_pause("blob_after");
        }
        Ok(cache.progress())
    }
}

#[cfg(test)]
#[path = "evaluation_blob_input_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! { static HASHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
