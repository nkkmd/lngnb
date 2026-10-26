//! R20/R24/R26/R27/R30: 上限付き入力集合の親評価を永続cursorから再開する。
//! 入力収集・署名/Blob再照合・依存順序の構築は各回の別予算。通信探索ではない。
use super::*;
use crate::cbor::{self, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct EvaluationStepBudget {
    /// 一回で新たに判定するRecord数。入力収集の上限はEvaluationLimits。
    pub nodes: u64,
}
impl Default for EvaluationStepBudget {
    fn default() -> Self {
        Self { nodes: 32 }
    }
}
#[derive(Debug)]
pub struct EvaluationProgress {
    pub processed: u64,
    pub total: u64,
    /// 必要依存不足のpendingも評価済みとして数える。検査完了とは別。
    pub processed_complete: bool,
    pub validation_complete: bool,
    /// 全体の保存確定後だけ返す。その入力世代の管理用結果であり公開資格ではない。
    pub snapshot: Option<EvaluationSnapshot>,
}
pub struct EvaluationJob {
    pub(super) writer: RecordWriter,
    pub(super) started_clean: bool,
    #[cfg(test)]
    pub(super) pause_at: Option<&'static str>,
}
impl RecordStore {
    /// 起動局所検査済みStoreから評価だけを再開する。通常writerや手動解除を公開しない。
    pub fn evaluation_job(mut self) -> Result<EvaluationJob> {
        if !self.records_checked
            || inspection::checkpoint(&self.conn, self.limits.sql_inspection)?.pending()
        {
            return Err(StorageError::InspectionPending);
        }
        let started_clean = self.startup_state()? == StartupState::Clean;
        transition(&mut self.conn, "running", "begin_evaluation_job")?;
        Ok(EvaluationJob {
            writer: RecordWriter::new(self),
            started_clean,
            #[cfg(test)]
            pause_at: None,
        })
    }
}
struct Saved {
    input: Key,
    results: BTreeMap<Key, Assessment>,
    label: String,
}
pub(super) fn validate_for_resume(store: &RecordStore, c: &Computed) -> Result<()> {
    if let Some(saved) = load(store, &c.budget)? {
        if saved.input != input_digest(c) || saved.results.len() != c.nodes.len() {
            return Err(StorageError::EvaluationInputPending);
        }
        for row in &c.snapshot.records {
            c.budget.check()?;
            if saved.results.get(&row.record_id.bytes) != Some(row) {
                return Err(StorageError::Corrupt);
            }
        }
    }
    Ok(())
}
fn optional<T: Copy>(v: &Value, choices: &[(&str, T)]) -> Result<Option<T>> {
    match v {
        Value::Null => Ok(None),
        Value::Text(s) => choices
            .iter()
            .find(|(name, _)| *name == s)
            .map(|(_, v)| Some(*v))
            .ok_or(StorageError::Corrupt),
        _ => Err(StorageError::Corrupt),
    }
}
fn text(value: Option<&str>) -> Value {
    value.map(|s| Value::Text(s.into())).unwrap_or(Value::Null)
}
fn encoded(a: &Assessment) -> Result<Vec<u8>> {
    let related = a
        .related
        .map(|id| {
            Value::Array(vec![
                Value::Text(
                    match id.kind {
                        Kind::Record => "record",
                        Kind::Blob => "blob",
                        _ => unreachable!(),
                    }
                    .into(),
                ),
                Value::Bytes(id.bytes.to_vec()),
            ])
        })
        .unwrap_or(Value::Null);
    cbor::encode(&Value::Array(vec![
        Value::Bytes(a.record_id.bytes.to_vec()),
        text(Some(a.validation.text())),
        text(a.payload_status.map(PayloadStatus::text)),
        text(a.payload_reason.map(PayloadReason::code)),
        text(a.reason.map(Reason::code)),
        related,
    ]))
    .map_err(|_| StorageError::Corrupt)
}
fn decoded(raw: &[u8], id: Key) -> Result<Assessment> {
    let v = cbor::decode(raw).map_err(|_| StorageError::Corrupt)?;
    let Value::Array(fields) = v else {
        return Err(StorageError::Corrupt);
    };
    let [
        Value::Bytes(key),
        validation,
        payload,
        payload_reason,
        reason,
        related,
    ] = fields.as_slice()
    else {
        return Err(StorageError::Corrupt);
    };
    if key.as_slice() != id {
        return Err(StorageError::Corrupt);
    }
    let validation = optional(
        validation,
        &[
            ("valid", Validation::Valid),
            ("pending", Validation::Pending),
            ("invalid", Validation::Invalid),
        ],
    )?
    .ok_or(StorageError::Corrupt)?;
    let payload_status = optional(
        payload,
        &[
            ("verified", PayloadStatus::Verified),
            ("missing", PayloadStatus::Missing),
            ("unavailable", PayloadStatus::Unavailable),
        ],
    )?;
    let payload_reason = optional(
        payload_reason,
        &[
            (
                "transfer_hash_mismatch",
                PayloadReason::TransferHashMismatch,
            ),
            ("transfer_failed", PayloadReason::TransferFailed),
            ("storage_corruption", PayloadReason::StorageCorruption),
            (
                "declared_length_mismatch",
                PayloadReason::DeclaredLengthMismatch,
            ),
            ("evidence_unavailable", PayloadReason::EvidenceUnavailable),
        ],
    )?;
    let reason = optional(
        reason,
        &[
            ("missing_genesis", Reason::MissingGenesis),
            ("genesis_mismatch", Reason::GenesisMismatch),
            ("wrong_publisher", Reason::WrongPublisher),
            ("missing_parent", Reason::MissingParent),
            ("invalid_parent", Reason::InvalidParent),
            ("revalidation_in_progress", Reason::RevalidationInProgress),
            ("declared_length_mismatch", Reason::DeclaredLengthMismatch),
            ("evidence_unavailable", Reason::EvidenceUnavailable),
        ],
    )?;
    let related = match related {
        Value::Null => None,
        Value::Array(a) => {
            let [Value::Text(kind), Value::Bytes(key)] = a.as_slice() else {
                return Err(StorageError::Corrupt);
            };
            let key: Key = key
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Corrupt)?;
            Some(match kind.as_str() {
                "record" => record_id(key),
                "blob" => blob_id(key),
                _ => return Err(StorageError::Corrupt),
            })
        }
        _ => return Err(StorageError::Corrupt),
    };
    if (validation == Validation::Valid) != reason.is_none()
        || reason.is_some() != related.is_some()
        || (payload_reason.is_some() && payload_status != Some(PayloadStatus::Unavailable))
    {
        return Err(StorageError::Corrupt);
    }
    Ok(Assessment {
        record_id: record_id(id),
        validation,
        payload_status,
        payload_reason,
        reason,
        related,
    })
}
fn input_digest(c: &Computed) -> Key {
    let mut h = Sha256::new();
    h.update(b"lngnb:evaluation-input:1\0lngnb-validation-1\0");
    h.update((c.nodes.len() as u64).to_be_bytes());
    for key in c.nodes.keys() {
        h.update(key);
    }
    h.update((c.blobs.len() as u64).to_be_bytes());
    for (key, fact) in &c.blobs {
        h.update(key);
        match fact {
            BlobFact::Missing => h.update([0]),
            BlobFact::Verified(n) => {
                h.update([1]);
                h.update(n.to_be_bytes());
            }
            BlobFact::Unavailable => h.update([2]),
            BlobFact::TransferFailed(PayloadReason::TransferHashMismatch) => h.update([3]),
            BlobFact::TransferFailed(_) => h.update([4]),
        }
    }
    // 今回初めて得た真正な矛盾も同じcheckpointで保持するため、既知集合へ正規化。
    let roots: BTreeMap<_, _> = c
        .known
        .iter()
        .chain(c.conflicts.iter())
        .map(|(k, v)| (*k, *v))
        .collect();
    h.update((roots.len() as u64).to_be_bytes());
    for (key, (blob, n)) in roots {
        h.update(key);
        h.update(blob);
        h.update(n.to_be_bytes());
    }
    h.finalize().into()
}
fn result_digest(input: Key, total: i64, complete: bool, rows: &BTreeMap<Key, Vec<u8>>) -> Key {
    let mut h = Sha256::new();
    h.update(b"lngnb:evaluation-checkpoint:1\0");
    h.update(input);
    h.update(total.to_be_bytes());
    h.update([u8::from(complete)]);
    h.update((rows.len() as u64).to_be_bytes());
    for (key, bytes) in rows {
        h.update(key);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    h.finalize().into()
}
fn label(input: Key, digest: Key, count: usize, total: i64) -> String {
    format!(
        "input={}:digest={}:count={count}:total={total}",
        data_encoding::HEXLOWER.encode(&input),
        data_encoding::HEXLOWER.encode(&digest)
    )
}
type Header = (Vec<u8>, Vec<u8>, i64, i64, i64);
fn load(store: &RecordStore, budget: &Budget) -> Result<Option<Saved>> {
    let started: i64 = store.conn.query_row(
        "SELECT job_started FROM evaluation_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let header: Option<Header> = store.conn.query_row("SELECT input,digest,total,complete,checkpoint_generation FROM evaluation_job WHERE singleton=1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    let mut rows = BTreeMap::new();
    let mut stmt = store.conn.prepare(
        "SELECT record_id,length(result),result FROM evaluation_work ORDER BY record_id",
    )?;
    let mut query = stmt.query([])?;
    while let Some(r) = query.next()? {
        budget.check()?;
        if rows.len() as u64 >= budget.limits.records {
            return Err(StorageError::BudgetExceeded);
        }
        let id: Vec<u8> = r.get(0)?;
        let n: i64 = r.get(1)?;
        if !(1..=1024).contains(&n) {
            return Err(StorageError::Corrupt);
        }
        let id: Key = id.try_into().map_err(|_| StorageError::Corrupt)?;
        rows.insert(id, r.get::<_, Vec<u8>>(2)?);
    }
    let Some((input, digest, total, complete, generation)) = header else {
        if !rows.is_empty() || started != 0 {
            return Err(StorageError::Corrupt);
        }
        return Ok(None);
    };
    let input: Key = input.try_into().map_err(|_| StorageError::Corrupt)?;
    let digest: Key = digest.try_into().map_err(|_| StorageError::Corrupt)?;
    if total >= 0 && total as u64 > budget.limits.records {
        return Err(StorageError::BudgetExceeded);
    }
    if started != 1
        || total < 0
        || rows.len() as i64 > total
        || ![0, 1].contains(&complete)
        || (complete == 1) != (rows.len() as i64 == total)
        || result_digest(input, total, complete == 1, &rows) != digest
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
    let current_namespace: Vec<u8> = store.conn.query_row(
        "SELECT namespace FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if generation < 0
        || generation > store.generation()?
        || target.is_some()
        || (old != "evaluation_not_started" && !old.starts_with("input="))
        || reason
            != format!(
                "evaluation_queue_checkpoint:{}",
                label(input, digest, rows.len(), total)
            )
        || new
            != if complete == 1 {
                "evaluation_job_complete"
            } else {
                "evaluation_job_pending"
            }
        || rules != "lngnb-validation-1"
        || namespace != current_namespace
    {
        return Err(StorageError::Corrupt);
    }
    let label = label(input, digest, rows.len(), total);
    let results = rows
        .into_iter()
        .map(|(id, bytes)| Ok((id, decoded(&bytes, id)?)))
        .collect::<Result<_>>()?;
    Ok(Some(Saved {
        input,
        results,
        label,
    }))
}
impl EvaluationJob {
    pub fn step(
        &mut self,
        limits: EvaluationLimits,
        work: EvaluationStepBudget,
    ) -> Result<EvaluationProgress> {
        if self.writer.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.step_inner(limits, work);
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
    fn step_inner(
        &mut self,
        limits: EvaluationLimits,
        work: EvaluationStepBudget,
    ) -> Result<EvaluationProgress> {
        if work.nodes == 0 {
            return Err(StorageError::BudgetExceeded);
        }
        let start = Instant::now();
        // 旧台帳の不整合を入力変更によるリセットで隠さない。
        let saved = load(&self.writer.store, &Budget { start, limits })?;
        let mut c = self.writer.store.load_job_evaluation(limits, start)?;
        if c.storage_fault {
            return Err(StorageError::Corrupt);
        }
        let input = input_digest(&c);
        let plan = evaluation_order(&c.nodes, &c.budget)?;
        let fresh = saved.as_ref().is_none_or(|s| s.input != input);
        let old_label = saved
            .as_ref()
            .map(|s| s.label.as_str())
            .unwrap_or("evaluation_not_started")
            .to_owned();
        let mut results = if fresh {
            BTreeMap::new()
        } else {
            saved.unwrap().results
        };
        let previous = results.len();
        let prefix: BTreeSet<_> = plan.order.iter().take(previous).copied().collect();
        if results.keys().copied().collect::<BTreeSet<_>>() != prefix {
            return Err(StorageError::Corrupt);
        }
        for key in plan
            .order
            .iter()
            .skip(previous)
            .take(usize::try_from(work.nodes).unwrap_or(usize::MAX))
        {
            c.budget.check()?;
            let result = planned_assessment(*key, &plan, &c, &results);
            results.insert(*key, result);
        }
        let complete = results.len() == c.nodes.len();
        let total = i64::try_from(c.nodes.len()).map_err(|_| StorageError::Capacity)?;
        let rows: BTreeMap<_, _> = results
            .iter()
            .map(|(key, a)| Ok((*key, encoded(a)?)))
            .collect::<Result<_>>()?;
        let digest = result_digest(input, total, complete, &rows);
        let edges = c
            .nodes
            .values()
            .map(|n| n.parents.len() as u64)
            .sum::<u64>();
        let reserve = (c.nodes.len() as u64)
            .checked_mul(8192)
            .and_then(|n| edges.checked_mul(256).and_then(|e| n.checked_add(e)))
            .and_then(|n| n.checked_add(65536))
            .ok_or(StorageError::Capacity)?;
        let capacity = self.writer.store.capacity()?;
        if capacity.available <= capacity.reserved_floor.saturating_add(reserve) {
            return Err(StorageError::Capacity);
        }
        if complete {
            c.snapshot.records = results.values().cloned().collect();
        }
        #[cfg(test)]
        if self.pause_at == Some("eval_input_ready") {
            test_pause("eval_input_ready");
        }
        let tx = self.writer.store.conn.transaction()?;
        tx.execute(
            "UPDATE evaluation_state SET dirty=1,job_started=1 WHERE singleton=1",
            [],
        )?;
        if fresh {
            tx.execute("DELETE FROM evaluation_work", [])?;
        }
        let new_ids: BTreeSet<_> = plan
            .order
            .iter()
            .skip(previous)
            .take(results.len() - previous)
            .copied()
            .collect();
        for (key, bytes) in &rows {
            c.budget.check()?;
            if fresh || new_ids.contains(key) {
                tx.execute(
                    "INSERT INTO evaluation_work VALUES(?1,?2)",
                    params![key, bytes],
                )?;
            }
        }
        if complete {
            publish(&tx, &mut c, limits)?;
        }
        advance(&tx)?;
        // 部分ジョブで学習した不正根拠も失わない。評価全体の公開確定とは区別する。
        for (key, (blob, n)) in &c.conflicts {
            c.budget.check()?;
            tx.execute("INSERT INTO known_invalid(record_id,reason,blob_id,actual_length,rules,generation,at) SELECT ?1,'declared_length_mismatch',?2,?3,'lngnb-validation-1',generation,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM storage_state WHERE singleton=1 ON CONFLICT(record_id) DO NOTHING",params![key,blob,i64::try_from(*n).map_err(|_| StorageError::Corrupt)?])?;
        }
        tx.execute("INSERT INTO evaluation_job SELECT 1,?1,?2,?3,?4,generation FROM storage_state WHERE singleton=1 ON CONFLICT(singleton) DO UPDATE SET input=excluded.input,digest=excluded.digest,total=excluded.total,complete=excluded.complete,checkpoint_generation=excluded.checkpoint_generation", params![input,digest,total,i64::from(complete)])?;
        audit(
            &tx,
            None,
            &old_label,
            if complete {
                "evaluation_job_complete"
            } else {
                "evaluation_job_pending"
            },
            &format!(
                "evaluation_queue_checkpoint:{}",
                label(input, digest, rows.len(), total)
            ),
        )?;
        c.budget.check()?;
        #[cfg(test)]
        if self.pause_at == Some("before") {
            test_pause("before");
        }
        c.validate_evidence(&self.writer.store.dir, &tx)?;
        tx.commit()?;
        #[cfg(test)]
        if self.pause_at == Some("after") {
            test_pause("after");
        }
        let validation_complete = complete
            && results
                .values()
                .all(|a| a.validation != Validation::Pending);
        c.snapshot.committed = true;
        Ok(EvaluationProgress {
            processed: rows.len() as u64,
            total: total as u64,
            processed_complete: complete,
            validation_complete,
            snapshot: complete.then_some(c.snapshot),
        })
    }
    /// 正常なジョブ境界で終了する。開始時の手動待ちを解除せず、未処理を完了と呼ばない。
    pub fn pause(self) -> Result<()> {
        if self.writer.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if self.started_clean {
            self.writer.finish()
        } else {
            self.writer
                .store
                .conn
                .close()
                .map_err(|(_, e)| StorageError::Sql(e))?;
            Ok(())
        }
    }
}
#[cfg(test)]
pub(super) fn test_pause(phase: &str) {
    use std::io::Write;
    println!("LNGNB_EVALUATION_CHECKPOINT_{phase}");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}
#[cfg(test)]
#[path = "evaluation_queue_tests.rs"]
mod tests;
