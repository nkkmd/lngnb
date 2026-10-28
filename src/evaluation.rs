//! R07/R08/R10/R26/R27: 保存集合の管理用評価。pin・公開・候補選択は扱わない。
//! 集合評価と、入力照合後の親評価cursor再開。部分結果を現在の全体判定にしない。
use super::*;
use crate::record::{RecordIdentity, RecordKind};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::{Duration, Instant},
};

type Key = [u8; 32];
fn record_id(bytes: Key) -> Id {
    Id {
        kind: Kind::Record,
        bytes,
    }
}
fn blob_id(bytes: Key) -> Id {
    Id {
        kind: Kind::Blob,
        bytes,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EvaluationLimits {
    pub records: u64,
    pub record_bytes: u64,
    pub edges: u64,
    pub blob_bytes: u64,
    pub elapsed: Duration,
}
impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            records: 10_000,
            record_bytes: 64 * 1024 * 1024,
            edges: 100_000,
            blob_bytes: 64 * 1024 * 1024,
            elapsed: Duration::from_secs(60),
        }
    }
}
struct Budget {
    start: Instant,
    limits: EvaluationLimits,
}
impl Budget {
    fn check(&self) -> Result<()> {
        if self.start.elapsed() >= self.limits.elapsed {
            Err(StorageError::BudgetExceeded)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    Valid,
    Pending,
    Invalid,
}
impl Validation {
    fn text(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Pending => "pending",
            Self::Invalid => "invalid",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadStatus {
    Verified,
    Missing,
    Unavailable,
}
impl PayloadStatus {
    fn text(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Missing => "missing",
            Self::Unavailable => "unavailable",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadReason {
    TransferHashMismatch,
    TransferFailed,
    StorageCorruption,
    DeclaredLengthMismatch,
    EvidenceUnavailable,
}
impl PayloadReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::TransferHashMismatch => "transfer_hash_mismatch",
            Self::TransferFailed => "transfer_failed",
            Self::StorageCorruption => "storage_corruption",
            Self::DeclaredLengthMismatch => "declared_length_mismatch",
            Self::EvidenceUnavailable => "evidence_unavailable",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    MissingGenesis,
    GenesisMismatch,
    WrongPublisher,
    MissingParent,
    InvalidParent,
    RevalidationInProgress,
    DeclaredLengthMismatch,
    EvidenceUnavailable,
}
impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingGenesis => "missing_genesis",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::WrongPublisher => "wrong_publisher",
            Self::MissingParent => "missing_parent",
            Self::InvalidParent => "invalid_parent",
            Self::RevalidationInProgress => "revalidation_in_progress",
            Self::DeclaredLengthMismatch => "declared_length_mismatch",
            Self::EvidenceUnavailable => "evidence_unavailable",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub record_id: Id,
    pub validation: Validation,
    pub payload_status: Option<PayloadStatus>,
    pub payload_reason: Option<PayloadReason>,
    pub reason: Option<Reason>,
    /// 管理用診断の直接依存または根拠。一般応答へそのまま開示しない。
    pub related: Option<Id>,
}
/// この世代だけの管理用結果。後続入力・破損・設定変更後の現在判定へ流用しない。
#[derive(Debug)]
pub struct EvaluationSnapshot {
    pub generation: i64,
    /// falseの結果は診断だけであり、新しい判定・根拠を永続確定していない。
    pub committed: bool,
    pub records: Vec<Assessment>,
}
#[derive(Clone)]
struct Node {
    identity: RecordIdentity,
    genesis: Key,
    parents: Vec<Key>,
    payload: Option<(Key, u64)>,
}
impl Node {
    fn from_record(record: &LocalRecord) -> Result<Self> {
        Ok(Self {
            identity: record.identity(),
            genesis: record.genesis().map_err(|_| StorageError::Corrupt)?,
            parents: record.parents().map_err(|_| StorageError::Corrupt)?,
            payload: record.payload().map_err(|_| StorageError::Corrupt)?,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobFact {
    TransferFailed(PayloadReason),
    Missing,
    Verified(u64),
    Unavailable,
}
struct Computed {
    snapshot: EvaluationSnapshot,
    nodes: BTreeMap<Key, Node>,
    conflicts: BTreeMap<Key, (Key, u64)>,
    blobs: BTreeMap<Key, BlobFact>,
    known: BTreeMap<Key, (Key, u64)>,
    storage_fault: bool,
    record_epoch: i64,
    evidence: blob_preparation::Evidence,
    budget: Budget,
}
impl RecordStore {
    /// 排他中の一次集合と真正Blobを毎回照合する管理用診断。永続判定の成功ではない。
    /// 異常起動時も診断できるが、手動確認待ちを解除せず公開資格も付与しない。
    pub fn evaluate(&self, limits: EvaluationLimits) -> Result<EvaluationSnapshot> {
        Ok(self.compute_evaluation(limits)?.snapshot)
    }
    pub(super) fn diagnostic_evaluation(
        &self,
        limits: EvaluationLimits,
    ) -> Result<(EvaluationSnapshot, bool)> {
        let computed = self.compute_evaluation(limits)?;
        Ok((computed.snapshot, computed.storage_fault))
    }
    fn compute_evaluation(&self, limits: EvaluationLimits) -> Result<Computed> {
        let mut computed = self.load_evaluation(limits, Instant::now())?;
        computed.snapshot.records = evaluate_graph(
            &computed.nodes,
            &computed.blobs,
            &computed.known,
            &computed.budget,
        )?;
        computed.validate_evidence(&self.dir, &self.conn)?;
        Ok(computed)
    }
    fn load_evaluation(&self, limits: EvaluationLimits, start: Instant) -> Result<Computed> {
        let budget = Budget { start, limits };
        let (nodes, record_epoch) = self.collect_evaluation_nodes(&budget)?;
        self.evaluation_from_nodes(nodes, budget, record_epoch, false)
    }
    fn load_job_evaluation(&self, limits: EvaluationLimits, start: Instant) -> Result<Computed> {
        let budget = Budget { start, limits };
        let (nodes, record_epoch) = match preparation::ready(self, &budget)? {
            Some((epoch, nodes)) => (nodes, epoch),
            None => self.collect_evaluation_nodes(&budget)?,
        };
        self.evaluation_from_nodes(nodes, budget, record_epoch, true)
    }
    fn collect_evaluation_nodes(&self, budget: &Budget) -> Result<(BTreeMap<Key, Node>, i64)> {
        let limits = budget.limits;
        budget.check()?;
        let record_epoch = preparation::epoch(&self.conn)?;
        let mut nodes = BTreeMap::new();
        let mut byte_budget = limits.record_bytes;
        let mut edge_budget = limits.edges;
        let mut stmt = self
            .conn
            .prepare("SELECT id,length(bytes) FROM records ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            budget.check()?;
            if nodes.len() as u64 >= limits.records {
                return Err(StorageError::BudgetExceeded);
            }
            let raw: Vec<u8> = row.get(0)?;
            let key: Key = raw.try_into().map_err(|_| StorageError::Corrupt)?;
            let n: i64 = row.get(1)?;
            if n <= 0 || n > MAX_RECORD as i64 {
                return Err(StorageError::Corrupt);
            }
            byte_budget = byte_budget
                .checked_sub(n as u64)
                .ok_or(StorageError::BudgetExceeded)?;
            let record = self.record(record_id(key))?.ok_or(StorageError::Corrupt)?;
            let node = Node::from_record(&record)?;
            edge_budget = edge_budget
                .checked_sub(node.parents.len() as u64)
                .ok_or(StorageError::BudgetExceeded)?;
            nodes.insert(key, node);
        }
        Ok((nodes, record_epoch))
    }
    fn evaluation_from_nodes(
        &self,
        nodes: BTreeMap<Key, Node>,
        budget: Budget,
        record_epoch: i64,
        allow_prepared: bool,
    ) -> Result<Computed> {
        let known = self.load_known(&nodes, &budget)?;
        let prepared = if allow_prepared {
            blob_preparation::ready(self, &nodes, &budget, record_epoch)?
        } else {
            None
        };
        let (blobs, evidence) = match prepared {
            Some(inputs) => inputs,
            None => blob_preparation::fresh(self, &nodes, &budget, record_epoch)?,
        };
        let mut conflicts = BTreeMap::new();
        for (key, node) in &nodes {
            if let Some((id, declared)) = node.payload {
                if let BlobFact::Verified(n) = blobs[&id] {
                    if n != declared {
                        conflicts.insert(*key, (id, n));
                    }
                    if known.get(key).is_some_and(|old| *old != (id, n)) {
                        return Err(StorageError::Corrupt);
                    }
                }
            }
        }
        let storage_fault = blobs.values().any(|b| matches!(b, BlobFact::Unavailable));
        let records = Vec::new();
        budget.check()?;
        Ok(Computed {
            snapshot: EvaluationSnapshot {
                generation: self.generation()?,
                committed: false,
                records,
            },
            nodes,
            conflicts,
            blobs,
            known,
            storage_fault,
            record_epoch,
            evidence,
            budget,
        })
    }
    fn load_known(
        &self,
        nodes: &BTreeMap<Key, Node>,
        budget: &Budget,
    ) -> Result<BTreeMap<Key, (Key, u64)>> {
        // 既知不正の根拠を入力集合とは別に保持する。再投稿・再索引で消さない。
        let mut known = BTreeMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT record_id,blob_id,actual_length,rules FROM known_invalid ORDER BY record_id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            budget.check()?;
            if known.len() >= nodes.len() {
                return Err(StorageError::Corrupt);
            }
            let key: Vec<u8> = row.get(0)?;
            let key: Key = key.try_into().map_err(|_| StorageError::Corrupt)?;
            let blob: Vec<u8> = row.get(1)?;
            let blob: Key = blob.try_into().map_err(|_| StorageError::Corrupt)?;
            let n: i64 = row.get(2)?;
            let rules: String = row.get(3)?;
            let node = nodes.get(&key).ok_or(StorageError::Corrupt)?;
            if n < 0
                || rules != "lngnb-validation-1"
                || !node
                    .payload
                    .is_some_and(|(id, declared)| id == blob && declared != n as u64)
            {
                return Err(StorageError::Corrupt);
            }
            known.insert(key, (blob, n as u64));
        }
        Ok(known)
    }
}

fn base_result(node: &Node, nodes: &BTreeMap<Key, Node>) -> Option<(Validation, Reason, Id)> {
    if node.identity.kind == RecordKind::Genesis {
        return None;
    }
    let Some(genesis) = nodes.get(&node.genesis) else {
        return Some((
            Validation::Pending,
            Reason::MissingGenesis,
            record_id(node.genesis),
        ));
    };
    match node.identity.check_genesis(node.genesis, &genesis.identity) {
        Ok(()) => None,
        Err(crate::Error::WrongPublisher) => Some((
            Validation::Invalid,
            Reason::WrongPublisher,
            record_id(node.genesis),
        )),
        Err(_) => Some((
            Validation::Invalid,
            Reason::GenesisMismatch,
            record_id(node.genesis),
        )),
    }
}
fn same_scope(child: &Node, parent: &Node) -> bool {
    parent.identity.kind == RecordKind::Revision
        && parent.identity.knowledge == child.identity.knowledge
        && parent.genesis == child.genesis
}
struct GraphPlan {
    order: Vec<Key>,
    remaining: BTreeMap<Key, usize>,
}
fn evaluation_order(nodes: &BTreeMap<Key, Node>, budget: &Budget) -> Result<GraphPlan> {
    let mut remaining = BTreeMap::new();
    let mut reverse: BTreeMap<Key, Vec<Key>> = BTreeMap::new();
    let mut ready = VecDeque::new();
    for (key, node) in nodes {
        budget.check()?;
        let mut count = 0usize;
        for parent in &node.parents {
            if nodes.get(parent).is_some_and(|p| same_scope(node, p)) {
                count += 1;
                reverse.entry(*parent).or_default().push(*key);
            }
        }
        remaining.insert(*key, count);
        if count == 0 {
            ready.push_back(*key);
        }
    }
    let mut order = Vec::new();
    while let Some(key) = ready.pop_front() {
        budget.check()?;
        order.push(key);
        if let Some(children) = reverse.get(&key) {
            for child in children {
                let count = remaining.get_mut(child).ok_or(StorageError::Corrupt)?;
                *count -= 1;
                if *count == 0 {
                    ready.push_back(*child);
                }
            }
        }
    }
    order.extend(remaining.iter().filter(|(_, n)| **n > 0).map(|(id, _)| *id));
    Ok(GraphPlan { order, remaining })
}
fn planned_assessment(
    key: Key,
    plan: &GraphPlan,
    computed: &Computed,
    results: &BTreeMap<Key, Assessment>,
) -> Assessment {
    planned_result(
        key,
        plan,
        &computed.nodes,
        &computed.blobs,
        &computed.known,
        results,
    )
}
fn planned_result(
    key: Key,
    plan: &GraphPlan,
    nodes: &BTreeMap<Key, Node>,
    blobs: &BTreeMap<Key, BlobFact>,
    known: &BTreeMap<Key, (Key, u64)>,
    results: &BTreeMap<Key, Assessment>,
) -> Assessment {
    let node = &nodes[&key];
    let mut result = assess(node, nodes, blobs, known, results);
    if plan.remaining[&key] > 0 && base_result(node, nodes).is_none() {
        result.validation = Validation::Invalid;
        result.reason = Some(Reason::InvalidParent);
        result.related = node
            .parents
            .iter()
            .find(|p| plan.remaining.get(*p).is_some_and(|n| *n > 0))
            .copied()
            .map(record_id);
    }
    result.record_id = record_id(key);
    result
}
fn evaluate_graph(
    nodes: &BTreeMap<Key, Node>,
    blobs: &BTreeMap<Key, BlobFact>,
    known: &BTreeMap<Key, (Key, u64)>,
    budget: &Budget,
) -> Result<Vec<Assessment>> {
    let plan = evaluation_order(nodes, budget)?;
    let mut results = BTreeMap::new();
    for key in &plan.order {
        budget.check()?;
        let result = planned_result(*key, &plan, nodes, blobs, known, &results);
        results.insert(*key, result);
    }
    Ok(results.into_values().collect())
}

fn assess(
    node: &Node,
    nodes: &BTreeMap<Key, Node>,
    blobs: &BTreeMap<Key, BlobFact>,
    known: &BTreeMap<Key, (Key, u64)>,
    results: &BTreeMap<Key, Assessment>,
) -> Assessment {
    let mut out = Assessment {
        record_id: node.identity.id,
        validation: Validation::Valid,
        payload_status: None,
        payload_reason: None,
        reason: None,
        related: None,
    };
    if let Some((id, declared)) = node.payload {
        out.payload_reason = match blobs[&id] {
            BlobFact::Verified(n) if n != declared => Some(PayloadReason::DeclaredLengthMismatch),
            BlobFact::Missing | BlobFact::Unavailable | BlobFact::TransferFailed(_)
                if known.contains_key(&node.identity.id.bytes) =>
            {
                Some(PayloadReason::EvidenceUnavailable)
            }
            BlobFact::Unavailable => Some(PayloadReason::StorageCorruption),
            BlobFact::TransferFailed(reason) => Some(reason),
            _ => None,
        };
        out.payload_status = Some(match blobs[&id] {
            BlobFact::Verified(n) if n == declared => PayloadStatus::Verified,
            BlobFact::Missing if !known.contains_key(&node.identity.id.bytes) => {
                PayloadStatus::Missing
            }
            _ => PayloadStatus::Unavailable,
        });
    }
    let set = |out: &mut Assessment, state, reason, id| {
        out.validation = state;
        out.reason = Some(reason);
        out.related = Some(id);
    };
    if let Some((state, reason, id)) = base_result(node, nodes) {
        set(&mut out, state, reason, id);
        return out;
    }
    // 親の明確な不正を不足より優先し、同じ優先順位内は生ID順で安定させる。
    for parent in &node.parents {
        if nodes.get(parent).is_some_and(|p| !same_scope(node, p))
            || results
                .get(parent)
                .is_some_and(|p| p.validation == Validation::Invalid)
        {
            set(
                &mut out,
                Validation::Invalid,
                Reason::InvalidParent,
                record_id(*parent),
            );
            return out;
        }
    }
    for parent in &node.parents {
        if !nodes.contains_key(parent) {
            set(
                &mut out,
                Validation::Pending,
                Reason::MissingParent,
                record_id(*parent),
            );
            return out;
        }
        if let Some(p) = results.get(parent) {
            if p.validation == Validation::Pending {
                let reason = if p.reason == Some(Reason::EvidenceUnavailable) {
                    Reason::EvidenceUnavailable
                } else {
                    Reason::RevalidationInProgress
                };
                set(&mut out, Validation::Pending, reason, record_id(*parent));
                return out;
            }
        }
    }
    if let Some((id, declared)) = node.payload {
        match blobs[&id] {
            BlobFact::Verified(n) if n != declared => set(
                &mut out,
                Validation::Invalid,
                Reason::DeclaredLengthMismatch,
                blob_id(id),
            ),
            BlobFact::Missing | BlobFact::Unavailable | BlobFact::TransferFailed(_)
                if known.contains_key(&node.identity.id.bytes) =>
            {
                set(
                    &mut out,
                    Validation::Pending,
                    Reason::EvidenceUnavailable,
                    blob_id(id),
                )
            }
            _ => (),
        }
    }
    out
}
impl RecordWriter {
    pub(super) fn observe_blob_failure(&mut self, id: Id, reason: &str) -> Result<()> {
        let tx = self.store.conn.transaction()?;
        advance(&tx)?;
        tx.execute("INSERT INTO blob_failures(id,reason,generation,at) SELECT ?1,?2,generation,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM storage_state WHERE singleton=1 ON CONFLICT(id) DO UPDATE SET reason=excluded.reason,generation=excluded.generation,at=excluded.at",params![&id.bytes,reason])?;
        audit(
            &tx,
            Some(&id.bytes),
            "transfer_attempt",
            "blob_failure_observed",
            reason,
        )?;
        tx.commit()?;
        Ok(())
    }
    /// 全集合の完了後だけ、評価・逆依存・新しい不正根拠・履歴・世代を原子的に確定。
    /// この内部操作は公開許可・pin・手動再開を付与しない。
    pub fn revalidate(&mut self, limits: EvaluationLimits) -> Result<EvaluationSnapshot> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.revalidate_inner(limits);
        if let Err(ref e) = result {
            if !matches!(e, StorageError::BudgetExceeded | StorageError::Capacity) {
                self.failed = true;
            }
        }
        result
    }
    fn revalidate_inner(&mut self, limits: EvaluationLimits) -> Result<EvaluationSnapshot> {
        let mut computed = self.store.compute_evaluation(limits)?;
        if computed.storage_fault {
            return Err(StorageError::Corrupt);
        }
        let edges: u64 = computed
            .nodes
            .values()
            .map(|n| n.parents.len() as u64)
            .sum();
        let reserve = (computed.nodes.len() as u64)
            .checked_mul(4096)
            .and_then(|n| edges.checked_mul(256).and_then(|e| n.checked_add(e)))
            .and_then(|n| n.checked_add(65536))
            .ok_or(StorageError::Capacity)?;
        let capacity = self.store.capacity()?;
        if capacity.available
            <= capacity
                .reserved_floor
                .saturating_add(self.reserved)
                .saturating_add(reserve)
        {
            return Err(StorageError::Capacity);
        }
        self.reserved += reserve;
        let result: Result<()> = (|| {
            let tx = self.store.conn.transaction()?;
            publish(&tx, &mut computed, limits)?;
            #[cfg(test)]
            if self.evaluation_pause {
                use std::io::Write;
                println!("LNGNB_EVALUATION_BEFORE_COMMIT");
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
            }
            computed.validate_evidence(&self.store.dir, &tx)?;
            tx.commit()?;
            Ok(())
        })();
        self.reserved -= reserve;
        result?;
        computed.snapshot.committed = true;
        Ok(computed.snapshot)
    }
}

#[cfg(test)]
#[path = "evaluation_tests.rs"]
pub(super) mod tests;

fn publish(tx: &Transaction<'_>, computed: &mut Computed, limits: EvaluationLimits) -> Result<()> {
    let old_rows = {
        let mut statement = tx.prepare("SELECT record_id,validation,payload,reason,related,payload_reason FROM evaluations ORDER BY record_id")?;
        let mut old = BTreeMap::new();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            computed.budget.check()?;
            if old.len() as u64 >= limits.records {
                return Err(StorageError::BudgetExceeded);
            }
            let id: Vec<u8> = row.get(0)?;
            let validation: String = row.get(1)?;
            let payload: Option<String> = row.get(2)?;
            let reason: Option<String> = row.get(3)?;
            let related: Option<Vec<u8>> = row.get(4)?;
            let payload_reason: Option<String> = row.get(5)?;
            old.insert(
                id,
                format!(
                    "{}:{}:{}:{:?}:{}",
                    validation,
                    payload.as_deref().unwrap_or("none"),
                    reason.as_deref().unwrap_or("none"),
                    related,
                    payload_reason.as_deref().unwrap_or("none")
                ),
            );
        }
        old
    };
    tx.execute("DELETE FROM evaluations", [])?;
    tx.execute("DELETE FROM parent_edges", [])?;
    for (key, node) in &computed.nodes {
        computed.budget.check()?;
        for parent in &node.parents {
            tx.execute(
                "INSERT INTO parent_edges(child,parent) VALUES(?1,?2)",
                params![key, parent],
            )?;
        }
    }
    for row in &computed.snapshot.records {
        computed.budget.check()?;
        let new_state = format!(
            "{}:{}:{}:{:?}:{}",
            row.validation.text(),
            row.payload_status
                .map(PayloadStatus::text)
                .unwrap_or("none"),
            row.reason.map(Reason::code).unwrap_or("none"),
            row.related.map(|id| id.bytes.to_vec()),
            row.payload_reason
                .map(PayloadReason::code)
                .unwrap_or("none")
        );
        let old_state = old_rows
            .get(row.record_id.bytes.as_slice())
            .map(String::as_str)
            .unwrap_or("unevaluated");
        if old_state != new_state {
            advance(tx)?;
            audit(
                tx,
                Some(&row.record_id.bytes),
                old_state,
                &new_state,
                "record_dependency_evaluation",
            )?;
        }
        tx.execute(
            "INSERT INTO evaluations VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                &row.record_id.bytes,
                row.validation.text(),
                row.payload_status.map(PayloadStatus::text),
                row.reason.map(Reason::code),
                row.related.map(|id| id.bytes),
                row.payload_reason.map(PayloadReason::code)
            ],
        )?;
    }
    advance(tx)?;
    for (key, (blob, n)) in &computed.conflicts {
        computed.budget.check()?;
        tx.execute("INSERT INTO known_invalid(record_id,reason,blob_id,actual_length,rules,generation,at) SELECT ?1,'declared_length_mismatch',?2,?3,'lngnb-validation-1',generation,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM storage_state WHERE singleton=1 ON CONFLICT(record_id) DO NOTHING",params![key,blob,i64::try_from(*n).map_err(|_| StorageError::Corrupt)?])?;
    }
    tx.execute("UPDATE evaluation_state SET dirty=0,generation=(SELECT generation FROM storage_state WHERE singleton=1) WHERE singleton=1",[])?;
    audit(
        tx,
        None,
        "evaluation_pending",
        "evaluated_local_only",
        "revalidate_dependencies_and_payloads",
    )?;
    computed.budget.check()?;
    computed.snapshot.generation = tx.query_row(
        "SELECT generation FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    Ok(())
}

#[path = "evaluation_queue.rs"]
mod queue;
pub use queue::{EvaluationJob, EvaluationProgress, EvaluationStepBudget};

fn blob_stamp(dir: &OwnedFd, key: Key) -> Result<Option<String>> {
    match blobs::checked_file(dir, &blobs::hex(&key)) {
        Ok(file) => Ok(Some(fingerprint(&file.metadata()?))),
        Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
impl Computed {
    fn validate_evidence(&self, root: &OwnedFd, conn: &Connection) -> Result<()> {
        if preparation::epoch(conn)? != self.record_epoch {
            return Err(StorageError::Corrupt);
        }
        self.evidence.validate(root, conn, &self.budget)
    }
}

#[path = "evaluation_input.rs"]
mod preparation;
pub use preparation::{EvaluationInputBudget, EvaluationInputProgress};

#[path = "evaluation_blob_input.rs"]
mod blob_preparation;
pub use blob_preparation::{EvaluationBlobBudget, EvaluationBlobProgress};

#[path = "recovery_review.rs"]
mod recovery_review;
pub use recovery_review::EvidenceRecoveryReview;

impl RecordStore {
    pub(super) fn startup_evaluation(self, began_clean: bool) -> Result<EvaluationJob> {
        let mut job = self.evaluation_job()?;
        job.started_clean = began_clean;
        Ok(job)
    }
}
impl EvaluationJob {
    pub(super) fn startup_writer(self) -> Result<RecordWriter> {
        if self.writer.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        Ok(self.writer)
    }
    pub(super) fn startup_store(&self) -> &RecordStore {
        &self.writer.store
    }
}
