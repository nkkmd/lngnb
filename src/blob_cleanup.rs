//! R23/R24/R26/R27/R30、A8.4: 削除予定と保持変更の直列化。物理削除は行わない。
use super::*;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct CleanupBudget {
    pub protection: ProtectionBudget,
    pub plans: u64,
    pub hash_bytes: u64,
}
impl Default for CleanupBudget {
    fn default() -> Self {
        Self {
            protection: ProtectionBudget::default(),
            plans: 10_000,
            hash_bytes: 64 * 1024 * 1024,
        }
    }
}
/// 管理用の予定来歴。保持実体の削除資格ではなく、実行時には再検査が必要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobCleanupPlan {
    pub plan_id: [u8; 32],
    pub blob_id: Id,
    pub byte_length: u64,
    pub planned_at: i64,
    pub planned_generation: i64,
    pub cancelled_generation: Option<i64>,
    pub cancellation: Option<String>,
    pub completed_generation: Option<i64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupDecision {
    Unregistered,
    Protected,
    Planned(BlobCleanupPlan),
}
fn key(raw: Vec<u8>) -> Result<[u8; 32]> {
    raw.try_into().map_err(|_| StorageError::Corrupt)
}
fn plan_reason(id: &[u8; 32], at: i64, n: i64, fingerprint: &str) -> String {
    format!(
        "plan_blob_cleanup:{}:{at}:{n}:{fingerprint}",
        blobs::hex(id)
    )
}
pub(super) fn validate(conn: &Connection) -> Result<()> {
    let bad:bool=conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM blob_cleanup_plans p
            LEFT JOIN blob_objects b ON b.id=p.blob_id
            LEFT JOIN history h ON h.generation=p.planned_generation
            LEFT JOIN history c ON c.generation=p.cancelled_generation
            WHERE b.id IS NULL OR b.byte_length!=p.byte_length OR p.byte_length<0
               OR length(p.plan_id)!=32 OR p.planned_at NOT BETWEEN 0 AND 253402300799
               OR length(p.fingerprint) NOT BETWEEN 1 AND 512
               OR p.planned_generation<0 OR p.planned_generation>(SELECT generation FROM storage_state WHERE singleton=1)
               OR (p.cancelled_generation IS NULL)!=(p.cancellation IS NULL)
               OR (p.cancelled_generation IS NOT NULL AND p.completed_generation IS NOT NULL)
               OR (p.completed_generation IS NOT NULL AND (p.completed_generation<=p.planned_generation
                   OR NOT EXISTS(SELECT 1 FROM blob_cleanup_runs r WHERE r.plan_id=p.plan_id AND r.finished_generation=p.completed_generation)))
               OR h.generation IS NULL OR h.target IS NOT p.blob_id
               OR h.old_state!='temporary_blob_expired' OR h.new_state!='blob_cleanup_planned_local_only'
               OR h.namespace IS NOT (SELECT namespace FROM storage_state WHERE singleton=1)
               OR h.rules!='lngnb-validation-1'
               OR h.reason!='plan_blob_cleanup:'||lower(hex(p.plan_id))||':'||p.planned_at||':'||p.byte_length||':'||p.fingerprint
               OR (p.cancelled_generation IS NOT NULL AND (
                   p.cancelled_generation<=p.planned_generation
                   OR p.cancelled_generation>(SELECT generation FROM storage_state WHERE singleton=1)
                   OR p.cancellation NOT IN ('record_reference','manual_retention','temporary_promise')
                   OR c.generation IS NULL OR c.target IS NOT p.blob_id
                   OR c.old_state!='blob_cleanup_planned_local_only' OR c.new_state!='blob_cleanup_cancelled_local_only'
                   OR c.namespace IS NOT h.namespace OR c.rules!='lngnb-validation-1'
                   OR c.reason!='cancel_blob_cleanup:'||lower(hex(p.plan_id))||':'||p.cancellation
               ))
        ) OR EXISTS(
            SELECT 1 FROM history h LEFT JOIN blob_cleanup_plans p ON p.planned_generation=h.generation
            WHERE h.new_state='blob_cleanup_planned_local_only' AND p.plan_id IS NULL
        ) OR EXISTS(
            SELECT 1 FROM history h LEFT JOIN blob_cleanup_plans p ON p.cancelled_generation=h.generation
            WHERE h.new_state='blob_cleanup_cancelled_local_only' AND p.plan_id IS NULL
        )", [], |r|r.get(0))?;
    if bad {
        return Err(StorageError::Corrupt);
    }
    execution::validate_runs(conn)?;
    Ok(())
}
fn plans(conn: &Connection, limit: u64) -> Result<Vec<BlobCleanupPlan>> {
    let mut stmt=conn.prepare("SELECT plan_id,blob_id,byte_length,planned_at,planned_generation,cancelled_generation,cancellation,completed_generation FROM blob_cleanup_plans ORDER BY planned_generation")?;
    let mut query = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = query.next()? {
        if out.len() as u64 >= limit {
            return Err(StorageError::BudgetExceeded);
        }
        let n: i64 = row.get(2)?;
        if n < 0 {
            return Err(StorageError::Corrupt);
        }
        out.push(BlobCleanupPlan {
            plan_id: key(row.get(0)?)?,
            blob_id: Id {
                kind: Kind::Blob,
                bytes: key(row.get(1)?)?,
            },
            byte_length: n as u64,
            planned_at: row.get(3)?,
            planned_generation: row.get(4)?,
            cancelled_generation: row.get(5)?,
            cancellation: row.get(6)?,
            completed_generation: row.get(7)?,
        });
    }
    Ok(out)
}
/// 呼出し側の変更transactionでだけ取り消す。新しい保持根拠と取消履歴を分離しない。
pub(super) fn cancel(tx: &Transaction<'_>, blob: &[u8; 32], cause: &str) -> Result<()> {
    let pending:Option<Vec<u8>>=tx.query_row("SELECT plan_id FROM blob_cleanup_plans WHERE blob_id=?1 AND cancelled_generation IS NULL AND completed_generation IS NULL",[blob],|r|r.get(0)).optional()?;
    if let Some(raw) = pending {
        validate(tx)?;
        let id = key(raw)?;
        advance(tx)?;
        tx.execute("UPDATE blob_cleanup_plans SET cancelled_generation=(SELECT generation FROM storage_state WHERE singleton=1),cancellation=?2 WHERE plan_id=?1",params![&id,cause])?;
        audit(
            tx,
            Some(blob),
            "blob_cleanup_planned_local_only",
            "blob_cleanup_cancelled_local_only",
            &format!("cancel_blob_cleanup:{}:{cause}", blobs::hex(&id)),
        )?;
    }
    Ok(())
}
impl RecordStore {
    pub fn blob_cleanup_plans(&self, limit: u64) -> Result<Vec<BlobCleanupPlan>> {
        let tx = self.conn.unchecked_transaction()?;
        validate(&tx)?;
        let out = plans(&tx, limit)?;
        tx.commit()?;
        Ok(out)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    BeforeCommit,
    AfterCommit,
}
impl RecordWriter {
    /// 全保護根拠・期限・現在の本文hashを検査し、削除予定だけを保存する。
    /// 公開/backup holdは未提供であり、この戻り値を物理削除の許可へ流用しない。
    pub fn plan_blob_cleanup(&mut self, id: Id, budget: CleanupBudget) -> Result<CleanupDecision> {
        let now = blobs::unix_now()?;
        self.plan_at(id, budget, now, |_, _| Ok(()))
    }
    fn plan_at(
        &mut self,
        id: Id,
        budget: CleanupBudget,
        now: i64,
        hook: impl FnMut(Point, &Connection) -> Result<()>,
    ) -> Result<CleanupDecision> {
        let result = self.plan_cleanup_inner(id, budget, now, hook);
        if result.as_ref().is_err_and(|e| {
            !matches!(
                e,
                StorageError::BudgetExceeded | StorageError::Capacity | StorageError::InvalidBlobId
            )
        }) {
            self.failed = true;
        }
        result
    }
    fn plan_cleanup_inner(
        &mut self,
        id: Id,
        budget: CleanupBudget,
        now: i64,
        mut hook: impl FnMut(Point, &Connection) -> Result<()>,
    ) -> Result<CleanupDecision> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if id.kind != Kind::Blob {
            return Err(StorageError::InvalidBlobId);
        }
        if !(0..=253402300799).contains(&now) {
            return Err(StorageError::BudgetExceeded);
        }
        let start = Instant::now();
        let check = || {
            if start.elapsed() >= budget.protection.elapsed {
                Err(StorageError::BudgetExceeded)
            } else {
                Ok(())
            }
        };
        check()?;
        let capacity = self.store.capacity()?;
        if capacity.available
            <= capacity
                .reserved_floor
                .saturating_add(self.reserved)
                .saturating_add(65536)
        {
            return Err(StorageError::Capacity);
        }
        // BEGIN IMMEDIATEで保護の読取りから予定のcommitまで別writerを排除する。
        let tx =
            Transaction::new_unchecked(&self.store.conn, rusqlite::TransactionBehavior::Immediate)?;
        validate(&tx)?;
        let prior = plans(&tx, budget.plans)?;
        let floor:i64=tx.query_row("SELECT max(coalesce((SELECT max(created_at) FROM temporary_blob_holds),0),coalesce((SELECT max(planned_at) FROM blob_cleanup_plans),0))",[],|r|r.get(0))?;
        if now < floor {
            return Err(StorageError::BudgetExceeded);
        }
        let snapshot = protection::collect(&tx, budget.protection, start)?;
        let Some(target) = snapshot.blobs.iter().find(|b| b.blob_id == id) else {
            check()?;
            return Ok(CleanupDecision::Unregistered);
        };
        let Some(length) = target.recorded_length else {
            check()?;
            return Ok(CleanupDecision::Unregistered);
        };
        let live: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM temporary_blob_holds WHERE blob_id=?1 AND expires_at>?2)",
            params![&id.bytes, now],
            |r| r.get(0),
        )?;
        if target.manual_retention_recorded
            || !target.referencing_records.is_empty()
            || !target.known_invalid_records.is_empty()
            || live
        {
            // 正規の保持変更は既に同じtransactionで取り消す。古い予定を有効化しない。
            check()?;
            return Ok(CleanupDecision::Protected);
        }
        if target.temporary_holds.is_empty() {
            return Err(StorageError::Corrupt);
        }
        let dir = blobs::blob_directory(&self.store.dir, "blobs")?;
        let name = blobs::hex(&id.bytes);
        let original = blobs::checked_file(&dir, &name)?;
        let original = fingerprint(&original.metadata()?);
        let (file, _) = blobs::verify_file(&dir, id, Some(length), budget.hash_bytes)?;
        let verified = fingerprint(&file.metadata()?);
        if verified != original {
            return Err(StorageError::Corrupt);
        }
        let pending = prior.into_iter().find(|p| {
            p.blob_id == id && p.cancelled_generation.is_none() && p.completed_generation.is_none()
        });
        let plan = if let Some(plan) = pending {
            let saved: String = tx.query_row(
                "SELECT fingerprint FROM blob_cleanup_plans WHERE plan_id=?1",
                [&plan.plan_id],
                |r| r.get(0),
            )?;
            if saved != verified {
                return Err(StorageError::Corrupt);
            }
            plan
        } else {
            let total: i64 =
                tx.query_row("SELECT count(*) FROM blob_cleanup_plans", [], |r| r.get(0))?;
            if total as u64 >= budget.plans {
                return Err(StorageError::BudgetExceeded);
            }
            let plan_id = Id::random_knowledge()
                .map_err(|_| StorageError::RandomUnavailable)?
                .bytes;
            advance(&tx)?;
            let generation: i64 = tx.query_row(
                "SELECT generation FROM storage_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            tx.execute("INSERT INTO blob_cleanup_plans(plan_id,blob_id,byte_length,planned_at,fingerprint,planned_generation) VALUES(?1,?2,?3,?4,?5,?6)",params![&plan_id,&id.bytes,length as i64,now,&verified,generation])?;
            audit(
                &tx,
                Some(&id.bytes),
                "temporary_blob_expired",
                "blob_cleanup_planned_local_only",
                &plan_reason(&plan_id, now, length as i64, &verified),
            )?;
            BlobCleanupPlan {
                plan_id,
                blob_id: id,
                byte_length: length,
                planned_at: now,
                planned_generation: generation,
                cancelled_generation: None,
                cancellation: None,
                completed_generation: None,
            }
        };
        let expected_generation: i64 = tx.query_row(
            "SELECT generation FROM storage_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        hook(Point::BeforeCommit, &tx)?;
        // 同じconnectionを使う内部変更も最終確認し、hash検査後の実体変更を拒否する。
        let current = blobs::checked_file(&dir, &name)?;
        if fingerprint(&current.metadata()?) != verified
            || fingerprint(&file.metadata()?) != verified
        {
            return Err(StorageError::Corrupt);
        }
        let epochs:(i64,i64,i64)=tx.query_row("SELECT record_epoch,payload_epoch,source_epoch FROM evaluation_state,record_inspection WHERE evaluation_state.singleton=1 AND record_inspection.singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if epochs
            != (
                snapshot.version.record_epoch,
                snapshot.version.payload_epoch,
                snapshot.version.inspection_epoch,
            )
        {
            return Err(StorageError::ProtectionChanged);
        }
        let (generation, namespace): (i64, Vec<u8>) = tx.query_row(
            "SELECT generation,namespace FROM storage_state WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let protected:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM manual_blob_holds WHERE blob_id=?1) OR EXISTS(SELECT 1 FROM temporary_blob_holds WHERE blob_id=?1 AND expires_at>?2) OR EXISTS(SELECT 1 FROM known_invalid WHERE blob_id=?1)",params![&id.bytes,now],|r|r.get(0))?;
        if generation != expected_generation || namespace != snapshot.version.namespace || protected
        {
            return Err(StorageError::ProtectionChanged);
        }
        check()?;
        tx.commit()?;
        hook(Point::AfterCommit, &self.store.conn)?;
        Ok(CleanupDecision::Planned(plan))
    }
}
#[cfg(test)]
#[path = "blob_cleanup_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn cancel_point(pause: Option<bool>, before: bool) -> Result<()> {
    if pause == Some(before) {
        use std::io::Write;
        println!("LNGNB_CANCEL_READY");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
    }
    Ok(())
}

#[path = "blob_cleanup_execution.rs"]
mod execution;
pub use execution::{CleanupExecution, CleanupOutcome};
pub(super) fn pending(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_cleanup_runs WHERE finished_generation IS NULL)",
        [],
        |r| r.get(0),
    )?)
}
