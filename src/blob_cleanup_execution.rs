//! R23/R24/R26/R27/R30: 削除意思を先行確定し、物理削除と台帳確定を明示復旧可能にする。
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    Removed,
    RecoveryRemoved,
    RecoveryAbsent,
}
impl CleanupOutcome {
    fn text(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::RecoveryRemoved => "recovery_removed",
            Self::RecoveryAbsent => "recovery_absent",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "removed" => Ok(Self::Removed),
            "recovery_removed" => Ok(Self::RecoveryRemoved),
            "recovery_absent" => Ok(Self::RecoveryAbsent),
            _ => Err(StorageError::Corrupt),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupExecution {
    pub run_id: [u8; 32],
    pub plan_id: [u8; 32],
    pub blob_id: Id,
    pub finished_generation: Option<i64>,
    pub outcome: Option<CleanupOutcome>,
}
pub(super) fn validate_runs(conn: &Connection) -> Result<()> {
    let bad:bool=conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM blob_cleanup_runs r
            LEFT JOIN blob_cleanup_plans p ON p.plan_id=r.plan_id
            LEFT JOIN history h ON h.generation=r.started_generation
            LEFT JOIN history f ON f.generation=r.finished_generation
            WHERE p.plan_id IS NULL OR length(r.run_id)!=32
               OR r.started_generation<=p.planned_generation
               OR r.started_generation>(SELECT generation FROM storage_state WHERE singleton=1)
               OR p.cancelled_generation IS NOT NULL OR h.generation IS NULL
               OR h.target IS NOT p.blob_id OR h.old_state!='blob_cleanup_planned_local_only'
               OR h.new_state!='blob_cleanup_started_local_only' OR h.rules!='lngnb-validation-1'
               OR h.namespace IS NOT (SELECT namespace FROM storage_state WHERE singleton=1)
               OR h.reason!='start_blob_cleanup:'||lower(hex(r.run_id))||':'||lower(hex(p.plan_id))
               OR (r.finished_generation IS NULL)!=(r.outcome IS NULL)
               OR p.completed_generation IS NOT r.finished_generation
               OR (r.finished_generation IS NOT NULL AND (
                   r.finished_generation<=r.started_generation OR f.generation IS NULL
                   OR r.finished_generation>(SELECT generation FROM storage_state WHERE singleton=1)
                   OR r.outcome NOT IN ('removed','recovery_removed','recovery_absent')
                   OR f.target IS NOT p.blob_id OR f.namespace IS NOT h.namespace
                   OR f.rules!='lngnb-validation-1' OR f.old_state!='blob_cleanup_started_local_only'
                   OR f.new_state!='blob_cleanup_completed_local_only'
                   OR f.reason!='finish_blob_cleanup:'||lower(hex(r.run_id))||':'||lower(hex(p.plan_id))||':'||r.outcome
               ))
        ) OR EXISTS(
            SELECT 1 FROM history h LEFT JOIN blob_cleanup_runs r ON r.started_generation=h.generation
            WHERE h.new_state='blob_cleanup_started_local_only' AND r.run_id IS NULL
        ) OR EXISTS(
            SELECT 1 FROM history h LEFT JOIN blob_cleanup_runs r ON r.finished_generation=h.generation
            WHERE h.new_state='blob_cleanup_completed_local_only' AND r.run_id IS NULL
        )",[],|r|r.get(0))?;
    if bad {
        return Err(StorageError::Corrupt);
    }
    Ok(())
}
fn executions(conn: &Connection, limit: u64) -> Result<Vec<CleanupExecution>> {
    let mut stmt=conn.prepare("SELECT r.run_id,r.plan_id,p.blob_id,r.finished_generation,r.outcome FROM blob_cleanup_runs r JOIN blob_cleanup_plans p ON p.plan_id=r.plan_id ORDER BY r.started_generation")?;
    let mut q = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = q.next()? {
        if out.len() as u64 >= limit {
            return Err(StorageError::BudgetExceeded);
        }
        let outcome: Option<String> = r.get(4)?;
        out.push(CleanupExecution {
            run_id: key(r.get(0)?)?,
            plan_id: key(r.get(1)?)?,
            blob_id: Id {
                kind: Kind::Blob,
                bytes: key(r.get(2)?)?,
            },
            finished_generation: r.get(3)?,
            outcome: outcome.map(|x| CleanupOutcome::parse(&x)).transpose()?,
        });
    }
    Ok(out)
}
fn check(start: Instant, b: CleanupBudget) -> Result<()> {
    if start.elapsed() >= b.protection.elapsed {
        Err(StorageError::BudgetExceeded)
    } else {
        Ok(())
    }
}
fn capacity(s: &RecordStore) -> Result<()> {
    let c = s.capacity()?;
    if c.available <= c.reserved_floor.saturating_add(65536) {
        Err(StorageError::Capacity)
    } else {
        Ok(())
    }
}
fn eligible(
    conn: &Connection,
    p: &BlobCleanupPlan,
    b: CleanupBudget,
    now: i64,
    start: Instant,
) -> Result<ProtectionVersion> {
    check(start, b)?;
    if !(0..=253402300799).contains(&now) || now < p.planned_at {
        return Err(StorageError::BudgetExceeded);
    }
    let floor:i64=conn.query_row("SELECT max(coalesce((SELECT max(created_at) FROM temporary_blob_holds),0),coalesce((SELECT max(planned_at) FROM blob_cleanup_plans),0))",[],|r|r.get(0))?;
    if now < floor {
        return Err(StorageError::BudgetExceeded);
    }
    let s = protection::collect(conn, b.protection, start)?;
    let target = s
        .blobs
        .iter()
        .find(|v| v.blob_id == p.blob_id)
        .ok_or(StorageError::Corrupt)?;
    let live: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM temporary_blob_holds WHERE blob_id=?1 AND expires_at>?2)",
        params![&p.blob_id.bytes, now],
        |r| r.get(0),
    )?;
    if target.recorded_length != Some(p.byte_length)
        || target.manual_retention_recorded
        || !target.referencing_records.is_empty()
        || !target.known_invalid_records.is_empty()
        || target.temporary_holds.is_empty()
        || live
    {
        return Err(StorageError::ProtectionChanged);
    }
    check(start, b)?;
    Ok(s.version)
}
fn selected(conn: &Connection, id: [u8; 32], b: CleanupBudget) -> Result<BlobCleanupPlan> {
    validate(conn)?;
    plans(conn, b.plans)?
        .into_iter()
        .find(|p| p.plan_id == id)
        .ok_or(StorageError::Corrupt)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    BeforeIntentCommit,
    AfterIntentCommit,
    BeforeUnlink,
    AfterUnlink,
    AfterDirectorySync,
    BeforeFinishCommit,
    AfterFinishCommit,
}
fn absent(dir: &OwnedFd, name: &str) -> Result<()> {
    match std::fs::symlink_metadata(anchored(dir, name)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(StorageError::Corrupt),
    }
}
fn finish_run(
    s: &mut RecordStore,
    run: CleanupExecution,
    b: CleanupBudget,
    now: i64,
    recovery: bool,
    start: Instant,
    hook: &mut impl FnMut(Point, &Connection) -> Result<()>,
) -> Result<CleanupExecution> {
    capacity(s)?;
    let tx = Transaction::new_unchecked(&s.conn, rusqlite::TransactionBehavior::Immediate)?;
    let p = selected(&tx, run.plan_id, b)?;
    let current = executions(&tx, b.plans)?
        .into_iter()
        .find(|r| r.run_id == run.run_id)
        .ok_or(StorageError::Corrupt)?;
    if current.finished_generation.is_some() || current.plan_id != p.plan_id {
        return Err(StorageError::Corrupt);
    }
    let input = eligible(&tx, &p, b, now, start)?;
    let dir = blobs::blob_directory(&s.dir, "blobs")?;
    let name = blobs::hex(&p.blob_id.bytes);
    let file = match blobs::checked_file(&dir, &name) {
        Ok(original) => {
            let original = fingerprint(&original.metadata()?);
            let (f, _) = blobs::verify_file(&dir, p.blob_id, Some(p.byte_length), b.hash_bytes)?;
            if fingerprint(&f.metadata()?) != original {
                return Err(StorageError::Corrupt);
            }
            if !recovery {
                let saved: String = tx.query_row(
                    "SELECT fingerprint FROM blob_cleanup_plans WHERE plan_id=?1",
                    [&p.plan_id],
                    |r| r.get(0),
                )?;
                if saved != original {
                    return Err(StorageError::Corrupt);
                }
            }
            Some((f, original))
        }
        Err(StorageError::Io(e)) if recovery && e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    hook(Point::BeforeUnlink, &tx)?;
    if eligible(&tx, &p, b, now, start)? != input {
        return Err(StorageError::ProtectionChanged);
    }
    check(start, b)?;
    let outcome = if let Some((f, identity)) = &file {
        let current = blobs::checked_file(&dir, &name)?;
        if fingerprint(&current.metadata()?) != *identity
            || fingerprint(&f.metadata()?) != *identity
        {
            return Err(StorageError::Corrupt);
        }
        fs::unlinkat(&dir, name.as_str(), fs::AtFlags::empty())?;
        if recovery {
            CleanupOutcome::RecoveryRemoved
        } else {
            CleanupOutcome::Removed
        }
    } else {
        // 不在は、永続化済み意思を現在の根拠で再確認した明示復旧に限る。
        match blobs::checked_file(&dir, &name) {
            Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
            Ok(_) => return Err(StorageError::Corrupt),
        }
        CleanupOutcome::RecoveryAbsent
    };
    hook(Point::AfterUnlink, &tx)?;
    fs::fsync(&dir)?;
    hook(Point::AfterDirectorySync, &tx)?;
    absent(&dir, &name)?;
    if eligible(&tx, &p, b, now, start)? != input {
        return Err(StorageError::ProtectionChanged);
    }
    if tx.execute(
        "DELETE FROM blobs WHERE id=?1 AND byte_length=?2",
        params![&p.blob_id.bytes, p.byte_length as i64],
    )? != 1
    {
        return Err(StorageError::Corrupt);
    }
    advance(&tx)?;
    let generation: i64 = tx.query_row(
        "SELECT generation FROM storage_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    tx.execute(
        "UPDATE blob_cleanup_plans SET completed_generation=?2 WHERE plan_id=?1",
        params![&p.plan_id, generation],
    )?;
    tx.execute(
        "UPDATE blob_cleanup_runs SET finished_generation=?2,outcome=?3 WHERE run_id=?1",
        params![&run.run_id, generation, outcome.text()],
    )?;
    audit(
        &tx,
        Some(&p.blob_id.bytes),
        "blob_cleanup_started_local_only",
        "blob_cleanup_completed_local_only",
        &format!(
            "finish_blob_cleanup:{}:{}:{}",
            blobs::hex(&run.run_id),
            blobs::hex(&p.plan_id),
            outcome.text()
        ),
    )?;
    let expected = protection::version(&tx)?;
    hook(Point::BeforeFinishCommit, &tx)?;
    absent(&dir, &name)?;
    if protection::version(&tx)? != expected {
        return Err(StorageError::ProtectionChanged);
    }
    blobs::validate_holds(&tx)?;
    check(start, b)?;
    tx.commit()?;
    hook(Point::AfterFinishCommit, &s.conn)?;
    Ok(CleanupExecution {
        finished_generation: Some(generation),
        outcome: Some(outcome),
        ..run
    })
}
impl RecordWriter {
    /// 内部ローカル整理。実行意思を確定してからunlinkし、directory fsync後に完了する。
    pub fn execute_blob_cleanup(
        &mut self,
        plan_id: [u8; 32],
        budget: CleanupBudget,
    ) -> Result<CleanupExecution> {
        let now = blobs::unix_now()?;
        self.execute_at(plan_id, budget, now, |_, _| Ok(()))
    }
    fn execute_at(
        &mut self,
        plan_id: [u8; 32],
        b: CleanupBudget,
        now: i64,
        mut hook: impl FnMut(Point, &Connection) -> Result<()>,
    ) -> Result<CleanupExecution> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = (|| {
            if pending(&self.store.conn)? {
                return Err(StorageError::CleanupPending);
            }
            capacity(&self.store)?;
            let start = Instant::now();
            check(start, b)?;
            let tx = Transaction::new_unchecked(
                &self.store.conn,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let p = selected(&tx, plan_id, b)?;
            if p.cancelled_generation.is_some() || p.completed_generation.is_some() {
                return Err(StorageError::ProtectionChanged);
            }
            if p.byte_length
                .checked_mul(2)
                .is_none_or(|n| n > b.hash_bytes)
            {
                return Err(StorageError::BudgetExceeded);
            }
            let input = eligible(&tx, &p, b, now, start)?;
            let dir = blobs::blob_directory(&self.store.dir, "blobs")?;
            let (file, _) = blobs::verify_file(&dir, p.blob_id, Some(p.byte_length), b.hash_bytes)?;
            let identity = fingerprint(&file.metadata()?);
            let saved: String = tx.query_row(
                "SELECT fingerprint FROM blob_cleanup_plans WHERE plan_id=?1",
                [&plan_id],
                |r| r.get(0),
            )?;
            if saved != identity {
                return Err(StorageError::Corrupt);
            }
            let run_id = Id::random_knowledge()
                .map_err(|_| StorageError::RandomUnavailable)?
                .bytes;
            advance(&tx)?;
            tx.execute("INSERT INTO blob_cleanup_runs(run_id,plan_id,started_generation) SELECT ?1,?2,generation FROM storage_state WHERE singleton=1",params![&run_id,&plan_id])?;
            audit(
                &tx,
                Some(&p.blob_id.bytes),
                "blob_cleanup_planned_local_only",
                "blob_cleanup_started_local_only",
                &format!(
                    "start_blob_cleanup:{}:{}",
                    blobs::hex(&run_id),
                    blobs::hex(&plan_id)
                ),
            )?;
            hook(Point::BeforeIntentCommit, &tx)?;
            let current = blobs::checked_file(&dir, &blobs::hex(&p.blob_id.bytes))?;
            if fingerprint(&current.metadata()?) != identity
                || fingerprint(&file.metadata()?) != identity
            {
                return Err(StorageError::Corrupt);
            }
            // 自分の意思記録による世代更新以外に入力が変わっていないことを確認。
            let after = eligible(&tx, &p, b, now, start)?;
            if after.namespace != input.namespace
                || after.record_epoch != input.record_epoch
                || after.payload_epoch != input.payload_epoch
                || after.inspection_epoch != input.inspection_epoch
                || after.generation != input.generation + 1
            {
                return Err(StorageError::ProtectionChanged);
            }
            check(start, b)?;
            tx.commit()?;
            hook(Point::AfterIntentCommit, &self.store.conn)?;
            let run = CleanupExecution {
                run_id,
                plan_id,
                blob_id: p.blob_id,
                finished_generation: None,
                outcome: None,
            };
            let remaining = CleanupBudget {
                hash_bytes: b.hash_bytes - p.byte_length,
                ..b
            };
            finish_run(
                &mut self.store,
                run,
                remaining,
                now,
                false,
                start,
                &mut hook,
            )
        })();
        if result.is_err()
            && (pending(&self.store.conn).unwrap_or(true)
                || result.as_ref().is_err_and(|e| {
                    !matches!(e, StorageError::BudgetExceeded | StorageError::Capacity)
                }))
        {
            self.failed = true;
        }
        result
    }
}
impl RecordStore {
    pub fn blob_cleanup_executions(&self, limit: u64) -> Result<Vec<CleanupExecution>> {
        let tx = self.conn.unchecked_transaction()?;
        validate(&tx)?;
        let out = executions(&tx, limit)?;
        tx.commit()?;
        Ok(out)
    }
    /// 異常終了後の管理者による明示復旧。成功しても手動確認待ちを維持する。
    pub fn recover_blob_cleanup(
        &mut self,
        run_id: [u8; 32],
        budget: CleanupBudget,
        confirmation: &str,
    ) -> Result<CleanupExecution> {
        self.recover_at(run_id, budget, confirmation, blobs::unix_now()?, |_, _| {
            Ok(())
        })
    }
    fn recover_at(
        &mut self,
        run_id: [u8; 32],
        b: CleanupBudget,
        confirmation: &str,
        now: i64,
        mut hook: impl FnMut(Point, &Connection) -> Result<()>,
    ) -> Result<CleanupExecution> {
        if confirmation.trim().is_empty()
            || confirmation.len() > 4096
            || confirmation.contains('\0')
        {
            return Err(StorageError::InvalidRecoveryReview);
        }
        if !self.records_checked || inspection::checkpoint(&self.conn)?.pending() {
            return Err(StorageError::InspectionPending);
        }
        if state(&self.conn)? != StartupState::NeedsReview {
            return Err(StorageError::NeedsReview);
        }
        validate(&self.conn)?;
        let run = executions(&self.conn, b.plans)?
            .into_iter()
            .find(|r| r.run_id == run_id && r.finished_generation.is_none())
            .ok_or(StorageError::Corrupt)?;
        capacity(self)?;
        transition(
            &mut self.conn,
            "running",
            &format!(
                "recover_blob_cleanup:{}:{confirmation}",
                blobs::hex(&run_id)
            ),
        )?;
        let result = finish_run(self, run, b, now, true, Instant::now(), &mut hook)?;
        self.blob_recovery = self.scan_blobs()?;
        Ok(result)
    }
}
#[cfg(test)]
#[path = "blob_cleanup_execution_tests.rs"]
mod tests;
