//! R20/R24/R27/R28/R30: 起動時のRecord局所検査を永続cursorから再開する。
//! 親依存評価キュー・Blobの分割検査・管理者の明示復旧ではない。
use super::*;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct InspectionBudget {
    pub records: u64,
    pub bytes: u64,
    pub elapsed: Duration,
}
impl Default for InspectionBudget {
    fn default() -> Self {
        Self {
            records: 10_000,
            bytes: 64 * 1024 * 1024,
            elapsed: Duration::from_secs(60),
        }
    }
}
/// Record検査と、実装済みの起動整合検査の終了を分離する。公開・pin資格ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectionProgress {
    pub checked_records: u64,
    pub checked_bytes: u64,
    pub records_complete: bool,
    pub checks_complete: bool,
}
#[derive(Debug)]
pub(super) struct Checkpoint {
    epoch: i64,
    phase: String,
    cursor: Option<[u8; 32]>,
    count: i64,
    bytes: i64,
}
impl Checkpoint {
    pub(super) fn pending(&self) -> bool {
        matches!(self.phase.as_str(), "records" | "blobs")
    }
    fn progress(&self) -> InspectionProgress {
        InspectionProgress {
            checked_records: self.count as u64,
            checked_bytes: self.bytes as u64,
            records_complete: matches!(self.phase.as_str(), "blobs" | "complete"),
            checks_complete: self.phase == "complete",
        }
    }
}
/// 再開台帳の型・対象epoch・累計・cursor・完了端点・履歴を整合確認する。
/// SQLの索引走査/SQLite整合検査は署名検査の件数・byte予算とは別である。
pub(super) fn checkpoint(conn: &Connection) -> Result<Checkpoint> {
    let (epoch,phase,raw,count,bytes,generation):(i64,String,Option<Vec<u8>>,i64,i64,Option<i64>)=conn.query_row(
        "SELECT source_epoch,phase,cursor,checked_records,checked_bytes,checkpoint_generation FROM record_inspection WHERE singleton=1",[],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let cursor: Option<[u8; 32]> = raw
        .map(|b| b.try_into().map_err(|_| StorageError::Corrupt))
        .transpose()?;
    if epoch < 0
        || count < 0
        || bytes < 0
        || !["idle", "records", "blobs", "complete"].contains(&phase.as_str())
        || (cursor.is_none() && (count != 0 || bytes != 0))
        || (cursor.is_some() && (count == 0 || bytes == 0))
    {
        return Err(StorageError::Corrupt);
    }
    if phase == "idle" && (cursor.is_some() || generation.is_some()) {
        return Err(StorageError::Corrupt);
    }
    if let Some(id) = cursor {
        let (n, total): (i64, i64) = conn.query_row(
            "SELECT count(*),coalesce(sum(length(bytes)),0) FROM records WHERE id<=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
            [&id],
            |r| r.get(0),
        )?;
        if !exists || n != count || total != bytes {
            return Err(StorageError::Corrupt);
        }
    }
    if matches!(phase.as_str(), "blobs" | "complete") {
        let total: i64 = conn.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
        if total != count {
            return Err(StorageError::Corrupt);
        }
    }
    match generation {
        Some(g) if g >= 0 => {
            let (target, new, reason, old, rules): (
                Option<Vec<u8>>,
                String,
                String,
                String,
                String,
            ) = conn.query_row(
                "SELECT target,new_state,reason,old_state,rules FROM history WHERE generation=?1",
                [g],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            let expected = if phase == "complete" {
                "record_inspection_complete"
            } else {
                "record_inspection_pending"
            };
            if target != cursor.map(|c| c.to_vec())
                || new != expected
                || reason != "record_inspection_checkpoint"
                || old.split(':').nth(1) != Some(format!("epoch={epoch}").as_str())
                || rules != "lngnb-validation-1"
            {
                return Err(StorageError::Corrupt);
            }
        }
        None if phase == "idle" || (phase == "records" && cursor.is_none()) => (),
        _ => return Err(StorageError::Corrupt),
    }
    Ok(Checkpoint {
        epoch,
        phase,
        cursor,
        count,
        bytes,
    })
}
fn save(conn: &mut Connection, old: &Checkpoint, new: &Checkpoint) -> Result<()> {
    let tx = conn.transaction()?;
    advance(&tx)?;
    let changed=tx.execute("UPDATE record_inspection SET phase=?1,cursor=?2,checked_records=?3,checked_bytes=?4,checkpoint_generation=(SELECT generation FROM storage_state WHERE singleton=1) WHERE singleton=1 AND source_epoch=?5",
        params![&new.phase,new.cursor,new.count,new.bytes,new.epoch])?;
    if changed != 1 {
        return Err(StorageError::Corrupt);
    }
    let previous = format!(
        "{}:epoch={}:records={}:bytes={}",
        old.phase, old.epoch, old.count, old.bytes
    );
    let state = if new.phase == "complete" {
        "record_inspection_complete"
    } else {
        "record_inspection_pending"
    };
    audit(
        &tx,
        new.cursor.as_ref().map(|c| c.as_slice()),
        &previous,
        state,
        "record_inspection_checkpoint",
    )?;
    tx.commit()?;
    Ok(())
}
/// 検査専用ハンドル。通常writerを保持せず、未検査のStoreを外へ渡さない。
/// 正常なpauseは位置だけを保存し、未完了の検査を完了/公開再開とは呼ばない。
pub struct RecordInspection {
    store: RecordStore,
    epoch: i64,
    started_clean: bool,
    failed: bool,
    #[cfg(test)]
    pause_before_checkpoint: bool,
}
impl RecordInspection {
    pub fn open(path: &Path, limits: Limits) -> Result<Self> {
        let mut store = RecordStore::open_locked(path, limits)?;
        let started_clean = state(&store.conn)? == StartupState::Clean;
        let old = checkpoint(&store.conn)?;
        // 一般配信/管理変更を許可する前の印。検査cursorを書くだけでも先に確定する。
        transition(&mut store.conn, "running", "begin_record_inspection")?;
        if !old.pending() {
            let new = Checkpoint {
                epoch: old.epoch,
                phase: "records".into(),
                cursor: None,
                count: 0,
                bytes: 0,
            };
            save(&mut store.conn, &old, &new)?;
        }
        Ok(Self {
            store,
            epoch: old.epoch,
            started_clean,
            failed: false,
            #[cfg(test)]
            pause_before_checkpoint: false,
        })
    }
    pub fn progress(&self) -> Result<InspectionProgress> {
        Ok(checkpoint(&self.store.conn)?.progress())
    }
    pub fn step(&mut self, budget: InspectionBudget) -> Result<InspectionProgress> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.step_inner(budget);
        if let Err(ref e) = result {
            if !matches!(e, StorageError::BudgetExceeded | StorageError::Capacity) {
                self.failed = true;
            }
        }
        result
    }
    fn step_inner(&mut self, budget: InspectionBudget) -> Result<InspectionProgress> {
        let start = Instant::now();
        if budget.records == 0 || budget.bytes == 0 || budget.elapsed.is_zero() {
            return Err(StorageError::BudgetExceeded);
        }
        let old = checkpoint(&self.store.conn)?;
        if old.epoch != self.epoch || old.phase == "idle" {
            return Err(StorageError::Corrupt);
        }
        if old.phase == "complete" {
            return Ok(old.progress());
        }
        // 検査位置/履歴の保存は管理用予約領域を使える。測定は書込み成功の保証ではない。
        if self.store.capacity()?.available <= 65536 {
            return Err(StorageError::Capacity);
        }
        let mut new = Checkpoint {
            epoch: old.epoch,
            phase: old.phase.clone(),
            cursor: old.cursor,
            count: old.count,
            bytes: old.bytes,
        };
        if old.phase == "records" {
            let mut n = 0u64;
            let mut total = 0u64;
            loop {
                let next: Option<(Vec<u8>, i64)> = match new.cursor {
                    Some(cursor) => self
                        .store
                        .conn
                        .query_row(
                            "SELECT id,length(bytes) FROM records WHERE id>?1 ORDER BY id LIMIT 1",
                            [cursor],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?,
                    None => self
                        .store
                        .conn
                        .query_row(
                            "SELECT id,length(bytes) FROM records ORDER BY id LIMIT 1",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?,
                };
                let Some((key, length)) = next else {
                    new.phase = "blobs".into();
                    break;
                };
                if key.len() != 32 || length <= 0 || length > MAX_RECORD as i64 {
                    return Err(StorageError::Corrupt);
                }
                if n >= budget.records
                    || length as u64 > budget.bytes - total
                    || start.elapsed() >= budget.elapsed
                {
                    if n == 0 {
                        return Err(StorageError::BudgetExceeded);
                    }
                    break;
                }
                let key: [u8; 32] = key.try_into().map_err(|_| StorageError::Corrupt)?;
                self.store
                    .record(Id {
                        kind: Kind::Record,
                        bytes: key,
                    })?
                    .ok_or(StorageError::Corrupt)?;
                n += 1;
                total += length as u64;
                new.cursor = Some(key);
                new.count = new.count.checked_add(1).ok_or(StorageError::Corrupt)?;
                new.bytes = new.bytes.checked_add(length).ok_or(StorageError::Corrupt)?;
            }
        } else {
            // Blobの分割検査は次の単位。ここは従来のファイル件数/実長予算を守る。
            let check: String = self
                .store
                .conn
                .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            if check != "ok" {
                return Err(StorageError::Corrupt);
            }
            self.store.blob_recovery = self.store.scan_blobs()?;
            if start.elapsed() >= budget.elapsed {
                return Err(StorageError::BudgetExceeded);
            }
            new.phase = "complete".into();
        }
        #[cfg(test)]
        if self.pause_before_checkpoint {
            use std::io::Write;
            println!("LNGNB_RECORD_CHECK_BEFORE_CHECKPOINT");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
        }
        save(&mut self.store.conn, &old, &new)?;
        Ok(new.progress())
    }
    /// ジョブ間の正常停止。開始時からの手動待ちを、検査やpauseの成功で解除しない。
    pub fn pause(mut self) -> Result<()> {
        if self.failed || self.store.blob_recovery.needs_review() {
            return Err(StorageError::UnresolvedFailure);
        }
        checkpoint(&self.store.conn)?;
        if self.started_clean {
            transition(&mut self.store.conn, "clean", "pause_record_inspection")?;
        }
        self.store
            .conn
            .close()
            .map_err(|(_, e)| StorageError::Sql(e))?;
        Ok(())
    }
    /// 実装済みのRecord/Blob起動検査が終了したStoreだけを返す。
    /// 元からの異常終了/根拠欠損の手動待ちを解除する復旧操作ではない。
    pub fn into_store(mut self) -> Result<RecordStore> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if !checkpoint(&self.store.conn)?.progress().checks_complete {
            return Err(StorageError::InspectionPending);
        }
        if self.started_clean && !self.store.blob_recovery.needs_review() {
            transition(&mut self.store.conn, "clean", "finish_record_inspection")?;
        }
        self.store.records_checked = true;
        Ok(self.store)
    }
}

#[cfg(test)]
#[path = "record_inspection_tests.rs"]
mod tests;
