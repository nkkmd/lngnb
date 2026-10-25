//! R23/R26/R28: 現在の評価集合・明示保持・既知不正からBlobの保護根拠を集める。
//! 管理用の読取り診断。削除可否・仮保存受付・保持移行・本文hash検査は行わない。
use super::*;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy)]
pub struct ProtectionBudget {
    pub records: u64,
    pub record_bytes: u64,
    pub retained_blobs: u64,
    pub evidence: u64,
    pub targets: u64,
    pub elapsed: Duration,
}
impl Default for ProtectionBudget {
    fn default() -> Self {
        Self {
            records: 10_000,
            record_bytes: 64 * 1024 * 1024,
            retained_blobs: 10_000,
            evidence: 10_000,
            targets: 20_000,
            elapsed: Duration::from_secs(60),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobProtection {
    pub blob_id: Id,
    /// schema 8の台帳は管理者による明示保持。現在の実体の存在や正常性とは別。
    pub manual_retention_recorded: bool,
    pub recorded_length: Option<u64>,
    pub referencing_records: Vec<Id>,
    pub known_invalid_records: Vec<Id>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionVersion {
    pub namespace: [u8; 32],
    pub generation: i64,
    pub record_epoch: i64,
    pub payload_epoch: i64,
    pub inspection_epoch: i64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobProtectionSnapshot {
    pub version: ProtectionVersion,
    /// 生Blob ID順。未掲載は「削除してよい」の意味ではない。
    pub blobs: Vec<BlobProtection>,
}
fn version(conn: &Connection) -> Result<ProtectionVersion> {
    let (ns,g,r,p,i):(Vec<u8>,i64,i64,i64,i64)=conn.query_row("SELECT storage_state.namespace,storage_state.generation,evaluation_state.record_epoch,evaluation_state.payload_epoch,record_inspection.source_epoch FROM storage_state,evaluation_state,record_inspection WHERE storage_state.singleton=1 AND evaluation_state.singleton=1 AND record_inspection.singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
    if [g, r, p, i].iter().any(|n| *n < 0) {
        return Err(StorageError::Corrupt);
    }
    Ok(ProtectionVersion {
        namespace: ns.try_into().map_err(|_| StorageError::Corrupt)?,
        generation: g,
        record_epoch: r,
        payload_epoch: p,
        inspection_epoch: i,
    })
}
fn key(raw: Vec<u8>) -> Result<[u8; 32]> {
    raw.try_into().map_err(|_| StorageError::Corrupt)
}
fn record_id(bytes: [u8; 32]) -> Id {
    Id {
        kind: Kind::Record,
        bytes,
    }
}
fn entry(
    rows: &mut BTreeMap<[u8; 32], BlobProtection>,
    id: [u8; 32],
    limit: u64,
) -> Result<&mut BlobProtection> {
    if !rows.contains_key(&id) && rows.len() as u64 >= limit {
        return Err(StorageError::BudgetExceeded);
    }
    Ok(rows.entry(id).or_insert_with(|| BlobProtection {
        blob_id: Id {
            kind: Kind::Blob,
            bytes: id,
        },
        manual_retention_recorded: false,
        recorded_length: None,
        referencing_records: Vec::new(),
        known_invalid_records: Vec::new(),
    }))
}
impl RecordStore {
    /// 同じDBスナップショットで保護根拠を照合する。一次RecordのID/署名は毎回検査。
    /// 派生評価/索引がdirtyや途中でも、保存した評価集合の本文参照を見落とさない。
    /// 本文の存在/hash、起動検査終了、pin/公開、手動解除、削除資格は示さない。
    pub fn blob_protection(&self, budget: ProtectionBudget) -> Result<BlobProtectionSnapshot> {
        self.protection_inner(budget, || Ok(()))
    }
    fn protection_inner(
        &self,
        budget: ProtectionBudget,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<BlobProtectionSnapshot> {
        let start = Instant::now();
        let check = || {
            if start.elapsed() >= budget.elapsed {
                Err(StorageError::BudgetExceeded)
            } else {
                Ok(())
            }
        };
        check()?;
        let tx = self.conn.unchecked_transaction()?;
        let source = version(&tx)?;
        let mut rows = BTreeMap::new();
        let mut inputs = BTreeMap::new();
        // 派生要約を使わず、一次Recordから全参照を再構成する。
        let mut stmt = tx.prepare("SELECT id,length(bytes) FROM records ORDER BY id")?;
        let mut query = stmt.query([])?;
        let mut bytes = 0u64;
        while let Some(row) = query.next()? {
            check()?;
            if inputs.len() as u64 >= budget.records {
                return Err(StorageError::BudgetExceeded);
            }
            let id = key(row.get(0)?)?;
            let n: i64 = row.get(1)?;
            if !(1..=MAX_RECORD as i64).contains(&n) {
                return Err(StorageError::Corrupt);
            }
            bytes = bytes
                .checked_add(n as u64)
                .ok_or(StorageError::BudgetExceeded)?;
            if bytes > budget.record_bytes {
                return Err(StorageError::BudgetExceeded);
            }
            let record = self.record(record_id(id))?.ok_or(StorageError::Corrupt)?;
            let payload = record.payload().map_err(|_| StorageError::Corrupt)?;
            if let Some((blob, _)) = payload {
                entry(&mut rows, blob, budget.targets)?
                    .referencing_records
                    .push(record_id(id));
            }
            inputs.insert(id, payload);
        }
        drop(query);
        drop(stmt);
        let mut stmt = tx.prepare("SELECT id,byte_length FROM blobs ORDER BY id")?;
        let mut query = stmt.query([])?;
        let mut retained = 0u64;
        while let Some(row) = query.next()? {
            check()?;
            if retained >= budget.retained_blobs {
                return Err(StorageError::BudgetExceeded);
            }
            retained += 1;
            let id = key(row.get(0)?)?;
            let length: i64 = row.get(1)?;
            if length < 0 {
                return Err(StorageError::Corrupt);
            }
            let row = entry(&mut rows, id, budget.targets)?;
            row.manual_retention_recorded = true;
            row.recorded_length = Some(length as u64);
        }
        drop(query);
        drop(stmt);
        let mut stmt=tx.prepare("SELECT record_id,blob_id,actual_length,reason,rules,generation,length(at) FROM known_invalid ORDER BY record_id")?;
        let mut query = stmt.query([])?;
        let mut roots = 0u64;
        while let Some(row) = query.next()? {
            check()?;
            if roots >= budget.evidence {
                return Err(StorageError::BudgetExceeded);
            }
            roots += 1;
            let record = key(row.get(0)?)?;
            let blob = key(row.get(1)?)?;
            let actual: i64 = row.get(2)?;
            let reason: String = row.get(3)?;
            let rules: String = row.get(4)?;
            let generation: i64 = row.get(5)?;
            let at: i64 = row.get(6)?;
            let payload = inputs.get(&record).ok_or(StorageError::Corrupt)?;
            let target = rows.get_mut(&blob).ok_or(StorageError::Corrupt)?;
            if actual < 0
                || reason != "declared_length_mismatch"
                || rules != "lngnb-validation-1"
                || generation < 0
                || generation > source.generation
                || !(1..=64).contains(&at)
                || !payload.is_some_and(|(id, n)| id == blob && n != actual as u64)
                || !target.manual_retention_recorded
                || target.recorded_length != Some(actual as u64)
            {
                return Err(StorageError::Corrupt);
            }
            target.known_invalid_records.push(record_id(record));
        }
        drop(query);
        drop(stmt);
        before_commit()?;
        check()?;
        tx.commit()?;
        // 排他を無視した入力変更も、既に古い集合として成功返却しない。
        if version(&self.conn)? != source {
            return Err(StorageError::ProtectionChanged);
        }
        check()?;
        Ok(BlobProtectionSnapshot {
            version: source,
            blobs: rows.into_values().collect(),
        })
    }
}
impl RecordWriter {
    pub fn blob_protection(&mut self, budget: ProtectionBudget) -> Result<BlobProtectionSnapshot> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.store.blob_protection(budget);
        if result
            .as_ref()
            .is_err_and(|e| !matches!(e, StorageError::BudgetExceeded | StorageError::Capacity))
        {
            self.failed = true;
        }
        result
    }
}
#[cfg(test)]
#[path = "blob_protection_tests.rs"]
mod tests;
