//! ローカルCLIと受理側の完成署名Record・管理設定保存を共通化する。
//! 局所検査・保存確定は、親評価/本文保持/pin/公開/正常停止とは別。
use super::{
    Capacity, EvaluationLimits, PayloadStatus, RecordStore, RecordWriter, Result, StartupState,
    Validation,
};
use crate::{id::Id, record::LocalRecord};

/// ローカル管理専用の完全固定指定。公開APIの開示判断や可変参照解決ではない。
#[derive(Debug, Clone, Copy)]
pub struct RevisionRequest {
    knowledge: Id,
    genesis: Id,
    revision: Id,
}
/// 保存済みの元bytesと署名された参照宣言。valid/本文保持/公開を証明しない。
#[derive(Debug)]
pub struct SavedRevision {
    pub record: LocalRecord,
    pub references: crate::record::RevisionReferences,
}
impl RevisionRequest {
    pub fn check(knowledge: Id, genesis: Id, revision: Id) -> crate::Result<Self> {
        use crate::id::Kind;
        if knowledge.kind != Kind::Knowledge || genesis.kind != Kind::Record || revision.kind != Kind::Record {
            return Err(crate::Error::InvalidId);
        }
        Ok(Self { knowledge, genesis, revision })
    }
    /// 同じ排他中の既存読取り（最大2 MiB・ID/署名再検査）を利用する。
    /// 未保持・別種別・三ID不一致はNone。別版・別Genesisへ代替しない。
    /// Genesis/親/由来の参照先を読まず、評価確定・writer取得・finish・手動待ち解除を行わない。
    pub fn inspect(self, store: &RecordStore) -> Result<Option<SavedRevision>> {
        let Some(record) = store.record(self.revision)? else { return Ok(None); };
        if record.kind() != crate::record::RecordKind::Revision { return Ok(None); }
        let references = record.revision_references().map_err(|_| super::StorageError::Corrupt)?;
        if references.knowledge_id != self.knowledge || references.genesis_record_id != self.genesis {
            return Ok(None);
        }
        Ok(Some(SavedRevision { record, references }))
    }
}

/// 内部IPCの要求は完成したRecordの生bytes一つだけ。秘密鍵・パスフレーズは受けない。
pub struct RecordRequest(LocalRecord);
impl RecordRequest {
    pub fn check(bytes: &[u8]) -> crate::Result<Self> {
        LocalRecord::check(bytes, None).map(Self)
    }
    pub fn submit(self, writer: &mut RecordWriter) -> Result<Receipt> {
        store_record(writer, &self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub record_id: Id,
    pub inserted: bool,
}
impl Receipt {
    /// 内部応答: local-only確定1、挿入有無1、Record IDの32bytes。
    /// 元要求のIDとの照合は呼出し側。応答は公開やsession終了の証明ではない。
    pub fn bytes(self) -> [u8; 34] {
        let mut out = [0; 34];
        out[0] = 1;
        out[1] = u8::from(self.inserted);
        out[2..].copy_from_slice(&self.record_id.bytes);
        out
    }
}

/// 検査済み型しか受けず、既存writerの容量/履歴/commit/失敗規則を省略しない。
/// 成功は一件のcommit完了。後段失敗で既存Record/本文を削除しない。
pub fn store_record(writer: &mut RecordWriter, record: &LocalRecord) -> Result<Receipt> {
    Ok(Receipt {
        record_id: record.id(),
        inserted: writer.insert(record)?,
    })
}

/// 全4項目を明示した検査済み要求。内部型でありIPCのwire形式ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigRequest(super::AdminConfig);
impl ConfigRequest {
    pub fn check(config: super::AdminConfig) -> Result<Self> {
        if !config.is_valid() {
            return Err(super::StorageError::BudgetExceeded);
        }
        Ok(Self(config))
    }
    pub fn values(self) -> super::AdminConfig {
        self.0
    }
    /// 停止中の正常領域で、既定予算の全起動検査・保存・正常終了までを行う。
    /// 同じ排他を終始保持し、稼働中IPCへ切り替えない。設定値は今回の検査に適用しない。
    /// 途中失敗では保存済みの可能性があり、正常終了や手動待ち解除を推測しない。
    pub fn save_stopped(self, path: &std::path::Path) -> Result<super::AdminConfig> {
        let mut startup = super::LocalStartup::open(path, super::Limits::default())?;
        if startup.needs_review() {
            return Err(super::StorageError::NeedsReview);
        }
        while !startup
            .step(
                EvaluationLimits::default(),
                super::LocalStartupBudget::default(),
            )?
            .checks_complete()
        {}
        let mut writer = startup.into_writer()?;
        let saved = self.save(&mut writer)?;
        writer.finish()?;
        Ok(saved)
    }
    /// 保存確定だけ。実行時への適用・正常停止・手動待ち解除は行わない。
    pub fn save(self, writer: &mut RecordWriter) -> Result<super::AdminConfig> {
        writer.save_admin_config(self.0)?;
        Ok(self.0)
    }
}

/// 排他中のローカル診断。全件の管理用評価に成功した場合だけ返す。
/// 公開可否・永続評価・復旧確認を表さず、保持実体の件数はopen時の照合結果。
#[derive(Debug)]
pub struct Diagnostic {
    pub generation: i64,
    pub storage_fault: bool,
    pub startup_state: StartupState,
    pub records: usize,
    pub valid: usize,
    pub pending: usize,
    pub invalid: usize,
    pub payload_verified: usize,
    pub payload_missing: usize,
    pub payload_unavailable: usize,
    pub incomplete_staging: usize,
    pub orphaned_blobs: usize,
    pub missing_retained_blobs: usize,
    pub corrupt_retained_blobs: usize,
    pub capacity: Capacity,
}

impl RecordStore {
    /// 既存の同じ排他を使い、writer取得・評価確定・finish・手動待ち解除を行わない。
    /// 予算超過や検査失敗では部分集計を返さない。容量は試料で保存成功保証ではない。
    pub fn diagnose(&self, limits: EvaluationLimits) -> Result<Diagnostic> {
        let (snapshot, storage_fault) = self.diagnostic_evaluation(limits)?;
        let state = self.startup_state()?;
        let capacity = self.capacity()?;
        let recovery = self.blob_recovery();
        let mut diagnostic = Diagnostic {
            generation: snapshot.generation,
            storage_fault,
            startup_state: state,
            records: snapshot.records.len(),
            valid: 0,
            pending: 0,
            invalid: 0,
            payload_verified: 0,
            payload_missing: 0,
            payload_unavailable: 0,
            incomplete_staging: recovery.incomplete_staging.len(),
            orphaned_blobs: recovery.orphaned.len(),
            missing_retained_blobs: recovery.missing.len(),
            corrupt_retained_blobs: recovery.corrupt.len(),
            capacity,
        };
        for record in &snapshot.records {
            match record.validation {
                Validation::Valid => diagnostic.valid += 1,
                Validation::Pending => diagnostic.pending += 1,
                Validation::Invalid => diagnostic.invalid += 1,
            }
            match record.payload_status {
                Some(PayloadStatus::Verified) => diagnostic.payload_verified += 1,
                Some(PayloadStatus::Missing) => diagnostic.payload_missing += 1,
                Some(PayloadStatus::Unavailable) => diagnostic.payload_unavailable += 1,
                None => (),
            }
        }
        Ok(diagnostic)
    }
}

#[cfg(test)]
mod tests;
