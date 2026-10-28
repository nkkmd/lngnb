//! ローカルCLIと認証済みIPCの完成署名Record保存を共通化する。
//! 局所検査・保存確定は、親評価/本文保持/pin/公開/正常停止とは別。
use super::{
    Capacity, EvaluationLimits, PayloadStatus, RecordStore, RecordWriter, Result, StartupState,
    Validation,
};
use crate::{id::Id, record::LocalRecord};

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
