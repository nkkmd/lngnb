//! ローカルCLIと認証済みIPCの完成署名Record保存を共通化する。
//! 局所検査・保存確定は、親評価/本文保持/pin/公開/正常停止とは別。
use super::{RecordWriter, Result};
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

#[cfg(test)]
mod tests;
