//! R26/R27/R30: 根拠復旧の管理確認。明示再開や公開許可とは分離する。
use super::*;

/// 検査・記録済みの範囲だけを示す。起動完了・親評価完了・再開資格ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceRecoveryReview {
    pub source_generation: i64,
    pub recorded_generation: i64,
    pub checked_evidence: u64,
}
impl RecordStore {
    /// 手動確認待ちの領域で、現在の一次Recordと参照Blobを再検査する。
    /// 管理者が確認した復旧内容と確認できなかった事項を必ず記録する。
    /// 不正根拠・一次データは変更せず、派生評価をdirtyにして待ちを維持する。
    /// 呼出し元のOS認証・表示・明示再開は工程⑤以降で接続する。
    pub fn confirm_evidence_recovery(
        self,
        expected_generation: i64,
        restored: &str,
        unconfirmed: &str,
        limits: EvaluationLimits,
    ) -> Result<EvidenceRecoveryReview> {
        self.confirm_evidence_recovery_inner(
            expected_generation,
            restored,
            unconfirmed,
            limits,
            |_| Ok(()),
        )
    }
    fn confirm_evidence_recovery_inner(
        mut self,
        expected_generation: i64,
        restored: &str,
        unconfirmed: &str,
        limits: EvaluationLimits,
        before_commit: impl FnOnce(&Connection) -> Result<()>,
    ) -> Result<EvidenceRecoveryReview> {
        // 確認画面を見た後の入力変更を、別の確認への承認として扱わない。
        if self.generation()? != expected_generation {
            return Err(StorageError::StaleRecoveryReview);
        }
        if [restored, unconfirmed]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 4096 || s.contains('\0'))
        {
            return Err(StorageError::InvalidRecoveryReview);
        }
        if !self.records_checked || inspection::checkpoint(&self.conn)?.pending() {
            return Err(StorageError::InspectionPending);
        }
        if state(&self.conn)? != StartupState::NeedsReview {
            return Err(StorageError::InvalidRecoveryReview);
        }
        let capacity = self.capacity()?;
        if capacity.available <= capacity.reserved_floor.saturating_add(65536) {
            return Err(StorageError::Capacity);
        }
        // 失敗・drop・kill時にも手動待ちを残す。確認開始自体も重要履歴へ保存。
        transition(&mut self.conn, "running", "begin_evidence_recovery_review")?;
        let started_generation = self.generation()?;
        // 保存済みhash来歴を用いるjob経路ではなく、現在の実体をhashする。
        let computed = self.load_evaluation(limits, Instant::now())?;
        if computed.storage_fault || computed.known.iter().any(|(key, (blob, length))| {
            !computed.nodes.contains_key(key)
                || !matches!(computed.blobs.get(blob), Some(BlobFact::Verified(n)) if n == length)
        }) {
            return Err(StorageError::Corrupt);
        }
        let count = computed.known.len() as u64;
        let reason = crate::cbor::encode(&crate::cbor::Value::Map(vec![
            (
                "source_generation".into(),
                crate::cbor::Value::Int(expected_generation),
            ),
            (
                "checked_evidence".into(),
                crate::cbor::Value::Int(count as i64),
            ),
            (
                "operation".into(),
                crate::cbor::Value::Text("confirm_evidence_recovery".into()),
            ),
            ("restored".into(), crate::cbor::Value::Text(restored.into())),
            (
                "unconfirmed".into(),
                crate::cbor::Value::Text(unconfirmed.into()),
            ),
        ]))
        .map_err(|_| StorageError::InvalidRecoveryReview)?;
        let reason = format!(
            "evidence_recovery_review:{}",
            data_encoding::HEXLOWER.encode(&reason)
        );
        let tx = self.conn.transaction()?;
        advance(&tx)?;
        tx.execute("UPDATE evaluation_state SET dirty=1 WHERE singleton=1", [])?;
        audit(&tx, None, "running", "running", &reason)?;
        before_commit(&tx)?;
        let generation: i64 = tx.query_row(
            "SELECT generation FROM storage_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if generation
            != started_generation
                .checked_add(1)
                .ok_or(StorageError::Corrupt)?
        {
            return Err(StorageError::StaleRecoveryReview);
        }
        computed.validate_evidence(&self.dir, &tx)?;
        tx.commit()?;
        Ok(EvidenceRecoveryReview {
            source_generation: expected_generation,
            recorded_generation: generation,
            checked_evidence: count,
        })
    }
}

#[cfg(test)]
#[path = "recovery_review_tests.rs"]
mod tests;
