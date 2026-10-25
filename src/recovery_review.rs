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

impl RecordStore {
    /// 最新の根拠復旧確認に続く、管理者の明示操作。ローカル保存writerだけを返す。
    /// confirmationには未確定制限の確認・再適用と、残る障害がないと判断した理由を示す。
    /// 一般配信/公開設定/IPCの再開には使わず、それらの結合は担当工程で追加する。
    pub fn resume_local_writes(
        self,
        review: EvidenceRecoveryReview,
        confirmation: &str,
        limits: EvaluationLimits,
    ) -> Result<RecordWriter> {
        self.resume_local_writes_inner(review, confirmation, limits, |_| Ok(()))
    }
    fn resume_local_writes_inner(
        mut self,
        review: EvidenceRecoveryReview,
        confirmation: &str,
        limits: EvaluationLimits,
        before_commit: impl FnOnce(&Connection) -> Result<()>,
    ) -> Result<RecordWriter> {
        if confirmation.trim().is_empty()
            || confirmation.len() > 4096
            || confirmation.contains('\0')
        {
            return Err(StorageError::InvalidRecoveryReview);
        }
        self.validate_recovery_review(review)?;
        inspection::validate_for_resume(&self)?;
        if state(&self.conn)? != StartupState::NeedsReview {
            return Err(StorageError::InvalidRecoveryReview);
        }
        // 開始印は既にrunningだが、試行開始を永続記録し、失敗時は確認をやり直す。
        transition(&mut self.conn, "running", "begin_explicit_local_resume")?;
        let started_generation = self.generation()?;
        let start = Instant::now();
        let files = self.recovery_files()?;
        if self.scan_blobs()?.needs_review() {
            return Err(StorageError::NeedsReview);
        }
        let mut computed = self.load_evaluation(limits, start)?;
        computed.snapshot.records = evaluate_graph(
            &computed.nodes,
            &computed.blobs,
            &computed.known,
            &computed.budget,
        )?;
        computed.validate_evidence(&self.dir, &self.conn)?;
        if computed.storage_fault
            || computed
                .snapshot
                .records
                .iter()
                .any(|r| r.reason == Some(Reason::EvidenceUnavailable))
        {
            return Err(StorageError::Corrupt);
        }
        if computed.known.len() as u64 != review.checked_evidence {
            return Err(StorageError::StaleRecoveryReview);
        }
        preparation::validate_for_resume(&self, &computed)?;
        if let Some((saved, _)) = blob_preparation::ready(
            &self,
            &computed.nodes,
            &computed.budget,
            computed.record_epoch,
        )? {
            if saved != computed.blobs {
                return Err(StorageError::Corrupt);
            }
        }
        queue::validate_for_resume(&self, &computed)?;
        if self.recovery_files()? != files {
            return Err(StorageError::Corrupt);
        }
        let edges: u64 = computed
            .nodes
            .values()
            .map(|n| n.parents.len() as u64)
            .sum();
        let reserve = (computed.nodes.len() as u64)
            .checked_mul(8192)
            .and_then(|n| edges.checked_mul(256).and_then(|e| n.checked_add(e)))
            .and_then(|n| n.checked_add(131072))
            .ok_or(StorageError::Capacity)?;
        let capacity = self.capacity()?;
        if capacity.available <= capacity.reserved_floor.saturating_add(reserve) {
            return Err(StorageError::Capacity);
        }
        let reason = crate::cbor::encode(&crate::cbor::Value::Map(vec![
            (
                "review_generation".into(),
                crate::cbor::Value::Int(review.recorded_generation),
            ),
            (
                "confirmation".into(),
                crate::cbor::Value::Text(confirmation.into()),
            ),
            (
                "scope".into(),
                crate::cbor::Value::Text("local_storage_writes_only".into()),
            ),
        ]))
        .map_err(|_| StorageError::InvalidRecoveryReview)?;
        // 履歴と現在評価を同じ境界で確定。cleanはここでは記録しない。
        let tx = self.conn.transaction()?;
        if tx.query_row(
            "SELECT generation FROM storage_state WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0),
        )? != started_generation
        {
            return Err(StorageError::StaleRecoveryReview);
        }
        publish(&tx, &mut computed, limits)?;
        advance(&tx)?;
        audit(
            &tx,
            None,
            "running",
            "running",
            &format!(
                "explicit_local_resume:{}",
                data_encoding::HEXLOWER.encode(&reason)
            ),
        )?;
        let final_generation: i64 = tx.query_row(
            "SELECT generation FROM storage_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        before_commit(&tx)?;
        if tx.query_row(
            "SELECT generation FROM storage_state WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0),
        )? != final_generation
        {
            return Err(StorageError::StaleRecoveryReview);
        }
        computed.validate_evidence(&self.dir, &tx)?;
        // txと独立なファイルだけを照合する（別DB接続や再hashは作らない）。
        if blobs::recovery_files(&self.dir, self.limits.scan_blob_files)? != files {
            return Err(StorageError::Corrupt);
        }
        computed.budget.check()?;
        tx.commit()?;
        self.blob_recovery = BlobRecovery::default();
        Ok(RecordWriter::new(self))
    }
    fn validate_recovery_review(&self, review: EvidenceRecoveryReview) -> Result<()> {
        if self.generation()? != review.recorded_generation
            || review.source_generation < 0
            || review.source_generation.checked_add(2) != Some(review.recorded_generation)
        {
            return Err(StorageError::StaleRecoveryReview);
        }
        let reason_length: i64 = self.conn.query_row(
            "SELECT length(reason) FROM history WHERE generation=?1",
            [review.recorded_generation],
            |r| r.get(0),
        )?;
        if !(1..=18025).contains(&reason_length) {
            return Err(StorageError::InvalidRecoveryReview);
        }
        let (target, old, new, reason, rules): (Option<Vec<u8>>, String, String, String, String) =
            self.conn.query_row(
                "SELECT target,old_state,new_state,reason,rules FROM history WHERE generation=?1",
                [review.recorded_generation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        if target.is_some() || old != "running" || new != "running" || rules != "lngnb-validation-1"
        {
            return Err(StorageError::InvalidRecoveryReview);
        }
        let raw = reason
            .strip_prefix("evidence_recovery_review:")
            .ok_or(StorageError::InvalidRecoveryReview)?;
        // 申告文も含めて上限を先に検査。historyを無制限に復号しない。
        if raw.len() > 18000 {
            return Err(StorageError::InvalidRecoveryReview);
        }
        let raw = data_encoding::HEXLOWER
            .decode(raw.as_bytes())
            .map_err(|_| StorageError::InvalidRecoveryReview)?;
        let crate::cbor::Value::Map(fields) =
            crate::cbor::decode(&raw).map_err(|_| StorageError::InvalidRecoveryReview)?
        else {
            return Err(StorageError::InvalidRecoveryReview);
        };
        use crate::cbor::Value;
        let get = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        if fields.len()!=5 || get("operation") != Some(&Value::Text("confirm_evidence_recovery".into()))
            || get("source_generation") != Some(&Value::Int(review.source_generation))
            || get("checked_evidence") != Some(&Value::Int(i64::try_from(review.checked_evidence).map_err(|_| StorageError::InvalidRecoveryReview)?))
            || !["restored","unconfirmed"].iter().all(|key| matches!(get(key), Some(Value::Text(s)) if !s.trim().is_empty() && s.len()<=4096 && !s.contains('\0'))) {
            return Err(StorageError::InvalidRecoveryReview);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "local_resume_tests.rs"]
mod local_resume_tests;
