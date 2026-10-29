//! R20/R24/R26/R27/R30: 保存領域の起動検査から親評価までを同じ排他のまま接続する。
//! ローカル保存用。公開リレーの起動・公開許可・手動解除を提供しない。
use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalStartupBudget {
    pub inspection: InspectionBudget,
    pub records: EvaluationInputBudget,
    pub blobs: EvaluationBlobBudget,
    pub evaluation: EvaluationStepBudget,
}
#[derive(Debug)]
pub enum LocalStartupProgress {
    Inspection(InspectionProgress),
    Records(EvaluationInputProgress),
    Blobs(EvaluationBlobProgress),
    Evaluation(EvaluationProgress),
    Ready,
}
impl LocalStartupProgress {
    /// 起動検査と全対象の評価処理が終了。依存不足解消・公開・手動解除とは別。
    pub fn checks_complete(&self) -> bool {
        matches!(self, Self::Ready) || matches!(self, Self::Evaluation(p) if p.processed_complete)
    }
}
#[derive(Clone, Copy)]
enum Phase {
    Records,
    Blobs,
    Evaluation,
}
enum Stage {
    Inspection(RecordInspection),
    Evaluation(EvaluationJob, Phase),
    Ready(RecordWriter, i64),
}
struct Inputs {
    epochs: (i64, i64, i64),
    files: Vec<(String, String)>,
}
impl Inputs {
    fn capture(s: &RecordStore) -> Result<Self> {
        Ok(Self {
            epochs: Self::epochs(s)?,
            files: s.recovery_files()?,
        })
    }
    fn epochs(s: &RecordStore) -> Result<(i64, i64, i64)> {
        Ok(s.conn.query_row("SELECT source_epoch,record_epoch,payload_epoch FROM record_inspection,evaluation_state WHERE record_inspection.singleton=1 AND evaluation_state.singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?)
    }
    fn validate(&self, s: &RecordStore) -> Result<()> {
        if Self::epochs(s)? != self.epochs || s.recovery_files()? != self.files {
            return Err(StorageError::Corrupt);
        }
        Ok(())
    }
}
/// 各段階の既存cursorを利用し、未完了のwriterを取り出せない統合ハンドル。
/// crashはrunningを残す。pauseは正常なジョブ境界だけで、初期の手動待ちは解除しない。
pub struct LocalStartup {
    stage: Option<Stage>,
    began_clean: bool,
    inputs: Option<Inputs>,
    failed: bool,
}
impl LocalStartup {
    pub fn open(path: &Path, limits: Limits) -> Result<Self> {
        let inspection = RecordInspection::open(path, limits)?;
        Ok(Self::from_inspection(inspection))
    }
    /// 同じ排他中で保存設定を検査し、session件数を明示値→保存値→呼出し側既定の順で選ぶ。
    /// 他の設定は返すだけ。設定保存・手動確認待ち解除はしない。
    pub fn open_with_admin_config(
        path: &Path,
        limits: Limits,
        session_records: Option<u64>,
    ) -> Result<(Self, Option<AdminConfig>)> {
        let mut store = RecordStore::open_locked(path, limits)?;
        let saved = store.saved_admin_config()?;
        store.limits.session_records = session_records
            .or(saved.map(|c| c.max_new_records))
            .unwrap_or(store.limits.session_records);
        store.limits = store.limits.check()?;
        let inspection = RecordInspection::from_store(store)?;
        Ok((Self::from_inspection(inspection), saved))
    }
    fn from_inspection(inspection: RecordInspection) -> Self {
        let began_clean = inspection.began_clean();
        Self {
            stage: Some(Stage::Inspection(inspection)),
            began_clean,
            inputs: None,
            failed: false,
        }
    }
    pub fn needs_review(&self) -> bool {
        !self.began_clean || self.failed
    }
    pub fn step(
        &mut self,
        limits: EvaluationLimits,
        budget: LocalStartupBudget,
    ) -> Result<LocalStartupProgress> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let result = self.step_inner(limits, budget);
        if result.as_ref().is_err_and(|e| {
            !matches!(
                e,
                StorageError::BudgetExceeded
                    | StorageError::Capacity
                    | StorageError::EvaluationInputPending
            )
        }) || self.stage.is_none()
        {
            self.failed = true;
        }
        result
    }
    fn validate_inputs(&self) -> Result<()> {
        let store = match self.stage.as_ref() {
            Some(Stage::Evaluation(job, _)) => job.startup_store(),
            Some(Stage::Ready(writer, generation)) => {
                if writer.store.generation()? != *generation {
                    return Err(StorageError::Corrupt);
                }
                &writer.store
            }
            Some(Stage::Inspection(_)) => return Ok(()),
            None => return Err(StorageError::UnresolvedFailure),
        };
        self.inputs
            .as_ref()
            .ok_or(StorageError::Corrupt)?
            .validate(store)
    }
    fn step_inner(
        &mut self,
        limits: EvaluationLimits,
        budget: LocalStartupBudget,
    ) -> Result<LocalStartupProgress> {
        self.validate_inputs()?;
        match self.stage.as_mut().ok_or(StorageError::UnresolvedFailure)? {
            Stage::Inspection(inspection) => {
                let progress = inspection.step(budget.inspection)?;
                if inspection.recovery_needs_review() {
                    return Err(StorageError::NeedsReview);
                }
                if progress.checks_complete {
                    let Some(Stage::Inspection(inspection)) = self.stage.take() else {
                        unreachable!()
                    };
                    // cleanを挟まず、同じlock/接続を評価段階へ引き渡す。
                    let store = inspection.into_running_store()?;
                    if store.blob_recovery.needs_review() {
                        return Err(StorageError::NeedsReview);
                    }
                    self.inputs = Some(Inputs::capture(&store)?);
                    let job = store.startup_evaluation(self.began_clean)?;
                    self.stage = Some(Stage::Evaluation(job, Phase::Records));
                }
                Ok(LocalStartupProgress::Inspection(progress))
            }
            Stage::Evaluation(job, phase) => {
                let progress = match phase {
                    Phase::Records => {
                        let p = job.prepare(limits, budget.records)?;
                        if p.complete {
                            *phase = Phase::Blobs;
                        }
                        LocalStartupProgress::Records(p)
                    }
                    Phase::Blobs => {
                        let p = job.prepare_blobs(limits, budget.blobs)?;
                        if p.storage_fault {
                            return Err(StorageError::Corrupt);
                        }
                        if p.checks_complete {
                            *phase = Phase::Evaluation;
                        }
                        LocalStartupProgress::Blobs(p)
                    }
                    Phase::Evaluation => {
                        LocalStartupProgress::Evaluation(job.step(limits, budget.evaluation)?)
                    }
                };
                self.validate_inputs()?;
                if progress.checks_complete() {
                    let Some(Stage::Evaluation(job, _)) = self.stage.take() else {
                        unreachable!()
                    };
                    let writer = job.startup_writer()?;
                    let generation = writer.store.generation()?;
                    self.stage = Some(Stage::Ready(writer, generation));
                }
                Ok(progress)
            }
            Stage::Ready(_, _) => Ok(LocalStartupProgress::Ready),
        }
    }
    /// 初めが正常停止で、起動検査・全対象の評価処理が確定した時だけwriterを返す。
    /// 必要親不足はそのままpendingであり、valid・公開を付与しない。
    pub fn into_writer(mut self) -> Result<RecordWriter> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if !self.began_clean {
            return Err(StorageError::NeedsReview);
        }
        self.validate_inputs()?;
        match self.stage.take() {
            Some(Stage::Ready(writer, _)) => {
                inspection::validate_for_resume(&writer.store)?;
                Ok(writer)
            }
            _ => Err(StorageError::InspectionPending),
        }
    }
    /// 正常な中断だけを記録する。検査完了とは呼ばず、開始時の手動待ちも維持する。
    pub fn pause(mut self) -> Result<()> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        self.validate_inputs()?;
        match self.stage.take().ok_or(StorageError::UnresolvedFailure)? {
            Stage::Inspection(inspection) => inspection.pause(),
            Stage::Evaluation(job, _) => job.pause(),
            Stage::Ready(writer, _) if self.began_clean => writer.finish(),
            Stage::Ready(writer, _) => writer
                .store
                .conn
                .close()
                .map_err(|(_, e)| StorageError::Sql(e)),
        }
    }
}

#[cfg(test)]
#[path = "local_startup_tests.rs"]
mod tests;
