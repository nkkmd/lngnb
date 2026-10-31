//! ローカルCLIと受理側の完成署名Record・管理設定保存を共通化する。
//! 局所検査・保存確定は、親評価/本文保持/pin/公開/正常停止とは別。
use super::{
    Capacity, EvaluationLimits, PayloadStatus, RecordStore, RecordWriter, Result, StartupState,
    Validation,
};
use crate::{id::Id, record::LocalRecord};

/// ローカル管理専用の完全固定指定。公開APIの開示判断や可変参照解決ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        if knowledge.kind != Kind::Knowledge
            || genesis.kind != Kind::Record
            || revision.kind != Kind::Record
        {
            return Err(crate::Error::InvalidId);
        }
        Ok(Self {
            knowledge,
            genesis,
            revision,
        })
    }
    /// 同じ排他中の既存読取り（最大2 MiB・ID/署名再検査）を利用する。
    /// 未保持・別種別・三ID不一致はNone。別版・別Genesisへ代替しない。
    /// Genesis/親/由来の参照先を読まず、評価確定・writer取得・finish・手動待ち解除を行わない。
    pub fn inspect(self, store: &RecordStore) -> Result<Option<SavedRevision>> {
        let Some(record) = store.record(self.revision)? else {
            return Ok(None);
        };
        if record.kind() != crate::record::RecordKind::Revision {
            return Ok(None);
        }
        let references = record
            .revision_references()
            .map_err(|_| super::StorageError::Corrupt)?;
        if references.knowledge_id != self.knowledge || references.genesis_record_id != self.genesis
        {
            return Ok(None);
        }
        Ok(Some(SavedRevision { record, references }))
    }
}

/// ローカル保存範囲の明示指定。pin・公開範囲・現在候補を選択しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionInventoryRequest {
    knowledge: Id,
    genesis: Id,
}
/// 一回の全体読取り予算。規範上限や保存総量の制限ではない。
#[derive(Debug, Clone, Copy)]
pub struct RevisionInventoryBudget {
    /// 対象外Genesis/Knowledgeも含む走査Record数と元bytesの合計。
    pub records: u64,
    pub record_bytes: u64,
    /// 選択したRevisionの親と由来の宣言数。両者を履歴辺へ混ぜない。
    pub references: u64,
    pub sql_inspection: super::SqlInspectionBudget,
    pub elapsed: std::time::Duration,
}
impl Default for RevisionInventoryBudget {
    fn default() -> Self {
        Self {
            records: 10_000,
            record_bytes: 64 * 1024 * 1024,
            references: 100_000,
            sql_inspection: super::SqlInspectionBudget::default(),
            elapsed: std::time::Duration::from_secs(60),
        }
    }
}
/// この排他・読取りsnapshot内の保存版。世界の完全履歴やvalidな候補集合ではない。
#[derive(Debug)]
pub struct RevisionInventory {
    pub knowledge_id: Id,
    pub genesis_record_id: Id,
    pub generation: i64,
    /// 生Record ID昇順。局所署名の成功だけで発行鍵/祖先の有効性を認定しない。
    pub revisions: Vec<SavedRevision>,
}
/// 親宣言と保存された参照先の直接照合だけ。祖先有効性の判定ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedParentTarget {
    Missing,
    NotRevision,
    DifferentKnowledge,
    DifferentGenesis,
    DifferentPublisher,
    DirectMatch,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedParentLink {
    pub parent_id: Id,
    pub target: SavedParentTarget,
}
/// 保存範囲内の署名された親宣言。親なし/複数親、子の分岐/先端は宣言数で区別する。
/// 子なしは保存範囲内の宣言上の先端だけで、validな現在候補・公開候補ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRevisionRelations {
    pub revision_id: Id,
    pub parents: Vec<SavedParentLink>,
    /// このscope内で当該IDを親と宣言する版。署名鍵違いの宣言も消さない。
    pub declared_children: Vec<Id>,
}
#[derive(Debug)]
pub struct SavedRevisionHistory {
    pub inventory: RevisionInventory,
    /// 生Revision ID順、各親/子も生ID順。originsはinventory内の別宣言のまま。
    pub relations: Vec<SavedRevisionRelations>,
}
impl RevisionInventoryRequest {
    pub fn check(knowledge: Id, genesis: Id) -> crate::Result<Self> {
        use crate::id::Kind;
        if knowledge.kind != Kind::Knowledge || genesis.kind != Kind::Record {
            return Err(crate::Error::InvalidId);
        }
        Ok(Self { knowledge, genesis })
    }
    /// 同じ排他と一つのread transactionで一次Recordを再検査し、宣言の二IDで選別。
    /// 予算不足/破損/SQL失敗では部分集合を返さない。参照先取得・依存評価・本文検査・
    /// writer/finish・起動cursor更新・手動待ち解除なし。既存openの検査も迂回しない。
    pub fn inspect(
        self,
        store: &RecordStore,
        budget: RevisionInventoryBudget,
    ) -> Result<RevisionInventory> {
        Ok(self.inspect_inner(store, budget, false)?.0)
    }
    /// 一覧と親参照先/子の直接関係を同じtransaction・予算内で取得する。
    /// 全祖先評価・本文/既知不正根拠の再検査・現在候補解決は実行しない。
    pub fn inspect_history(
        self,
        store: &RecordStore,
        budget: RevisionInventoryBudget,
    ) -> Result<SavedRevisionHistory> {
        let (inventory, relations) = self.inspect_inner(store, budget, true)?;
        Ok(SavedRevisionHistory { inventory, relations })
    }
    fn inspect_inner(
        self,
        store: &RecordStore,
        budget: RevisionInventoryBudget,
        with_relations: bool,
    ) -> Result<(RevisionInventory, Vec<SavedRevisionRelations>)> {
        use super::{StorageError, sql_inspection};
        let start = std::time::Instant::now();
        let check = || {
            if start.elapsed() >= budget.elapsed {
                Err(StorageError::BudgetExceeded)
            } else {
                Ok(())
            }
        };
        check()?;
        let tx = store.conn.unchecked_transaction()?;
        let inventory = sql_inspection::run(
            &tx,
            budget.sql_inspection.within(start, budget.elapsed),
            || {
                let generation = store.generation()?;
                let mut revisions = Vec::new();
                let mut targets = std::collections::BTreeMap::new();
                let mut remaining_records = budget.records;
                let mut remaining_bytes = budget.record_bytes;
                let mut remaining_references = budget.references;
                let mut statement =
                    tx.prepare("SELECT id,length(bytes) FROM records ORDER BY id")?;
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    check()?;
                    remaining_records = remaining_records
                        .checked_sub(1)
                        .ok_or(StorageError::BudgetExceeded)?;
                    let raw: Vec<u8> = row.get(0)?;
                    let id = Id {
                        kind: crate::id::Kind::Record,
                        bytes: raw.try_into().map_err(|_| StorageError::Corrupt)?,
                    };
                    let length: i64 = row.get(1)?;
                    if length <= 0 || length > crate::cbor::MAX_RECORD as i64 {
                        return Err(StorageError::Corrupt);
                    }
                    // 不足を検出してから、元bytesを確保する既存読取りへ進む。
                    remaining_bytes = remaining_bytes
                        .checked_sub(length as u64)
                        .ok_or(StorageError::BudgetExceeded)?;
                    let record = store.record(id)?.ok_or(StorageError::Corrupt)?;
                    if with_relations {
                        targets.insert(id.bytes, (record.identity(), record.genesis().map_err(|_| StorageError::Corrupt)?));
                    }
                    if record.kind() != crate::record::RecordKind::Revision {
                        continue;
                    }
                    let identity = record.identity();
                    if identity.knowledge != self.knowledge.bytes
                        || record.genesis().map_err(|_| StorageError::Corrupt)?
                            != self.genesis.bytes
                    {
                        continue;
                    }
                    // 一Recordの抽出はA2の256親/128由来で有界。累積は追加前に検査。
                    let references = record
                        .revision_references()
                        .map_err(|_| StorageError::Corrupt)?;
                    let count =
                        references.parents.len() + references.origins.as_ref().map_or(0, Vec::len);
                    remaining_references = remaining_references
                        .checked_sub(count as u64)
                        .ok_or(StorageError::BudgetExceeded)?;
                    revisions.push(SavedRevision { record, references });
                }
                check()?;
                let relations = if with_relations {
                    saved_relations(&revisions, &targets, &check)?
                } else {
                    Vec::new()
                };
                Ok((RevisionInventory {
                    knowledge_id: self.knowledge,
                    genesis_record_id: self.genesis,
                    generation,
                    revisions,
                }, relations))
            },
        )?;
        // SQL進捗handlerはread群だけ。commit/rollbackへ残さない。
        check()?;
        tx.commit()?;
        check()?;
        Ok(inventory)
    }
}

fn saved_relations(
    revisions: &[SavedRevision],
    targets: &std::collections::BTreeMap<[u8; 32], (crate::record::RecordIdentity, [u8; 32])>,
    check: &impl Fn() -> Result<()>,
) -> Result<Vec<SavedRevisionRelations>> {
    use SavedParentTarget as Target;
    // 全対象は走査件数予算内、親/逆向き子は選択参照予算内。再帰・全祖先探索なし。
    let mut children: std::collections::BTreeMap<_, Vec<Id>> = revisions
        .iter()
        .map(|r| (r.record.id().bytes, Vec::new()))
        .collect();
    let mut relations = Vec::new();
    for revision in revisions {
        check()?;
        let refs = &revision.references;
        let mut parents = Vec::new();
        for parent in &refs.parents {
            check()?;
            let target = match targets.get(&parent.bytes) {
                None => Target::Missing,
                Some((identity, _)) if identity.kind != crate::record::RecordKind::Revision => Target::NotRevision,
                Some((identity, _)) if identity.knowledge != refs.knowledge_id.bytes => Target::DifferentKnowledge,
                Some((_, genesis)) if *genesis != refs.genesis_record_id.bytes => Target::DifferentGenesis,
                Some((identity, _)) if identity.public != revision.record.identity().public => Target::DifferentPublisher,
                Some(_) => Target::DirectMatch,
            };
            parents.push(SavedParentLink { parent_id: *parent, target });
            if let Some(declared) = children.get_mut(&parent.bytes) {
                declared.push(revision.record.id());
            }
        }
        relations.push(SavedRevisionRelations {
            revision_id: revision.record.id(),
            parents,
            declared_children: Vec::new(),
        });
    }
    for relation in &mut relations {
        check()?;
        relation.declared_children = children.remove(&relation.revision_id.bytes)
            .ok_or(super::StorageError::Corrupt)?;
    }
    check()?;
    Ok(relations)
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
