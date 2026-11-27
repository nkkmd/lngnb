//! RecordとBlob本文の公開可否。仕様 §7.2.2〜§7.2.3。

use super::*;

pub(crate) struct FixedRecordState {
    pub namespace: String,
    pub generation: i64,
    pub scope: &'static str,
    pub knowledge: Id,
    pub genesis: Id,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PublicationPermission {
    #[default]
    None,
    Public,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationAnchor {
    Pinned,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DistributionGate {
    #[default]
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordPublication {
    Private,
    Public,
    UntrustedPublic,
}

impl RecordPublication {
    /// 同じ対象の確定済み許可・現在評価・起点を使う。
    /// 現在評価が未確定または未対応なら validation は None。
    /// 手動確認待ち、起動未完了、配信停止、縮小未確定の間は gate を閉じる。
    pub fn assess(
        permission: PublicationPermission,
        validation: Option<Validation>,
        anchor: PublicationAnchor,
        explicitly_stopped: bool,
        gate: DistributionGate,
    ) -> Self {
        if gate == DistributionGate::Closed
            || explicitly_stopped
            || validation != Some(Validation::Valid)
        {
            return Self::Private;
        }

        match (permission, anchor) {
            (PublicationPermission::Public, PublicationAnchor::Pinned) => Self::Public,
            (PublicationPermission::Untrusted, PublicationAnchor::Untrusted) => {
                Self::UntrustedPublic
            }
            _ => Self::Private,
        }
    }
}

/// 対象Recordに対する明示的な手動操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualPublicationChange {
    ApprovePublic,
    ApproveUntrusted,
    Revoke,
}

impl ManualPublicationChange {
    fn as_str(self) -> &'static str {
        match self {
            Self::ApprovePublic => "approve_public",
            Self::ApproveUntrusted => "approve_untrusted",
            Self::Revoke => "revoke",
        }
    }
}

/// 保存済みの許可と停止。現在の配信可否は別途評価する。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SavedPublicationPermission {
    pub permission: PublicationPermission,
    pub explicitly_stopped: bool,
    /// Noneは明示操作の履歴がまだないことを示す。
    pub change_generation: Option<i64>,
}

fn load_permission(conn: &Connection, id: Id) -> Result<Option<SavedPublicationPermission>> {
    if id.kind != Kind::Record {
        return Ok(None);
    }
    let row = conn
        .query_row(
            "SELECT h.generation,p.decision,
                p.record_id IS r.id AND h.namespace=s.namespace AND h.generation<=s.generation
                AND h.new_state IS 'publication_saved_local_only'
         FROM records r CROSS JOIN storage_state s
         LEFT JOIN history h ON h.generation=(
             SELECT generation FROM history WHERE target=r.id
             AND new_state='publication_saved_local_only'
             ORDER BY generation DESC LIMIT 1
         )
         LEFT JOIN publication_changes p ON p.generation=h.generation
         WHERE r.id=?1 AND s.singleton=1",
            [&id.bytes[..]],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((generation, decision, audit_matches)) = row else {
        return Ok(None);
    };
    let (permission, explicitly_stopped) = match (generation, decision.as_deref(), audit_matches) {
        (None, None, false) => (PublicationPermission::None, false),
        (Some(_), Some("approve_public"), true) => (PublicationPermission::Public, false),
        (Some(_), Some("approve_untrusted"), true) => (PublicationPermission::Untrusted, false),
        (Some(_), Some("revoke"), true) => (PublicationPermission::None, true),
        _ => return Err(StorageError::Corrupt),
    };
    Ok(Some(SavedPublicationPermission {
        permission,
        explicitly_stopped,
        change_generation: generation,
    }))
}

/// 空のscope_genesisは通常公開、32 bytesは未確認公開のGenesisを表す。
fn advance_disclosure(tx: &Transaction<'_>, knowledge: &[u8; 32], scope: &[u8]) -> Result<()> {
    if tx.execute(
        "UPDATE disclosure_generations SET generation=generation+1
         WHERE knowledge_id=?1 AND scope_genesis=?2",
        params![knowledge, scope],
    )? == 0
    {
        let mut namespace = [0u8; 32];
        getrandom::getrandom(&mut namespace).map_err(|_| StorageError::RandomUnavailable)?;
        tx.execute(
            "INSERT INTO disclosure_generations(knowledge_id,scope_genesis,namespace,generation)
             VALUES(?1,?2,?3,1)",
            params![knowledge, scope, namespace],
        )?;
    }
    Ok(())
}

/// 公開Revisionの祖先だけをたどる。非公開の中間版は候補に含めない。
fn replace_disclosure_heads(
    tx: &Transaction<'_>,
    knowledge: &[u8; 32],
    scope: &[u8],
    limits: Limits,
    started: std::time::Instant,
) -> Result<()> {
    let budget = limits
        .sql_inspection
        .within(started, limits.sql_inspection.elapsed);
    let heads = sql_inspection::run(tx, budget, || {
        let mut stmt = tx.prepare(
            "WITH RECURSIVE members(id) AS MATERIALIZED (
                SELECT record_id FROM disclosure_records WHERE knowledge_id=?1
                AND visible_scope=?2 AND record_id<>genesis LIMIT ?3
             ), ancestors(id) AS (
                SELECT p.parent FROM members m CROSS JOIN parent_edges p ON p.child=m.id
                UNION
                SELECT p.parent FROM ancestors a CROSS JOIN parent_edges p ON p.child=a.id LIMIT ?3
             )
             SELECT NULL WHERE (SELECT count(*) FROM members)>=?3
                OR (SELECT count(*) FROM ancestors)>=?3
             UNION ALL SELECT id FROM (SELECT id FROM members EXCEPT SELECT id FROM ancestors)",
        )?;
        let limit = i64::try_from(limits.scan_records)
            .unwrap_or(i64::MAX)
            .saturating_add(1);
        let mut rows = stmt.query(params![knowledge, scope, limit])?;
        let mut heads = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Option<[u8; 32]> = row.get(0)?;
            heads.push(id.ok_or(StorageError::BudgetExceeded)?);
        }
        Ok(heads)
    })?;
    tx.execute(
        "DELETE FROM disclosure_heads WHERE knowledge_id=?1 AND scope_genesis=?2",
        params![knowledge, scope],
    )?;
    let mut insert = tx.prepare("INSERT INTO disclosure_heads VALUES(?1,?2,?3)")?;
    for id in heads {
        if started.elapsed() >= limits.sql_inspection.elapsed {
            return Err(StorageError::BudgetExceeded);
        }
        insert.execute(params![knowledge, scope, id])?;
    }
    Ok(())
}

impl RecordStore {
    /// 前回確定した公開範囲と比較する。評価待ちの間は新しい公開範囲を採用しない。
    pub(super) fn refresh_disclosures(
        &self,
        tx: &Transaction<'_>,
        knowledge: Option<Id>,
        record: Option<Id>,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let dirty: bool = tx.query_row(
            "SELECT dirty FROM evaluation_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let mut changed = std::collections::BTreeSet::new();
        let mut membership_changed = std::collections::BTreeSet::new();
        let mut updates = Vec::new();
        {
            let (selector, key) = if let Some(id) = record {
                (" WHERE record_id=?1", Some(id.bytes))
            } else if let Some(id) = knowledge {
                (" WHERE knowledge_id=?1", Some(id.bytes))
            } else {
                ("", None)
            };
            let sql = format!(
                "SELECT record_id,knowledge_id,genesis,visible_scope,visible_payload,visible_reason FROM disclosure_records{selector}"
            );
            let mut stmt = tx.prepare(&sql)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(key.iter()))?;
            let mut count = 0;
            while let Some(row) = rows.next()? {
                count += 1;
                if count > self.limits.scan_records
                    || started.elapsed() >= self.limits.sql_inspection.elapsed
                {
                    return Err(StorageError::BudgetExceeded);
                }
                let id = Id {
                    kind: Kind::Record,
                    bytes: row.get(0)?,
                };
                let knowledge = Id {
                    kind: Kind::Knowledge,
                    bytes: row.get(1)?,
                };
                let genesis: [u8; 32] = row.get(2)?;
                let old: Option<Vec<u8>> = row.get(3)?;
                let new = if dirty {
                    // 直近の確定範囲は維持できるが、失効した根拠だけは直ちに外す。
                    let permission = load_permission(tx, id)?.ok_or(StorageError::Corrupt)?;
                    let pinned = self
                        .saved_pin(knowledge)?
                        .is_some_and(|pin| pin.bytes == genesis);
                    match (permission.permission, pinned, old.as_deref()) {
                        (PublicationPermission::Public, true, Some([])) => old.clone(),
                        (PublicationPermission::Untrusted, false, Some(scope))
                            if scope == genesis =>
                        {
                            old.clone()
                        }
                        _ => None,
                    }
                } else {
                    match self.assess_record_publication(id, DistributionGate::Open, None)? {
                        Some((class, record)) => {
                            if record.identity().knowledge != knowledge.bytes
                                || record.genesis().map_err(|_| StorageError::Corrupt)? != genesis
                            {
                                return Err(StorageError::Corrupt);
                            }
                            match class {
                                RecordPublication::Public => Some(Vec::new()),
                                RecordPublication::UntrustedPublic => Some(genesis.to_vec()),
                                RecordPublication::Private => None,
                            }
                        }
                        None => None,
                    }
                };
                let old_payload: (Option<String>, Option<String>) = (row.get(4)?, row.get(5)?);
                let new_payload = if new.is_none() {
                    (None, None)
                } else if dirty {
                    old_payload.clone()
                } else {
                    tx.query_row(
                        "SELECT payload,CASE WHEN payload='unavailable' AND payload_reason IN
                         ('transfer_hash_mismatch','transfer_failed','storage_corruption')
                         THEN payload_reason END FROM evaluations WHERE record_id=?1",
                        [&id.bytes],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?
                };
                if old != new || old_payload != new_payload {
                    for scope in old.iter().chain(new.iter()) {
                        changed.insert((knowledge.bytes, scope.clone()));
                        if old != new {
                            membership_changed.insert((knowledge.bytes, scope.clone()));
                        }
                    }
                    updates.push((id.bytes, knowledge.bytes, genesis, old, new, new_payload));
                }
            }
        }
        for (knowledge, scope) in changed {
            advance_disclosure(tx, &knowledge, &scope)?;
        }
        for (id, knowledge, genesis, old, new, (payload, reason)) in updates {
            tx.execute(
                "UPDATE disclosure_records SET visible_scope=?1,visible_payload=?2,visible_reason=?3 WHERE record_id=?4",
                params![new, payload, reason, id],
            )?;
            // 移動元には非開示への変更、移動先には新たな開示内容だけを記録する。
            let removed = old.as_ref().filter(|scope| Some(*scope) != new.as_ref());
            for scope in removed.into_iter().chain(new.as_ref()) {
                let visible = Some(scope) == new.as_ref();
                if tx.execute(
                    "INSERT INTO disclosure_history(namespace,generation,record_id,genesis,visible,payload,reason,rules)
                     SELECT namespace,generation,?3,?4,?5,CASE WHEN ?5 THEN ?6 END,
                     CASE WHEN ?5 THEN ?7 END,'lngnb-validation-1' FROM disclosure_generations
                     WHERE knowledge_id=?1 AND scope_genesis=?2",
                    params![knowledge, scope, id, genesis, visible, payload, reason],
                )? != 1
                {
                    return Err(StorageError::Corrupt);
                }
            }
        }
        for (knowledge, scope) in membership_changed {
            replace_disclosure_heads(tx, &knowledge, &scope, self.limits, started)?;
        }
        Ok(())
    }

    /// 停止中の保存領域について、固定Record本体の配信可否を読み取る。
    /// gate は呼び出し側の運用制限。結果はこの読取り時点の判定で、送信許可証にはならない。
    pub fn record_publication(&self, id: Id, gate: DistributionGate) -> Result<RecordPublication> {
        let snapshot = self.conn.unchecked_transaction()?;
        let publication = if self.startup_state()? == StartupState::Clean {
            self.assess_record_publication(id, gate, None)?
                .map_or(RecordPublication::Private, |(publication, _)| publication)
        } else {
            RecordPublication::Private
        };
        snapshot.commit()?;
        Ok(publication)
    }

    fn assess_record_publication(
        &self,
        id: Id,
        gate: DistributionGate,
        genesis_id: Option<Id>,
    ) -> Result<Option<(RecordPublication, LocalRecord)>> {
        if gate == DistributionGate::Closed || id.kind != Kind::Record {
            return Ok(None);
        }
        let valid = self.conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM evaluations e
                JOIN evaluation_state v ON v.singleton=1
                JOIN history h ON h.generation=v.generation
                JOIN storage_state s ON s.singleton=1 AND s.namespace=h.namespace
                WHERE e.record_id=?1 AND e.validation='valid' AND v.dirty=0
                  AND h.new_state='evaluated_local_only' AND h.rules='lngnb-validation-1'
                  AND h.generation<=s.generation
                  AND NOT EXISTS (SELECT 1 FROM known_invalid k WHERE k.record_id=e.record_id)
            )",
            [&id.bytes],
            |row| row.get::<_, bool>(0),
        )?;
        if !valid {
            return Ok(None);
        }

        let permission = load_permission(&self.conn, id)?.ok_or(StorageError::Corrupt)?;
        let record = self.record(id)?.ok_or(StorageError::Corrupt)?;
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: record.identity().knowledge,
        };
        let genesis = record.genesis().map_err(|_| StorageError::Corrupt)?;
        let anchor = match self.saved_pin(knowledge)? {
            Some(pin) if pin.bytes == genesis => PublicationAnchor::Pinned,
            _ => PublicationAnchor::Untrusted,
        };
        if genesis_id.is_some_and(|expected| expected.bytes != genesis) {
            return Ok(None);
        }
        let publication = RecordPublication::assess(
            permission.permission,
            Some(Validation::Valid),
            anchor,
            permission.explicitly_stopped,
            gate,
        );
        Ok(Some((publication, record)))
    }

    /// 既存Recordの許可を返す。対象がなければNone。
    pub fn saved_publication_permission(
        &self,
        id: Id,
    ) -> Result<Option<SavedPublicationPermission>> {
        load_permission(&self.conn, id)
    }
}

/// 固定Record取得で指定できる公開経路。仕様 A4.2。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedRecordScope {
    Public { genesis_id: Option<Id> },
    Untrusted { genesis_id: Id },
}

impl FixedRecordScope {
    fn publication_target(self) -> (RecordPublication, Option<Id>) {
        match self {
            Self::Public { genesis_id } => (RecordPublication::Public, genesis_id),
            Self::Untrusted { genesis_id } => {
                (RecordPublication::UntrustedPublic, Some(genesis_id))
            }
        }
    }
}

impl RecordStore {
    pub(super) fn current_disclosure(
        &self,
        tx: &Transaction<'_>,
        knowledge: Id,
        scope: FixedRecordScope,
        key: &[u8],
    ) -> Result<Option<(Id, [u8; 32], i64)>> {
        let requested = scope.publication_target().1;
        let row = tx
            .query_row(
                "SELECT r.genesis,g.namespace,g.generation FROM disclosure_records r
                     JOIN disclosure_generations g ON g.knowledge_id=r.knowledge_id
                     AND g.scope_genesis=r.visible_scope
                     JOIN evaluation_state v ON v.singleton=1
                     JOIN history h ON h.generation=v.generation
                     JOIN storage_state s ON s.singleton=1 AND s.namespace=h.namespace
                     WHERE r.knowledge_id=?1 AND r.visible_scope=?2
                     AND h.new_state='evaluated_local_only' AND h.rules='lngnb-validation-1'
                     AND h.generation<=s.generation LIMIT 1",
                params![knowledge.bytes, key],
                |r| {
                    Ok((
                        r.get::<_, [u8; 32]>(0)?,
                        r.get::<_, [u8; 32]>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((bytes, ns, generation)) = row else {
            return Ok(None);
        };
        let genesis = Id {
            kind: Kind::Record,
            bytes,
        };
        if requested.is_some_and(|id| id != genesis)
            || (self.saved_pin(knowledge)? == Some(genesis)) != key.is_empty()
        {
            return Ok(None);
        }
        // 非公開行の追加で立つ全体dirtyは使わない。確定済みの有効な版も、
        // 自身または祖先に新しい長さ不一致の根拠があれば提示を止める。
        let blocked: bool = tx.query_row(
            "WITH RECURSIVE deps(id) AS (
                       SELECT record_id FROM disclosure_records WHERE knowledge_id=?1
                       AND visible_scope=?2 AND genesis=?3
                       UNION SELECT p.parent FROM deps d CROSS JOIN parent_edges p ON p.child=d.id
                     ) SELECT EXISTS(SELECT 1 FROM deps d
                       LEFT JOIN evaluations e ON e.record_id=d.id
                       LEFT JOIN blob_objects b ON b.id=e.payload_blob
                       LEFT JOIN known_invalid k ON k.record_id=d.id
                       WHERE e.validation IS NOT 'valid' OR k.record_id IS NOT NULL
                       OR b.byte_length<>e.declared_length)",
            params![knowledge.bytes, key, bytes],
            |r| r.get(0),
        )?;
        if blocked {
            return Ok(None);
        }
        Ok(Some((genesis, ns, generation)))
    }
}

impl RecordWriter {
    /// 排他writerの下で確定した公開集合とその依存だけを照合する。
    pub(crate) fn knowledge_response(
        &mut self,
        knowledge: Id,
        scope: FixedRecordScope,
        gate: DistributionGate,
        resolve: bool,
    ) -> Result<Option<String>> {
        if gate == DistributionGate::Closed
            || !self.began_clean
            || self.failed
            || self.publication_block.is_some()
            || self.store.blob_recovery.needs_review()
        {
            return Ok(None);
        }
        let result = (|| {
            let tx = self.store.conn.unchecked_transaction()?;
            let body = sql_inspection::run(&tx, self.store.limits.sql_inspection, || {
                let (key, label): (&[u8], _) = match &scope {
                    FixedRecordScope::Public { .. } => (&[], "public"),
                    FixedRecordScope::Untrusted { genesis_id } => (&genesis_id.bytes, "untrusted"),
                };
                let Some((genesis, ns, generation)) =
                    self.store.current_disclosure(&tx, knowledge, scope, key)?
                else {
                    return Ok(None);
                };
                let bytes = genesis.bytes;
                let sql = if resolve {
                    "SELECT h.record_id,r.visible_payload,r.visible_reason,
                       CASE WHEN b.id IS NULL THEN
                         (r.visible_payload='missing' AND f.reason IS NULL) OR
                         (r.visible_payload='unavailable' AND r.visible_reason IS f.reason)
                       ELSE r.visible_payload='verified' OR
                         (r.visible_payload='unavailable' AND r.visible_reason='storage_corruption') END
                     FROM disclosure_heads h
                     LEFT JOIN disclosure_records r ON r.record_id=h.record_id
                       AND r.knowledge_id=h.knowledge_id AND r.visible_scope=h.scope_genesis AND r.genesis=?3
                     LEFT JOIN evaluations e ON e.record_id=r.record_id
                     LEFT JOIN blobs b ON b.id=e.payload_blob
                     LEFT JOIN blob_failures f ON f.id=e.payload_blob
                     WHERE h.knowledge_id=?1 AND h.scope_genesis=?2 ORDER BY h.record_id"
                } else {
                    "SELECT record_id FROM disclosure_heads WHERE knowledge_id=?1
                     AND scope_genesis=?2 ORDER BY record_id"
                };
                let mut stmt = tx.prepare(sql)?;
                let mut heads = Vec::new();
                let mut revisions = Vec::new();
                let mut rows = if resolve {
                    stmt.query(params![knowledge.bytes, key, bytes])?
                } else {
                    stmt.query(params![knowledge.bytes, key])?
                };
                while let Some(row) = rows.next()? {
                    if heads.len() as u64 >= self.store.limits.scan_records {
                        return Err(StorageError::BudgetExceeded);
                    }
                    let id = Id {
                        kind: Kind::Record,
                        bytes: row.get(0)?,
                    }
                    .to_string();
                    if resolve {
                        let payload: String = row.get(1)?;
                        let reason: Option<String> = row.get(2)?;
                        if !row.get::<_, Option<bool>>(3)?.unwrap_or(false) {
                            return Err(StorageError::EvaluationInputPending);
                        }
                        revisions.push(serde_json::json!({
                            "revision_id":id, "record_validation":"valid",
                            "publisher_verified":key.is_empty(), "payload_status":payload,
                            "reasons":reason.into_iter().collect::<Vec<_>>()
                        }));
                    }
                    heads.push(id);
                }
                let namespace = format!(
                    "ns1_{}",
                    data_encoding::BASE32_NOPAD.encode(&ns).to_ascii_lowercase()
                );
                let mut state = serde_json::json!({"namespace":namespace,"generation":generation.to_string(),"scope":label});
                if !key.is_empty() {
                    state["candidate_genesis_id"] = genesis.to_string().into();
                }
                if resolve {
                    let status = match heads.len() {
                        0 => "none",
                        1 => "single",
                        _ => "multiple",
                    };
                    let evaluated_at: String =
                        tx.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| {
                            r.get(0)
                        })?;
                    // この経路で状態案内できるのは現在許可したvalidな候補だけ。
                    // 同期元の一般開示は未接続なので観測を含めない。
                    return Ok(Some(serde_json::json!({
                        "api_version":"lngnb-http-1", "record_profile":crate::record::PROFILE,
                        "knowledge_id":knowledge.to_string(), "local_state":state, "evaluated_at":evaluated_at,
                        "resolution":{"status":status,"heads":heads,"scope":label,"genesis_record_id":genesis.to_string(),"has_pending_candidates":false},
                        "verification":{"rules_version":"lngnb-validation-1","trust_anchor":if key.is_empty() { "pinned" } else { "untrusted" },
                            "local_operation":"normal","revisions":revisions},
                        "completeness":{"world_complete":false,"scopes":[]}, "freshness":{"sources":[]}
                    }).to_string()));
                }
                Ok(Some(serde_json::json!({"api_version":"lngnb-http-1","knowledge_id":knowledge.to_string(),
                    "scope":label,"local_state":state,"genesis_record_id":genesis.to_string(),
                    "publisher_verified":key.is_empty(),"trust_anchor":if key.is_empty() { "pinned" } else { "untrusted" },"heads":heads}).to_string()))
            })?;
            tx.commit()?;
            Ok(body)
        })();
        if result.is_err()
            && !matches!(
                result,
                Err(StorageError::BudgetExceeded | StorageError::EvaluationInputPending)
            )
        {
            self.failed = true;
        }
        result
    }

    /// 排他writerを保持したまま固定Recordの配信可否を判定して送信する。
    /// 呼び出し側はゲートの変更を同じ所有者で直列化し、指定経路へ期限付きで同期送信する。
    pub fn send_record(
        &mut self,
        id: Id,
        gate: DistributionGate,
        route: PublicationPermission,
        send: impl FnOnce(&[u8]) -> std::io::Result<()>,
    ) -> Result<bool> {
        self.send_record_in_scope(id, gate, route, None, send)
    }

    /// 取得要求のGenesisを現在の評価・公開許可と同じ保存世代で照合する。
    /// 呼び出し側は要求IDの種類を検査し、期限付きで同期送信する。
    pub fn send_fixed_record(
        &mut self,
        id: Id,
        gate: DistributionGate,
        scope: FixedRecordScope,
        send: impl FnOnce(&[u8]) -> std::io::Result<()>,
    ) -> Result<bool> {
        let (route, genesis_id) = match scope {
            FixedRecordScope::Public { genesis_id } => (PublicationPermission::Public, genesis_id),
            FixedRecordScope::Untrusted { genesis_id } => {
                (PublicationPermission::Untrusted, Some(genesis_id))
            }
        };
        if genesis_id.is_some_and(|genesis| genesis.kind != Kind::Record) {
            return Ok(false);
        }
        self.send_record_in_scope(id, gate, route, genesis_id, send)
    }

    fn send_record_in_scope(
        &mut self,
        id: Id,
        gate: DistributionGate,
        route: PublicationPermission,
        genesis_id: Option<Id>,
        send: impl FnOnce(&[u8]) -> std::io::Result<()>,
    ) -> Result<bool> {
        if !self.began_clean
            || self.failed
            || self.publication_block == Some(id)
            || self.store.blob_recovery.needs_review()
        {
            return Ok(false);
        }

        let result: Result<_> = (|| {
            let snapshot = self.store.conn.unchecked_transaction()?;
            let assessment = self.store.assess_record_publication(id, gate, genesis_id)?;
            snapshot.commit()?;
            Ok(assessment)
        })();
        if result.is_err() {
            self.failed = true;
        }
        let Some((publication, record)) = result? else {
            return Ok(false);
        };
        if !matches!(
            (publication, route),
            (RecordPublication::Public, PublicationPermission::Public)
                | (
                    RecordPublication::UntrustedPublic,
                    PublicationPermission::Untrusted
                )
        ) {
            return Ok(false);
        }
        send(record.bytes()).map_err(StorageError::Io)?;
        Ok(true)
    }

    pub(crate) fn send_fixed_representation(
        &mut self,
        id: Id,
        gate: DistributionGate,
        scope: FixedRecordScope,
        verification: bool,
        send: impl FnOnce(&[u8], Option<&FixedRecordState>) -> std::io::Result<()>,
    ) -> Result<bool> {
        if !self.began_clean
            || self.failed
            || self.publication_block == Some(id)
            || self.store.blob_recovery.needs_review()
        {
            return Ok(false);
        }
        let result: Result<_> = (|| {
            let tx = self.store.conn.unchecked_transaction()?;
            let (expected, requested) = scope.publication_target();
            let assessed = self.store.assess_record_publication(id, gate, requested)?;
            let Some((_, record)) = assessed.filter(|(class, _)| *class == expected) else {
                return Ok(None);
            };
            let genesis = Id {
                kind: Kind::Record,
                bytes: record.genesis().map_err(|_| StorageError::Corrupt)?,
            };
            let knowledge = Id {
                kind: Kind::Knowledge,
                bytes: record.identity().knowledge,
            };
            let (label, anchor, key): (_, _, &[u8]) = match scope {
                FixedRecordScope::Public { .. } => ("public", "pinned", &[]),
                FixedRecordScope::Untrusted { .. } => ("untrusted", "untrusted", &genesis.bytes),
            };
            let (ns, generation, payload, reason) = tx.query_row(
                "SELECT g.namespace,g.generation,r.visible_payload,r.visible_reason
                 FROM disclosure_records r JOIN disclosure_generations g
                 ON g.knowledge_id=r.knowledge_id AND g.scope_genesis=r.visible_scope
                 WHERE r.record_id=?1 AND r.knowledge_id=?2 AND r.genesis=?3 AND r.visible_scope=?4",
                params![id.bytes,knowledge.bytes,genesis.bytes,key],
                |r| Ok((r.get::<_,[u8;32]>(0)?, r.get::<_,i64>(1)?, r.get::<_,Option<String>>(2)?, r.get::<_,Option<String>>(3)?)),
            )?;
            let namespace = format!(
                "ns1_{}",
                data_encoding::BASE32_NOPAD.encode(&ns).to_ascii_lowercase()
            );
            let body = verification.then(|| {
                let mut state = serde_json::json!({"namespace": namespace, "generation": generation.to_string(), "scope": label});
                if label == "untrusted" {
                    state["candidate_genesis_id"] = genesis.to_string().into();
                }
                serde_json::json!({
                    "api_version":"lngnb-http-1", "record_id":id.to_string(), "knowledge_id":knowledge.to_string(),
                    "genesis_record_id":genesis.to_string(), "local_state":state, "record_validation":"valid",
                    "rules_version":"lngnb-validation-1", "trust_anchor":anchor, "payload_status":payload,
                    "reasons":reason.into_iter().collect::<Vec<_>>(),
                    "evaluation_ref":format!("lngnb-eval:1:{namespace}:{knowledge}:{label}:{genesis}:{generation}")
                }).to_string()
            });
            let state = FixedRecordState {
                namespace,
                generation,
                scope: label,
                knowledge,
                genesis,
            };
            tx.commit()?;
            Ok(Some((record, state, body)))
        })();
        if result.is_err() {
            self.failed = true;
        }
        let Some((record, state, body)) = result? else {
            return Ok(false);
        };
        match body {
            Some(body) => send(body.as_bytes(), None),
            None => send(record.bytes(), Some(&state)),
        }
        .map_err(StorageError::Io)?;
        Ok(true)
    }

    /// 指定Revisionを公開根拠として照合し、検査済み本文だけを同期送信処理に渡す。
    /// Revisionは内部で選んだ候補。候補の列挙と通信の処理予算は呼び出し側で管理する。
    pub fn send_blob_from_revision(
        &mut self,
        blob_id: Id,
        revision: Id,
        gate: DistributionGate,
        scope: FixedRecordScope,
        send: impl FnOnce(&mut std::fs::File, u64) -> std::io::Result<()>,
    ) -> Result<bool> {
        let (expected, genesis) = scope.publication_target();
        if blob_id.kind != Kind::Blob
            || genesis.is_some_and(|id| id.kind != Kind::Record)
            || !self.began_clean
            || self.failed
            || self.publication_block == Some(revision)
            || self.store.blob_recovery.needs_review()
        {
            return Ok(false);
        }

        let result: Result<_> = (|| {
            let snapshot = self.store.conn.unchecked_transaction()?;
            let candidate =
                self.verified_public_blob(blob_id, revision, gate, expected, genesis)?;
            snapshot.commit()?;
            Ok(candidate)
        })();
        if result.is_err() {
            self.failed = true;
        }
        let Some((mut file, length)) = result? else {
            return Ok(false);
        };
        send(&mut file, length).map_err(StorageError::Io)?;
        Ok(true)
    }

    /// Blob IDから現在の公開根拠を探し、根拠を満たした本文だけを同期処理に渡す。
    /// 探索上限に達して結論を出せない場合は、未発見と区別して予算超過を返す。
    pub fn send_public_blob(
        &mut self,
        blob_id: Id,
        gate: DistributionGate,
        scope: FixedRecordScope,
        max_candidates: std::num::NonZeroU32,
        send: impl FnOnce(&mut std::fs::File, u64) -> std::io::Result<()>,
    ) -> Result<bool> {
        let (expected, genesis) = scope.publication_target();
        if blob_id.kind != Kind::Blob
            || genesis.is_some_and(|id| id.kind != Kind::Record)
            || gate == DistributionGate::Closed
            || !self.began_clean
            || self.failed
            || self.store.blob_recovery.needs_review()
        {
            return Ok(false);
        }

        let result: Result<_> = (|| {
            let conn = &self.store.conn;
            let snapshot = conn.unchecked_transaction()?;
            let candidate = sql_inspection::run(conn, self.store.limits.sql_inspection, || {
                let mut query = conn.prepare(
                    "SELECT e.record_id FROM evaluations e
                     JOIN evaluation_state v ON v.singleton=1 AND v.dirty=0
                     WHERE e.payload_blob=?1 AND e.validation='valid' AND e.payload='verified'
                     ORDER BY e.record_id LIMIT ?2",
                )?;
                let mut rows =
                    query.query(params![blob_id.bytes, i64::from(max_candidates.get()) + 1])?;
                let mut remaining = max_candidates.get();
                while let Some(row) = rows.next()? {
                    if remaining == 0 {
                        return Err(StorageError::BudgetExceeded);
                    }
                    remaining -= 1;
                    let revision = Id {
                        kind: Kind::Record,
                        bytes: row.get(0)?,
                    };
                    if self.publication_block != Some(revision) {
                        if let Some(candidate) =
                            self.verified_public_blob(blob_id, revision, gate, expected, genesis)?
                        {
                            return Ok(Some(candidate));
                        }
                    }
                }
                Ok(None)
            })?;
            snapshot.commit()?;
            Ok(candidate)
        })();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, StorageError::BudgetExceeded))
        {
            self.failed = true;
        }
        let Some((mut file, length)) = result? else {
            return Ok(false);
        };
        send(&mut file, length).map_err(StorageError::Io)?;
        Ok(true)
    }

    fn verified_public_blob(
        &self,
        blob_id: Id,
        revision: Id,
        gate: DistributionGate,
        expected: RecordPublication,
        genesis: Option<Id>,
    ) -> Result<Option<(std::fs::File, u64)>> {
        let Some((publication, record)) = self
            .store
            .assess_record_publication(revision, gate, genesis)?
        else {
            return Ok(None);
        };
        if publication != expected {
            return Ok(None);
        }
        let Some((declared_id, length)) = record.payload().map_err(|_| StorageError::Corrupt)?
        else {
            return Ok(None);
        };
        if declared_id != blob_id.bytes {
            return Ok(None);
        }
        let verified: bool = self.store.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM evaluations WHERE record_id=?1 AND payload='verified')",
            [&revision.bytes],
            |row| row.get(0),
        )?;
        if !verified {
            return Ok(None);
        }

        let file = self.store.blob(blob_id)?.ok_or(StorageError::Corrupt)?;
        if file.metadata()?.len() != length {
            return Err(StorageError::Corrupt);
        }
        Ok(Some((file, length)))
    }

    #[cfg(test)]
    fn revoke_authenticated_publication(&mut self, id: Id, reason: &str, uid: u32) -> Result<bool> {
        self.save_publication_change(id, ManualPublicationChange::Revoke, reason, uid)
    }

    /// 認証と必要な配信遮断を済ませた呼び出し元向けの内部保存操作。
    /// 対象がなければfalse。成功は配信を開始または再開する資格を与えない。
    pub fn save_manual_publication_change(
        &mut self,
        id: Id,
        change: ManualPublicationChange,
        reason: &str,
    ) -> Result<bool> {
        self.save_publication_change(id, change, reason, rustix::process::geteuid().as_raw())
    }

    pub(super) fn save_publication_change(
        &mut self,
        id: Id,
        change: ManualPublicationChange,
        reason: &str,
        uid: u32,
    ) -> Result<bool> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if reason.len() > 1024 || reason.trim().is_empty() {
            return Err(StorageError::BudgetExceeded);
        }
        let result = (|| {
            let Some(old) = load_permission(&self.store.conn, id)? else {
                return Ok(false);
            };
            if change == ManualPublicationChange::Revoke
                || matches!(
                    (old.permission, change),
                    (
                        PublicationPermission::Public,
                        ManualPublicationChange::ApproveUntrusted
                    ) | (
                        PublicationPermission::Untrusted,
                        ManualPublicationChange::ApprovePublic
                    )
                )
            {
                self.publication_block = Some(id);
            }
            let capacity = self.store.capacity()?;
            if capacity.available <= capacity.reserved_floor.saturating_add(65536) {
                return Err(StorageError::Capacity);
            }
            let tx = self.store.conn.unchecked_transaction()?;
            advance(&tx)?;
            let previous = match (old.permission, old.explicitly_stopped) {
                (_, true) => "revoke",
                (PublicationPermission::None, false) => "unset",
                (PublicationPermission::Public, false) => "approve_public",
                (PublicationPermission::Untrusted, false) => "approve_untrusted",
            };
            audit_with_uid(
                &tx,
                Some(&id.bytes),
                previous,
                "publication_saved_local_only",
                reason,
                uid,
            )?;
            if tx.execute(
                "INSERT INTO publication_changes(generation,record_id,decision)
                 SELECT generation,?1,?2 FROM storage_state WHERE singleton=1",
                params![&id.bytes[..], change.as_str()],
            )? != 1
            {
                return Err(StorageError::Corrupt);
            }
            if change != ManualPublicationChange::Revoke {
                let record = self.store.record(id)?.ok_or(StorageError::Corrupt)?;
                tx.execute(
                    "INSERT INTO disclosure_records(record_id,knowledge_id,genesis) VALUES(?1,?2,?3)
                     ON CONFLICT(record_id) DO NOTHING",
                    params![id.bytes,record.identity().knowledge,record.genesis().map_err(|_| StorageError::Corrupt)?],
                )?;
            }
            self.store.refresh_disclosures(&tx, None, Some(id))?;
            if change == ManualPublicationChange::Revoke {
                tx.execute(
                    "DELETE FROM disclosure_records WHERE record_id=?1",
                    [&id.bytes],
                )?;
            }
            tx.commit()?;
            self.publication_block = None;
            Ok(true)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::tests::{Temp, fixture, logical_snapshot};

    #[test]
    fn scoped_heads_follow_private_parents_and_commit_with_generation() {
        use crate::storage::evaluation::tests::rev;

        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        let genesis = fixture();
        let root = rev(&[], 14, "root");
        let hidden = rev(&[root.id()], 14, "hidden");
        let left = rev(&[hidden.id()], 14, "left");
        let right = rev(&[root.id()], 14, "right");
        let merge = rev(&[left.id(), right.id()], 14, "merge");
        for record in [&genesis, &root, &hidden, &left, &right, &merge] {
            writer.insert(record).unwrap();
        }
        writer.revalidate(EvaluationLimits::default()).unwrap();
        let state = |writer: &RecordWriter, scope: &[u8]| {
            let conn = &writer.store.conn;
            let knowledge = genesis.identity().knowledge;
            let generation: Option<i64> = conn
                .query_row(
                    "SELECT generation FROM disclosure_generations
                     WHERE knowledge_id=?1 AND scope_genesis=?2",
                    params![knowledge, scope],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();
            let heads = conn
                .prepare(
                    "SELECT record_id FROM disclosure_heads WHERE knowledge_id=?1
                     AND scope_genesis=?2 ORDER BY record_id",
                )
                .unwrap()
                .query_map(params![knowledge, scope], |row| row.get::<_, [u8; 32]>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (generation, heads)
        };
        let scope = genesis.id().bytes;
        let listing = |writer: &RecordWriter, scope_key: &[u8], genesis_key: &[u8]| {
            writer
                .store
                .conn
                .prepare(
                    "SELECT record_id,disclosure_epoch FROM record_listing_members
                 WHERE knowledge_id=?1 AND visible_scope=?2 AND genesis=?3 ORDER BY record_id",
                )
                .unwrap()
                .query_map(
                    params![genesis.identity().knowledge, scope_key, genesis_key],
                    |row| Ok((row.get::<_, [u8; 32]>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let approve = ManualPublicationChange::ApproveUntrusted;
        for record in [&genesis, &root, &left, &right] {
            writer
                .save_manual_publication_change(record.id(), approve, "allow")
                .unwrap();
        }
        let mut branches = vec![left.id().bytes, right.id().bytes];
        branches.sort();
        assert_eq!(state(&writer, &scope), (Some(4), branches.clone()));
        assert_eq!(state(&writer, &[]), (None, vec![]));
        let initial = listing(&writer, &scope, &scope);
        let mut ids = vec![scope, root.id().bytes, left.id().bytes, right.id().bytes];
        ids.sort();
        assert_eq!(
            initial,
            ids.into_iter().map(|id| (id, 0)).collect::<Vec<_>>()
        );
        assert!(listing(&writer, &[], &scope).is_empty());
        assert!(listing(&writer, &scope, &[0; 32]).is_empty());
        let private_child = rev(&[right.id()], 14, "private child");
        writer.insert(&private_child).unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer, &scope), (Some(4), branches.clone()));
        assert_eq!(listing(&writer, &scope, &scope), initial);
        writer
            .save_manual_publication_change(merge.id(), approve, "allow")
            .unwrap();
        assert_eq!(state(&writer, &scope), (Some(5), vec![merge.id().bytes]));
        let expanded = listing(&writer, &scope, &scope);
        assert_eq!(expanded.len(), initial.len() + 1);
        assert!(expanded.iter().all(|(_, epoch)| *epoch == 0));
        writer
            .save_manual_publication_change(merge.id(), ManualPublicationChange::Revoke, "hide")
            .unwrap();
        assert_eq!(state(&writer, &scope), (Some(6), branches));
        writer.finish().unwrap();
        let mut writer = RecordStore::open(&temp.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        let reduced = listing(&writer, &scope, &scope);
        assert_eq!(
            reduced,
            initial.iter().map(|(id, _)| (*id, 6)).collect::<Vec<_>>()
        );
        writer
            .save_manual_publication_change(merge.id(), approve, "allow")
            .unwrap();
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER fail_heads BEFORE INSERT ON disclosure_heads
                 BEGIN SELECT RAISE(ABORT,'test'); END;",
            )
            .unwrap();
        assert!(
            writer
                .save_manual_publication_change(merge.id(), ManualPublicationChange::Revoke, "hide")
                .is_err()
        );
        assert_eq!(state(&writer, &scope), (Some(7), vec![merge.id().bytes]));
        assert_eq!(
            listing(&writer, &scope, &scope),
            expanded.iter().map(|(id, _)| (*id, 6)).collect::<Vec<_>>()
        );
        assert!(writer.failed || writer.publication_block == Some(merge.id()));
    }

    #[test]
    fn knowledge_response_isolated_from_other_genesis_and_private_changes() {
        use crate::cbor::Value;
        use crate::storage::evaluation::tests::{bytes, rev, set};

        let temp = Temp::new();
        let mut writer = temp.store().begin().unwrap();
        let genesis = fixture();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: genesis.identity().knowledge,
        };
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mut body = genesis.body().clone();
        set(
            &mut body,
            "publisher_public_key",
            Value::Bytes(other_key.verifying_key().to_bytes().to_vec()),
        );
        let other = LocalRecord::sign(body, &other_key).unwrap();
        let revision = rev(&[], bytes().len() as u64 + 1, "mismatch when received");
        for record in [&genesis, &revision, &other] {
            writer.insert(record).unwrap();
        }
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_pin(knowledge, Some(genesis.id()), "pin")
            .unwrap();
        writer
            .save_manual_publication_change(
                revision.id(),
                ManualPublicationChange::ApprovePublic,
                "allow",
            )
            .unwrap();
        let public = FixedRecordScope::Public { genesis_id: None };
        let untrusted = FixedRecordScope::Untrusted {
            genesis_id: other.id(),
        };
        let read = |w: &mut RecordWriter, scope| {
            w.knowledge_response(knowledge, scope, DistributionGate::Open, false)
                .unwrap()
        };
        let resolve = |w: &mut RecordWriter, scope| {
            w.knowledge_response(knowledge, scope, DistributionGate::Open, true)
                .unwrap()
                .map(|body| {
                    let mut json: serde_json::Value = serde_json::from_str(&body).unwrap();
                    json.as_object_mut()
                        .unwrap()
                        .remove("evaluated_at")
                        .unwrap();
                    json
                })
        };
        let published = resolve(&mut writer, public).unwrap();
        assert_eq!(published["verification"]["trust_anchor"], "pinned");
        let before = read(&mut writer, public).unwrap();
        let json: serde_json::Value = serde_json::from_str(&before).unwrap();
        assert_eq!(
            json["heads"],
            serde_json::json!([revision.id().to_string()])
        );
        assert!(json["local_state"].get("candidate_genesis_id").is_none());
        assert!(read(&mut writer, untrusted).is_none());
        assert!(
            read(
                &mut writer,
                FixedRecordScope::Public {
                    genesis_id: Some(other.id())
                }
            )
            .is_none()
        );
        writer
            .save_manual_publication_change(
                other.id(),
                ManualPublicationChange::ApproveUntrusted,
                "allow",
            )
            .unwrap();
        let isolated = read(&mut writer, untrusted).unwrap();
        let other_resolved = resolve(&mut writer, untrusted).unwrap();
        assert_eq!(other_resolved["resolution"]["status"], "none");
        assert_eq!(
            other_resolved["verification"]["revisions"],
            serde_json::json!([])
        );
        assert_eq!(resolve(&mut writer, public), Some(published));
        writer.insert(&rev(&[], 14, "private")).unwrap();
        assert_eq!(read(&mut writer, public).as_deref(), Some(before.as_str()));
        assert!(
            writer
                .knowledge_response(knowledge, public, DistributionGate::Closed, false)
                .unwrap()
                .is_none()
        );
        let payload = bytes();
        writer
            .put_blob(crate::id::blob_id(&payload), payload.as_slice())
            .unwrap();
        assert!(read(&mut writer, public).is_none());
        assert_eq!(read(&mut writer, untrusted), Some(isolated));
        assert_eq!(resolve(&mut writer, untrusted), Some(other_resolved));
        assert!(resolve(&mut writer, public).is_none());
        writer
            .save_manual_publication_change(other.id(), ManualPublicationChange::Revoke, "hide")
            .unwrap();
        assert!(read(&mut writer, untrusted).is_none());
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_manual_publication_change(
                genesis.id(),
                ManualPublicationChange::ApprovePublic,
                "allow",
            )
            .unwrap();
        assert!(read(&mut writer, public).is_some());
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER fail_revoke BEFORE UPDATE ON disclosure_generations
             BEGIN SELECT RAISE(ABORT,'test'); END;",
            )
            .unwrap();
        assert!(
            writer
                .save_manual_publication_change(
                    genesis.id(),
                    ManualPublicationChange::Revoke,
                    "hide"
                )
                .is_err()
        );
        assert!(read(&mut writer, public).is_none());
        assert!(resolve(&mut writer, public).is_none());
    }

    #[test]
    fn disclosed_payload_changes_only_on_committed_visible_status_changes() {
        use crate::storage::evaluation::tests::{bytes, rev};

        let temp = Temp::new();
        let genesis = fixture();
        let payload = bytes();
        let blob = crate::id::blob_id(&payload);
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&genesis).unwrap();
        for tag in ["first", "shared"] {
            let revision = rev(&[], payload.len() as u64, tag);
            writer.insert(&revision).unwrap();
            writer
                .save_manual_publication_change(
                    revision.id(),
                    ManualPublicationChange::ApproveUntrusted,
                    "allow",
                )
                .unwrap();
        }
        let state = |writer: &RecordWriter| {
            writer
                .store
                .conn
                .query_row(
                    "SELECT g.generation, min(r.visible_payload), max(r.visible_payload), count(*)
                 FROM disclosure_generations g JOIN disclosure_records r
                 ON g.knowledge_id=r.knowledge_id AND g.scope_genesis=r.visible_scope
                 WHERE g.scope_genesis=?1 GROUP BY g.generation",
                    [genesis.id().bytes],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, i64>(3)?,
                        ))
                    },
                )
                .unwrap()
        };
        let expected =
            |generation, status: &str| (generation, status.to_owned(), status.to_owned(), 2);
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer), expected(1, "missing"));
        let resolve = |w: &mut RecordWriter| {
            w.knowledge_response(
                Id {
                    kind: Kind::Knowledge,
                    bytes: genesis.identity().knowledge,
                },
                FixedRecordScope::Untrusted {
                    genesis_id: genesis.id(),
                },
                DistributionGate::Open,
                true,
            )
            .map(|body| {
                let mut json: serde_json::Value = serde_json::from_str(&body.unwrap()).unwrap();
                let time = json
                    .as_object_mut()
                    .unwrap()
                    .remove("evaluated_at")
                    .unwrap();
                assert_eq!(time.as_str().unwrap().len(), 24);
                json
            })
        };
        let initial = resolve(&mut writer).unwrap();
        assert_eq!(initial["resolution"]["status"], "multiple");
        assert_eq!(initial["resolution"]["has_pending_candidates"], false);
        assert_eq!(
            initial["verification"]["revisions"][0]["payload_status"],
            "missing"
        );
        let unrelated = b"unpublished";
        writer
            .put_blob(crate::id::blob_id(unrelated), unrelated.as_slice())
            .unwrap();
        assert_eq!(initial, resolve(&mut writer).unwrap());
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer), expected(1, "missing"));
        writer
            .observe_blob_failure(blob, "transfer_failed")
            .unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer), expected(2, "unavailable"));
        assert_eq!(
            resolve(&mut writer).unwrap()["verification"]["revisions"][0]["reasons"],
            serde_json::json!(["transfer_failed"])
        );
        writer
            .observe_blob_failure(blob, "transfer_hash_mismatch")
            .unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer), expected(3, "unavailable"));
        writer.put_blob(blob, payload.as_slice()).unwrap();
        assert!(matches!(
            resolve(&mut writer),
            Err(StorageError::EvaluationInputPending)
        ));
        assert_eq!(state(&writer), expected(3, "unavailable"));
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer), expected(4, "verified"));
        assert_eq!(
            resolve(&mut writer).unwrap()["verification"]["revisions"][0]["payload_status"],
            "verified"
        );
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(state(&writer), expected(4, "verified"));
        writer.finish().unwrap();
    }

    #[test]
    fn shared_blob_requires_a_current_verified_public_revision() {
        use crate::storage::evaluation::tests::{bytes, rev};
        use std::io::Read;

        let temp = Temp::new();
        let genesis = fixture();
        let first = rev(&[], 14, "first");
        let shared = rev(&[first.id()], 14, "shared");
        let blob = crate::id::blob_id(&bytes());
        let scope = FixedRecordScope::Untrusted {
            genesis_id: genesis.id(),
        };
        let mut writer = temp.store().begin().unwrap();
        for record in [&genesis, &first, &shared] {
            writer.insert(record).unwrap();
        }
        for id in [genesis.id(), first.id()] {
            writer
                .save_manual_publication_change(
                    id,
                    ManualPublicationChange::ApproveUntrusted,
                    "allow",
                )
                .unwrap();
        }
        writer.revalidate(EvaluationLimits::default()).unwrap();

        let denied = |_: &mut std::fs::File, _: u64| panic!("unexpected blob send");
        let open = DistributionGate::Open;
        assert!(
            !writer
                .send_blob_from_revision(blob, first.id(), open, scope, denied)
                .unwrap()
        );
        writer.put_blob(blob, bytes().as_slice()).unwrap();
        assert!(
            !writer
                .send_blob_from_revision(blob, first.id(), open, scope, denied)
                .unwrap()
        );
        writer.revalidate(EvaluationLimits::default()).unwrap();

        for (candidate, gate, scope) in [
            (genesis.id(), open, scope),
            (shared.id(), open, scope),
            (first.id(), DistributionGate::Closed, scope),
            (
                first.id(),
                open,
                FixedRecordScope::Public { genesis_id: None },
            ),
            (
                first.id(),
                open,
                FixedRecordScope::Untrusted {
                    genesis_id: first.id(),
                },
            ),
        ] {
            assert!(
                !writer
                    .send_blob_from_revision(blob, candidate, gate, scope, denied)
                    .unwrap()
            );
        }
        let send = |file: &mut std::fs::File, length| {
            let mut actual = Vec::new();
            file.read_to_end(&mut actual)?;
            assert_eq!(actual, bytes());
            assert_eq!(length, actual.len() as u64);
            Ok(())
        };
        assert!(
            writer
                .send_blob_from_revision(blob, first.id(), open, scope, send)
                .unwrap()
        );
        writer
            .save_manual_publication_change(
                shared.id(),
                ManualPublicationChange::ApproveUntrusted,
                "allow",
            )
            .unwrap();
        writer
            .save_manual_publication_change(first.id(), ManualPublicationChange::Revoke, "stop")
            .unwrap();
        assert!(
            !writer
                .send_blob_from_revision(blob, first.id(), open, scope, denied)
                .unwrap()
        );
        assert!(
            writer
                .send_blob_from_revision(blob, shared.id(), open, scope, send)
                .unwrap()
        );
        let limit = std::num::NonZeroU32::new(2).unwrap();
        let missing = crate::id::blob_id(b"unreferenced");
        assert!(
            !writer
                .send_public_blob(missing, open, scope, std::num::NonZeroU32::MIN, denied)
                .unwrap()
        );
        assert!(
            !writer
                .send_public_blob(missing, open, scope, limit, denied)
                .unwrap()
        );
        assert!(
            writer
                .send_public_blob(blob, open, scope, limit, send)
                .unwrap()
        );
        writer
            .save_manual_publication_change(shared.id(), ManualPublicationChange::Revoke, "stop")
            .unwrap();
        assert!(
            !writer
                .send_public_blob(blob, open, scope, limit, denied)
                .unwrap()
        );
        assert!(matches!(
            writer.send_public_blob(blob, open, scope, std::num::NonZeroU32::MIN, denied),
            Err(StorageError::BudgetExceeded)
        ));
        writer.finish().unwrap();
    }

    #[test]
    fn fixed_http_connection_reads_and_sends_a_record() {
        use crate::fixed_record_http::FixedRecordLoopbackListener;
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::{Duration, Instant};

        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "allow")
            .unwrap();

        writer.finish().unwrap();
        let mut startup =
            crate::storage::LocalStartup::open(&temp.data(), crate::storage::Limits::default())
                .unwrap();
        loop {
            if startup
                .step(
                    EvaluationLimits::default(),
                    crate::storage::LocalStartupBudget::default(),
                )
                .unwrap()
                .checks_complete()
            {
                break;
            }
        }
        let mut writer = startup.into_writer().unwrap();

        assert!(matches!(
            FixedRecordLoopbackListener::bind(([0, 0, 0, 0], 0).into()),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        let mut listener = FixedRecordLoopbackListener::bind(([127, 0, 0, 1], 0).into()).unwrap();
        assert_eq!(
            listener
                .serve_ready(&mut writer, DistributionGate::Open, Instant::now())
                .unwrap(),
            None
        );

        for (extra, accepted) in [("", true), ("Content-Length: 1\r\n", false)] {
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            write!(client, "GET /v1/records/{id}?scope=untrusted&genesis_id={id} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let result = listener.serve_ready(&mut writer, DistributionGate::Open, deadline);
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            if accepted {
                assert_eq!(result.unwrap(), Some(true));
                assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
                let body_start = response
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                assert_eq!(&response[body_start..], record.bytes());
            } else {
                assert!(
                    matches!(result, Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
                );
                assert!(response.is_empty());
            }
        }
        writer.finish().unwrap();
    }

    #[test]
    fn fixed_http_router_dispatches_only_single_record_paths() {
        use crate::fixed_record_http::route_fixed_record_request;

        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "allow")
            .unwrap();
        let path = format!("/v1/records/{id}");
        let target = format!("{path}?scope=untrusted&genesis_id={id}");
        for target in ["/v1/records/", &format!("{path}/unknown")] {
            assert!(
                !route_fixed_record_request(
                    &mut writer,
                    DistributionGate::Open,
                    "GET",
                    target,
                    |_, _, _| panic!("unhandled route"),
                )
                .unwrap()
            );
        }
        for (method, target, expected) in [
            ("GET", target.as_str(), 200),
            ("GET", path.as_str(), 404),
            ("PUT", target.as_str(), 405),
            ("GET", "/v1/records/invalid", 400),
            ("GET", "/v1/records", 400),
            ("GET", &format!("{target}&{}", "x".repeat(16 * 1024)), 400),
        ] {
            assert!(
                route_fixed_record_request(
                    &mut writer,
                    DistributionGate::Open,
                    method,
                    target,
                    |status, content_type, bytes| {
                        assert_eq!(status, expected);
                        if status == 200 {
                            assert_eq!((content_type, bytes), ("application/cbor", record.bytes()));
                        }
                        Ok(())
                    },
                )
                .unwrap()
            );
        }
        writer.finish().unwrap();
    }

    #[test]
    fn fixed_http_get_preserves_cbor_and_hides_private_records() {
        use crate::fixed_record_http::send_fixed_record_get;

        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        let query = format!("genesis_id={id}&scope=untrust%65d");
        let missing = crate::id::record_id(b"missing");
        let mut get = |id: Id, query: Option<&str>| {
            let mut response = None;
            send_fixed_record_get(
                &mut writer,
                DistributionGate::Open,
                &id.to_string(),
                query,
                |status, content_type, bytes| {
                    response = Some((status, content_type, bytes.to_vec()));
                    Ok(())
                },
            )
            .unwrap();
            response.unwrap()
        };
        let private = get(id, Some(&query));
        assert_eq!(private.0, 404);
        assert_eq!(private, get(missing, Some(&query)));
        for invalid in [
            "scope=untrusted",
            "scope=%FF",
            "scope=%2570ublic",
            "scope=public&scope=public",
            "unknown=public",
            "scope=%",
        ] {
            assert_eq!(get(id, Some(invalid)).0, 400);
        }
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "allow")
            .unwrap();
        send_fixed_record_get(
            &mut writer,
            DistributionGate::Open,
            &id.to_string(),
            Some(&query),
            |status, content_type, bytes| {
                assert_eq!(
                    (status, content_type, bytes),
                    (200, "application/cbor", record.bytes())
                );
                Ok(())
            },
        )
        .unwrap();
        writer.finish().unwrap();
    }

    #[test]
    fn fixed_send_requires_the_requested_genesis_and_scope() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: record.identity().knowledge,
        };
        let mut other_genesis = id;
        other_genesis.bytes[0] ^= 1;
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "allow")
            .unwrap();
        let untrusted = FixedRecordScope::Untrusted { genesis_id: id };

        assert!(
            writer
                .send_fixed_record(id, DistributionGate::Open, untrusted, |bytes| {
                    assert_eq!(bytes, record.bytes());
                    Ok(())
                })
                .unwrap()
        );
        for genesis_id in [other_genesis, knowledge] {
            assert!(
                !writer
                    .send_fixed_record(
                        id,
                        DistributionGate::Open,
                        FixedRecordScope::Untrusted { genesis_id },
                        |_| panic!("unexpected Genesis")
                    )
                    .unwrap()
            );
        }

        writer
            .save_pin_change(knowledge, Some(id), "adopt", None)
            .unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApprovePublic, "allow")
            .unwrap();
        for genesis_id in [None, Some(id)] {
            assert!(
                writer
                    .send_fixed_record(
                        id,
                        DistributionGate::Open,
                        FixedRecordScope::Public { genesis_id },
                        |bytes| {
                            assert_eq!(bytes, record.bytes());
                            Ok(())
                        }
                    )
                    .unwrap()
            );
        }
        for scope in [
            untrusted,
            FixedRecordScope::Public {
                genesis_id: Some(other_genesis),
            },
        ] {
            assert!(
                !writer
                    .send_fixed_record(id, DistributionGate::Open, scope, |_| panic!(
                        "wrong public scope or Genesis"
                    ))
                    .unwrap()
            );
        }
        writer.finish().unwrap();
    }

    #[test]
    fn live_send_rechecks_route_gate_and_revocation() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer
            .revalidate(super::super::EvaluationLimits::default())
            .unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "allow")
            .unwrap();

        assert!(
            writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Untrusted,
                    |bytes| {
                        assert_eq!(bytes, record.bytes());
                        Ok(())
                    }
                )
                .unwrap()
        );
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Public,
                    |_| panic!("wrong route")
                )
                .unwrap()
        );
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Closed,
                    PublicationPermission::Untrusted,
                    |_| panic!("gate closed")
                )
                .unwrap()
        );

        writer
            .revoke_authenticated_publication(id, "stop", 1234)
            .unwrap();
        assert_eq!(writer.publication_block, None);
        let actor: String = writer
            .store
            .conn
            .query_row(
                "SELECT actor FROM history ORDER BY generation DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(actor, "uid:1234");
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Untrusted,
                    |_| panic!("revoked")
                )
                .unwrap()
        );
        writer
            .save_manual_publication_change(
                id,
                ManualPublicationChange::ApproveUntrusted,
                "allow again",
            )
            .unwrap();
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Closed,
                    PublicationPermission::Untrusted,
                    |_| panic!("gate closed after approval")
                )
                .unwrap()
        );
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Public,
                    |_| panic!("wrong route after approval")
                )
                .unwrap()
        );
        assert!(
            writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Untrusted,
                    |_| Ok(())
                )
                .unwrap()
        );
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER fail_revoke BEFORE INSERT ON publication_changes
             WHEN NEW.decision='revoke' BEGIN SELECT RAISE(ABORT, 'test failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            writer.revoke_authenticated_publication(id, "stop", 1234),
            Err(StorageError::Sql(_))
        ));
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Untrusted,
                    |_| panic!("revocation failed")
                )
                .unwrap()
        );
        assert_eq!(writer.publication_block, Some(id));
        assert!(matches!(
            writer.finish(),
            Err(StorageError::UnresolvedFailure)
        ));
    }

    #[test]
    fn current_publication_requires_matching_pin_permission_and_clean_evaluation() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: record.identity().knowledge,
        };
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "allow")
            .unwrap();
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store
                .record_publication(id, DistributionGate::Open)
                .unwrap(),
            RecordPublication::Private
        );

        let mut writer = store.begin().unwrap();
        writer
            .revalidate(super::super::EvaluationLimits::default())
            .unwrap();
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store
                .record_publication(id, DistributionGate::Open)
                .unwrap(),
            RecordPublication::UntrustedPublic
        );
        assert_eq!(
            store
                .record_publication(id, DistributionGate::Closed)
                .unwrap(),
            RecordPublication::Private
        );

        let mut writer = store.begin().unwrap();
        writer.save_pin(knowledge, Some(id), "adopt").unwrap();
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store
                .record_publication(id, DistributionGate::Open)
                .unwrap(),
            RecordPublication::Private
        );

        let mut writer = store.begin().unwrap();
        writer
            .save_manual_publication_change(
                id,
                ManualPublicationChange::ApprovePublic,
                "allow pinned",
            )
            .unwrap();
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store
                .record_publication(id, DistributionGate::Open)
                .unwrap(),
            RecordPublication::Public
        );

        let writer = store.begin().unwrap();
        drop(writer);
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(
            store
                .record_publication(id, DistributionGate::Open)
                .unwrap(),
            RecordPublication::Private
        );
    }

    #[test]
    fn manual_disclosure_generation_survives_reopen_and_failed_revocation() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer.revalidate(EvaluationLimits::default()).unwrap();
        for reason in ["first", "repeat"] {
            writer
                .save_manual_publication_change(
                    id,
                    ManualPublicationChange::ApproveUntrusted,
                    reason,
                )
                .unwrap();
        }
        let read = |conn: &Connection| {
            conn.query_row(
                "SELECT namespace,generation FROM disclosure_generations
                 WHERE knowledge_id=?1 AND scope_genesis=?2",
                params![record.identity().knowledge, id.bytes],
                |r| Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, i64>(1)?)),
            )
            .unwrap()
        };
        let scoped_ids = "SELECT record_id FROM disclosure_records
            WHERE knowledge_id=?1 AND visible_scope=?2 AND genesis=?3 ORDER BY record_id";
        let selected = |conn: &Connection, scope: &[u8], genesis: &[u8; 32]| {
            conn.prepare(scoped_ids)
                .unwrap()
                .query_map(params![record.identity().knowledge, scope, genesis], |r| {
                    r.get::<_, [u8; 32]>(0)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let plan: String = writer
            .store
            .conn
            .query_row(
                &format!("EXPLAIN QUERY PLAN {scoped_ids}"),
                params![record.identity().knowledge, id.bytes, id.bytes],
                |row| row.get(3),
            )
            .unwrap();
        assert!(plan.contains("SEARCH") && plan.contains("disclosure_records_by_scope"));
        assert_eq!(
            selected(&writer.store.conn, &id.bytes, &id.bytes),
            [id.bytes]
        );
        assert!(selected(&writer.store.conn, &[], &id.bytes).is_empty());
        let mut other = id.bytes;
        other[0] ^= 1;
        assert!(selected(&writer.store.conn, &other, &other).is_empty());
        let (namespace, generation) = read(&writer.store.conn);
        assert_eq!(generation, 1);
        writer.finish().unwrap();
        let mut writer = RecordStore::open(&temp.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::Revoke, "hide")
            .unwrap();
        assert_eq!(read(&writer.store.conn), (namespace, 2));
        assert!(selected(&writer.store.conn, &id.bytes, &id.bytes).is_empty());
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER reject_generation BEFORE UPDATE ON disclosure_generations
             BEGIN SELECT RAISE(ABORT,'test'); END;",
            )
            .unwrap();
        assert!(
            writer
                .save_manual_publication_change(
                    id,
                    ManualPublicationChange::ApproveUntrusted,
                    "show"
                )
                .is_err()
        );
        assert_eq!(read(&writer.store.conn), (namespace, 2));
        assert!(selected(&writer.store.conn, &id.bytes, &id.bytes).is_empty());
        let mut stmt = writer.store.conn.prepare(
            "SELECT generation,visible FROM disclosure_history WHERE namespace=?1 AND record_id=?2
             AND genesis=?2 AND payload IS NULL AND reason IS NULL ORDER BY generation",
        ).unwrap();
        let history = stmt
            .query_map(params![namespace, id.bytes], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(history, [(1, true), (2, false)]);
        assert!(
            writer
                .store
                .saved_publication_permission(id)
                .unwrap()
                .unwrap()
                .explicitly_stopped
        );
    }

    #[test]
    fn manual_permission_and_revocation_survive_reopen_and_duplicate_receive() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let store = temp.store();
        assert_eq!(store.saved_publication_permission(id).unwrap(), None);
        let mut writer = store.begin().unwrap();
        assert!(
            !writer
                .save_manual_publication_change(
                    id,
                    ManualPublicationChange::Revoke,
                    "unknown target"
                )
                .unwrap()
        );
        assert!(writer.insert(&record).unwrap());
        assert_eq!(
            load_permission(&writer.store.conn, id).unwrap(),
            Some(SavedPublicationPermission::default())
        );

        for (change, expected, stopped) in [
            (
                ManualPublicationChange::ApprovePublic,
                PublicationPermission::Public,
                false,
            ),
            (
                ManualPublicationChange::Revoke,
                PublicationPermission::None,
                true,
            ),
            (
                ManualPublicationChange::ApproveUntrusted,
                PublicationPermission::Untrusted,
                false,
            ),
        ] {
            assert!(
                writer
                    .save_manual_publication_change(id, change, "explicit decision")
                    .unwrap()
            );
            assert!(!writer.insert(&record).unwrap());
            writer.finish().unwrap();
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            let saved = store.saved_publication_permission(id).unwrap().unwrap();
            assert_eq!(saved.permission, expected);
            assert_eq!(saved.explicitly_stopped, stopped);
            assert!(saved.change_generation.is_some());
            writer = store.begin().unwrap();
        }
        let history_count: i64 = writer
            .store
            .conn
            .query_row(
                "SELECT count(*) FROM history JOIN publication_changes USING(generation)
             WHERE target=record_id AND reason='explicit decision' AND actor LIKE 'uid:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 3);
        writer.finish().unwrap();
    }

    #[test]
    fn failed_publication_append_rolls_back_history_and_preserves_previous_permission() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        writer
            .save_manual_publication_change(
                id,
                ManualPublicationChange::ApprovePublic,
                "initial approval",
            )
            .unwrap();
        let before = logical_snapshot(&writer.store.conn);
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER reject_publication BEFORE INSERT ON publication_changes
             BEGIN SELECT RAISE(ABORT,'test failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            writer.save_manual_publication_change(id, ManualPublicationChange::Revoke, "revoke"),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(logical_snapshot(&writer.store.conn), before);
        assert!(matches!(
            writer.save_manual_publication_change(id, ManualPublicationChange::Revoke, "retry"),
            Err(StorageError::UnresolvedFailure)
        ));
        drop(writer);
        let conn = Connection::open(temp.data().join(DB)).unwrap();
        assert_eq!(state(&conn).unwrap(), StartupState::NeedsReview);
    }

    #[test]
    fn permission_and_anchor_must_match() {
        use PublicationAnchor::{Pinned, Unknown, Untrusted};
        use RecordPublication::{Private, Public, UntrustedPublic};

        for (permission, expected) in [
            (
                PublicationPermission::default(),
                [Private, Private, Private],
            ),
            (PublicationPermission::Public, [Public, Private, Private]),
            (
                PublicationPermission::Untrusted,
                [Private, UntrustedPublic, Private],
            ),
        ] {
            for (anchor, expected) in [Pinned, Untrusted, Unknown].into_iter().zip(expected) {
                assert_eq!(
                    RecordPublication::assess(
                        permission,
                        Some(Validation::Valid),
                        anchor,
                        false,
                        DistributionGate::Open,
                    ),
                    expected,
                );
            }
        }
    }

    #[test]
    fn either_publication_route_denies_stopped_or_unverified_records() {
        for (permission, anchor) in [
            (PublicationPermission::Public, PublicationAnchor::Pinned),
            (
                PublicationPermission::Untrusted,
                PublicationAnchor::Untrusted,
            ),
        ] {
            for (validation, explicitly_stopped, gate) in [
                (Some(Validation::Valid), false, DistributionGate::default()),
                (Some(Validation::Valid), true, DistributionGate::Open),
                (Some(Validation::Pending), false, DistributionGate::Open),
                (Some(Validation::Invalid), false, DistributionGate::Open),
                (None, false, DistributionGate::Open),
            ] {
                assert_eq!(
                    RecordPublication::assess(
                        permission,
                        validation,
                        anchor,
                        explicitly_stopped,
                        gate
                    ),
                    RecordPublication::Private,
                );
            }
        }
    }
}
