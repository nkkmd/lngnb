//! Record本体の公開可否。仕様 §7.2.2。状態案内、候補一覧、本文には別の条件がある。

use super::*;

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

impl RecordStore {
    /// 停止中の保存領域について、固定Record本体の配信可否を読み取る。
    /// gate は呼び出し側の運用制限。結果はこの読取り時点の判定で、送信許可証にはならない。
    pub fn record_publication(&self, id: Id, gate: DistributionGate) -> Result<RecordPublication> {
        let snapshot = self.conn.unchecked_transaction()?;
        let publication = self.assess_record_publication(id, gate)?;
        snapshot.commit()?;
        Ok(publication)
    }

    fn assess_record_publication(
        &self,
        id: Id,
        gate: DistributionGate,
    ) -> Result<RecordPublication> {
        if gate == DistributionGate::Closed
            || id.kind != Kind::Record
            || self.startup_state()? != StartupState::Clean
        {
            return Ok(RecordPublication::Private);
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
            return Ok(RecordPublication::Private);
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
        Ok(RecordPublication::assess(
            permission.permission,
            Some(Validation::Valid),
            anchor,
            permission.explicitly_stopped,
            gate,
        ))
    }

    /// 既存Recordの許可を返す。対象がなければNone。
    pub fn saved_publication_permission(
        &self,
        id: Id,
    ) -> Result<Option<SavedPublicationPermission>> {
        load_permission(&self.conn, id)
    }
}

impl RecordWriter {
    /// 認証と必要な配信遮断を済ませた呼び出し元向けの内部保存操作。
    /// 対象がなければfalse。成功は配信を開始または再開する資格を与えない。
    pub fn save_manual_publication_change(
        &mut self,
        id: Id,
        change: ManualPublicationChange,
        reason: &str,
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
            let capacity = self.store.capacity()?;
            if capacity.available <= capacity.reserved_floor.saturating_add(65536) {
                return Err(StorageError::Capacity);
            }
            let tx = self.store.conn.transaction()?;
            advance(&tx)?;
            let previous = match (old.permission, old.explicitly_stopped) {
                (_, true) => "revoke",
                (PublicationPermission::None, false) => "unset",
                (PublicationPermission::Public, false) => "approve_public",
                (PublicationPermission::Untrusted, false) => "approve_untrusted",
            };
            audit(
                &tx,
                Some(&id.bytes),
                previous,
                "publication_saved_local_only",
                reason,
            )?;
            if tx.execute(
                "INSERT INTO publication_changes(generation,record_id,decision)
                 SELECT generation,?1,?2 FROM storage_state WHERE singleton=1",
                params![&id.bytes[..], change.as_str()],
            )? != 1
            {
                return Err(StorageError::Corrupt);
            }
            tx.commit()?;
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
