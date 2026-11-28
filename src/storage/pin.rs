//! Knowledgeごとの明示的なGenesis採用記録。仕様 §5.1。

use super::*;
use crate::record::RecordKind;

fn check_pin(store: &RecordStore, knowledge: Id, genesis: Id) -> Result<bool> {
    if genesis.kind != Kind::Record {
        return Ok(false);
    }
    Ok(store.record(genesis)?.is_some_and(|record| {
        let identity = record.identity();
        identity.kind == RecordKind::Genesis && identity.knowledge == knowledge.bytes
    }))
}

impl RecordStore {
    /// 保存された最新のpinを取得する。履歴のない対象や解除済みの対象はNone。
    pub fn saved_pin(&self, knowledge: Id) -> Result<Option<Id>> {
        if knowledge.kind != Kind::Knowledge {
            return Err(StorageError::InvalidPinTarget);
        }
        let row = self
            .conn
            .query_row(
                "SELECT p.generation,p.new_genesis,
                    h.namespace=s.namespace AND h.generation<=s.generation
             FROM history h CROSS JOIN storage_state s
             LEFT JOIN pin_changes p ON p.generation=h.generation
             WHERE h.target=?1 AND h.new_state='pin_saved_local_only' AND s.singleton=1
             ORDER BY h.generation DESC LIMIT 1",
                [&knowledge.bytes],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?,
                        r.get::<_, Option<[u8; 32]>>(1)?,
                        r.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None | Some((Some(_), None, true)) => Ok(None),
            Some((Some(_), Some(bytes), true)) => {
                let genesis = Id {
                    kind: Kind::Record,
                    bytes,
                };
                if !check_pin(self, knowledge, genesis)? {
                    return Err(StorageError::Corrupt);
                }
                Ok(Some(genesis))
            }
            _ => Err(StorageError::Corrupt),
        }
    }
}

impl RecordWriter {
    /// 認証・必要な配信遮断を済ませた管理操作向け。指定なしで解除する。
    /// 同じ指定の再適用では履歴・世代を進めずfalseを返す。
    pub fn save_pin(&mut self, knowledge: Id, genesis: Option<Id>, reason: &str) -> Result<bool> {
        self.save_pin_change(knowledge, genesis, reason, None)
    }

    pub(super) fn save_pin_change(
        &mut self,
        knowledge: Id,
        genesis: Option<Id>,
        reason: &str,
        peer_uid: Option<u32>,
    ) -> Result<bool> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if knowledge.kind != Kind::Knowledge {
            return Err(StorageError::InvalidPinTarget);
        }
        if reason.len() > 1024 || reason.trim().is_empty() {
            return Err(StorageError::BudgetExceeded);
        }
        let result = (|| {
            if let Some(genesis) = genesis {
                if !check_pin(&self.store, knowledge, genesis)? {
                    return Err(StorageError::InvalidPinTarget);
                }
            }
            let previous = self.store.saved_pin(knowledge)?;
            if previous == genesis {
                return Ok(false);
            }
            let capacity = self.store.capacity()?;
            if capacity.available <= capacity.reserved_floor.saturating_add(65536) {
                return Err(StorageError::Capacity);
            }
            let tx = self.store.conn.unchecked_transaction()?;
            advance(&tx)?;
            if peer_uid.is_some() {
                tx.execute("UPDATE evaluation_state SET dirty=1 WHERE singleton=1", [])?;
            }
            audit_with_uid(
                &tx,
                Some(&knowledge.bytes),
                if previous.is_some() {
                    "pinned"
                } else {
                    "unpinned"
                },
                "pin_saved_local_only",
                reason,
                peer_uid.unwrap_or_else(|| rustix::process::geteuid().as_raw()),
            )?;
            if tx.execute(
                "INSERT INTO pin_changes(generation,old_genesis,new_genesis)
                 SELECT generation,?1,?2 FROM storage_state WHERE singleton=1",
                params![previous.map(|id| id.bytes), genesis.map(|id| id.bytes)],
            )? != 1
            {
                return Err(StorageError::Corrupt);
            }
            if let Some(old) = previous {
                tx.execute(
                    "UPDATE quarantine_records SET managed_genesis=NULL,managed_generation=NULL WHERE managed_genesis=?1",
                    [old.bytes],
                )?;
            }
            self.store.refresh_disclosures(&tx, Some(knowledge), None)?;
            tx.commit()?;
            Ok(true)
        })();
        if result.is_err() && !matches!(result, Err(StorageError::InvalidPinTarget)) {
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
    fn management_pin_requires_reevaluation_and_keeps_approval_bound_to_record() {
        let temp = Temp::new();
        let record = fixture();
        let id = record.id();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: record.identity().knowledge,
        };
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&record).unwrap();
        let public_generation = |writer: &RecordWriter| {
            writer.store.conn.query_row(
                "SELECT generation FROM disclosure_generations WHERE knowledge_id=?1 AND scope_genesis=X''",
                [knowledge.bytes],
                |row| row.get::<_, i64>(0),
            ).optional().unwrap()
        };
        writer.revalidate(EvaluationLimits::default()).unwrap();
        writer
            .save_manual_publication_change(id, ManualPublicationChange::ApprovePublic, "approve")
            .unwrap();
        assert!(
            writer
                .save_pin_change(knowledge, Some(id), "adopt", Some(1234))
                .unwrap()
        );
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Public,
                    |_| panic!("evaluation is stale")
                )
                .unwrap()
        );
        assert_eq!(public_generation(&writer), None);
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(public_generation(&writer), Some(1));
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(public_generation(&writer), Some(1));
        assert!(
            writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Public,
                    |_| Ok(())
                )
                .unwrap()
        );
        assert!(
            writer
                .save_pin_change(knowledge, None, "release", Some(1234))
                .unwrap()
        );
        assert_eq!(public_generation(&writer), Some(2));
        writer.revalidate(EvaluationLimits::default()).unwrap();
        assert_eq!(public_generation(&writer), Some(2));
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Public,
                    |_| panic!("pin was released")
                )
                .unwrap()
        );
        assert!(
            !writer
                .send_record(
                    id,
                    DistributionGate::Open,
                    PublicationPermission::Untrusted,
                    |_| panic!("approval must not transfer")
                )
                .unwrap()
        );
        writer.finish().unwrap();
    }

    #[test]
    fn pin_and_release_preserve_history_across_reopen() {
        let temp = Temp::new();
        let genesis = fixture();
        let id = genesis.id();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: genesis.identity().knowledge,
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let mut body = genesis.body().clone();
        let crate::cbor::Value::Map(fields) = &mut body else {
            panic!("Genesis body must be a map");
        };
        fields
            .iter_mut()
            .filter(|(name, _)| name == "publisher_public_key")
            .for_each(|(_, value)| {
                *value = crate::cbor::Value::Bytes(key.verifying_key().to_bytes().to_vec());
            });
        let replacement = LocalRecord::sign(body, &key).unwrap();
        let replacement_id = replacement.id();
        let wrong = Id {
            kind: Kind::Knowledge,
            bytes: [0; 32],
        };
        let mut writer = temp.store().begin().unwrap();
        assert!(matches!(
            writer.save_pin(knowledge, Some(id), "missing"),
            Err(StorageError::InvalidPinTarget)
        ));
        writer.insert(&genesis).unwrap();
        assert!(matches!(
            writer.save_pin(wrong, Some(id), "mismatch"),
            Err(StorageError::InvalidPinTarget)
        ));
        assert!(writer.save_pin(knowledge, Some(id), "adopt").unwrap());
        assert!(!writer.save_pin(knowledge, Some(id), "retry").unwrap());
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.saved_pin(knowledge).unwrap(), Some(id));
        let mut writer = store.begin().unwrap();
        writer.insert(&replacement).unwrap();
        assert_eq!(writer.store.saved_pin(knowledge).unwrap(), Some(id));
        assert!(
            writer
                .save_pin(knowledge, Some(replacement_id), "replace")
                .unwrap()
        );
        assert_eq!(
            writer.store.saved_pin(knowledge).unwrap(),
            Some(replacement_id)
        );
        assert!(writer.save_pin(knowledge, None, "release").unwrap());
        writer.finish().unwrap();
        let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
        assert_eq!(store.saved_pin(knowledge).unwrap(), None);
        let count: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM history JOIN pin_changes USING(generation)
             WHERE target=?1 AND ((reason='adopt' AND old_genesis IS NULL AND new_genesis=?2)
                               OR (reason='replace' AND old_genesis=?2 AND new_genesis=?3)
                               OR (reason='release' AND old_genesis=?3 AND new_genesis IS NULL))",
                params![knowledge.bytes, id.bytes, replacement_id.bytes],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn failed_pin_change_preserves_previous_pin_and_generation() {
        let temp = Temp::new();
        let genesis = fixture();
        let id = genesis.id();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: genesis.identity().knowledge,
        };
        let mut writer = temp.store().begin().unwrap();
        writer.insert(&genesis).unwrap();
        writer.save_pin(knowledge, Some(id), "adopt").unwrap();
        let before = logical_snapshot(&writer.store.conn);
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER reject_pin BEFORE INSERT ON pin_changes
             BEGIN SELECT RAISE(ABORT,'test failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            writer.save_pin(knowledge, None, "release"),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(logical_snapshot(&writer.store.conn), before);
        assert_eq!(writer.store.saved_pin(knowledge).unwrap(), Some(id));
        assert!(matches!(
            writer.save_pin(knowledge, None, "retry"),
            Err(StorageError::UnresolvedFailure)
        ));
    }
}
