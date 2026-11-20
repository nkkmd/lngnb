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
            let tx = self.store.conn.transaction()?;
            advance(&tx)?;
            audit(
                &tx,
                Some(&knowledge.bytes),
                if previous.is_some() {
                    "pinned"
                } else {
                    "unpinned"
                },
                "pin_saved_local_only",
                reason,
            )?;
            if tx.execute(
                "INSERT INTO pin_changes(generation,old_genesis,new_genesis)
                 SELECT generation,?1,?2 FROM storage_state WHERE singleton=1",
                params![previous.map(|id| id.bytes), genesis.map(|id| id.bytes)],
            )? != 1
            {
                return Err(StorageError::Corrupt);
            }
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
                params![knowledge.bytes, id.bytes],
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
