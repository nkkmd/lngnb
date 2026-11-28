//! A8.3。現在のpinに基づく隔離Revisionの本文管理。単一writerの明示操作。
use super::*;

/// 同じGenesis IDは署名bytesで一つのKnowledgeに束縛される。
const DEFAULT_MANAGED_BYTES: u64 = 1024 * 1024 * 1024;

impl RecordWriter {
    /// 対象参照が現在のpinに基づいて管理されていればtrue。再試行でも資格と実体を再検査する。
    /// 上限Noneは1 GiB。一般公開、仮保存の期限更新、親の正式性の確定は行わない。
    pub fn promote_quarantine_payload(&mut self, id: Id, byte_limit: Option<u64>) -> Result<bool> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        if id.kind != Kind::Record {
            return Ok(false);
        }
        let result = self.promote_payload_inner(id, byte_limit.unwrap_or(DEFAULT_MANAGED_BYTES));
        if result
            .as_ref()
            .is_err_and(|e| !matches!(e, StorageError::Capacity | StorageError::BudgetExceeded))
        {
            self.failed = true;
        }
        result
    }

    fn promote_payload_inner(&self, id: Id, limit: u64) -> Result<bool> {
        let tx = self.store.conn.unchecked_transaction()?;
        let Some(previous) = tx
            .query_row(
                "SELECT managed_genesis FROM quarantine_records WHERE id=?1 AND adopted=1",
                [id.bytes],
                |row| row.get::<_, Option<[u8; 32]>>(0),
            )
            .optional()?
        else {
            return Ok(false);
        };
        let mut scan_key = id.bytes.to_vec();
        scan_key.push(1);
        let record = RecordStore::checked_stored_record(&tx, &scan_key)?;
        let Some((payload, declared)) = record.payload().map_err(|_| StorageError::Corrupt)? else {
            return Ok(false);
        };
        let scope = Id {
            kind: Kind::Knowledge,
            bytes: record.identity().knowledge,
        };
        let genesis = Id {
            kind: Kind::Record,
            bytes: record.genesis().map_err(|_| StorageError::Corrupt)?,
        };
        if self.store.saved_pin(scope)? != Some(genesis) {
            return Ok(false);
        }
        let anchor = self.store.record(genesis)?.ok_or(StorageError::Corrupt)?;
        if record.check_genesis(&anchor).is_err() {
            return Ok(false);
        }
        let blob = Id {
            kind: Kind::Blob,
            bytes: payload,
        };
        let Some((_, actual)) = RecordStore::verified_blob(
            &tx,
            &self.store.dir,
            self.store.limits.scan_blob_bytes,
            blob,
        )?
        else {
            return Ok(false);
        };
        if actual != declared {
            return Ok(false);
        }
        if let Some(prior) = previous {
            if prior != genesis.bytes {
                return Err(StorageError::Corrupt);
            }
            return Ok(true);
        }
        let capacity = self.store.capacity()?;
        if capacity.available <= capacity.reserved_floor.saturating_add(65536) {
            return Err(StorageError::Capacity);
        }
        advance(&tx)?;
        audit(
            &tx,
            Some(&id.bytes),
            "quarantined_payload",
            "payload_managed_local_only",
            &format!(
                "manage_payload:{}:{}",
                blobs::hex(&genesis.bytes),
                blobs::hex(&payload)
            ),
        )?;
        let changed = tx.execute(
            "UPDATE quarantine_records SET managed_genesis=?2,managed_generation=(SELECT generation FROM storage_state WHERE singleton=1) WHERE id=?1 AND adopted=1 AND managed_genesis IS NULL",
            params![id.bytes, genesis.bytes],
        )?;
        if changed != 1 {
            return Err(StorageError::Corrupt);
        }
        let used: u64 = sql_inspection::run(&tx, self.store.limits.sql_inspection, || {
            Ok(tx.query_row(
                "SELECT coalesce(sum(byte_length),0) FROM blobs WHERE id IN
                (SELECT payload_id FROM quarantine_records WHERE managed_genesis=?1)",
                [genesis.bytes],
                |r| r.get(0),
            )?)
        })?;
        if used > limit {
            return Err(StorageError::Capacity);
        }
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::blob_id;
    use crate::storage::evaluation::tests::{bytes, rev};
    use crate::storage::tests::{Temp, fixture, logical_snapshot};

    fn usage(writer: &RecordWriter) -> u64 {
        writer
            .store
            .conn
            .query_row(
                "SELECT coalesce(sum(byte_length),0) FROM quarantine_blob_usage",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn promotion_rechecks_pin_and_charges_unique_blobs_without_publishing() {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let genesis = fixture();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: genesis.identity().knowledge,
        };
        let missing_parent = rev(&[], 14, "not received");
        let first = rev(&[missing_parent.id()], 14, "first");
        let second = rev(&[], 14, "second");
        let blob = blob_id(&bytes());
        w.insert(&genesis).unwrap();
        for record in [&first, &second] {
            w.receive_record(record).unwrap();
            assert!(!w.promote_quarantine_payload(record.id(), None).unwrap());
            w.adopt_quarantine_record(record.id(), 1024).unwrap();
        }
        w.save_pin(knowledge, Some(genesis.id()), "pin").unwrap();
        assert!(!w.promote_quarantine_payload(first.id(), None).unwrap());
        w.stage_blob(blob, bytes().as_slice(), 60, TemporaryLimits::default())
            .unwrap();
        let before = logical_snapshot(&w.store.conn);
        assert!(matches!(
            w.promote_quarantine_payload(first.id(), Some(13)),
            Err(StorageError::Capacity)
        ));
        assert_eq!(before, logical_snapshot(&w.store.conn));
        assert!(w.promote_quarantine_payload(first.id(), Some(14)).unwrap());
        assert_eq!(usage(&w), 14);
        assert!(w.promote_quarantine_payload(second.id(), Some(14)).unwrap());
        assert_eq!(usage(&w), 0);
        let stable = logical_snapshot(&w.store.conn);
        assert!(w.promote_quarantine_payload(first.id(), Some(14)).unwrap());
        assert_eq!(stable, logical_snapshot(&w.store.conn));
        w.stage_blob(
            blob,
            bytes().as_slice(),
            60,
            TemporaryLimits { bytes: 0, holds: 3 },
        )
        .unwrap();
        assert!(w.record(first.id()).unwrap().is_none());
        w.finish().unwrap();
        let mut w = RecordStore::open(&t.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        assert_eq!(usage(&w), 0);
        w.save_pin(knowledge, None, "release").unwrap();
        assert_eq!(usage(&w), 14);
        assert!(!w.promote_quarantine_payload(second.id(), None).unwrap());
        w.finish().unwrap();
    }

    #[test]
    fn aggregate_limit_is_per_genesis_and_failed_pin_release_rolls_back() {
        use crate::cbor::Value;
        use crate::storage::evaluation::tests::{key, set};
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let original = fixture();
        let mut other_body = original.body().clone();
        set(&mut other_body, "knowledge_id", Value::Bytes(vec![6; 32]));
        let other = LocalRecord::sign(other_body, &key()).unwrap();
        for genesis in [&original, &other] {
            w.insert(genesis).unwrap();
            w.save_pin(
                Id {
                    kind: Kind::Knowledge,
                    bytes: genesis.identity().knowledge,
                },
                Some(genesis.id()),
                "pin",
            )
            .unwrap();
        }
        let first = rev(&[], 14, "first");
        let mut body = rev(&[], 1, "second").body().clone();
        let Value::Map(fields) = &mut body else {
            panic!()
        };
        let payload = &mut fields.iter_mut().find(|(k, _)| k == "payload").unwrap().1;
        let small = blob_id(b"x");
        set(payload, "blob_id", Value::Bytes(small.bytes.to_vec()));
        let second = LocalRecord::sign(body, &key()).unwrap();
        let mut body = first.body().clone();
        set(
            &mut body,
            "knowledge_id",
            Value::Bytes(other.identity().knowledge.to_vec()),
        );
        set(
            &mut body,
            "genesis_record_id",
            Value::Bytes(other.id().bytes.to_vec()),
        );
        let shared = LocalRecord::sign(body, &key()).unwrap();
        for data in [bytes().as_slice(), b"x".as_slice()] {
            w.stage_blob(blob_id(data), data, 60, TemporaryLimits::default())
                .unwrap();
        }
        for record in [&first, &second, &shared] {
            w.receive_record(record).unwrap();
            w.adopt_quarantine_record(record.id(), 1024).unwrap();
        }
        assert!(w.promote_quarantine_payload(first.id(), Some(14)).unwrap());
        assert!(matches!(
            w.promote_quarantine_payload(second.id(), Some(14)),
            Err(StorageError::Capacity)
        ));
        assert!(w.promote_quarantine_payload(shared.id(), Some(14)).unwrap());
        assert_eq!(usage(&w), 1);
        assert!(w.promote_quarantine_payload(second.id(), Some(15)).unwrap());
        assert_eq!(usage(&w), 0);
        w.store.conn.execute_batch("CREATE TEMP TRIGGER refuse_release BEFORE UPDATE OF managed_genesis ON quarantine_records
            WHEN NEW.managed_genesis IS NULL BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        let before = logical_snapshot(&w.store.conn);
        assert!(
            w.save_pin(
                Id {
                    kind: Kind::Knowledge,
                    bytes: original.identity().knowledge
                },
                None,
                "release"
            )
            .is_err()
        );
        assert_eq!(before, logical_snapshot(&w.store.conn));
        assert!(w.finish().is_err());
    }

    #[test]
    fn restored_marker_from_before_pin_withdrawal_is_not_valid_provenance() {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let g = fixture();
        let k = Id {
            kind: Kind::Knowledge,
            bytes: g.identity().knowledge,
        };
        w.insert(&g).unwrap();
        w.save_pin(k, Some(g.id()), "pin").unwrap();
        let r = rev(&[], 14, "reopen");
        w.stage_blob(
            blob_id(&bytes()),
            bytes().as_slice(),
            60,
            TemporaryLimits::default(),
        )
        .unwrap();
        w.receive_record(&r).unwrap();
        w.adopt_quarantine_record(r.id(), 1024).unwrap();
        assert!(w.promote_quarantine_payload(r.id(), None).unwrap());
        let promoted = w.store.generation().unwrap();
        w.save_pin(k, None, "release").unwrap();
        w.save_pin(k, Some(g.id()), "re-pin").unwrap();
        w.finish().unwrap();
        let db = Connection::open(t.data().join(DB)).unwrap();
        db.execute(
            "UPDATE quarantine_records SET managed_genesis=?1,managed_generation=?2 WHERE id=?3",
            params![g.id().bytes, promoted, r.id().bytes],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            RecordStore::open(&t.data(), Limits::default()),
            Err(StorageError::Corrupt)
        ));
    }

    #[test]
    fn wrong_signer_conflict_and_corrupt_bytes_never_promote() {
        let t = Temp::new();
        let mut w = t.store().begin().unwrap();
        let genesis = fixture();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: genesis.identity().knowledge,
        };
        w.insert(&genesis).unwrap();
        w.save_pin(knowledge, Some(genesis.id()), "pin").unwrap();
        let good = rev(&[], 14, "reference");
        let wrong = LocalRecord::sign(
            good.body().clone(),
            &ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
        )
        .unwrap();
        let bad_length = rev(&[], 15, "mismatch");
        let blob = blob_id(&bytes());
        w.stage_blob(blob, bytes().as_slice(), 60, TemporaryLimits::default())
            .unwrap();
        for record in [&wrong, &bad_length, &good] {
            w.receive_record(record).unwrap();
            w.adopt_quarantine_record(record.id(), 1024).unwrap();
        }
        assert!(!w.promote_quarantine_payload(wrong.id(), None).unwrap());
        assert!(!w.promote_quarantine_payload(bad_length.id(), None).unwrap());
        std::fs::write(
            t.data().join("blobs").join(blobs::hex(&blob.bytes)),
            vec![0; 14],
        )
        .unwrap();
        let before = logical_snapshot(&w.store.conn);
        assert!(matches!(
            w.promote_quarantine_payload(good.id(), None),
            Err(StorageError::Corrupt)
        ));
        assert_eq!(before, logical_snapshot(&w.store.conn));
        assert!(w.finish().is_err());
    }
}
