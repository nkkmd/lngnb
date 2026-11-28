//! A8.2。受付資格の検査はHTTP接続時に行う。内部受付だけで公開許可を作らない。
use super::*;
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// commitが成功した受付。秘密をDebugや通常ログに含めない。
pub struct RecordReceipt {
    pub id: String,
    pub secret: Zeroizing<String>,
}

struct Credentials {
    id: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl Credentials {
    fn persist(
        &self,
        tx: &Transaction<'_>,
        record: &LocalRecord,
        max_bytes: u64,
        max_receipts: u64,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO quarantine_records VALUES(?1,?2) ON CONFLICT(id) DO NOTHING",
            params![record.id().bytes, record.bytes()],
        )?;
        let identical: bool = tx.query_row(
            "SELECT bytes=?2 FROM quarantine_records WHERE id=?1",
            params![record.id().bytes, record.bytes()],
            |row| row.get(0),
        )?;
        if !identical {
            return Err(StorageError::Corrupt);
        }
        let full: bool = tx.query_row(
            "SELECT (SELECT count(*) FROM record_receipts)>=?1
             OR (SELECT sum(length(bytes)) FROM quarantine_records)>?2",
            params![max_receipts, max_bytes],
            |row| row.get(0),
        )?;
        if full {
            return Err(StorageError::Capacity);
        }
        let verifier = Sha256::new()
            .chain_update(b"lngnb:receipt-secret:1\0")
            .chain_update(self.secret.as_slice())
            .finalize();
        tx.execute(
            "INSERT INTO record_receipts VALUES(?1,?2,?3,unixepoch())",
            params![self.id, &verifier[..], record.id().bytes],
        )?;
        Ok(())
    }
}

impl RecordWriter {
    /// 局所検査済みRecordの内部受付。HTTP投稿の認証や頻度予算を代行しない。
    pub fn receive_record(&mut self, record: &LocalRecord) -> Result<RecordReceipt> {
        self.receive_record_with_limits(record, 64 * 1024 * 1024, 100_000)
    }

    fn receive_record_with_limits(
        &mut self,
        record: &LocalRecord,
        max_bytes: u64,
        max_receipts: u64,
    ) -> Result<RecordReceipt> {
        if self.failed {
            return Err(StorageError::UnresolvedFailure);
        }
        let mut credentials = Credentials {
            id: [0; 32],
            secret: Zeroizing::new([0; 32]),
        };
        getrandom::getrandom(&mut credentials.id).map_err(|_| StorageError::RandomUnavailable)?;
        getrandom::getrandom(credentials.secret.as_mut())
            .map_err(|_| StorageError::RandomUnavailable)?;
        let result = (|| {
            let capacity = self.store.capacity()?;
            let reserve = record.bytes().len() as u64 * 4 + 65536;
            if capacity.available <= capacity.reserved_floor.saturating_add(reserve) {
                return Err(StorageError::Capacity);
            }
            let tx = self.store.conn.transaction()?;
            credentials.persist(&tx, record, max_bytes, max_receipts)?;
            if let Some((blob, _)) = record.payload().map_err(|_| StorageError::Corrupt)? {
                cleanup::cancel(
                    &tx,
                    &blob,
                    "record_reference",
                    self.store.limits.sql_inspection,
                )?;
            }
            tx.commit()?;
            Ok(())
        })();
        if let Err(error) = result {
            if !matches!(error, StorageError::BudgetExceeded | StorageError::Capacity) {
                self.failed = true;
            }
            return Err(error);
        }
        let mut secret = Zeroizing::new(String::from("rs1_"));
        BASE32_NOPAD.encode_append(credentials.secret.as_slice(), &mut secret);
        secret.make_ascii_lowercase();
        Ok(RecordReceipt {
            id: format!(
                "ri1_{}",
                BASE32_NOPAD.encode(&credentials.id).to_ascii_lowercase()
            ),
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::tests::{Temp, fixture, logical_snapshot};

    #[test]
    fn receipt_retry_changes_only_private_rows() {
        let tmp = Temp::new();
        let mut writer = tmp.store().begin().unwrap();
        let record = fixture();
        let before = logical_snapshot(&writer.store.conn);
        let first = writer.receive_record(&record).unwrap();
        let second = writer.receive_record(&record).unwrap();
        assert_ne!(first.id, second.id);
        assert_ne!(*first.secret, *second.secret);
        let after = logical_snapshot(&writer.store.conn);
        for ((table, old), (name, new)) in before.iter().zip(&after) {
            assert_eq!(table, name);
            match table.as_str() {
                "quarantine_records" => assert_eq!(new.len(), 1),
                "record_receipts" => assert_eq!(new.len(), 2),
                "record_inspection" => assert_ne!(old, new),
                _ => assert_eq!(old, new, "{table}"),
            }
        }
        assert!(writer.record(record.id()).unwrap().is_none());
        writer.finish().unwrap();
        let store = super::RecordStore::open(&tmp.data(), super::Limits::default()).unwrap();
        for receipt in [first, second] {
            use sha2::{Digest, Sha256};
            let decode = |payload: &str| {
                data_encoding::BASE32_NOPAD
                    .decode(payload.to_ascii_uppercase().as_bytes())
                    .unwrap()
            };
            let id = decode(receipt.id.strip_prefix("ri1_").unwrap());
            let secret = decode(receipt.secret.strip_prefix("rs1_").unwrap());
            let (bytes, verifier): (Vec<u8>, Vec<u8>) = store.conn.query_row(
                "SELECT q.bytes,r.verifier FROM record_receipts r JOIN quarantine_records q ON q.id=r.record_id WHERE r.id=?1",
                [id], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            assert_eq!(bytes, record.bytes());
            let mut expected = b"lngnb:receipt-secret:1".to_vec();
            expected.push(0);
            expected.extend(secret);
            assert_eq!(verifier, Sha256::digest(expected).to_vec());
        }
    }

    #[test]
    fn both_startup_paths_check_quarantine_even_with_a_valid_local_copy() {
        use super::{InspectionBudget, Limits, RecordInspection, RecordStore, StorageError};
        let tmp = Temp::new();
        let mut writer = tmp.store().begin().unwrap();
        let record = fixture();
        writer.insert(&record).unwrap();
        writer.receive_record(&record).unwrap();
        writer.finish().unwrap();
        let conn = rusqlite::Connection::open(tmp.data().join(super::DB)).unwrap();
        conn.execute(
            "UPDATE quarantine_records SET bytes=zeroblob(length(bytes))",
            [],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            RecordStore::open(&tmp.data(), Limits::default()),
            Err(StorageError::Corrupt)
        ));
        let mut scan = RecordInspection::open(&tmp.data(), Limits::default()).unwrap();
        let one = InspectionBudget {
            records: 1,
            ..InspectionBudget::default()
        };
        assert_eq!(scan.step(one).unwrap().checked_records, 1);
        scan.pause().unwrap();
        let mut scan = RecordInspection::open(&tmp.data(), Limits::default()).unwrap();
        assert!(matches!(scan.step(one), Err(StorageError::Corrupt)));
    }

    #[test]
    fn quota_refusal_preserves_rows_and_retry_budget() {
        let tmp = Temp::new();
        let mut writer = tmp.store().begin().unwrap();
        let record = fixture();
        let len = record.bytes().len() as u64;
        let before = logical_snapshot(&writer.store.conn);
        assert!(matches!(
            writer.receive_record_with_limits(&record, len - 1, 2),
            Err(super::StorageError::Capacity)
        ));
        assert_eq!(before, logical_snapshot(&writer.store.conn));
        writer.receive_record_with_limits(&record, len, 2).unwrap();
        writer.receive_record_with_limits(&record, len, 2).unwrap();
        let full = logical_snapshot(&writer.store.conn);
        assert!(matches!(
            writer.receive_record_with_limits(&record, len, 2),
            Err(super::StorageError::Capacity)
        ));
        assert_eq!(full, logical_snapshot(&writer.store.conn));
        writer.finish().unwrap();
    }

    #[test]
    fn failed_receipt_rolls_back_quarantine_bytes() {
        let tmp = Temp::new();
        let mut writer = tmp.store().begin().unwrap();
        writer
            .store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER refuse BEFORE INSERT ON record_receipts
             BEGIN SELECT RAISE(ABORT,'test refusal'); END;",
            )
            .unwrap();
        let before = logical_snapshot(&writer.store.conn);
        assert!(writer.receive_record(&fixture()).is_err());
        assert_eq!(logical_snapshot(&writer.store.conn), before);
        assert!(writer.finish().is_err());
    }
}
