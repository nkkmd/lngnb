//! 保存実体と管理用評価の診断。Record/実行時診断とは別の要求0bytes endpoint。
use super::*;
use crate::storage::EvaluationLimits;

pub(super) const NAME: &str = "admin-evaluate.sock";
pub(super) const MAGIC: [u8; 4] = *b"LNE\x01";
pub(super) const SIZE: usize = 65;
const ELAPSED: Duration = Duration::from_secs(5);

/// 予算内で完了した局所評価の集計。pin・公開・復旧・正常終了の資格ではない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u64,
    pub records: u64,
    pub valid: u64,
    pub pending: u64,
    pub invalid: u64,
    pub payload_verified: u64,
    pub payload_missing: u64,
    pub payload_unavailable: u64,
}
impl Snapshot {
    fn bytes(self) -> [u8; SIZE] {
        let mut bytes = [0; SIZE];
        bytes[0] = 2; // local evaluated collection, not runtime/session counts
        for (i, value) in [
            self.generation,
            self.records,
            self.valid,
            self.pending,
            self.invalid,
            self.payload_verified,
            self.payload_missing,
            self.payload_unavailable,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[1 + i * 8..9 + i * 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }
    pub(super) fn check(bytes: &[u8; SIZE]) -> Option<Self> {
        let n = |i: usize| u64::from_be_bytes(bytes[1 + i * 8..9 + i * 8].try_into().unwrap());
        let snapshot = Self {
            generation: n(0),
            records: n(1),
            valid: n(2),
            pending: n(3),
            invalid: n(4),
            payload_verified: n(5),
            payload_missing: n(6),
            payload_unavailable: n(7),
        };
        if bytes[0] != 2
            || snapshot.generation > i64::MAX as u64
            || snapshot.records > 10_000
            || snapshot
                .valid
                .checked_add(snapshot.pending)?
                .checked_add(snapshot.invalid)?
                != snapshot.records
            || snapshot
                .payload_verified
                .checked_add(snapshot.payload_missing)?
                .checked_add(snapshot.payload_unavailable)?
                > snapshot.records
        {
            return None;
        }
        Some(snapshot)
    }
}
impl Listener {
    /// 同じwriter/排他の存続中だけ専用socketを追加。既存名は保全する。
    pub fn enable_evaluation(&mut self) -> Result<()> {
        self.check_endpoint()?;
        match &self.access {
            Access::Write(writer) if writer.failed => return Err(Error::SessionFailed),
            Access::Write(_) => (),
            _ => return Err(Error::WrongMode),
        }
        if self.evaluation.is_some() {
            return Err(Error::EndpointExists);
        }
        self.evaluation = Some(status::Endpoint::bind(
            self.access.store(),
            self.owner,
            NAME,
        )?);
        Ok(())
    }
    /// 一回一接続、認証後に同じwriter内で再検査。失敗はAPI呼出し側が無視してもfinish不可。
    pub fn serve_evaluation_if_pending(&mut self) -> Result<bool> {
        let result = self.evaluation_if_pending();
        if result.is_err() {
            if let Access::Write(writer) = &mut self.access {
                writer.failed = true;
            }
        }
        result
    }
    fn evaluation_if_pending(&mut self) -> Result<bool> {
        self.check_endpoint()?;
        let endpoint = self.evaluation.as_ref().ok_or(Error::WrongMode)?;
        endpoint.check(self.access.store(), self.owner)?;
        let Some(mut stream) = endpoint.accept()? else {
            return Ok(false);
        };
        authenticate(&stream, self.owner)?;
        self.check_endpoint()?;
        endpoint.check(self.access.store(), self.owner)?;
        stream.set_nonblocking(true).map_err(|_| Error::Io)?;
        let Access::Write(writer) = &self.access else {
            return Err(Error::WrongMode);
        };
        if writer.failed {
            return Err(Error::SessionFailed);
        }
        let start = Instant::now();
        // open時のBlobRecoveryを現在の走査結果へ読み替えない。全保持実体を再照合する。
        let recovery = writer
            .store
            .scan_blobs()
            .map_err(|_| Error::SessionFailed)?;
        if recovery.needs_review() {
            return Err(Error::SessionFailed);
        }
        let elapsed = ELAPSED
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(Error::Policy)?;
        let diagnostic = writer
            .store
            .diagnose(EvaluationLimits {
                elapsed,
                ..EvaluationLimits::default()
            })
            .map_err(|_| Error::SessionFailed)?;
        if diagnostic.storage_fault || start.elapsed() >= ELAPSED {
            return Err(Error::SessionFailed);
        }
        let snapshot = Snapshot {
            generation: diagnostic
                .generation
                .try_into()
                .map_err(|_| Error::SessionFailed)?,
            records: diagnostic.records as u64,
            valid: diagnostic.valid as u64,
            pending: diagnostic.pending as u64,
            invalid: diagnostic.invalid as u64,
            payload_verified: diagnostic.payload_verified as u64,
            payload_missing: diagnostic.payload_missing as u64,
            payload_unavailable: diagnostic.payload_unavailable as u64,
        };
        let bytes = snapshot.bytes();
        if Snapshot::check(&bytes).is_none() {
            return Err(Error::SessionFailed);
        }
        self.check_endpoint()?;
        endpoint.check(self.access.store(), self.owner)?;
        let deadline = Instant::now() + self.timeout;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&(SIZE as u32).to_be_bytes());
        send_all(&mut stream, &header, deadline)?;
        send_all(&mut stream, &bytes, deadline)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        Limits, StartupState,
        tests::{Temp, fixture, logical_snapshot},
    };
    use std::thread;
    fn query(temp: &Temp, listener: &mut Listener) -> Snapshot {
        let path = temp.data();
        let worker =
            thread::spawn(move || client::evaluate(&path, Duration::from_secs(10)).unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !listener.serve_evaluation_if_pending().unwrap() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        worker.join().unwrap()
    }
    #[test]
    fn independent_fixed_bytes_and_invalid_count_totals_are_checked() {
        let hex = "0200000000000000010000000000000003000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000000";
        let expected: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let snapshot = Snapshot {
            generation: 1,
            records: 3,
            valid: 1,
            pending: 1,
            invalid: 1,
            payload_verified: 1,
            payload_missing: 1,
            payload_unavailable: 0,
        };
        assert_eq!(snapshot.bytes().as_slice(), expected);
        assert_eq!(Snapshot::check(&snapshot.bytes()), Some(snapshot));
        for (offset, value) in [(0, 1), (1, 255), (16, 4), (32, 4), (64, 4)] {
            let mut bad = snapshot.bytes();
            bad[offset] = value;
            assert!(Snapshot::check(&bad).is_none());
        }
        let mut bad = snapshot.bytes();
        bad[17..25].fill(255);
        assert!(Snapshot::check(&bad).is_none());
    }
    #[test]
    fn evaluation_uses_same_lock_rechecks_new_records_and_does_not_commit() {
        let temp = Temp::new();
        let mut listener = Listener::bind_writer(
            temp.store().begin().unwrap(),
            MAX_FRAME,
            Duration::from_secs(2),
        )
        .unwrap();
        listener.enable_evaluation().unwrap();
        assert_eq!(listener.enable_evaluation(), Err(Error::EndpointExists));
        let before = logical_snapshot(&listener.access.store().conn);
        assert_eq!(query(&temp, &mut listener).records, 0);
        assert_eq!(logical_snapshot(&listener.access.store().conn), before);
        assert!(RecordStore::open(&temp.data(), Limits::default()).is_err());
        let path = temp.data();
        let worker = thread::spawn(move || {
            client::submit(&path, &fixture(), Duration::from_secs(2)).unwrap()
        });
        listener.accept().unwrap().store_record().unwrap();
        worker.join().unwrap();
        let before = logical_snapshot(&listener.access.store().conn);
        let diagnostic = query(&temp, &mut listener);
        assert_eq!(
            (diagnostic.records, diagnostic.valid, diagnostic.pending),
            (1, 1, 0)
        );
        assert_eq!(logical_snapshot(&listener.access.store().conn), before);
        listener.close_writer().unwrap().finish().unwrap();
        assert!(!temp.data().join(NAME).exists());
    }
    #[test]
    fn fresh_missing_retained_blob_and_budget_failure_latch_failed_writer() {
        for missing in [false, true] {
            let temp = Temp::new();
            let mut writer = temp.store().begin().unwrap();
            if missing {
                let body = b"public retained diagnostic fixture";
                let id = crate::id::blob_id(body);
                writer.put_blob(id, std::io::Cursor::new(body)).unwrap();
                std::fs::remove_file(
                    temp.data()
                        .join("blobs")
                        .join(data_encoding::HEXLOWER.encode(&id.bytes)),
                )
                .unwrap();
            } else {
                writer.insert(&fixture()).unwrap();
                let body = b"public budget fixture";
                writer
                    .put_blob(crate::id::blob_id(body), std::io::Cursor::new(body))
                    .unwrap();
                writer.store.limits.scan_blob_files = 0;
                writer.store.limits.scan_blob_bytes = 0;
            }
            let mut listener =
                Listener::bind_writer(writer, MAX_FRAME, Duration::from_secs(2)).unwrap();
            listener.enable_evaluation().unwrap();
            let dir = super::super::super::directory(&temp.data()).unwrap();
            let _stream = UnixStream::connect(anchored(&dir, NAME)).unwrap();
            let before = logical_snapshot(&listener.access.store().conn);
            assert!(listener.serve_evaluation_if_pending().is_err());
            assert_eq!(logical_snapshot(&listener.access.store().conn), before);
            let writer = listener.close_writer().unwrap();
            assert!(matches!(
                writer.finish(),
                Err(StorageError::UnresolvedFailure)
            ));
            let store = RecordStore::open(&temp.data(), Limits::default()).unwrap();
            assert_eq!(store.startup_state().unwrap(), StartupState::NeedsReview);
        }
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use crate::storage::{
        Limits, StartupState,
        tests::{Temp, logical_snapshot},
    };
    #[test]
    fn residues_replacements_and_lost_replies_never_confirm_clean_finish() {
        for mode in 0..3 {
            let temp = Temp::new();
            let mut listener = Listener::bind_writer(
                temp.store().begin().unwrap(),
                MAX_FRAME,
                Duration::from_secs(1),
            )
            .unwrap();
            let path = temp.data().join(NAME);
            if mode == 0 {
                std::fs::write(&path, b"preserve").unwrap();
                assert_eq!(listener.enable_evaluation(), Err(Error::EndpointExists));
                drop(listener);
            } else if mode == 1 {
                listener.enable_evaluation().unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::write(&path, b"preserve").unwrap();
                assert!(matches!(
                    listener.close_writer(),
                    Err(Error::UnsafeEndpoint)
                ));
            } else {
                listener.enable_evaluation().unwrap();
                let dir = super::super::super::directory(&temp.data()).unwrap();
                let stream = UnixStream::connect(anchored(&dir, NAME)).unwrap();
                stream.shutdown(std::net::Shutdown::Read).unwrap();
                let before = logical_snapshot(&listener.access.store().conn);
                assert!(listener.serve_evaluation_if_pending().is_err());
                assert_eq!(logical_snapshot(&listener.access.store().conn), before);
                assert!(matches!(
                    listener.close_writer().unwrap().finish(),
                    Err(StorageError::UnresolvedFailure)
                ));
            }
            if mode < 2 {
                assert_eq!(std::fs::read(&path).unwrap(), b"preserve");
            }
            assert_eq!(
                RecordStore::open(&temp.data(), Limits::default())
                    .unwrap()
                    .startup_state()
                    .unwrap(),
                StartupState::NeedsReview
            );
        }
    }
}
