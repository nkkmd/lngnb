//! RecordとBlob本文の公開可否。仕様 §7.2.2〜§7.2.3。

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

impl RecordWriter {
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
        let (expected, genesis) = match scope {
            FixedRecordScope::Public { genesis_id } => (RecordPublication::Public, genesis_id),
            FixedRecordScope::Untrusted { genesis_id } => {
                (RecordPublication::UntrustedPublic, Some(genesis_id))
            }
        };
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
            let tx = self.store.conn.transaction()?;
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
        for target in [
            "/v1/records",
            "/v1/records/",
            &format!("{path}/verification"),
        ] {
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
