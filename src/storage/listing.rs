//! A6の一覧はwriterの寿命内で保持し、配信資格はページごとに照合する。
use super::*;
use data_encoding::BASE32_NOPAD;
use std::time::{Duration, Instant};

type Token = [u8; 32];
const TTL: Duration = Duration::from_secs(600);
// 固定欄、Vec台帳の空き枠、期限文字列を含む一一覧あたりの予約。
const SNAPSHOT_OVERHEAD: usize = 1024;

pub(crate) fn parse_token(s: &str, prefix: &str) -> Option<Token> {
    let raw = s.strip_prefix(prefix)?;
    if raw.len() != 52 || raw.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    BASE32_NOPAD
        .decode(raw.to_ascii_uppercase().as_bytes())
        .ok()?
        .try_into()
        .ok()
}
fn encode(prefix: &str, token: &Token) -> String {
    format!(
        "{prefix}{}",
        BASE32_NOPAD.encode(token).to_ascii_lowercase()
    )
}
fn random() -> Result<Token> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| StorageError::RandomUnavailable)?;
    Ok(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Listing {
    pub knowledge: Id,
    pub genesis: Id,
    pub untrusted: bool,
    pub with_payloads: bool,
    pub page_size: usize,
}

pub(super) struct Snapshot {
    listing: Listing,
    token: Token,
    namespace: Token,
    epoch: i64,
    deadline: Instant,
    expires_at: String,
    ids: Vec<Token>,
    cursors: Vec<Token>,
}
impl Snapshot {
    fn bytes(&self) -> usize {
        SNAPSHOT_OVERHEAD + 32 * (self.ids.capacity() + self.cursors.capacity())
    }
}

pub(crate) enum Page {
    Available(String),
    Hidden,
    Invalid,
}

impl RecordWriter {
    pub(crate) fn record_page(
        &mut self,
        listing: Listing,
        token: Option<Token>,
        cursor: Option<Token>,
        gate: DistributionGate,
    ) -> Result<Page> {
        let hidden = || {
            if token.is_some() {
                Page::Invalid
            } else {
                Page::Hidden
            }
        };
        if gate == DistributionGate::Closed
            || self.failed
            || !self.began_clean
            || self.publication_block.is_some()
            || self.store.blob_recovery.needs_review()
        {
            self.listings.clear();
            return Ok(hidden());
        }
        if !(1..=500).contains(&listing.page_size) || (cursor.is_some() && token.is_none()) {
            return Ok(Page::Invalid);
        }
        let now = Instant::now();
        self.listings.retain(|s| now < s.deadline);
        let existing = match token {
            Some(t) => match self
                .listings
                .iter()
                .position(|s| s.token == t && s.listing == listing)
            {
                Some(index) => Some(index),
                None => return Ok(Page::Invalid),
            },
            None => None,
        };
        let key: &[u8] = if listing.untrusted {
            &listing.genesis.bytes
        } else {
            &[]
        };
        let scope = if listing.untrusted {
            FixedRecordScope::Untrusted {
                genesis_id: listing.genesis,
            }
        } else {
            FixedRecordScope::Public {
                genesis_id: Some(listing.genesis),
            }
        };
        let result = (|| {
            let tx = self.store.conn.unchecked_transaction()?;
            let data = sql_inspection::run(&tx, self.store.limits.sql_inspection, || {
                let Some((_, ns, _)) =
                    self.store
                        .current_disclosure(&tx, listing.knowledge, scope, key)?
                else {
                    return Ok(None);
                };
                let epoch: i64 = tx.query_row(
                    "SELECT disclosure_epoch FROM record_listing_members
                    WHERE knowledge_id=?1 AND genesis=?2 AND visible_scope=?3 LIMIT 1",
                    params![listing.knowledge.bytes, listing.genesis.bytes, key],
                    |r| r.get(0),
                )?;
                let snapshot = if existing.is_none() {
                    if self.listings.len() >= self.store.limits.listing_snapshots as usize {
                        return Err(StorageError::BudgetExceeded);
                    }
                    let used: usize = self.listings.iter().map(Snapshot::bytes).sum();
                    let available = (self.store.limits.listing_bytes as usize).saturating_sub(used);
                    let max_ids = (self.store.limits.listing_ids as usize)
                        .min(available.saturating_sub(SNAPSHOT_OVERHEAD) / 32);
                    let mut stmt = tx.prepare(
                        "SELECT record_id FROM disclosure_records WHERE knowledge_id=?1
                        AND genesis=?2 AND visible_scope=?3 ORDER BY record_id LIMIT ?4",
                    )?;
                    let ids = stmt
                        .query_map(
                            params![
                                listing.knowledge.bytes,
                                listing.genesis.bytes,
                                key,
                                max_ids + 1
                            ],
                            |r| r.get(0),
                        )?
                        .collect::<rusqlite::Result<Vec<Token>>>()?;
                    if ids.len() > max_ids {
                        return Err(StorageError::BudgetExceeded);
                    }
                    let num_cursors = ids.len().saturating_sub(1) / listing.page_size;
                    if SNAPSHOT_OVERHEAD + 32 * (ids.capacity() + num_cursors) > available {
                        return Err(StorageError::BudgetExceeded);
                    }
                    let mut cursors = vec![[0; 32]; num_cursors];
                    getrandom::getrandom(cursors.as_flattened_mut())
                        .map_err(|_| StorageError::RandomUnavailable)?;
                    let issued = Instant::now();
                    let expires_at = tx.query_row(
                        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now','+600 seconds')",
                        [],
                        |r| r.get(0),
                    )?;
                    Some(Snapshot {
                        listing,
                        token: random()?,
                        namespace: ns,
                        epoch,
                        deadline: issued + TTL,
                        expires_at,
                        ids,
                        cursors,
                    })
                } else {
                    None
                };
                Ok(Some((ns, epoch, snapshot)))
            })?;
            tx.commit()?;
            Ok(data)
        })();
        if result.is_err()
            && !matches!(
                result,
                Err(StorageError::BudgetExceeded | StorageError::RandomUnavailable)
            )
        {
            self.failed = true;
        }
        let Some((ns, epoch, new)) = result? else {
            if let Some(index) = existing {
                self.listings.swap_remove(index);
            }
            return Ok(hidden());
        };
        let index = if let Some(index) = existing {
            index
        } else {
            self.listings.push(new.expect("initial page snapshot"));
            self.listings.len() - 1
        };
        let s = &self.listings[index];
        if s.namespace != ns || s.epoch != epoch || Instant::now() >= s.deadline {
            self.listings.swap_remove(index);
            return Ok(Page::Invalid);
        }
        let page = match cursor {
            Some(c) => match s.cursors.iter().position(|token| *token == c) {
                Some(i) => i + 1,
                None => return Ok(Page::Invalid),
            },
            None => 0,
        };
        let start = page * listing.page_size;
        let end = (start + listing.page_size).min(s.ids.len());
        let ids: Vec<_> = s.ids[start..end]
            .iter()
            .map(|bytes| {
                Id {
                    kind: Kind::Record,
                    bytes: *bytes,
                }
                .to_string()
            })
            .collect();
        let next = s.cursors.get(page).map(|c| encode("cu1_", c));
        Ok(Page::Available(serde_json::json!({
            "api_version":"lngnb-http-1", "profile_id":crate::record::PROFILE,
            "knowledge_id":listing.knowledge.to_string(), "genesis_record_id":listing.genesis.to_string(),
            "scope":if listing.untrusted {"untrusted"} else {"public"},
            "mode":if listing.with_payloads {"with_payloads"} else {"metadata"},
            "snapshot_id":encode("st1_", &s.token), "expires_at":s.expires_at, "record_ids":ids,
            "next_cursor":next,"listing_complete":next.is_none()
        }).to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_record_http::route_fixed_record_request;
    use crate::storage::evaluation::tests::rev;
    use crate::storage::tests::{Temp, fixture};

    fn get(w: &mut RecordWriter, target: &str) -> (u16, serde_json::Value) {
        let mut out = None;
        assert!(
            route_fixed_record_request(
                w,
                DistributionGate::Open,
                "GET",
                target,
                |status, _, data| {
                    out = Some((status, serde_json::from_slice(data).unwrap()));
                    Ok(())
                }
            )
            .unwrap()
        );
        out.unwrap()
    }

    #[test]
    fn pages_bind_scope_and_survive_only_expansions() {
        let temp = Temp::new();
        let mut w = temp.store().begin().unwrap();
        let genesis = fixture();
        let g = genesis.id();
        let k = Id {
            kind: Kind::Knowledge,
            bytes: genesis.identity().knowledge,
        };
        let first = rev(&[], 14, "first");
        let added = rev(&[], 14, "added");
        for r in [&genesis, &first, &added] {
            w.insert(r).unwrap();
        }
        w.revalidate(EvaluationLimits::default()).unwrap();
        for id in [g, first.id()] {
            w.save_manual_publication_change(id, ManualPublicationChange::ApproveUntrusted, "test")
                .unwrap();
        }
        let base = format!("/v1/knowledge/{k}/records?genesis_id={g}&scope=untrusted&page_size=1");
        let alias =
            format!("/v1/records?knowledge_id={k}&genesis_id={g}&scope=untrusted&page_size=1");
        let (status, page) = get(&mut w, &base);
        assert_eq!(status, 200);
        let token = page["snapshot_id"].as_str().unwrap();
        let cursor = page["next_cursor"].as_str().unwrap();
        assert_eq!(page["listing_complete"], false);
        let private = rev(&[], 14, "pending submission");
        w.receive_record(&private).unwrap();
        w.adopt_quarantine_record(private.id(), 256 * 1024 * 1024)
            .unwrap();
        let again = format!("{alias}&snapshot_id={token}");
        assert_eq!(get(&mut w, &again).1, page);
        let next = format!("{again}&cursor={cursor}");
        let invalid = get(&mut w, &format!("{next}&mode=with_payloads"));
        assert_eq!(invalid.0, 409);
        assert_eq!(invalid.1["error"]["code"], "snapshot_invalid");
        assert_eq!(
            get(&mut w, &next.replace("scope=untrusted", "scope=public")),
            invalid
        );
        assert_eq!(
            get(&mut w, &next.replace("page_size=1", "page_size=2")),
            invalid
        );
        let (_, other) = get(&mut w, &base);
        assert_eq!(
            get(
                &mut w,
                &next.replace(cursor, other["next_cursor"].as_str().unwrap())
            ),
            invalid
        );
        w.save_manual_publication_change(
            added.id(),
            ManualPublicationChange::ApproveUntrusted,
            "expand",
        )
        .unwrap();
        let (status, last) = get(&mut w, &next);
        assert_eq!(status, 200);
        let mut expected = [g, first.id()];
        expected.sort_by_key(|id| id.bytes);
        assert_eq!(
            page["record_ids"],
            serde_json::json!([expected[0].to_string()])
        );
        assert_eq!(
            last["record_ids"],
            serde_json::json!([expected[1].to_string()])
        );
        assert_eq!(last["expires_at"], page["expires_at"]);
        assert_eq!(last["listing_complete"], true);
        assert!(last["next_cursor"].is_null());
        w.save_manual_publication_change(first.id(), ManualPublicationChange::Revoke, "hide")
            .unwrap();
        w.save_manual_publication_change(
            first.id(),
            ManualPublicationChange::ApproveUntrusted,
            "republish",
        )
        .unwrap();
        assert_eq!(get(&mut w, &next), invalid);
        let (_, fresh) = get(&mut w, &base);
        let fresh_token = fresh["snapshot_id"].as_str().unwrap();
        w.listings.last_mut().unwrap().deadline = Instant::now();
        assert_eq!(
            get(&mut w, &format!("{base}&snapshot_id={fresh_token}")),
            invalid
        );
        assert_eq!(get(&mut w, &format!("{base}&page_size=2")).0, 400);
        assert_eq!(get(&mut w, &format!("{base}&cursor={cursor}")).0, 400);
        assert_eq!(
            get(&mut w, &base.replace("scope=untrusted", "scope=public")).0,
            404
        );
        w.save_pin(k, Some(g), "pin").unwrap();
        w.save_manual_publication_change(g, ManualPublicationChange::ApprovePublic, "publish")
            .unwrap();
        let public = format!("/v1/records?knowledge_id={k}&genesis_id={g}&mode=with_payloads");
        let (status, public_page) = get(&mut w, &public);
        assert_eq!(status, 200);
        assert_eq!(
            public_page["record_ids"],
            serde_json::json!([g.to_string()])
        );
        assert_eq!(public_page["mode"], "with_payloads");
        let saved_size = w.listings.len();
        w.store.limits.listing_ids = 0;
        assert_eq!(get(&mut w, &public).0, 503);
        w.store.limits.listing_ids = 100_000;
        w.store.limits.listing_bytes = 50;
        assert_eq!(get(&mut w, &public).0, 503);
        w.store.limits.listing_bytes = 64 * 1024 * 1024;
        w.store.limits.listing_snapshots = saved_size as u32;
        assert_eq!(get(&mut w, &public).0, 503);
        assert_eq!(w.listings.len(), saved_size);
        let replay = format!(
            "{public}&snapshot_id={}",
            public_page["snapshot_id"].as_str().unwrap()
        );
        assert_eq!(get(&mut w, &replay).1, public_page);
        w.finish().unwrap();
        let mut w = RecordStore::open(&temp.data(), Limits::default())
            .unwrap()
            .begin()
            .unwrap();
        assert_eq!(get(&mut w, &replay), invalid);
        w.finish().unwrap();
    }
}
