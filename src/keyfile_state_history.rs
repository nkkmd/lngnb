//! §5.100: 全履歴の厳密な読取りだけ。追記・整理・保存資格は提供しない。
use super::*;
use crate::cbor::{self, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const RULES: &str = "lngnb-key-operations-1";
const STARTED: &str = "residue_cleanup_started";
const COMPLETED: &str = "residue_cleanup_completed";
const ABSENT: &str = "confirmed_absent_on_recovery";
const RESUMED: &str = "key_changes_resumed";
#[path = "keyfile_passphrase_journal.rs"]
mod journal;
pub(super) use journal::first_change_fits;
#[path = "keyfile_resume_codec.rs"]
mod resume;
pub(super) use resume::{
    file_identity as recorded_file_identity, guard_identity as recorded_guard_identity,
};
const COMMON: [&str; 6] = [
    "sequence",
    "operation_id",
    "kind",
    "actor_uid",
    "recorded_unix_seconds",
    "rules",
];

/// 履歴だけから導いた状態。Readyも認証・保存確定・通常変更許可ではない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyHistoryState {
    Held,
    Active {
        started_operation_id: [u8; 32],
    },
    Ready {
        resumed_operation_id: [u8; 32],
    },
    PassphraseChangeStarted {
        started_operation_id: [u8; 32],
    },
    PassphraseChangePrepared {
        prepared_operation_id: [u8; 32],
    },
    /// 履歴上のReady。guard解除・通常変更資格の確認は別途必要。
    PassphraseChangeCompleted {
        completed_operation_id: [u8; 32],
    },
}

/// 現在の有界読取りの整合だけ。認証・過去のfsync・保全確定の証明ではない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyStateDiagnostic {
    pub initial: KeyInitialState,
    pub generation: u64,
    pub snapshot_hash: [u8; 32],
    pub state: KeyHistoryState,
}

fn invalid<T>() -> Result<T> {
    Err(KeyFileError::RecoveryStateInvalid)
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    if let Value::Map(m) = value {
        if let Some((_, v)) = m.iter().find(|(k, _)| k == key) {
            return Ok(v);
        }
    }
    invalid()
}
fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let Value::Map(m) = value else {
        return invalid();
    };
    if m.len() != expected.len()
        || expected
            .iter()
            .any(|key| m.iter().filter(|(k, _)| k.as_str() == *key).count() != 1)
    {
        return invalid();
    }
    Ok(())
}
fn bytes<const N: usize>(v: &Value) -> Result<[u8; N]> {
    let Value::Bytes(b) = v else {
        return invalid();
    };
    b.as_slice()
        .try_into()
        .map_err(|_| KeyFileError::RecoveryStateInvalid)
}
fn text(v: &Value) -> Result<&str> {
    match v {
        Value::Text(s) => Ok(s),
        _ => invalid(),
    }
}
fn integer(v: &Value) -> Result<i64> {
    match v {
        Value::Int(n) => Ok(*n),
        _ => invalid(),
    }
}
fn equal_text(v: &Value, expected: &str) -> Result<()> {
    if text(v)? != expected {
        return invalid();
    }
    Ok(())
}
fn encoded(v: &Value) -> Result<Vec<u8>> {
    cbor::encode(v).map_err(|_| KeyFileError::RecoveryStateInvalid)
}
fn identity(v: &Value, owner: [u8; 4]) -> Result<()> {
    keys(
        v,
        &[
            "dev",
            "ino",
            "length",
            "nlink",
            "uid",
            "mode",
            "mtime_seconds",
            "ctime_seconds",
            "mtime_nanoseconds",
            "ctime_nanoseconds",
        ],
    )?;
    bytes::<8>(field(v, "dev")?)?;
    bytes::<8>(field(v, "ino")?)?;
    let length = u64::from_be_bytes(bytes(field(v, "length")?)?);
    if length == 0
        || length > MAX_KEYFILE_BYTES as u64
        || u64::from_be_bytes(bytes(field(v, "nlink")?)?) != 1
        || bytes::<4>(field(v, "uid")?)? != owner
        || u32::from_be_bytes(bytes(field(v, "mode")?)?) != 0o100600
    {
        return invalid();
    }
    integer(field(v, "mtime_seconds")?)?;
    integer(field(v, "ctime_seconds")?)?;
    for key in ["mtime_nanoseconds", "ctime_nanoseconds"] {
        if !(0..=999_999_999).contains(&integer(field(v, key)?)?) {
            return invalid();
        }
    }
    Ok(())
}
fn started(event: &Value, source: &[u8]) -> Result<()> {
    let target = field(event, "target")?;
    keys(
        target,
        &["name", "identity", "ciphertext_sha256", "public_key"],
    )?;
    if !recovery_name(text(field(target, "name")?)?) {
        return invalid();
    }
    let owner = source[69..73]
        .try_into()
        .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    identity(field(target, "identity")?, owner)?;
    bytes::<32>(field(target, "ciphertext_sha256")?)?;
    bytes::<32>(field(target, "public_key")?)?;
    let preserved = field(event, "preserved")?;
    keys(preserved, &["name", "identity", "directory"])?;
    name(text(field(preserved, "name")?)?).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    let directory = field(preserved, "directory")?;
    keys(directory, &["dev", "ino", "uid"])?;
    let dev = bytes::<8>(field(directory, "dev")?)?;
    let ino = bytes::<8>(field(directory, "ino")?)?;
    if (dev == source[53..61] && ino == source[61..69])
        || bytes::<4>(field(directory, "uid")?)? != owner
    {
        return invalid();
    }
    let target_identity = field(target, "identity")?;
    let preserved_identity = field(preserved, "identity")?;
    identity(preserved_identity, owner)?;
    if field(target_identity, "length")? != field(preserved_identity, "length")?
        || (field(target_identity, "dev")? == field(preserved_identity, "dev")?
            && field(target_identity, "ino")? == field(preserved_identity, "ino")?)
    {
        return invalid();
    }
    Ok(())
}
fn array_head(count: usize) -> usize {
    match count {
        0..=23 => 1,
        24..=255 => 2,
        _ => 3,
    }
}
fn maximum_completion_bytes() -> Result<usize> {
    // 全可変整数の最大長と、長いdisposition。ID/UIDは固定長。
    let v = Value::Map(vec![
        ("sequence".into(), Value::Int(1024)),
        ("operation_id".into(), Value::Bytes(vec![0; 32])),
        ("kind".into(), Value::Text(COMPLETED.into())),
        ("actor_uid".into(), Value::Bytes(vec![0; 4])),
        ("recorded_unix_seconds".into(), Value::Int(i64::MAX)),
        ("rules".into(), Value::Text(RULES.into())),
        ("started_operation_id".into(), Value::Bytes(vec![0; 32])),
        ("disposition".into(), Value::Text(ABSENT.into())),
    ]);
    Ok(encoded(&v)?.len())
}
fn completion_fits(
    count: usize,
    prefix_bytes: usize,
    completion_bytes: usize,
    limit: usize,
) -> bool {
    count < 1024
        && prefix_bytes
            .checked_add(completion_bytes)
            .and_then(|n| n.checked_add(array_head(count + 1) - array_head(count)))
            .is_some_and(|n| n <= limit)
}

pub(super) fn decode_history(
    snapshot: &[u8],
    source: &[u8],
    area_id: [u8; 32],
    root: [u8; 32],
) -> Result<KeyStateDiagnostic> {
    if snapshot.len() > initial_state::STATE_LIMIT
        || source.len() != 73
        || !source.starts_with(b"lngnb:key-recovery:1\0")
        || source[21..53] != area_id
    {
        return invalid();
    }
    let value = cbor::decode(snapshot).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    keys(&value, &["format", "area_id", "source_marker", "events"])?;
    equal_text(field(&value, "format")?, "lngnb-key-state-1")?;
    if bytes::<32>(field(&value, "area_id")?)? != area_id
        || bytes::<73>(field(&value, "source_marker")?)? != source
    {
        return invalid();
    }
    let Value::Array(events) = field(&value, "events")? else {
        return invalid();
    };
    if events.is_empty() || events.len() > 1024 {
        return invalid();
    }
    let first = &events[0];
    keys(first, &["sequence", "operation_id", "kind"])?;
    equal_text(field(first, "kind")?, "initial_hold_confirmed")?;
    if integer(field(first, "sequence")?)? != 1 {
        return invalid();
    }
    let operation_id = bytes(field(first, "operation_id")?)?;
    let initial_bytes = encoded(&initial_state::initial_value(source, area_id, operation_id))?;
    let initial = initial_state::decode_initial(&initial_bytes, source, area_id)?;
    if initial.snapshot_hash != root {
        return invalid();
    }
    let mut ids = BTreeSet::from([operation_id]);
    let mut active = None;
    let mut ready = None;
    let mut change = None;
    let mut completions = Vec::new();
    let mut prefix_bytes = initial_bytes.len();
    let completion_bytes = maximum_completion_bytes()?;
    for (i, event) in events.iter().enumerate().skip(1) {
        let count = i + 1;
        let kind = text(field(event, "kind")?)?;
        let journal_keys = journal::additional_keys(kind);
        if ready.is_some() != journal_keys.is_some() {
            return invalid();
        }
        let additional: &[&str] = match kind {
            STARTED => &["target", "preserved"],
            COMPLETED => &["started_operation_id", "disposition"],
            RESUMED => &[
                "current",
                "preserved",
                "guard_identity",
                "cleanup_operations",
                "reason",
            ],
            _ => journal_keys.ok_or(KeyFileError::RecoveryStateInvalid)?,
        };
        let mut expected = COMMON.to_vec();
        expected.extend_from_slice(additional);
        keys(event, &expected)?;
        if integer(field(event, "sequence")?)? != count as i64
            || !ids.insert(bytes::<32>(field(event, "operation_id")?)?)
            || integer(field(event, "recorded_unix_seconds")?)? < 0
        {
            return invalid();
        }
        bytes::<4>(field(event, "actor_uid")?)?;
        equal_text(field(event, "rules")?, RULES)?;
        prefix_bytes += encoded(event)?.len() + array_head(count) - array_head(i);
        if journal_keys.is_some() {
            change = Some(journal::validate(
                &value,
                &events[..count],
                source,
                prefix_bytes,
            )?);
        } else if kind == STARTED {
            if active.is_some()
                || !completion_fits(
                    count,
                    prefix_bytes,
                    completion_bytes,
                    initial_state::STATE_LIMIT,
                )
            {
                return invalid();
            }
            started(event, source)?;
            active = Some(bytes(field(event, "operation_id")?)?);
        } else if kind == COMPLETED {
            let reference = bytes::<32>(field(event, "started_operation_id")?)?;
            if active != Some(reference)
                || !["removed_present", ABSENT].contains(&text(field(event, "disposition")?)?)
            {
                return invalid();
            }
            active = None;
            completions.push(bytes::<32>(field(event, "operation_id")?)?);
        } else {
            if active.is_some() {
                return invalid();
            }
            resume::validate(event, source, &completions)?;
            ready = Some(bytes::<32>(field(event, "operation_id")?)?);
        }
    }
    // 全件を保持したまま検査。初回一件への切詰め/履歴再生成はしない。
    if prefix_bytes != snapshot.len() || encoded(&value)? != snapshot {
        return invalid();
    }
    Ok(KeyStateDiagnostic {
        initial,
        generation: events.len() as u64,
        snapshot_hash: Sha256::digest(snapshot).into(),
        state: change.unwrap_or(match (ready, active) {
            (Some(resumed_operation_id), _) => KeyHistoryState::Ready {
                resumed_operation_id,
            },
            (None, Some(started_operation_id)) => KeyHistoryState::Active {
                started_operation_id,
            },
            (None, None) => KeyHistoryState::Held,
        }),
    })
}

impl KeyDirectory {
    /// 履歴全件・初回root・guardを診断するだけ。初回専用復旧は呼ばない。
    pub fn key_state_history(&mut self, expected_area_id: &[u8; 32]) -> Result<KeyStateDiagnostic> {
        self.reject_state_artifacts(true)?;
        let marker = self.read(recovery_hold::MARKER)?;
        if marker.len() != 105 || !marker.starts_with(b"lngnb:key-recovery:2\0") {
            return invalid();
        }
        let mut source = marker[..73].to_vec();
        source[19] = b'1';
        let area_id = self.marker_area_id(&source)?;
        if &area_id != expected_area_id {
            return invalid();
        }
        let mut guard = b"lngnb:key-hold:1\0".to_vec();
        guard.extend_from_slice(&area_id);
        if self.read(recovery_hold::GUARD)? != guard {
            return invalid();
        }
        let (guard_file, guard_meta) = self.checked_hold_handle(recovery_hold::GUARD, &guard)?;
        let snapshot = self.state_bytes(initial_state::STATE, initial_state::STATE_LIMIT)?;
        let root = marker[73..]
            .try_into()
            .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
        let result = decode_history(&snapshot, &source, area_id, root)?;
        // 現物を伴う通常変更の診断・復旧は専用の接続で扱う。
        if matches!(
            result.state,
            KeyHistoryState::PassphraseChangeStarted { .. }
                | KeyHistoryState::PassphraseChangePrepared { .. }
                | KeyHistoryState::PassphraseChangeCompleted { .. }
        ) {
            return invalid();
        }
        if matches!(result.state, KeyHistoryState::Ready { .. }) {
            let value = cbor::decode(&snapshot).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
            let Value::Array(events) = field(&value, "events")? else {
                return invalid();
            };
            if resume::guard_identity(events.last().ok_or(KeyFileError::RecoveryStateInvalid)?)?
                != KeyFileIdentity::from_metadata(&guard_meta)
            {
                return invalid();
            }
        }
        self.recheck_hold_handle(recovery_hold::GUARD, &guard, &guard_file, &guard_meta)?;
        if self.read(recovery_hold::MARKER)? != marker
            || self.read(recovery_hold::GUARD)? != guard
            || self.state_bytes(initial_state::STATE, initial_state::STATE_LIMIT)? != snapshot
        {
            return Err(KeyFileError::RecoveryChanged);
        }
        self.reject_state_artifacts(true)?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "keyfile_state_history_tests.rs"]
mod tests;
