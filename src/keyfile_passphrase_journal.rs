//! §5.113の履歴値検査。鍵の交換・復旧・書込み資格は扱わない。
use super::*;

const BEGIN: &str = "key_passphrase_change_started";
const PREPARE: &str = "key_passphrase_change_prepared";
const FINISH: &str = "key_passphrase_change_completed";
const REMOVED: &str = "removed_retained_old_ciphertext";
const ABSENT_OLD: &str = "confirmed_old_ciphertext_absent";

pub(super) fn additional_keys(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        BEGIN => Some(&[
            "previous_snapshot_sha256",
            "name",
            "old_identity",
            "old_ciphertext_sha256",
            "new_ciphertext_sha256",
            "new_ciphertext_length",
            "public_key",
            "guard_identity",
        ]),
        PREPARE => Some(&[
            "previous_snapshot_sha256",
            "started_operation_id",
            "new_identity",
        ]),
        FINISH => Some(&[
            "previous_snapshot_sha256",
            "started_operation_id",
            "prepared_operation_id",
            "installed_identity",
            "disposition",
        ]),
        _ => None,
    }
}

fn source_identity(v: &Value, source: &[u8], owner: [u8; 4]) -> Result<()> {
    identity(v, owner)?;
    if bytes::<8>(field(v, "dev")?)? != source[53..61] {
        return invalid();
    }
    Ok(())
}

fn validate_begin(event: &Value, resumed: &Value, source: &[u8], owner: [u8; 4]) -> Result<()> {
    let current = field(resumed, "current")?;
    for (new_key, resumed_key) in [
        ("name", "name"),
        ("old_identity", "identity"),
        ("old_ciphertext_sha256", "ciphertext_sha256"),
        ("public_key", "public_key"),
    ] {
        if encoded(field(event, new_key)?)? != encoded(field(current, resumed_key)?)? {
            return invalid();
        }
    }
    let guard = field(event, "guard_identity")?;
    source_identity(guard, source, owner)?;
    let new_length = integer(field(event, "new_ciphertext_length")?)?;
    if !(1..=MAX_KEYFILE_BYTES as i64).contains(&new_length)
        || u64::from_be_bytes(bytes(field(guard, "length")?)?) != 49
        || field(guard, "ino")? == field(field(current, "identity")?, "ino")?
        || bytes::<32>(field(event, "new_ciphertext_sha256")?)?
            == bytes::<32>(field(event, "old_ciphertext_sha256")?)?
    {
        return invalid();
    }
    Ok(())
}

fn validate_prepare(event: &Value, started: &Value, source: &[u8], owner: [u8; 4]) -> Result<()> {
    let new = field(event, "new_identity")?;
    source_identity(new, source, owner)?;
    if field(event, "started_operation_id")? != field(started, "operation_id")?
        || u64::from_be_bytes(bytes(field(new, "length")?)?)
            != integer(field(started, "new_ciphertext_length")?)? as u64
    {
        return invalid();
    }
    for key in ["old_identity", "guard_identity"] {
        if field(new, "ino")? == field(field(started, key)?, "ino")? {
            return invalid();
        }
    }
    Ok(())
}

fn validate_finish(event: &Value, prepared: &Value, source: &[u8], owner: [u8; 4]) -> Result<()> {
    if field(event, "started_operation_id")? != field(prepared, "started_operation_id")?
        || field(event, "prepared_operation_id")? != field(prepared, "operation_id")?
        || ![REMOVED, ABSENT_OLD].contains(&text(field(event, "disposition")?)?)
    {
        return invalid();
    }
    let installed = field(event, "installed_identity")?;
    source_identity(installed, source, owner)?;
    let before = field(prepared, "new_identity")?;
    for key in [
        "dev",
        "ino",
        "length",
        "nlink",
        "uid",
        "mode",
        "mtime_seconds",
        "mtime_nanoseconds",
    ] {
        if field(installed, key)? != field(before, key)? {
            return invalid();
        }
    }
    Ok(())
}

fn maximum_event_bytes(kind: &str, sequence: usize, identity: Value) -> Result<usize> {
    let hash = || Value::Bytes(vec![0; 32]);
    let mut fields = vec![
        ("sequence", Value::Int(sequence as i64)),
        ("operation_id", hash()),
        ("kind", Value::Text(kind.into())),
        ("actor_uid", Value::Bytes(vec![0; 4])),
        ("recorded_unix_seconds", Value::Int(i64::MAX)),
        ("rules", Value::Text(RULES.into())),
        ("previous_snapshot_sha256", hash()),
        ("started_operation_id", hash()),
    ];
    if kind == PREPARE {
        fields.push(("new_identity", identity));
    } else {
        fields.extend([
            ("prepared_operation_id", hash()),
            ("installed_identity", identity),
            (
                "disposition",
                Value::Text(
                    if REMOVED.len() >= ABSENT_OLD.len() {
                        REMOVED
                    } else {
                        ABSENT_OLD
                    }
                    .into(),
                ),
            ),
        ]);
    }
    Ok(encoded(&Value::Map(
        fields.into_iter().map(|(k, v)| (k.into(), v)).collect(),
    ))?
    .len())
}

/// 現在のReadyに続く開始・準備・完了の最大サイズを、guard作成前に検査する。
pub(in super::super) fn first_change_fits(
    count: usize,
    prefix_bytes: usize,
    current_name: &str,
    current_identity: &Value,
    new_length: usize,
    limit: usize,
) -> Result<bool> {
    if count > 1021 || !(1..=MAX_KEYFILE_BYTES).contains(&new_length) {
        return Ok(false);
    }
    let hash = || Value::Bytes(vec![0; 32]);
    let mut guard = current_identity.clone();
    let Value::Map(fields) = &mut guard else {
        return invalid();
    };
    // guardの可変整数を最大符号化長にする。length等のbyte stringは固定幅。
    for (key, value) in fields {
        match key.as_str() {
            "mtime_seconds" | "ctime_seconds" => *value = Value::Int(i64::MAX),
            "mtime_nanoseconds" | "ctime_nanoseconds" => *value = Value::Int(999_999_999),
            _ => (),
        }
    }
    let begin = Value::Map(
        [
            ("sequence", Value::Int((count + 1) as i64)),
            ("operation_id", hash()),
            ("kind", Value::Text(BEGIN.into())),
            ("actor_uid", Value::Bytes(vec![0; 4])),
            ("recorded_unix_seconds", Value::Int(i64::MAX)),
            ("rules", Value::Text(RULES.into())),
            ("previous_snapshot_sha256", hash()),
            ("name", Value::Text(current_name.into())),
            ("old_identity", current_identity.clone()),
            ("old_ciphertext_sha256", hash()),
            ("new_ciphertext_sha256", hash()),
            ("new_ciphertext_length", Value::Int(new_length as i64)),
            ("public_key", hash()),
            ("guard_identity", guard),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect(),
    );
    let Some(started_size) = prefix_bytes
        .checked_add(encoded(&begin)?.len())
        .and_then(|size| size.checked_add(array_head(count + 1) - array_head(count)))
    else {
        return Ok(false);
    };
    if started_size > limit {
        return Ok(false);
    }
    reserved_fits(count + 1, started_size, current_identity, true, limit)
}

pub(super) fn reserved_fits(
    count: usize,
    prefix_bytes: usize,
    identity: &Value,
    needs_prepare: bool,
    limit: usize,
) -> Result<bool> {
    let final_count = count + if needs_prepare { 2 } else { 1 };
    if final_count > 1024 {
        return Ok(false);
    }
    let mut widest = identity.clone();
    let Value::Map(fields) = &mut widest else {
        return invalid();
    };
    for (key, value) in fields {
        match key.as_str() {
            "ctime_seconds" => *value = Value::Int(i64::MAX),
            "ctime_nanoseconds" => *value = Value::Int(999_999_999),
            "mtime_seconds" if needs_prepare => *value = Value::Int(i64::MAX),
            "mtime_nanoseconds" if needs_prepare => *value = Value::Int(999_999_999),
            _ => (),
        }
    }
    let prep_bytes = if needs_prepare {
        maximum_event_bytes(PREPARE, count + 1, widest.clone())?
    } else {
        0
    };
    let finish_bytes = maximum_event_bytes(FINISH, final_count, widest)?;
    Ok(
        prefix_bytes + prep_bytes + finish_bytes + array_head(final_count) - array_head(count)
            <= limit,
    )
}

pub(super) fn validate(
    snapshot: &Value,
    events: &[Value],
    source: &[u8],
    prefix_bytes: usize,
) -> Result<KeyHistoryState> {
    let [.., previous, event] = events else {
        return invalid();
    };
    let owner = bytes::<4>(field(event, "actor_uid")?)?;
    if owner != source[69..73] {
        return invalid();
    }
    let Value::Map(fields) = snapshot else {
        return invalid();
    };
    let prefix = Value::Map(
        fields
            .iter()
            .map(|(key, value)| {
                let value = if key == "events" {
                    Value::Array(events[..events.len() - 1].to_vec())
                } else {
                    value.clone()
                };
                (key.clone(), value)
            })
            .collect(),
    );
    let prefix_hash: [u8; 32] = Sha256::digest(encoded(&prefix)?).into();
    if bytes::<32>(field(event, "previous_snapshot_sha256")?)? != prefix_hash {
        return invalid();
    }
    let operation_id = bytes(field(event, "operation_id")?)?;
    let limit = initial_state::STATE_LIMIT;
    match (
        text(field(event, "kind")?)?,
        text(field(previous, "kind")?)?,
    ) {
        (BEGIN, RESUMED) => {
            validate_begin(event, previous, source, owner)?;
            if !reserved_fits(
                events.len(),
                prefix_bytes,
                field(event, "old_identity")?,
                true,
                limit,
            )? {
                return invalid();
            }
            Ok(KeyHistoryState::PassphraseChangeStarted {
                started_operation_id: operation_id,
            })
        }
        (PREPARE, BEGIN) => {
            validate_prepare(event, previous, source, owner)?;
            if !reserved_fits(
                events.len(),
                prefix_bytes,
                field(event, "new_identity")?,
                false,
                limit,
            )? {
                return invalid();
            }
            Ok(KeyHistoryState::PassphraseChangePrepared {
                prepared_operation_id: operation_id,
            })
        }
        (FINISH, PREPARE) => {
            validate_finish(event, previous, source, owner)?;
            Ok(KeyHistoryState::PassphraseChangeCompleted {
                completed_operation_id: operation_id,
            })
        }
        _ => invalid(),
    }
}
