//! §5.113の履歴値検査。鍵の交換・復旧・書込み資格は扱わない。
use super::*;

const BEGIN: &str = "key_passphrase_change_started";
const PREPARE: &str = "key_passphrase_change_prepared";
const FINISH: &str = "key_passphrase_change_completed";
const ROTATE_BEGIN: &str = "key_passphrase_rotation_started";
const ROTATE_PREPARE: &str = "key_passphrase_rotation_prepared";
const ROTATE_FINISH: &str = "key_passphrase_rotation_completed";
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
        ROTATE_BEGIN => Some(&[
            "previous_snapshot_sha256",
            "name",
            "old_identity",
            "old_ciphertext_sha256",
            "new_ciphertext_sha256",
            "new_ciphertext_length",
            "public_key",
            "guard_identity",
            "previous_completed_operation_id",
            "preserved",
        ]),
        PREPARE | ROTATE_PREPARE => Some(&[
            "previous_snapshot_sha256",
            "started_operation_id",
            "new_identity",
        ]),
        FINISH | ROTATE_FINISH => Some(&[
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
    validate_begin_fields(event, source, owner)
}

fn validate_begin_fields(event: &Value, source: &[u8], owner: [u8; 4]) -> Result<()> {
    let guard = field(event, "guard_identity")?;
    source_identity(guard, source, owner)?;
    let new_length = integer(field(event, "new_ciphertext_length")?)?;
    if !(1..=MAX_KEYFILE_BYTES as i64).contains(&new_length)
        || u64::from_be_bytes(bytes(field(guard, "length")?)?) != 49
        || field(guard, "ino")? == field(field(event, "old_identity")?, "ino")?
        || bytes::<32>(field(event, "new_ciphertext_sha256")?)?
            == bytes::<32>(field(event, "old_ciphertext_sha256")?)?
    {
        return invalid();
    }
    Ok(())
}

fn same_inode(a: &Value, b: &Value) -> Result<bool> {
    Ok(field(a, "dev")? == field(b, "dev")? && field(a, "ino")? == field(b, "ino")?)
}

fn validate_rotation_begin(
    event: &Value,
    prior: &[Value],
    source: &[u8],
    owner: [u8; 4],
) -> Result<()> {
    let [.., started, _, completed] = prior else {
        return invalid();
    };
    for (actual, record, expected) in [
        ("previous_completed_operation_id", completed, "operation_id"),
        ("old_identity", completed, "installed_identity"),
        ("old_ciphertext_sha256", started, "new_ciphertext_sha256"),
        ("name", started, "name"),
        ("public_key", started, "public_key"),
    ] {
        if field(event, actual)? != field(record, expected)? {
            return invalid();
        }
    }
    validate_begin_fields(event, source, owner)?;
    let preserved = field(event, "preserved")?;
    keys(preserved, &["directory", "name", "identity"])?;
    let preserved_name = field(preserved, "name")?;
    name(text(preserved_name)?).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    let dir = field(preserved, "directory")?;
    keys(dir, &["dev", "ino", "uid"])?;
    let dev = bytes::<8>(field(dir, "dev")?)?;
    let ino = bytes::<8>(field(dir, "ino")?)?;
    let file = field(preserved, "identity")?;
    identity(file, owner)?;
    let old = field(event, "old_identity")?;
    if bytes::<4>(field(dir, "uid")?)? != owner
        || (dev == source[53..61] && ino == source[61..69])
        || bytes::<8>(field(file, "dev")?)? != dev
        || field(file, "length")? != field(old, "length")?
        || same_inode(file, old)?
        || same_inode(file, field(event, "guard_identity")?)?
    {
        return invalid();
    }
    for previous in prior {
        if matches!(
            text(field(previous, "kind")?)?,
            STARTED | RESUMED | ROTATE_BEGIN
        ) {
            let saved = field(previous, "preserved")?;
            if same_inode(file, field(saved, "identity")?)?
                || (same_inode(dir, field(saved, "directory")?)?
                    && preserved_name == field(saved, "name")?)
            {
                return invalid();
            }
        }
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
    if matches!(kind, PREPARE | ROTATE_PREPARE) {
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
            ("guard_identity", current_identity.clone()),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect(),
    );
    start_reservation_fits(count, prefix_bytes, &begin, limit)
}

// 開始記録の既知の名前・保全先・暗号文長を含め、未確定の時刻は最大幅で予約する。
pub(super) fn start_reservation_fits(
    count: usize,
    prefix_bytes: usize,
    begin: &Value,
    limit: usize,
) -> Result<bool> {
    if count > 1021 || prefix_bytes > limit {
        return Ok(false);
    }
    let mut widest = begin.clone();
    let Value::Map(fields) = &mut widest else {
        return invalid();
    };
    for (key, value) in fields {
        match key.as_str() {
            "recorded_unix_seconds" => *value = Value::Int(i64::MAX),
            "guard_identity" => {
                let Value::Map(guard) = value else {
                    return invalid();
                };
                for (key, value) in guard {
                    match key.as_str() {
                        "mtime_seconds" | "ctime_seconds" => *value = Value::Int(i64::MAX),
                        "mtime_nanoseconds" | "ctime_nanoseconds" => {
                            *value = Value::Int(999_999_999)
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
    let Some(started_size) = prefix_bytes
        .checked_add(encoded(&widest)?.len())
        .and_then(|size| size.checked_add(array_head(count + 1) - array_head(count)))
    else {
        return Ok(false);
    };
    journal_tail_fits(
        count + 1,
        started_size,
        field(begin, "old_identity")?,
        true,
        text(field(begin, "kind")?)? == ROTATE_BEGIN,
        limit,
    )
}

pub(super) fn reserved_fits(
    count: usize,
    prefix_bytes: usize,
    identity: &Value,
    needs_prepare: bool,
    limit: usize,
) -> Result<bool> {
    journal_tail_fits(count, prefix_bytes, identity, needs_prepare, false, limit)
}

pub(super) fn journal_tail_fits(
    count: usize,
    prefix_bytes: usize,
    identity: &Value,
    needs_prepare: bool,
    rotation: bool,
    limit: usize,
) -> Result<bool> {
    let remaining = if needs_prepare { 2 } else { 1 };
    if count > 1024 - remaining || prefix_bytes > limit {
        return Ok(false);
    }
    let final_count = count + remaining;
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
        maximum_event_bytes(
            if rotation { ROTATE_PREPARE } else { PREPARE },
            count + 1,
            widest.clone(),
        )?
    } else {
        0
    };
    let finish_bytes = maximum_event_bytes(
        if rotation { ROTATE_FINISH } else { FINISH },
        final_count,
        widest,
    )?;
    let tail_bytes = prep_bytes + finish_bytes + array_head(final_count) - array_head(count);
    Ok(tail_bytes <= limit - prefix_bytes)
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
        (ROTATE_BEGIN, FINISH | ROTATE_FINISH) => {
            validate_rotation_begin(event, &events[..events.len() - 1], source, owner)?;
            let count = events.len() - 1;
            let previous_size =
                prefix_bytes - encoded(event)?.len() - (array_head(count + 1) - array_head(count));
            if !start_reservation_fits(count, previous_size, event, limit)? {
                return invalid();
            }
            Ok(KeyHistoryState::PassphraseRotationStarted {
                started_operation_id: operation_id,
            })
        }
        (ROTATE_PREPARE, ROTATE_BEGIN) => {
            validate_prepare(event, previous, source, owner)?;
            if !journal_tail_fits(
                events.len(),
                prefix_bytes,
                field(event, "new_identity")?,
                false,
                true,
                limit,
            )? {
                return invalid();
            }
            Ok(KeyHistoryState::PassphraseRotationPrepared {
                prepared_operation_id: operation_id,
            })
        }
        (ROTATE_FINISH, ROTATE_PREPARE) => {
            validate_finish(event, previous, source, owner)?;
            Ok(KeyHistoryState::PassphraseRotationCompleted {
                completed_operation_id: operation_id,
            })
        }
        _ => invalid(),
    }
}
