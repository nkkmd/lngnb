//! §5.108: 再開eventの値検査だけ。保持fd資格・保存・guard解除は提供しない。
use super::*;

pub(super) fn validate(event: &Value, source: &[u8], completions: &[[u8; 32]]) -> Result<()> {
    let owner: [u8; 4] = source[69..73]
        .try_into()
        .map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    if bytes::<4>(field(event, "actor_uid")?)? != owner {
        return invalid();
    }
    equal_text(
        field(event, "reason")?,
        "reviewed_current_key_and_preservations",
    )?;
    let current = field(event, "current")?;
    keys(
        current,
        &["name", "identity", "ciphertext_sha256", "public_key"],
    )?;
    name(text(field(current, "name")?)?).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    bytes::<32>(field(current, "ciphertext_sha256")?)?;
    bytes::<32>(field(current, "public_key")?)?;
    let current_id = field(current, "identity")?;
    identity(current_id, owner)?;
    if bytes::<8>(field(current_id, "dev")?)? != source[53..61] {
        return invalid();
    }
    let preserved = field(event, "preserved")?;
    keys(preserved, &["directory", "name", "identity"])?;
    name(text(field(preserved, "name")?)?).map_err(|_| KeyFileError::RecoveryStateInvalid)?;
    let directory = field(preserved, "directory")?;
    keys(directory, &["dev", "ino", "uid"])?;
    let dev = bytes::<8>(field(directory, "dev")?)?;
    let ino = bytes::<8>(field(directory, "ino")?)?;
    if bytes::<4>(field(directory, "uid")?)? != owner
        || (dev == source[53..61] && ino == source[61..69])
    {
        return invalid();
    }
    let preserved_id = field(preserved, "identity")?;
    identity(preserved_id, owner)?;
    if bytes::<8>(field(preserved_id, "dev")?)? != dev
        || field(current_id, "length")? != field(preserved_id, "length")?
    {
        return invalid();
    }
    let guard = field(event, "guard_identity")?;
    identity(guard, owner)?;
    if bytes::<8>(field(guard, "dev")?)? != source[53..61]
        || u64::from_be_bytes(bytes(field(guard, "length")?)?) != 49
    {
        return invalid();
    }
    for (a, b) in [
        (current_id, preserved_id),
        (current_id, guard),
        (preserved_id, guard),
    ] {
        if field(a, "dev")? == field(b, "dev")? && field(a, "ino")? == field(b, "ino")? {
            return invalid();
        }
    }
    let Value::Array(references) = field(event, "cleanup_operations")? else {
        return invalid();
    };
    if references.len() != completions.len() {
        return invalid();
    }
    for (reference, expected) in references.iter().zip(completions) {
        if &bytes::<32>(reference)? != expected {
            return invalid();
        }
    }
    Ok(())
}

pub(super) fn guard_identity(event: &Value) -> Result<KeyFileIdentity> {
    let v = field(event, "guard_identity")?;
    Ok(KeyFileIdentity {
        dev: u64::from_be_bytes(bytes(field(v, "dev")?)?),
        ino: u64::from_be_bytes(bytes(field(v, "ino")?)?),
        length: u64::from_be_bytes(bytes(field(v, "length")?)?),
        nlink: u64::from_be_bytes(bytes(field(v, "nlink")?)?),
        uid: u32::from_be_bytes(bytes(field(v, "uid")?)?),
        mode: u32::from_be_bytes(bytes(field(v, "mode")?)?),
        mtime_seconds: integer(field(v, "mtime_seconds")?)?,
        mtime_nanoseconds: integer(field(v, "mtime_nanoseconds")?)?,
        ctime_seconds: integer(field(v, "ctime_seconds")?)?,
        ctime_nanoseconds: integer(field(v, "ctime_nanoseconds")?)?,
    })
}
