//! A1: 決定的CBORの制限プロファイル。入力の再符号化による救済は行わない。
use crate::{Error::InvalidFormat, Result};

pub const MAX_RECORD: usize = 2_097_152;
pub const MAX_STRING: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
    Bool(bool),
    Null,
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let (ai, size) = match n {
        0..=23 => {
            out.push((major << 5) | n as u8);
            return;
        }
        24..=255 => (24, 1),
        256..=65535 => (25, 2),
        65536..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    out.push((major << 5) | ai);
    out.extend_from_slice(&n.to_be_bytes()[8 - size..]);
}
fn key_bytes(key: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    head(3, key.len() as u64, &mut bytes);
    bytes.extend_from_slice(key.as_bytes());
    bytes
}

/// ローカル生成用。重複キーも拒否し、受信時と同じ上限を適用する。
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    fn emit(v: &Value, depth: usize, out: &mut Vec<u8>) -> Result<()> {
        let container = matches!(v, Value::Map(_) | Value::Array(_));
        let depth = depth + usize::from(container);
        if depth > 16 {
            return Err(InvalidFormat);
        }
        match v {
            Value::Int(n) if *n >= 0 => head(0, *n as u64, out),
            Value::Int(n) => head(1, (-1i128 - *n as i128) as u64, out),
            Value::Text(s) => {
                if s.len() > MAX_STRING {
                    return Err(InvalidFormat);
                }
                head(3, s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Bytes(b) => {
                if b.len() > MAX_STRING {
                    return Err(InvalidFormat);
                }
                head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Value::Array(a) => {
                if a.len() > 4096 {
                    return Err(InvalidFormat);
                }
                head(4, a.len() as u64, out);
                for x in a {
                    emit(x, depth, out)?;
                }
            }
            Value::Map(m) => {
                if m.len() > 1024 || m.iter().any(|(k, _)| k.len() > MAX_STRING) {
                    return Err(InvalidFormat);
                }
                let mut entries: Vec<_> = m.iter().map(|(k, v)| (key_bytes(k), v)).collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                if entries.windows(2).any(|w| w[0].0 == w[1].0) {
                    return Err(InvalidFormat);
                }
                head(5, entries.len() as u64, out);
                for (key, v) in entries {
                    out.extend(key);
                    emit(v, depth, out)?;
                }
            }
            Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Value::Null => out.push(0xf6),
        }
        if out.len() > MAX_RECORD {
            return Err(InvalidFormat);
        }
        Ok(())
    }
    let mut out = Vec::new();
    emit(value, 0, &mut out)?;
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            let end = self.at.checked_add(n).ok_or(InvalidFormat)?;
            let b = self.bytes.get(self.at..end).ok_or(InvalidFormat)?;
            self.at = end;
            Ok(b)
        }
        fn number(&mut self, ai: u8) -> Result<u64> {
            let (n, min) = match ai {
                0..=23 => return Ok(ai as u64),
                24 => (1, 24),
                25 => (2, 256),
                26 => (4, 65536),
                27 => (8, 0x1_0000_0000),
                _ => return Err(InvalidFormat),
            };
            let mut buf = [0; 8];
            buf[8 - n..].copy_from_slice(self.take(n)?);
            let value = u64::from_be_bytes(buf);
            if value < min {
                return Err(InvalidFormat);
            }
            Ok(value)
        }
        fn value(&mut self, depth: usize) -> Result<Value> {
            let b = self.take(1)?[0];
            let major = b >> 5;
            let ai = b & 31;
            if major == 7 {
                return match b {
                    0xf4 => Ok(Value::Bool(false)),
                    0xf5 => Ok(Value::Bool(true)),
                    0xf6 => Ok(Value::Null),
                    _ => Err(InvalidFormat),
                };
            }
            if major > 5 {
                return Err(InvalidFormat);
            }
            let n = self.number(ai)?;
            if major < 2 {
                let n = i64::try_from(n).map_err(|_| InvalidFormat)?;
                return Ok(Value::Int(if major == 0 { n } else { -1 - n }));
            }
            let n = usize::try_from(n).map_err(|_| InvalidFormat)?;
            if major < 4 {
                if n > MAX_STRING {
                    return Err(InvalidFormat);
                }
                let bytes = self.take(n)?;
                return if major == 2 {
                    Ok(Value::Bytes(bytes.to_vec()))
                } else {
                    Ok(Value::Text(
                        std::str::from_utf8(bytes)
                            .map_err(|_| InvalidFormat)?
                            .to_owned(),
                    ))
                };
            }
            if depth >= 16 {
                return Err(InvalidFormat);
            }
            if major == 4 {
                if n > 4096 {
                    return Err(InvalidFormat);
                }
                // 入力長を超える宣言で大きな予約を行わない。
                if n > self.bytes.len() - self.at {
                    return Err(InvalidFormat);
                }
                let mut array = Vec::with_capacity(n);
                for _ in 0..n {
                    array.push(self.value(depth + 1)?);
                }
                return Ok(Value::Array(array));
            }
            if n > 1024 || n > (self.bytes.len() - self.at) / 2 {
                return Err(InvalidFormat);
            }
            let mut map = Vec::with_capacity(n);
            let mut previous: Option<&[u8]> = None;
            for _ in 0..n {
                let start = self.at;
                let Value::Text(key) = self.value(depth + 1)? else {
                    return Err(InvalidFormat);
                };
                let raw_key = &self.bytes[start..self.at];
                if previous.is_some_and(|p| p >= raw_key) {
                    return Err(InvalidFormat);
                }
                previous = Some(raw_key);
                map.push((key, self.value(depth + 1)?));
            }
            Ok(Value::Map(map))
        }
    }
    if bytes.len() > MAX_RECORD {
        return Err(InvalidFormat);
    }
    let mut reader = Reader { bytes, at: 0 };
    let value = reader.value(0)?;
    if reader.at != bytes.len() {
        return Err(InvalidFormat);
    }
    Ok(value)
}
