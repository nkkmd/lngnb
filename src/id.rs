//! A3: 用途を区別したハッシュと、補正しない外部ID表記。
use crate::{Error::InvalidId, Result};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Knowledge,
    Record,
    Blob,
    Key,
}
impl Kind {
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Knowledge => "kn1_",
            Self::Record => "rc1_",
            Self::Blob => "bl1_",
            Self::Key => "ky1_",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Id {
    pub kind: Kind,
    pub bytes: [u8; 32],
}
impl Id {
    pub fn parse(kind: Kind, text: &str) -> Result<Self> {
        if text.len() != 56 || !text.starts_with(kind.prefix()) {
            return Err(InvalidId);
        }
        let payload = &text[4..];
        if !payload
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(InvalidId);
        }
        let bytes: [u8; 32] = BASE32_NOPAD
            .decode(payload.to_ascii_uppercase().as_bytes())
            .map_err(|_| InvalidId)?
            .try_into()
            .map_err(|_| InvalidId)?;
        let id = Self { kind, bytes };
        if id.to_string() != text {
            return Err(InvalidId);
        }
        Ok(id)
    }
    pub fn random_knowledge() -> std::result::Result<Self, getrandom::Error> {
        let mut bytes = [0; 32];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self {
            kind: Kind::Knowledge,
            bytes,
        })
    }
}
impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            self.kind.prefix(),
            BASE32_NOPAD.encode(&self.bytes).to_ascii_lowercase()
        )
    }
}
pub fn record_id(bytes: &[u8]) -> Id {
    hash(Kind::Record, b"lngnb:record:library-core-1\0", bytes)
}
pub fn blob_id(bytes: &[u8]) -> Id {
    hash(Kind::Blob, b"lngnb:blob:1\0", bytes)
}
pub fn key_id(bytes: &[u8; 32]) -> Id {
    hash(Kind::Key, b"lngnb:key:ed25519:1\0", bytes)
}
fn hash(kind: Kind, domain: &[u8], bytes: &[u8]) -> Id {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    Id {
        kind,
        bytes: h.finalize().into(),
    }
}
