//! A11: 暗号化鍵データの内部基盤。Linuxのファイル操作はfilesへ分離し、端末・IPCは扱わない。
use crate::{
    cbor::{self, Value},
    record::LocalRecord,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{AeadInPlace, Tag},
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

pub const MAX_KEYFILE_BYTES: usize = 4096;
const DOMAIN: &[u8] = b"lngnb:keyfile:1\0";
type Result<T> = std::result::Result<T, KeyError>;

/// 入力値・秘密・下位ライブラリの診断を含めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    InvalidFormat,
    InvalidPassphrase,
    AuthenticationFailed,
    RandomUnavailable,
    CryptoFailed,
    InvalidRecord,
}
impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid_keyfile",
            Self::InvalidPassphrase => "invalid_passphrase",
            Self::AuthenticationFailed => "key_authentication_failed",
            Self::RandomUnavailable => "random_unavailable",
            Self::CryptoFailed => "key_crypto_failed",
            Self::InvalidRecord => "invalid_signing_record",
        })
    }
}
impl std::error::Error for KeyError {}

/// Debug/Clone/seed取得を提供しない。操作終了時にdalekが秘密鍵を消去する。
pub struct UnlockedKey(SigningKey);
impl UnlockedKey {
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    /// 既存のdomain・形式・厳格署名自己検査を共有する。親検査/pin/公開ではない。
    pub fn sign_record(&self, body: Value) -> Result<LocalRecord> {
        LocalRecord::sign(body, &self.0).map_err(|_| KeyError::InvalidRecord)
    }
    /// 毎回新しいsalt/nonceを生成。保存・原子的置換は呼出し側の別責務。
    pub fn encrypt(&self, passphrase: &str) -> Result<Vec<u8>> {
        validate_passphrase(passphrase)?;
        let mut salt = [0; 16];
        let mut nonce = [0; 12];
        random(&mut salt)?;
        random(&mut nonce)?;
        encrypt_with(self, passphrase, salt, nonce)
    }
}
fn random(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|_| KeyError::RandomUnavailable)
}
fn validate_passphrase(p: &str) -> Result<()> {
    if p.is_empty() || p.len() > 1024 {
        Err(KeyError::InvalidPassphrase)
    } else {
        Ok(())
    }
}
fn derive(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    validate_passphrase(passphrase)?;
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| KeyError::CryptoFailed)?;
    let mut key = Zeroizing::new([0; 32]);
    // Argon2の作業領域もdrop時に消去する。固定64 MiBを入力指定で拡大しない。
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase.as_bytes(), salt, &mut *key, &mut memory)
        .map_err(|_| KeyError::CryptoFailed)?;
    Ok(key)
}
fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn header(public: [u8; 32], salt: [u8; 16], nonce: [u8; 12]) -> Value {
    map(vec![
        ("format", text("lngnb-keyfile-1")),
        ("public_key", Value::Bytes(public.to_vec())),
        (
            "kdf",
            map(vec![
                ("name", text("argon2id")),
                ("version", Value::Int(19)),
                ("memory_kib", Value::Int(65536)),
                ("iterations", Value::Int(3)),
                ("parallelism", Value::Int(1)),
                ("salt", Value::Bytes(salt.to_vec())),
            ]),
        ),
        (
            "cipher",
            map(vec![
                ("name", text("chacha20-poly1305")),
                ("nonce", Value::Bytes(nonce.to_vec())),
            ]),
        ),
    ])
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    cbor::encode(value).map_err(|_| KeyError::InvalidFormat)
}
fn aad(header: &Value) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(encode(header)?);
    Ok(bytes)
}
fn encrypt_with(
    key: &UnlockedKey,
    passphrase: &str,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Result<Vec<u8>> {
    let mut h = header(key.public_key(), salt, nonce);
    let derived = derive(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&*derived).into());
    let mut seed = Zeroizing::new(key.0.to_bytes());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad(&h)?, &mut *seed)
        .map_err(|_| KeyError::CryptoFailed)?;
    let mut ciphertext = seed.to_vec(); // この時点では暗号文だけ。
    ciphertext.extend_from_slice(&tag);
    if let Value::Map(ref mut m) = h {
        m.push(("ciphertext".into(), Value::Bytes(ciphertext)));
    }
    encode(&h)
}
/// OS乱数だけでseedを生成し、暗号化データのみ返す。復号済みcacheを残さない。
pub fn generate(passphrase: &str) -> Result<Vec<u8>> {
    validate_passphrase(passphrase)?;
    let mut seed = Zeroizing::new([0; 32]);
    random(&mut *seed)?;
    UnlockedKey(SigningKey::from_bytes(&seed)).encrypt(passphrase)
}
fn get<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    if let Value::Map(m) = v {
        m.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or(KeyError::InvalidFormat)
    } else {
        Err(KeyError::InvalidFormat)
    }
}
fn bytes<const N: usize>(v: &Value) -> Result<[u8; N]> {
    if let Value::Bytes(b) = v {
        b.as_slice().try_into().map_err(|_| KeyError::InvalidFormat)
    } else {
        Err(KeyError::InvalidFormat)
    }
}
/// 全schema・固定KDFを検査してから暗号処理を開始する。入力を補正しない。
pub fn unlock(input: &[u8], passphrase: &str) -> Result<UnlockedKey> {
    validate_passphrase(passphrase)?;
    if input.len() > MAX_KEYFILE_BYTES {
        return Err(KeyError::InvalidFormat);
    }
    let mut value = cbor::decode(input).map_err(|_| KeyError::InvalidFormat)?;
    let public = bytes(get(&value, "public_key")?)?;
    let salt = bytes(get(get(&value, "kdf")?, "salt")?)?;
    let nonce = bytes(get(get(&value, "cipher")?, "nonce")?)?;
    let ciphertext: [u8; 48] = bytes(get(&value, "ciphertext")?)?;
    if let Value::Map(ref mut m) = value {
        m.retain(|(k, _)| k != "ciphertext");
    }
    let expected = header(public, salt, nonce);
    // CBOR decodeで順序/重複/余剰bytesを拒否済み。既知の全キー・型・値を完全照合。
    if encode(&value)? != encode(&expected)? {
        return Err(KeyError::InvalidFormat);
    }
    let derived = derive(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&*derived).into());
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&ciphertext[..32]);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad(&expected)?,
            &mut *seed,
            Tag::<ChaCha20Poly1305>::from_slice(&ciphertext[32..]),
        )
        .map_err(|_| KeyError::AuthenticationFailed)?;
    let key = UnlockedKey(SigningKey::from_bytes(&seed));
    if key.public_key() != public {
        return Err(KeyError::AuthenticationFailed);
    }
    Ok(key)
}

#[cfg(test)]
#[path = "keyfile_tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
#[path = "keyfile_storage.rs"]
mod files;
#[cfg(target_os = "linux")]
pub use files::{KeyDirectory, KeyFileError};
