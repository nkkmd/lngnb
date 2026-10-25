//! 初期プロファイルの局所検査。親履歴・pin・公開・保存の判定は含まない。
pub mod cbor;
pub mod id;
pub mod record;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidFormat,
    InvalidId,
    IdMismatch,
    InvalidSignature,
    UnsupportedProfile,
    UnsupportedKind,
    GenesisMismatch,
    WrongPublisher,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid_format",
            Self::InvalidId => "invalid_id",
            Self::IdMismatch => "record_id_mismatch",
            Self::InvalidSignature => "invalid_signature",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::UnsupportedKind => "unsupported_kind",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::WrongPublisher => "wrong_publisher",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
