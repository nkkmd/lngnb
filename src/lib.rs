//! 初期プロファイルの局所検査、保存・依存評価とRecord公開判定の内部基盤。
pub mod authoring;
#[cfg(target_os = "linux")]
pub mod authoring_input;
pub mod cbor;
#[cfg(target_os = "linux")]
pub mod fixed_record_http;
pub mod id;
pub mod keyfile;
pub mod record;
#[cfg(target_os = "linux")]
pub mod secret_terminal;
#[cfg(target_os = "linux")]
pub mod server_tls;
#[cfg(target_os = "linux")]
pub mod storage;

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
