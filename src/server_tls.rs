//! 内蔵HTTPSの証明書と秘密鍵を検査し、待受け前にTLS設定を組み立てる。

use std::{
    fs::File,
    io::{self, BufReader, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
};

use rustix::fs::{Mode, OFlags, open};
use rustls::ServerConfig;
use zeroize::Zeroizing;

const MAX_PEM_BYTES: u64 = 1024 * 1024;

/// 明示されたPEM証明書チェーンと単一の秘密鍵でTLS 1.3の設定を作る。
/// エラーにはファイル名や秘密鍵の内容を含めない。
pub fn load_server_config(cert_path: &Path, key_path: &Path) -> io::Result<ServerConfig> {
    let cert_bytes = read_pem(cert_path, false)?;
    let key_bytes = read_pem(key_path, true)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_pem())?;
    let mut key_reader = key_bytes.as_slice();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| invalid_pem())?
        .ok_or_else(invalid_pem)?;
    if rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| invalid_pem())?
        .is_some()
    {
        return Err(invalid_pem());
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid_pem())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| invalid_pem())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn read_pem(path: &Path, secret: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PEM_BYTES {
        return Err(invalid_pem());
    }
    if secret
        && (metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(invalid_pem());
    }
    Ok(bytes)
}

fn invalid_pem() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid TLS certificate or private key",
    )
}
