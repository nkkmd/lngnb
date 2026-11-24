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
    if secret {
        check_key_permissions(
            metadata.uid(),
            metadata.mode(),
            rustix::process::geteuid().as_raw(),
        )?;
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(invalid_pem());
    }
    Ok(bytes)
}

fn check_key_permissions(owner: u32, mode: u32, effective_uid: u32) -> io::Result<()> {
    if owner != effective_uid || mode & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn invalid_pem() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid TLS certificate or private key",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::PathBuf,
        process::Command,
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lngnb-server-tls-{}",
                crate::id::Id::random_knowledge().unwrap()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn certificate(&self, name: &str) -> (PathBuf, PathBuf) {
            let cert = self.0.join(format!("{name}.crt"));
            let key = self.0.join(format!("{name}.key"));
            let output = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-out",
                ])
                .arg(&cert)
                .arg("-keyout")
                .arg(&key)
                .output()
                .expect("TLS regression tests require openssl");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            (cert, key)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn verified_client(cert: &Path) -> rustls::ClientConnection {
        let mut roots = rustls::RootCertStore::empty();
        let cert_file = File::open(cert).unwrap();
        roots
            .add(
                rustls_pemfile::certs(&mut BufReader::new(cert_file))
                    .next()
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap()
    }

    #[test]
    fn matching_pem_negotiates_tls13_with_verified_certificate_and_http11() {
        let temp = TempDir::new();
        let (cert, key) = temp.certificate("server");
        let server_config = load_server_config(&cert, &key).unwrap();
        let mut client = verified_client(&cert);
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..8 {
            let mut outgoing = Vec::new();
            client.write_tls(&mut outgoing).unwrap();
            if !outgoing.is_empty() {
                server.read_tls(&mut outgoing.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }
            outgoing.clear();
            server.write_tls(&mut outgoing).unwrap();
            if !outgoing.is_empty() {
                client.read_tls(&mut outgoing.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
    }

    #[test]
    fn https_listener_closes_incomplete_handshake_and_serves_next_request() {
        use crate::fixed_record_http::FixedRecordHttpsListener;
        use crate::storage::{DistributionGate, Limits, RecordStore};
        use std::io::Write;
        use std::net::TcpStream;
        use std::time::{Duration, Instant};

        let temp = TempDir::new();
        let (cert, key) = temp.certificate("server");
        let store = RecordStore::initialize(&temp.0.join("data"), Limits::default()).unwrap();
        let mut writer = store.begin().unwrap();
        let config = load_server_config(&cert, &key).unwrap();
        let mut listener =
            FixedRecordHttpsListener::bind(([127, 0, 0, 1], 0).into(), config, None).unwrap();
        let address = listener.local_addr().unwrap();
        let mut stalled = TcpStream::connect(address).unwrap();
        stalled
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        listener
            .serve_ready(
                &mut writer,
                DistributionGate::Open,
                Instant::now() + Duration::from_millis(50),
            )
            .unwrap();
        assert_eq!(stalled.read(&mut [0]).unwrap(), 0);

        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut client = rustls::StreamOwned::new(verified_client(&cert), socket);
        let reader = std::thread::spawn(move || {
            client
                .write_all(b"GET /v1/records/invalid HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        });
        listener
            .serve_ready(
                &mut writer,
                DistributionGate::Open,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        reader.join().unwrap();
        writer.finish().unwrap();
    }

    #[test]
    fn rejects_mismatched_multiple_symlinked_and_public_keys() {
        let temp = TempDir::new();
        let (cert, key) = temp.certificate("server");
        let (_, other_key) = temp.certificate("other");
        assert_eq!(
            load_server_config(&cert, &other_key).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut duplicate = Zeroizing::new(fs::read(&key).unwrap());
        duplicate.extend_from_within(..);
        fs::write(&other_key, duplicate.as_slice()).unwrap();
        assert_eq!(
            load_server_config(&cert, &other_key).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let link = temp.0.join("linked.key");
        symlink(&key, &link).unwrap();
        assert_eq!(
            load_server_config(&cert, &link).unwrap_err().raw_os_error(),
            Some(rustix::io::Errno::LOOP.raw_os_error()),
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_server_config(&cert, &key).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn rejects_key_owned_by_another_user_even_with_private_mode() {
        assert_eq!(
            check_key_permissions(1001, 0o600, 1000).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
        );
    }

    #[test]
    fn accepts_exact_pem_limit_and_rejects_one_extra_byte() {
        let temp = TempDir::new();
        let (cert, key) = temp.certificate("server");
        let mut padded = fs::read(&cert).unwrap();
        padded.resize(MAX_PEM_BYTES as usize, b'\n');
        fs::write(&cert, &padded).unwrap();
        load_server_config(&cert, &key).unwrap();
        padded.push(b'\n');
        fs::write(&cert, padded).unwrap();
        assert_eq!(
            load_server_config(&cert, &key).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
