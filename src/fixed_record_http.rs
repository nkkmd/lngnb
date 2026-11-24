//! 固定Record取得のHTTP応答。接続の解析と期限管理は呼び出し側が担う。

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use crate::id::{Id, Kind};
use crate::storage::{DistributionGate, FixedRecordScope, RecordWriter, StorageError};

const JSON: &str = "application/json";
const INVALID: &[u8] = br#"{"api_version":"lngnb-http-1","error":{"code":"invalid_request","message":"Invalid request","retry_after_seconds":null}}"#;
const UNAVAILABLE: &[u8] = br#"{"api_version":"lngnb-http-1","error":{"code":"not_available","message":"This Record is unavailable on this relay","retry_after_seconds":null}}"#;

const REQUEST_TARGET_LIMIT: usize = 16 * 1024;
const METHOD_NOT_ALLOWED: &[u8] = br#"{"api_version":"lngnb-http-1","error":{"code":"method_not_allowed","message":"Method not allowed","retry_after_seconds":null}}"#;

const REQUEST_LINE_LIMIT: usize = REQUEST_TARGET_LIMIT + 1024;
const REQUEST_HEADERS_LIMIT: usize = 32 * 1024;

/// HTTP/1.xのリクエスト行とヘッダー終端までを絶対期限付きで受信する。
/// 解析と振り分けはこの受信が成功した後に行う。残りのデータはreaderに保持する。
/// blocking socketを専有し、エラー時は接続を閉じる。
pub fn read_request_head(
    reader: &mut BufReader<TcpStream>,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    read_request_head_from(reader, deadline, |socket| {
        socket.read_until_deadline(deadline)
    })
}

fn read_request_head_from<R: Read>(
    reader: &mut BufReader<R>,
    deadline: Instant,
    mut prepare: impl FnMut(&mut R) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut line_start = 0;
    let mut request_line_end = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        prepare(reader.get_mut())?;
        let chunk = match reader.fill_buf() {
            Ok([]) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(chunk) => chunk,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(error) => return Err(error),
        };
        let mut end = None;
        for (index, &byte) in chunk.iter().enumerate() {
            let (start, limit) = request_line_end.map_or((0, REQUEST_LINE_LIMIT), |start| {
                (start, REQUEST_HEADERS_LIMIT)
            });
            if head.len() - start == limit {
                return Err(io::ErrorKind::InvalidData.into());
            }
            head.push(byte);
            if byte == b'\n' {
                if !head.ends_with(b"\r\n") {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if request_line_end.is_none() {
                    if head.len() == 2 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    request_line_end = Some(head.len());
                } else if head.len() - line_start == 2 {
                    end = Some(index + 1);
                    break;
                }
                line_start = head.len();
            }
        }
        let consumed = end.unwrap_or(chunk.len());
        reader.consume(consumed);
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if end.is_some() {
            return Ok(head);
        }
    }
}

/// 明示的に起動する開発用の平文HTTP待受け。ループバックだけにbindする。
pub struct FixedRecordLoopbackListener {
    listener: TcpListener,
}

impl FixedRecordLoopbackListener {
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "loopback address required",
            ));
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// 待機中の接続を最大一件処理する。接続がなければNoneを返す。
    /// 接続を受理した場合のboolは固定Record処理の応答有無を示す。
    pub fn serve_ready(
        &mut self,
        writer: &mut RecordWriter,
        gate: DistributionGate,
        deadline: Instant,
    ) -> Result<Option<bool>, StorageError> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        stream.set_nonblocking(false)?;
        serve_fixed_record_connection(writer, gate, stream, deadline, deadline).map(Some)
    }
}

/// 明示的なTLS設定で固定Recordだけを提供するHTTPS待受け。
pub struct FixedRecordHttpsListener {
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
}

impl FixedRecordHttpsListener {
    pub fn bind(address: SocketAddr, config: rustls::ServerConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// 検証済みの設定を新しい接続に適用する。
    pub fn replace_config(&mut self, config: rustls::ServerConfig) {
        self.config = Arc::new(config);
    }

    pub(crate) fn serve_ready(
        &mut self,
        writer: &mut RecordWriter,
        gate: DistributionGate,
        deadline: Instant,
    ) -> Result<(), StorageError> {
        let socket = match self.listener.accept() {
            Ok((socket, _)) => socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        socket.set_nonblocking(false)?;
        let mut connection =
            rustls::ServerConnection::new(Arc::clone(&self.config)).map_err(io::Error::other)?;
        let mut socket = DeadlineTcp { socket, deadline };
        // HTTPへ進む前にTLSを確立し、相手側の失敗はこの接続だけで処理する。
        if connection.complete_io(&mut socket).is_err() || connection.is_handshaking() {
            return Ok(());
        }

        let mut stream = rustls::StreamOwned::new(connection, socket);
        serve_request(writer, gate, &mut stream, deadline, deadline)?;
        stream.conn.send_close_notify();
        // 応答送信後の切断は保存セッションの失敗にしない。
        let _ = stream.flush();
        Ok(())
    }
}

fn remaining(deadline: Instant) -> io::Result<std::time::Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(duration)
}

// rustlsが内部で行う複数回のI/Oにも毎回同じ絶対期限を適用する。
struct DeadlineTcp {
    socket: TcpStream,
    deadline: Instant,
}

fn connection_error(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::Interrupted => error,
        io::ErrorKind::WouldBlock => io::ErrorKind::TimedOut.into(),
        _ => io::Error::new(io::ErrorKind::ConnectionAborted, error),
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket
            .set_read_timeout(Some(remaining(self.deadline)?))
            .map_err(connection_error)?;
        self.socket.read(bytes).map_err(connection_error)
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(remaining(self.deadline)?))
            .map_err(connection_error)?;
        self.socket.write(bytes).map_err(connection_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

trait RequestStream: Read + Write {
    fn read_until_deadline(&mut self, deadline: Instant) -> io::Result<()>;
    fn write_until_deadline(&mut self, deadline: Instant) -> io::Result<()>;
}

impl RequestStream for TcpStream {
    fn read_until_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.set_read_timeout(Some(remaining(deadline)?))
    }

    fn write_until_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.set_write_timeout(Some(remaining(deadline)?))
    }
}

impl RequestStream for rustls::StreamOwned<rustls::ServerConnection, DeadlineTcp> {
    fn read_until_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.sock.deadline = deadline;
        Ok(())
    }

    fn write_until_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.sock.deadline = deadline;
        Ok(())
    }
}

/// 受理済みのTCP接続から、本文を持たないHTTP/1.1要求を一件処理する。
/// 接続はこの関数が所有し、戻る際に閉じる。
/// falseは固定Record以外の経路、Errは受信・保存・送信の失敗を示す。
pub fn serve_fixed_record_connection(
    writer: &mut RecordWriter,
    gate: DistributionGate,
    mut stream: TcpStream,
    read_deadline: Instant,
    write_deadline: Instant,
) -> Result<bool, StorageError> {
    serve_request(writer, gate, &mut stream, read_deadline, write_deadline)
}

fn serve_request(
    writer: &mut RecordWriter,
    gate: DistributionGate,
    stream: &mut impl RequestStream,
    read_deadline: Instant,
    write_deadline: Instant,
) -> Result<bool, StorageError> {
    let mut reader = BufReader::new(stream);
    let head = read_request_head_from(&mut reader, read_deadline, |stream| {
        stream.read_until_deadline(read_deadline)
    })?;
    let (method, target) =
        parse_bodyless_request(&head).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    route_fixed_record_request(
        writer,
        gate,
        method,
        target,
        |status, content_type, bytes| {
            write_response(
                *reader.get_mut(),
                write_deadline,
                method,
                status,
                content_type,
                bytes,
            )
        },
    )
}

fn parse_bodyless_request(head: &[u8]) -> Option<(&str, &str)> {
    let head = std::str::from_utf8(head).ok()?.strip_suffix("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let mut request = lines.next()?.split(' ');
    let method = request.next()?;
    let target = request.next()?;
    if method.is_empty()
        || !method.bytes().all(is_token)
        || !target.starts_with('/')
        || target.len() > REQUEST_TARGET_LIMIT
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        || request.next() != Some("HTTP/1.1")
        || request.next().is_some()
    {
        return None;
    }

    let mut host_seen = false;
    let mut length_seen = false;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.is_empty()
            || !name.bytes().all(is_token)
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if host_seen
                || value.is_empty()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_:[]".contains(&byte))
            {
                return None;
            }
            host_seen = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if length_seen || value.is_empty() || !value.bytes().all(|byte| byte == b'0') {
                return None;
            }
            length_seen = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("expect")
        {
            return None;
        }
    }
    host_seen.then_some((method, target))
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || b"!#$%&'*+-.^_".contains(&byte)
        || matches!(byte, b'`' | b'|' | b'~')
}

/// 解析済みHTTP要求を固定Record経路へ振り分ける。
/// falseの場合は応答を送らず、呼び出し側が他の経路を処理する。
/// sendは応答全体を期限内に同期送信し、405にはAllow: GETを付ける。
pub fn route_fixed_record_request(
    writer: &mut RecordWriter,
    gate: DistributionGate,
    method: &str,
    target: &str,
    send: impl FnOnce(u16, &'static str, &[u8]) -> io::Result<()>,
) -> Result<bool, StorageError> {
    if target.len() > REQUEST_TARGET_LIMIT {
        send(400, JSON, INVALID)?;
        return Ok(true);
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let Some(record_id) = path.strip_prefix("/v1/records/") else {
        return Ok(false);
    };
    if record_id.is_empty() || record_id.contains('/') {
        return Ok(false);
    }
    if method == "GET" {
        send_fixed_record_get(writer, gate, record_id, query, send)?;
    } else {
        send(405, JSON, METHOD_NOT_ALLOWED)?;
    }
    Ok(true)
}

/// 解析済みの固定Record要求にHTTP/1.1応答を送る。
/// deadlineはヘッダーと本文に共通の絶対期限。呼び出し側はblocking
/// socketを専有し、応答済みまたは送信エラーの場合は接続を閉じる。
pub fn send_fixed_record_response(
    writer: &mut RecordWriter,
    gate: DistributionGate,
    method: &str,
    target: &str,
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<bool, StorageError> {
    route_fixed_record_request(
        writer,
        gate,
        method,
        target,
        |status, content_type, bytes| {
            write_response(stream, deadline, method, status, content_type, bytes)
        },
    )
}

fn write_response(
    stream: &mut impl RequestStream,
    deadline: Instant,
    method: &str,
    status: u16,
    content_type: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let allow = if status == 405 { "Allow: GET\r\n" } else { "" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n{allow}\r\n",
        bytes.len()
    );
    write_before(stream, deadline, head.as_bytes())?;
    if method != "HEAD" {
        write_before(stream, deadline, bytes)?;
    }
    stream.flush()
}

fn write_before(
    stream: &mut impl RequestStream,
    deadline: Instant,
    mut bytes: &[u8],
) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.write_until_deadline(deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// 固定RecordのGETへ振り分け済みの要求を処理する。
/// IDはパスの正規表記、queryはHTTP層で分離した未デコードの値。
/// sendは応答全体を期限内に同期送信する。エラー後の再送は行わない。
pub fn send_fixed_record_get(
    writer: &mut RecordWriter,
    gate: DistributionGate,
    record_id: &str,
    query: Option<&str>,
    send: impl FnOnce(u16, &'static str, &[u8]) -> io::Result<()>,
) -> Result<(), StorageError> {
    let Ok(id) = Id::parse(Kind::Record, record_id) else {
        return send(400, JSON, INVALID).map_err(StorageError::Io);
    };
    let Some(scope) = parse_scope(query) else {
        return send(400, JSON, INVALID).map_err(StorageError::Io);
    };

    let mut send = Some(send);
    let sent = writer.send_fixed_record(id, gate, scope, |bytes| {
        send.take().expect("single response")(200, "application/cbor", bytes)
    })?;
    if !sent {
        send.expect("response not started")(404, JSON, UNAVAILABLE)?;
    }
    Ok(())
}

fn parse_scope(query: Option<&str>) -> Option<FixedRecordScope> {
    let mut scope = None;
    let mut genesis_id = None;
    for parameter in query
        .filter(|q| !q.is_empty())
        .into_iter()
        .flat_map(|q| q.split('&'))
    {
        let (key, value) = parameter.split_once('=')?;
        match key {
            "scope" if scope.is_none() => scope = Some(decode_value(value)?),
            "genesis_id" if genesis_id.is_none() => {
                genesis_id = Some(Id::parse(Kind::Record, &decode_value(value)?).ok()?);
            }
            _ => return None,
        }
    }
    match scope.as_deref().unwrap_or("public") {
        "public" => Some(FixedRecordScope::Public { genesis_id }),
        "untrusted" => Some(FixedRecordScope::Untrusted {
            genesis_id: genesis_id?,
        }),
        _ => None,
    }
}

fn decode_value(raw: &str) -> Option<String> {
    let mut bytes = raw.bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let high = char::from(bytes.next()?).to_digit(16)?;
            let low = char::from(bytes.next()?).to_digit(16)?;
            (high * 16 + low) as u8
        } else {
            byte
        };
        decoded.push(byte);
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::Duration;

    #[test]
    fn request_head_bounds_and_preserves_remaining_bytes() {
        for (header_size, expected_error) in [
            (REQUEST_HEADERS_LIMIT, None),
            (REQUEST_HEADERS_LIMIT + 1, Some(io::ErrorKind::InvalidData)),
        ] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let head = format!(
                "GET /v1/records/id HTTP/1.1\r\nX: {}\r\n\r\n",
                "a".repeat(header_size - 7)
            );
            client.write_all(head.as_bytes()).unwrap();
            client.write_all(b"tail").unwrap();
            let mut reader = BufReader::with_capacity(1024, server);
            assert_eq!(
                read_request_head(&mut reader, Instant::now())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            let result = read_request_head(&mut reader, Instant::now() + Duration::from_secs(2));
            if let Some(kind) = expected_error {
                assert_eq!(result.unwrap_err().kind(), kind);
            } else {
                assert_eq!(result.unwrap(), head.as_bytes());
                let mut tail = [0; 4];
                reader.read_exact(&mut tail).unwrap();
                assert_eq!(&tail, b"tail");
            }
        }
    }

    #[test]
    fn response_writes_allow_and_refuses_expired_deadlines() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        assert_eq!(
            write_response(&mut server, Instant::now(), "PUT", 405, JSON, b"error")
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut,
        );
        write_response(
            &mut server,
            Instant::now() + Duration::from_secs(2),
            "PUT",
            405,
            JSON,
            b"error",
        )
        .unwrap();
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(response.contains("\r\nAllow: GET\r\n"));
        assert!(response.contains("\r\nContent-Length: 5\r\n"));
        assert!(response.ends_with("\r\n\r\nerror"));
    }
}
