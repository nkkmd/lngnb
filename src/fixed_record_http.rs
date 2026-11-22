//! 固定Record取得のHTTP応答。接続の解析と期限管理は呼び出し側が担う。

use std::io;

use crate::id::{Id, Kind};
use crate::storage::{DistributionGate, FixedRecordScope, RecordWriter, StorageError};

const JSON: &str = "application/json";
const INVALID: &[u8] = br#"{"api_version":"lngnb-http-1","error":{"code":"invalid_request","message":"Invalid request","retry_after_seconds":null}}"#;
const UNAVAILABLE: &[u8] = br#"{"api_version":"lngnb-http-1","error":{"code":"not_available","message":"This Record is unavailable on this relay","retry_after_seconds":null}}"#;

const REQUEST_TARGET_LIMIT: usize = 16 * 1024;
const METHOD_NOT_ALLOWED: &[u8] = br#"{"api_version":"lngnb-http-1","error":{"code":"method_not_allowed","message":"Method not allowed","retry_after_seconds":null}}"#;

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
