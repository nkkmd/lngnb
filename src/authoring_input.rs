//! R03/R04/R28: 作成用の本文・metadataを上限付きで読み取るLinux内部基盤。
//! metadataは既存の決定的CBOR。署名・保存・pin・公開は行わない。
use crate::{
    authoring::{CreationBudget, MAX_METADATA_BYTES},
    cbor::{self, Value},
};
use rustix::fs::{self, CWD, Mode, OFlags};
use std::{
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    UnsafePath,
    Io,
    PayloadLimit,
    MetadataLimit,
    Changed,
    InvalidMetadata,
    Cancelled,
    Allocation,
    RecordLimit,
}
impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsafePath => "unsafe_creation_input_path",
            Self::Io => "creation_input_io_failed",
            Self::PayloadLimit => "creation_input_payload_limit",
            Self::MetadataLimit => "creation_input_metadata_limit",
            Self::Changed => "creation_input_changed",
            Self::InvalidMetadata => "invalid_creation_metadata_cbor",
            Self::Cancelled => "creation_input_cancelled",
            Self::Allocation => "creation_input_allocation_failed",
            Self::RecordLimit => "record_input_limit",
        })
    }
}
impl std::error::Error for InputError {}
type Result<T> = std::result::Result<T, InputError>;

/// 読取り時点の所有bytes。Debug/Cloneで未公開内容を暗黙に出力・複製しない。
/// ファイルを後から再openせず、この本文そのものを署名・保存へ渡す。
pub struct InitialInput {
    payload: Vec<u8>,
    metadata: Value,
}
impl InitialInput {
    pub fn into_parts(self) -> (Vec<u8>, Value) {
        (self.payload, self.metadata)
    }
}

// pathnameの全階層をNOFOLLOWで開く。入力は秘密鍵ではなく、所有UID/0600は要求しない。
fn open_regular(path: &Path) -> Result<File> {
    let mut parts = path.components().peekable();
    let dirs = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = fs::openat(CWD, ".", dirs, Mode::empty()).map_err(|_| InputError::Io)?;
    while let Some(c) = parts.next() {
        match c {
            Component::RootDir => {
                dir = fs::openat(CWD, "/", dirs, Mode::empty()).map_err(|_| InputError::Io)?;
            }
            Component::CurDir => (),
            Component::Normal(n) if parts.peek().is_none() => {
                let fd = fs::openat(
                    &dir,
                    n,
                    OFlags::RDONLY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC
                        | OFlags::NONBLOCK
                        | OFlags::NOCTTY,
                    Mode::empty(),
                )
                .map_err(|_| InputError::UnsafePath)?;
                let file = File::from(fd);
                regular(&file.metadata().map_err(|_| InputError::Io)?)?;
                return Ok(file);
            }
            Component::Normal(n) => {
                dir =
                    fs::openat(&dir, n, dirs, Mode::empty()).map_err(|_| InputError::UnsafePath)?;
            }
            _ => return Err(InputError::UnsafePath),
        }
    }
    Err(InputError::UnsafePath)
}
fn regular(m: &Metadata) -> Result<()> {
    if !m.is_file() || m.nlink() != 1 {
        return Err(InputError::UnsafePath);
    }
    Ok(())
}
fn unchanged(file: &File, before: &Metadata) -> Result<()> {
    let now = file.metadata().map_err(|_| InputError::Io)?;
    regular(&now)?;
    if before.dev() != now.dev()
        || before.ino() != now.ino()
        || before.len() != now.len()
        || before.mode() != now.mode()
        || before.uid() != now.uid()
        || before.gid() != now.gid()
        || before.mtime() != now.mtime()
        || before.mtime_nsec() != now.mtime_nsec()
        || before.ctime() != now.ctime()
        || before.ctime_nsec() != now.ctime_nsec()
    {
        return Err(InputError::Changed);
    }
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    BeforeOpen,
    Opened,
    ReadChunk,
    PayloadRead,
    MetadataRead,
    BeforeReturn,
}

fn bounded(
    reader: &mut impl Read,
    length: u64,
    limit: usize,
    limit_error: InputError,
    poll: &mut impl FnMut(Stage) -> Result<()>,
) -> Result<Vec<u8>> {
    if length > limit as u64 {
        return Err(limit_error);
    }
    let mut out = Vec::new();
    let mut buf = [0; 64 * 1024];
    loop {
        poll(Stage::ReadChunk)?;
        // 追加一byteだけで超過を検出。usize::MAXでも加算overflowしない。
        let request = buf
            .len()
            .min(limit.saturating_sub(out.len()).saturating_add(1));
        let n = match reader.read(&mut buf[..request]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(InputError::Io),
        };
        if n == 0 {
            break;
        }
        if n > limit - out.len() {
            return Err(limit_error);
        }
        out.try_reserve_exact(n)
            .map_err(|_| InputError::Allocation)?;
        out.extend_from_slice(&buf[..n]);
    }
    if out.len() as u64 != length {
        return Err(InputError::Changed);
    }
    Ok(out)
}

/// 完成Recordの通常fileを既存と同じNOFOLLOW/単一link/変更照合で読む。
/// 最大2 MiB。署名・構造は呼出し側でLocalRecord.checkを行う。
pub fn read_record_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = open_regular(path)?;
    let before = file.metadata().map_err(|_| InputError::Io)?;
    let bytes = bounded(
        &mut file,
        before.len(),
        cbor::MAX_RECORD,
        InputError::RecordLimit,
        &mut |_| Ok(()),
    )?;
    unchanged(&file, &before)?;
    Ok(bytes)
}

/// 本文予算は変更可能。metadata CBORは規範上限262,144 bytesを超えない。
/// 通常file/単一linkのみ。symlink（親も含む）、..、特殊fileを拒否する。
/// 取消しをopen前・各read前・復号前後に確認する。OS I/O待ちの強制中断ではない。
/// 両fdの属性を前後照合するが、二fileの原子的snapshotや悪意ある所有者への保証はない。
/// 返却後の元path変更は所有bytesに影響しない。metadataのスキーマ/正規化は署名時の共通検査で行う。
pub fn read_initial_files(
    payload: &Path,
    metadata: &Path,
    budget: CreationBudget,
    mut cancelled: impl FnMut() -> bool,
) -> Result<InitialInput> {
    read_with(payload, metadata, budget, |_| {
        if cancelled() {
            Err(InputError::Cancelled)
        } else {
            Ok(())
        }
    })
}
fn read_with(
    payload: &Path,
    metadata: &Path,
    budget: CreationBudget,
    mut poll: impl FnMut(Stage) -> Result<()>,
) -> Result<InitialInput> {
    poll(Stage::BeforeOpen)?;
    let mut payload = open_regular(payload)?;
    let mut metadata = open_regular(metadata)?;
    let p = payload.metadata().map_err(|_| InputError::Io)?;
    let m = metadata.metadata().map_err(|_| InputError::Io)?;
    // どちらかが長過ぎれば、本文を読む/確保する前に拒否する。
    if p.len() > budget.max_payload_bytes as u64 {
        return Err(InputError::PayloadLimit);
    }
    if m.len() > MAX_METADATA_BYTES as u64 {
        return Err(InputError::MetadataLimit);
    }
    poll(Stage::Opened)?;
    let payload_bytes = bounded(
        &mut payload,
        p.len(),
        budget.max_payload_bytes,
        InputError::PayloadLimit,
        &mut poll,
    )?;
    poll(Stage::PayloadRead)?;
    unchanged(&payload, &p)?;
    let metadata_bytes = bounded(
        &mut metadata,
        m.len(),
        MAX_METADATA_BYTES,
        InputError::MetadataLimit,
        &mut poll,
    )?;
    poll(Stage::MetadataRead)?;
    unchanged(&metadata, &m)?;
    let metadata_value = cbor::decode(&metadata_bytes).map_err(|_| InputError::InvalidMetadata)?;
    if !matches!(metadata_value, Value::Map(_)) {
        return Err(InputError::InvalidMetadata);
    }
    poll(Stage::BeforeReturn)?;
    unchanged(&payload, &p)?;
    unchanged(&metadata, &m)?;
    Ok(InitialInput {
        payload: payload_bytes,
        metadata: metadata_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs as stdfs,
        io::Cursor,
        os::unix::fs::{DirBuilderExt, symlink},
        path::PathBuf,
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "lngnb-input-{}",
                crate::id::Id::random_knowledge().unwrap()
            ));
            stdfs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir)
        }
        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            stdfs::write(&path, bytes).unwrap();
            path
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = stdfs::remove_dir_all(&self.0);
        }
    }
    fn error(r: Result<InitialInput>) -> InputError {
        r.err().expect("must reject")
    }
    fn budget(n: usize) -> CreationBudget {
        CreationBudget {
            max_payload_bytes: n,
        }
    }

    #[test]
    fn completed_record_input_keeps_exact_bytes_and_rejects_one_byte_over_limit() {
        let t = Temp::new();
        let bytes = vec![0xa5; cbor::MAX_RECORD];
        let path = t.file("record", &bytes);
        assert_eq!(read_record_file(&path).unwrap(), bytes);
        let larger = t.file("larger", &vec![0; cbor::MAX_RECORD + 1]);
        assert_eq!(read_record_file(&larger), Err(InputError::RecordLimit));
        let link = t.0.join("link");
        symlink(&path, &link).unwrap();
        assert_eq!(read_record_file(&link), Err(InputError::UnsafePath));
        assert_eq!(stdfs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn owned_binary_input_and_cbor_preserve_bytes_and_empty_payload() {
        let t = Temp::new();
        let p = t.file("body", b"\x00\xff\r\n");
        let value = Value::Map(vec![(
            "titles".into(),
            Value::Map(vec![("JA".into(), Value::Text(" e\u{301} é \n".into()))]),
        )]);
        let m = t.file("meta", &cbor::encode(&value).unwrap());
        let (body, meta) = read_initial_files(&p, &m, budget(4), || false)
            .unwrap()
            .into_parts();
        stdfs::write(&p, b"changed").unwrap();
        stdfs::write(&m, b"changed").unwrap();
        assert_eq!(body, b"\x00\xff\r\n");
        assert_eq!(meta, value);
        stdfs::write(&p, b"").unwrap();
        stdfs::write(&m, [0xa0]).unwrap();
        assert!(
            read_initial_files(&p, &m, budget(0), || false)
                .unwrap()
                .into_parts()
                .0
                .is_empty()
        );
    }
    #[test]
    fn limits_growth_truncation_and_read_failure_return_no_partial_input() {
        let mut ok = |_: Stage| Ok(());
        for n in [3, 4] {
            assert_eq!(
                bounded(
                    &mut Cursor::new(vec![1; n]),
                    n as u64,
                    4,
                    InputError::PayloadLimit,
                    &mut ok
                )
                .unwrap()
                .len(),
                n
            );
        }
        assert_eq!(
            bounded(
                &mut Cursor::new([0; 5]),
                4,
                4,
                InputError::PayloadLimit,
                &mut ok
            )
            .unwrap_err(),
            InputError::PayloadLimit
        );
        assert_eq!(
            bounded(
                &mut Cursor::new([0; 3]),
                4,
                4,
                InputError::PayloadLimit,
                &mut ok
            )
            .unwrap_err(),
            InputError::Changed
        );
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("private path/value"))
            }
        }
        let e = bounded(&mut Fails, 0, 1, InputError::PayloadLimit, &mut ok).unwrap_err();
        assert_eq!(e.to_string(), "creation_input_io_failed");
        assert!(std::error::Error::source(&e).is_none());
        let mut reads = 0;
        let mut reader = Cursor::new(vec![0; 65_537]);
        assert_eq!(
            bounded(
                &mut reader,
                65_537,
                65_537,
                InputError::PayloadLimit,
                &mut |_| {
                    reads += 1;
                    if reads == 2 {
                        Err(InputError::Cancelled)
                    } else {
                        Ok(())
                    }
                }
            )
            .unwrap_err(),
            InputError::Cancelled
        );
        assert_eq!(reader.position(), 65_536);
        let t = Temp::new();
        let p = t.file("body", b"12345");
        let m = t.file("meta", &[0xa0]);
        assert_eq!(
            error(read_initial_files(&p, &m, budget(4), || false)),
            InputError::PayloadLimit
        );
        stdfs::write(&p, b"").unwrap();
        stdfs::write(&m, vec![0; MAX_METADATA_BYTES + 1]).unwrap();
        assert_eq!(
            error(read_initial_files(&p, &m, budget(0), || false)),
            InputError::MetadataLimit
        );
        // metadata符号化長の直前/一致は読込み可。意味上のschema検査は後段。
        for n in [MAX_METADATA_BYTES - 1, MAX_METADATA_BYTES] {
            let value = Value::Map(vec![("extensions".into(), Value::Bytes(vec![0; n - 17]))]);
            let bytes = cbor::encode(&value).unwrap();
            assert_eq!(bytes.len(), n);
            stdfs::write(&m, bytes).unwrap();
            assert!(read_initial_files(&p, &m, budget(0), || false).is_ok());
        }
    }
    #[test]
    fn unsafe_paths_special_files_links_and_parent_links_are_rejected() {
        let t = Temp::new();
        let p = t.file("body", b"");
        let m = t.file("meta", &[0xa0]);
        let link = t.0.join("link");
        symlink(&p, &link).unwrap();
        let hard = t.0.join("hard");
        stdfs::hard_link(&p, &hard).unwrap();
        let fifo = t.0.join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        for path in [
            &link,
            &hard,
            &fifo,
            &t.0,
            &t.0.join("missing"),
            &t.0.join("../body"),
        ] {
            assert_eq!(
                error(read_initial_files(path, &m, budget(0), || false)),
                InputError::UnsafePath
            );
        }
        stdfs::remove_file(hard).unwrap();
        let parent_link = t.0.join("parent");
        symlink(&t.0, &parent_link).unwrap();
        assert_eq!(
            error(read_initial_files(
                &parent_link.join("body"),
                &m,
                budget(0),
                || false
            )),
            InputError::UnsafePath
        );
        assert_eq!(
            error(read_initial_files(&p, &link, budget(0), || false)),
            InputError::UnsafePath
        );
    }
    #[test]
    fn modifications_across_reads_and_before_return_are_detected() {
        let t = Temp::new();
        let p = t.file("body", b"1234");
        let m = t.file("meta", &[0xa0]);
        for (stage, change_payload) in [
            (Stage::Opened, true),
            (Stage::PayloadRead, true),
            (Stage::MetadataRead, true),
            (Stage::BeforeReturn, false),
        ] {
            stdfs::write(&p, b"1234").unwrap();
            stdfs::write(&m, [0xa0]).unwrap();
            let result = read_with(&p, &m, budget(8), |s| {
                if s == stage {
                    stdfs::write(if change_payload { &p } else { &m }, b"different").unwrap();
                }
                Ok(())
            });
            assert!(matches!(
                error(result),
                InputError::Changed | InputError::PayloadLimit
            ));
        }
        stdfs::write(&p, b"1234").unwrap();
        stdfs::write(&m, [0xa0]).unwrap();
        assert_eq!(
            error(read_with(&p, &m, budget(4), |s| {
                if s == Stage::PayloadRead {
                    stdfs::write(&p, b"5678").unwrap();
                }
                Ok(())
            })),
            InputError::Changed
        );
    }
    #[test]
    fn cancellation_at_each_boundary_and_invalid_cbor_never_return_input() {
        let t = Temp::new();
        let p = t.file("body", b"1234");
        let m = t.file("meta", &[0xa0]);
        for at in [
            Stage::BeforeOpen,
            Stage::Opened,
            Stage::ReadChunk,
            Stage::PayloadRead,
            Stage::MetadataRead,
            Stage::BeforeReturn,
        ] {
            assert_eq!(
                error(read_with(&p, &m, budget(4), |s| if s == at {
                    Err(InputError::Cancelled)
                } else {
                    Ok(())
                })),
                InputError::Cancelled
            );
        }
        assert_eq!(
            error(read_initial_files(
                Path::new("missing"),
                &m,
                budget(4),
                || true
            )),
            InputError::Cancelled
        );
        for bytes in [
            &b"{}"[..],
            &[0xa0, 0],
            &[0xf6],
            &[0xa1, 0x61, 0x78, 0x18, 0x17],
            &[0xbf, 0xff],
        ] {
            stdfs::write(&m, bytes).unwrap();
            assert_eq!(
                error(read_initial_files(&p, &m, budget(4), || false)),
                InputError::InvalidMetadata
            );
        }
        assert_eq!(stdfs::read(&p).unwrap(), b"1234");
    }

    #[test]
    fn files_to_signed_pair_are_independently_checked_and_schema_is_not_bypassed() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        fn fixture(section: &str) -> serde_json::Value {
            let part = include_str!("../docs/specification-v1.0.0.md")
                .split(section)
                .nth(1)
                .unwrap();
            serde_json::from_str(
                part.split("```json\n")
                    .nth(1)
                    .unwrap()
                    .split("\n```")
                    .next()
                    .unwrap(),
            )
            .unwrap()
        }
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        fn hex(bytes: &[u8]) -> String {
            data_encoding::HEXLOWER.encode(bytes)
        }
        // A14公開試験鍵専用。実運用へ流用禁止。seedを新規ファイル/ログへ出さない。
        let a14 = fixture("## 付録A14 ");
        let pass = String::from_utf8(unhex(a14["passphrase_utf8_hex"].as_str().unwrap())).unwrap();
        let key = crate::keyfile::unlock(&unhex(a14["keyfile_cbor_hex"].as_str().unwrap()), &pass)
            .unwrap();
        let t = Temp::new();
        let p = t.file("body", b"public file input\x00\xff\n");
        let m = t.file(
            "meta",
            &cbor::encode(&Value::Map(vec![(
                "titles".into(),
                Value::Map(vec![("JA".into(), Value::Text("e\u{301} é".into()))]),
            )]))
            .unwrap(),
        );
        let (body, meta) = read_initial_files(&p, &m, budget(64), || false)
            .unwrap()
            .into_parts();
        stdfs::write(&p, b"new path content must not be signed").unwrap();
        let pair = crate::authoring::create_initial(&key, &body, meta, None, budget(64)).unwrap();
        let a13 = fixture("## 付録A13 ");
        let cases: Vec<_> = [pair.genesis(),pair.revision()].iter().map(|r| serde_json::json!({
            "seed":a13["seed_hex"],"body":hex(&cbor::encode(r.body()).unwrap()),"envelope":hex(r.bytes()),
            "initial_creation":{"payload":hex(&body),"genesis":hex(pair.genesis().bytes())}
        })).collect();
        let mut child = Command::new(
            std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("independent checker required"),
        )
        .arg("tests/reference.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "independent file input signing check failed (details suppressed)"
        );
        let ids: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            ids,
            vec![
                pair.genesis().id().to_string(),
                pair.revision().id().to_string()
            ]
        );
        // CBOR mapの読取り成功はmetadataスキーマ受理ではない。
        stdfs::write(
            &m,
            cbor::encode(&Value::Map(vec![("unknown".into(), Value::Null)])).unwrap(),
        )
        .unwrap();
        let (body, meta) = read_initial_files(&p, &m, budget(64), || false)
            .unwrap()
            .into_parts();
        assert_eq!(
            crate::authoring::create_initial(&key, &body, meta, None, budget(64)).unwrap_err(),
            crate::authoring::CreationError::InvalidInput
        );
    }
}
