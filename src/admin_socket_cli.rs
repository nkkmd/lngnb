//! 固定管理socket名の属性表示。接続・不使用判定・整理はしない。
use super::admin_cli::Error;
use lngnb::storage::{
    Limits, RecordStore, StartupState,
    admin_transport::{AdminSocketPathInventory, SocketPathKind},
};
use std::{fmt::Write as _, io::Write, path::Path, time::Duration};

pub fn run(path: &Path, output: &mut impl Write) -> Result<(), Error> {
    // 既存openの検査を省略せず、同じ排他を出力完了まで保持する。
    let store = RecordStore::open(path, Limits::default()).map_err(|_| Error::SocketInventory)?;
    let inventory = store
        .admin_socket_inventory(Duration::from_secs(30))
        .map_err(|_| Error::SocketInventory)?;
    let state = store.startup_state().map_err(|_| Error::SocketInventory)?;
    report(&inventory, state, output)
}

fn report(
    inventory: &AdminSocketPathInventory,
    state: StartupState,
    output: &mut impl Write,
) -> Result<(), Error> {
    let state = match state {
        StartupState::Clean => "clean",
        StartupState::NeedsReview => "manual_review_required",
        StartupState::InspectionPending => "inspection_pending",
    };
    let mut text = format!(
        "固定管理socket名の属性観測（不使用・元socket・削除可否の判定ではありません）。\nstartup_state: {state}\ndirectory_device: {}\ndirectory_inode: {}\nowner_uid: {}\nentries: 4\n",
        inventory.directory_device, inventory.directory_inode, inventory.owner_uid
    );
    for (n, entry) in inventory.entries.iter().enumerate() {
        writeln!(text, "entry[{n}].name: {}", entry.name).expect("String write");
        let Some(m) = entry.observed else {
            writeln!(text, "entry[{n}].observed: absent").expect("String write");
            continue;
        };
        let kind = match m.kind {
            SocketPathKind::Socket => "socket",
            SocketPathKind::RegularFile => "regular_file",
            SocketPathKind::Directory => "directory",
            SocketPathKind::Symlink => "symlink",
            SocketPathKind::Other => "other",
        };
        writeln!(text, "entry[{n}].observed: present\nentry[{n}].kind: {kind}")
            .expect("String write");
        for (field, value) in [
            ("device", m.device),
            ("inode", m.inode),
            ("owner_uid", u64::from(m.owner_uid)),
            ("owner_gid", u64::from(m.owner_gid)),
            ("links", m.links),
            ("byte_length", m.byte_length),
        ] {
            writeln!(text, "entry[{n}].{field}: {value}").expect("String write");
        }
        writeln!(text, "entry[{n}].mode_octal: {:04o}", m.mode).expect("String write");
        for (field, value) in [
            ("modified_seconds", m.modified_seconds),
            ("modified_nanoseconds", m.modified_nanoseconds),
            ("changed_seconds", m.changed_seconds),
            ("changed_nanoseconds", m.changed_nanoseconds),
        ] {
            writeln!(text, "entry[{n}].{field}: {value}").expect("String write");
        }
    }
    text.push_str("不在はこの観測時点だけの情報です。2回の一致は原子的snapshotや返却後の不変を保証しません。接続・修復・採用・削除・writer/finish・手動待ち解除は行いません。表示成功は起動検査完了・正常停止・公開・復旧完了ではありません。\n");
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::SocketInventoryOutput)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_errors_do_not_claim_observation_failure_or_echo_sources() {
        let inventory = AdminSocketPathInventory {
            directory_device: 1,
            directory_inode: 2,
            owner_uid: 3,
            entries: [
                "admin.sock",
                "admin-status.sock",
                "admin-evaluate.sock",
                "admin-config.sock",
            ]
            .map(|name| lngnb::storage::admin_transport::AdminSocketPathEntry {
                name,
                observed: None,
            }),
        };
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("PRIVATE INPUT"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("PRIVATE INPUT"))
            }
        }
        for flush in [false, true] {
            let error = report(&inventory, StartupState::NeedsReview, &mut Sink(flush)).unwrap_err();
            assert!(matches!(error, Error::SocketInventoryOutput));
            assert_eq!(error.exit_code(), 1);
            assert!(!error.to_string().contains("PRIVATE INPUT"));
            assert!(error.to_string().contains("観測後"));
        }
        assert_eq!(Error::SocketInventory.exit_code(), 1);
        assert!(std::error::Error::source(&Error::SocketInventory).is_none());
    }
}
