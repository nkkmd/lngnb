//! R34/A11/K01〜04: 公開試験鍵のみ。実運用に流用禁止。各試験は隔離領域だけを操作。
use super::*;
use std::{
    fs as stdfs,
    io::BufRead,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Area(PathBuf);
impl Area {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "lngnb-keytest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        stdfs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
    fn put(&self, n: &str, b: &[u8]) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = stdfs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.0.join(n))
            .unwrap();
        f.write_all(b).unwrap();
        f.sync_all().unwrap();
        File::open(&self.0).unwrap().sync_all().unwrap();
    }
    fn pending(&self) -> Vec<PathBuf> {
        stdfs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .as_encoded_bytes()
                    .starts_with(PREFIX.as_bytes())
            })
            .collect()
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        let _ = stdfs::remove_dir_all(&self.0);
    }
}
fn fixture() -> (Vec<u8>, String) {
    let f = super::super::tests::a14();
    (
        super::super::tests::unhex(f["keyfile_cbor_hex"].as_str().unwrap()),
        super::super::tests::passphrase(),
    )
}
fn e<T>(r: Result<T>, wanted: KeyFileError) {
    match r {
        Err(x) => assert_eq!(x, wanted),
        Ok(_) => panic!("unexpected key operation success"),
    }
}
#[test]
fn create_load_change_preserves_identity_and_uses_private_files() {
    let a = Area::new();
    let mut dir = KeyDirectory::open(&a.0).unwrap();
    let public = dir.create("publisher.key", "public test password").unwrap();
    let first = stdfs::read(a.0.join("publisher.key")).unwrap();
    assert_eq!(
        stdfs::metadata(a.0.join("publisher.key")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        dir.load("publisher.key", "public test password")
            .unwrap()
            .public_key(),
        public
    );
    assert_eq!(
        dir.change_passphrase(
            "publisher.key",
            "public test password",
            "second public test password"
        )
        .unwrap(),
        public
    );
    assert!(stdfs::read(a.0.join("publisher.key")).unwrap() != first);
    assert_eq!(
        dir.load("publisher.key", "second public test password")
            .unwrap()
            .public_key(),
        public
    );
    e(
        dir.load("publisher.key", "public test password"),
        KeyFileError::Key(KeyError::AuthenticationFailed),
    );
    assert!(a.pending().is_empty());
}
#[test]
fn existing_targets_and_unsafe_names_are_never_overwritten() {
    let a = Area::new();
    let (b, p) = fixture();
    a.put("existing", &b);
    symlink("existing", a.0.join("link")).unwrap();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    for n in ["existing", "link"] {
        e(d.create(n, &p), KeyFileError::Exists);
    }
    for n in ["", ".", "..", "../escape", "x/y", ".lngnb-key-user", "x\0y"] {
        e(d.create(n, &p), KeyFileError::UnsafePath);
    }
    assert_eq!(stdfs::read(a.0.join("existing")).unwrap(), b);
    assert!(a.pending().is_empty());
}
#[test]
fn permissions_links_special_files_and_owner_are_checked() {
    let a = Area::new();
    let (b, p) = fixture();
    a.put("key", &b);
    let mut d = KeyDirectory::open(&a.0).unwrap();
    stdfs::set_permissions(a.0.join("key"), stdfs::Permissions::from_mode(0o644)).unwrap();
    e(d.load("key", &p), KeyFileError::UnsafePath);
    stdfs::set_permissions(a.0.join("key"), stdfs::Permissions::from_mode(0o600)).unwrap();
    stdfs::hard_link(a.0.join("key"), a.0.join("hard")).unwrap();
    e(d.load("key", &p), KeyFileError::UnsafePath);
    stdfs::remove_file(a.0.join("hard")).unwrap();
    symlink("key", a.0.join("link")).unwrap();
    e(d.load("link", &p), KeyFileError::UnsafePath);
    os(fs::mknodat(
        &d.dir,
        "fifo",
        fs::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    ))
    .unwrap();
    e(d.load("fifo", &p), KeyFileError::UnsafePath);
    stdfs::create_dir(a.0.join("directory")).unwrap();
    e(d.load("directory", &p), KeyFileError::UnsafePath);
    stdfs::set_permissions(&a.0, stdfs::Permissions::from_mode(0o755)).unwrap();
    e(d.load("key", &p), KeyFileError::UnsafePath);
    e(KeyDirectory::open(&a.0), KeyFileError::UnsafePath);
    stdfs::set_permissions(&a.0, stdfs::Permissions::from_mode(0o700)).unwrap();
    // 実UID変更はuser namespaceで禁止されるため、読戻した実属性に別の期待UIDを適用する。
    let metadata = stdfs::metadata(a.0.join("key")).unwrap();
    e(
        private_file(&metadata, metadata.uid().wrapping_add(1)),
        KeyFileError::UnsafePath,
    );
}
#[test]
fn parent_symlink_dotdot_and_missing_directory_are_rejected() {
    let a = Area::new();
    let target = a.0.join("private");
    stdfs::DirBuilder::new()
        .mode(0o700)
        .create(&target)
        .unwrap();
    symlink("private", a.0.join("alias")).unwrap();
    e(
        KeyDirectory::open(&a.0.join("alias")),
        KeyFileError::UnsafePath,
    );
    e(
        KeyDirectory::open(&a.0.join("alias/child")),
        KeyFileError::UnsafePath,
    );
    e(
        KeyDirectory::open(&a.0.join("private/../private")),
        KeyFileError::UnsafePath,
    );
    assert!(KeyDirectory::open(&a.0.join("missing")).is_err());
    assert!(!a.0.join("missing").exists());
    e(KeyDirectory::open(Path::new("")), KeyFileError::UnsafePath);
}
#[test]
fn invalid_input_is_bounded_and_never_creates_an_update() {
    let a = Area::new();
    let (b, p) = fixture();
    a.put("key", &b);
    a.put("large", &vec![0; 4097]);
    a.put("broken", b"not a key");
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(
        d.load("large", &p),
        KeyFileError::Key(KeyError::InvalidFormat),
    );
    e(
        d.load("broken", &p),
        KeyFileError::Key(KeyError::InvalidFormat),
    );
    e(d.load("absent", &p), KeyFileError::Missing);
    e(
        d.change_passphrase("key", "wrong public test password", &p),
        KeyFileError::Key(KeyError::AuthenticationFailed),
    );
    e(
        d.change_passphrase("key", &p, ""),
        KeyFileError::Key(KeyError::InvalidPassphrase),
    );
    assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
    assert!(a.pending().is_empty());
}
#[test]
fn failures_before_exchange_keep_original_bytes_and_leave_pending_input() {
    let (b, p) = fixture();
    for stage in [
        Stage::TempCreated,
        Stage::Written,
        Stage::FileSynced,
        Stage::Validated,
        Stage::BeforeInstall,
    ] {
        let a = Area::new();
        a.put("key", &b);
        let mut d = KeyDirectory::open(&a.0).unwrap();
        e(
            d.install("key", &b, &p, Some(&b), &mut |s| {
                if s == stage {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            }),
            KeyFileError::Io,
        );
        assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
        assert_eq!(
            d.load("key", &p).unwrap().public_key(),
            unlock(&b, &p).unwrap().public_key()
        );
        assert_eq!(a.pending().len(), 1);
        e(
            d.change_passphrase("key", &p, &p),
            KeyFileError::PendingRecovery,
        );
    }
}
#[test]
fn replacement_and_permission_change_before_install_are_detected() {
    let (b, p) = fixture();
    for permission in [false, true] {
        let a = Area::new();
        a.put("key", &b);
        let mut d = KeyDirectory::open(&a.0).unwrap();
        let r = d.install("key", &b, &p, Some(&b), &mut |s| {
            if s == Stage::BeforeInstall {
                if permission {
                    stdfs::set_permissions(&a.0, stdfs::Permissions::from_mode(0o755)).unwrap();
                } else {
                    stdfs::write(a.0.join("key"), b"externally changed bytes").unwrap();
                }
            }
            Ok(())
        });
        e(r, KeyFileError::UnsafePath);
        if !permission {
            assert_eq!(
                stdfs::read(a.0.join("key")).unwrap(),
                b"externally changed bytes"
            );
        }
        assert_eq!(a.pending().len(), 1);
    }
}
#[test]
fn no_replace_handles_a_target_appearing_after_preflight() {
    let a = Area::new();
    let (b, p) = fixture();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(
        d.install("key", &b, &p, None, &mut |s| {
            if s == Stage::BeforeInstall {
                a.put("key", b"existing data");
            }
            Ok(())
        }),
        KeyFileError::Exists,
    );
    assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b"existing data");
    assert_eq!(a.pending().len(), 1);
}
#[test]
fn failures_after_exchange_distinguish_uncertain_commit_and_cleanup() {
    let (b, p) = fixture();
    let key = unlock(&b, &p).unwrap();
    let new = key.encrypt("new public test password").unwrap();
    for (stage, error) in [
        (Stage::Installed, KeyFileError::CommitUncertain),
        (Stage::DirectorySynced, KeyFileError::CleanupUncertain),
        (Stage::BeforeCleanup, KeyFileError::CleanupUncertain),
        (Stage::Removed, KeyFileError::CleanupUncertain),
    ] {
        let a = Area::new();
        a.put("key", &b);
        let mut d = KeyDirectory::open(&a.0).unwrap();
        e(
            d.install(
                "key",
                &new,
                "new public test password",
                Some(&b),
                &mut |s| {
                    if s == stage {
                        Err(KeyFileError::Io)
                    } else {
                        Ok(())
                    }
                },
            ),
            error,
        );
        assert_eq!(stdfs::read(a.0.join("key")).unwrap(), new);
        assert_eq!(
            d.load("key", "new public test password")
                .unwrap()
                .public_key(),
            key.public_key()
        );
        if stage != Stage::Removed {
            assert_eq!(stdfs::read(&a.pending()[0]).unwrap(), b);
        } else {
            assert!(a.pending().is_empty());
        }
    }
}
#[test]
fn directory_lock_survives_key_inode_replacement_and_drop_unlocks() {
    let a = Area::new();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(KeyDirectory::open(&a.0), KeyFileError::Busy);
    let (b, p) = fixture();
    a.put("key", &b);
    let before = stdfs::metadata(a.0.join("key")).unwrap().ino();
    d.install("key", &b, &p, Some(&b), &mut |_| Ok(())).unwrap();
    assert_ne!(stdfs::metadata(a.0.join("key")).unwrap().ino(), before);
    e(KeyDirectory::open(&a.0), KeyFileError::Busy);
    drop(d);
    assert!(KeyDirectory::open(&a.0).is_ok());
}
#[test]
fn process_kill_preserves_old_or_new_key_and_releases_lock() {
    if let Some(path) = std::env::var_os("LNGNB_PUBLIC_KEY_KILL_DIR") {
        let path = PathBuf::from(path);
        assert!(
            path.file_name()
                .unwrap()
                .as_encoded_bytes()
                .starts_with(b"lngnb-keytest-")
        );
        assert_eq!(
            stdfs::read(path.join("fixture-marker")).unwrap(),
            b"public-key-fixture"
        );
        let stage = std::env::var("LNGNB_KEY_KILL_STAGE").unwrap();
        let (b, p) = fixture();
        let mut d = KeyDirectory::open(&path).unwrap();
        let new = unlock(&b, &p)
            .unwrap()
            .encrypt("new public test password")
            .unwrap();
        let _ = d.install(
            "key",
            &new,
            "new public test password",
            Some(&b),
            &mut |s| {
                if format!("{s:?}") == stage {
                    println!("READY");
                    std::io::stdout().flush().unwrap();
                    loop {
                        std::thread::park();
                    }
                }
                Ok(())
            },
        );
        panic!("kill point not reached");
    }
    let (b, p) = fixture();
    for stage in ["FileSynced", "Installed", "DirectorySynced"] {
        let a = Area::new();
        a.put("key", &b);
        a.put("fixture-marker", b"public-key-fixture");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "keyfile::files::tests::process_kill_preserves_old_or_new_key_and_releases_lock",
                "--nocapture",
            ])
            .env("LNGNB_PUBLIC_KEY_KILL_DIR", &a.0)
            .env("LNGNB_KEY_KILL_STAGE", stage)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(stdout.read_line(&mut line).unwrap() > 0);
            if line.trim() == "READY" {
                break;
            }
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let mut d = KeyDirectory::open(&a.0).unwrap();
        if stage == "FileSynced" {
            assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
            assert!(d.load("key", &p).is_ok());
        } else {
            assert_ne!(stdfs::read(a.0.join("key")).unwrap(), b);
            assert!(d.load("key", "new public test password").is_ok());
            assert_eq!(stdfs::read(&a.pending()[0]).unwrap(), b);
        }
        assert_eq!(a.pending().len(), 1);
        let current = stdfs::read(a.0.join("key")).unwrap();
        let pending_path = a.pending().pop().unwrap();
        let pending_bytes = stdfs::read(&pending_path).unwrap();
        let inventory = d.recovery_inventory().unwrap();
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].read_error, None);
        let password = if stage == "FileSynced" {
            "new public test password"
        } else {
            &p
        };
        assert_eq!(
            d.check_recovery_file(&inventory.entries[0].name, password)
                .unwrap(),
            unlock(&b, &p).unwrap().public_key()
        );
        assert_eq!(stdfs::read(a.0.join("key")).unwrap(), current);
        assert_eq!(stdfs::read(&pending_path).unwrap(), pending_bytes);
        e(
            d.change_passphrase("key", &p, &p),
            KeyFileError::PendingRecovery,
        );
    }
}

#[test]
fn tampered_readback_and_orphan_inputs_are_never_adopted() {
    let (b, p) = fixture();
    let a = Area::new();
    a.put("key", &b);
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(
        d.install("key", &b, &p, Some(&b), &mut |s| {
            if s == Stage::FileSynced {
                stdfs::write(&a.pending()[0], b"changed after fsync").unwrap();
            }
            Ok(())
        }),
        KeyFileError::Io,
    );
    assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
    let pending = a.pending();
    assert_eq!(stdfs::read(&pending[0]).unwrap(), b"changed after fsync");
    e(d.create("other", &p), KeyFileError::PendingRecovery);
    assert_eq!(stdfs::read(&pending[0]).unwrap(), b"changed after fsync");
}

#[test]
fn pending_scan_has_an_explicit_boundary_without_deleting_entries() {
    let a = Area::new();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    for i in 0..SCAN_LIMIT {
        File::create(a.0.join(format!("entry-{i}"))).unwrap();
    }
    d.pending().unwrap();
    assert!(!d.recovery_inventory().unwrap().has_residues());
    File::create(a.0.join("one-more")).unwrap();
    e(d.pending(), KeyFileError::ScanLimit);
    e(d.recovery_inventory(), KeyFileError::ScanLimit);
    assert_eq!(stdfs::read_dir(&a.0).unwrap().count(), SCAN_LIMIT + 1);
}

fn residue_name(index: u8) -> String {
    format!("{PREFIX}{}", data_encoding::HEXLOWER.encode(&[index; 32]))
}
#[test]
fn recovery_inventory_is_bounded_sorted_unauthenticated_and_never_adopts() {
    let a = Area::new();
    let (b, p) = fixture();
    a.put("key", &b);
    a.put(&residue_name(2), &b);
    a.put(&residue_name(1), b"public incomplete ciphertext");
    a.put(
        ".lngnb-key-unknown\npublic-untrusted-filename",
        b"public unknown input",
    );
    use std::os::unix::ffi::OsStringExt;
    let n = std::ffi::OsString::from_vec([PREFIX.as_bytes(), &[0xff]].concat());
    a.put("ordinary", b"public ordinary fixture");
    stdfs::write(a.0.join(n), b"public non-UTF8 name fixture").unwrap();
    let before = fingerprint(&stdfs::metadata(&a.0).unwrap());
    let mut d = KeyDirectory::open(&a.0).unwrap();
    let inventory = d.recovery_inventory().unwrap();
    assert!(inventory.has_residues());
    assert_eq!(inventory.unrecognized_entries, 2);
    assert_eq!(
        inventory
            .entries
            .iter()
            .map(|e| (&e.name, e.read_error))
            .collect::<Vec<_>>(),
        vec![(&residue_name(1), None), (&residue_name(2), None)]
    );
    // 通常fileの読取り成功を、不完全暗号文の認証成功へ読み替えない。
    e(
        d.check_recovery_file(&residue_name(1), &p),
        KeyError::InvalidFormat.into(),
    );
    e(d.create("other", &p), KeyFileError::PendingRecovery);
    e(
        d.change_passphrase("key", &p, &p),
        KeyFileError::PendingRecovery,
    );
    assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
    assert_eq!(stdfs::read(a.0.join(residue_name(2))).unwrap(), b);
    assert_eq!(before, fingerprint(&stdfs::metadata(&a.0).unwrap()));
    assert_eq!(stdfs::read_dir(&a.0).unwrap().count(), 6);
}
#[test]
fn recovery_inventory_reports_unsafe_entries_without_following_or_deleting_them() {
    let a = Area::new();
    let (b, _) = fixture();
    a.put("key", &b);
    symlink("key", a.0.join(residue_name(1))).unwrap();
    stdfs::hard_link(a.0.join("key"), a.0.join(residue_name(2))).unwrap();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    os(fs::mknodat(
        &d.dir,
        residue_name(3),
        fs::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    ))
    .unwrap();
    stdfs::create_dir(a.0.join(residue_name(4))).unwrap();
    a.put(&residue_name(5), &b);
    stdfs::set_permissions(
        a.0.join(residue_name(5)),
        stdfs::Permissions::from_mode(0o644),
    )
    .unwrap();
    a.put(&residue_name(6), &vec![0; MAX_KEYFILE_BYTES + 1]);
    let inventory = d.recovery_inventory().unwrap();
    assert_eq!(inventory.entries.len(), 6);
    for entry in &inventory.entries[..5] {
        assert_eq!(entry.read_error, Some(KeyFileError::UnsafePath));
    }
    assert_eq!(
        inventory.entries[5].read_error,
        Some(KeyError::InvalidFormat.into())
    );
    assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
    assert_eq!(stdfs::read_dir(&a.0).unwrap().count(), 7);
}
#[test]
fn inventory_change_is_not_a_complete_diagnosis_and_preserves_inputs() {
    let a = Area::new();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(
        d.recovery_inventory_with(&mut || {
            a.put(&residue_name(1), b"public added fixture");
            Ok(())
        }),
        KeyFileError::RecoveryChanged,
    );
    assert!(d.recovery_inventory().unwrap().has_residues());
    assert_eq!(
        stdfs::read(a.0.join(residue_name(1))).unwrap(),
        b"public added fixture"
    );
    stdfs::set_permissions(&a.0, stdfs::Permissions::from_mode(0o755)).unwrap();
    e(d.recovery_inventory(), KeyFileError::UnsafePath);
    stdfs::set_permissions(&a.0, stdfs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
fn selected_residue_requires_authentication_and_cannot_be_used_for_signing_or_adoption() {
    let a = Area::new();
    let (b, p) = fixture();
    let n = residue_name(1);
    a.put(&n, &b);
    let mut d = KeyDirectory::open(&a.0).unwrap();
    assert_eq!(
        d.check_recovery_file(&n, &p).unwrap(),
        unlock(&b, &p).unwrap().public_key()
    );
    e(
        d.check_recovery_file(&n, "public wrong password"),
        KeyError::AuthenticationFailed.into(),
    );
    for bad in [
        "key",
        ".lngnb-key-user",
        "../escape",
        &format!("{n}/child"),
        &n.to_uppercase(),
    ] {
        e(d.check_recovery_file(bad, &p), KeyFileError::UnsafePath);
    }
    e(d.load(&n, &p), KeyFileError::UnsafePath);
    e(d.create("key", &p), KeyFileError::PendingRecovery);
    e(
        d.check_recovery_file_with(&n, &p, &mut || {
            stdfs::write(a.0.join(&n), b"public changed ciphertext").unwrap();
            Ok(())
        }),
        KeyFileError::RecoveryChanged,
    );
    assert_eq!(
        stdfs::read(a.0.join(&n)).unwrap(),
        b"public changed ciphertext"
    );
    assert!(!a.0.join("key").exists());
}

#[test]
fn cleanup_never_unlinks_a_changed_recovery_file() {
    let (b, p) = fixture();
    let a = Area::new();
    a.put("key", &b);
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(
        d.install("key", &b, &p, Some(&b), &mut |s| {
            if s == Stage::BeforeCleanup {
                stdfs::write(&a.pending()[0], b"changed recovery input").unwrap();
            }
            Ok(())
        }),
        KeyFileError::CleanupUncertain,
    );
    assert_eq!(
        stdfs::read(&a.pending()[0]).unwrap(),
        b"changed recovery input"
    );
    assert_eq!(stdfs::read(a.0.join("key")).unwrap(), b);
}
