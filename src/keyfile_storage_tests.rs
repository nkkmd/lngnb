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
fn preservation_copies_authenticated_ciphertext_without_changing_source_or_overwriting() {
    let source = Area::new();
    let target = Area::new();
    let (bytes, p) = fixture();
    let residue = residue_name(1);
    source.put("key", &bytes);
    source.put(&residue, &bytes);
    source.put(".lngnb-key-unknown", b"public unknown residue");
    let source_before = fingerprint(&stdfs::metadata(&source.0).unwrap());
    let mut s = KeyDirectory::open(&source.0).unwrap();
    let mut t = KeyDirectory::open(&target.0).unwrap();
    let public = s
        .preserve_recovery_file(&residue, &p, &mut t, "saved.key")
        .unwrap();
    assert_eq!(public, unlock(&bytes, &p).unwrap().public_key());
    assert_eq!(stdfs::read(target.0.join("saved.key")).unwrap(), bytes);
    assert_eq!(
        stdfs::metadata(target.0.join("saved.key")).unwrap().mode() & 0o7777,
        0o600
    );
    assert!(t.recovery_inventory().unwrap().entries.is_empty());
    assert_eq!(t.load("saved.key", &p).unwrap().public_key(), public);
    e(
        s.preserve_recovery_file(&residue, &p, &mut t, "saved.key"),
        KeyFileError::Exists,
    );
    e(
        s.change_passphrase("key", &p, &p),
        KeyFileError::PendingRecovery,
    );
    assert_eq!(stdfs::read(source.0.join("key")).unwrap(), bytes);
    assert_eq!(stdfs::read(source.0.join(&residue)).unwrap(), bytes);
    assert_eq!(
        stdfs::read(source.0.join(".lngnb-key-unknown")).unwrap(),
        b"public unknown residue"
    );
    assert_eq!(
        source_before,
        fingerprint(&stdfs::metadata(&source.0).unwrap())
    );
}

#[test]
fn preservation_rejects_authentication_names_unsafe_paths_and_pending_destination_before_creation()
{
    let source = Area::new();
    let target = Area::new();
    let (bytes, p) = fixture();
    let residue = residue_name(1);
    source.put(&residue, &bytes);
    let mut s = KeyDirectory::open(&source.0).unwrap();
    let mut t = KeyDirectory::open(&target.0).unwrap();
    e(
        s.preserve_recovery_file(&residue, "public wrong password", &mut t, "saved"),
        KeyError::AuthenticationFailed.into(),
    );
    for (r, n) in [
        ("key", "saved"),
        (&residue, "../escape"),
        (&residue, ".lngnb-key-reserved"),
    ] {
        e(
            s.preserve_recovery_file(r, &p, &mut t, n),
            KeyFileError::UnsafePath,
        );
    }
    assert!(stdfs::read_dir(&target.0).unwrap().next().is_none());
    source.put(&residue_name(2), b"public incomplete ciphertext");
    e(
        s.preserve_recovery_file(&residue_name(2), &p, &mut t, "saved"),
        KeyError::InvalidFormat.into(),
    );
    symlink(&residue, source.0.join(residue_name(3))).unwrap();
    e(
        s.preserve_recovery_file(&residue_name(3), &p, &mut t, "saved"),
        KeyFileError::UnsafePath,
    );
    assert!(stdfs::read_dir(&target.0).unwrap().next().is_none());
    target.put("existing", b"public existing target");
    symlink("existing", target.0.join("link")).unwrap();
    for n in ["existing", "link"] {
        e(
            s.preserve_recovery_file(&residue, &p, &mut t, n),
            KeyFileError::Exists,
        );
    }
    target.put(".lngnb-key-unknown", b"public pending target");
    e(
        s.preserve_recovery_file(&residue, &p, &mut t, "saved"),
        KeyFileError::PendingRecovery,
    );
    assert_eq!(stdfs::read_dir(&target.0).unwrap().count(), 3);
    e(KeyDirectory::open(&source.0), KeyFileError::Busy);
    assert_eq!(stdfs::read(source.0.join(&residue)).unwrap(), bytes);
}

#[test]
fn preservation_failures_keep_source_and_distinguish_unconfirmed_and_confirmed_copy() {
    let source = Area::new();
    let (bytes, p) = fixture();
    let residue = residue_name(1);
    source.put(&residue, &bytes);
    let mut s = KeyDirectory::open(&source.0).unwrap();
    for stage in [
        Stage::TempCreated,
        Stage::Written,
        Stage::FileSynced,
        Stage::Validated,
        Stage::BeforeInstall,
        Stage::Installed,
        Stage::DirectorySynced,
    ] {
        let target = Area::new();
        let mut t = KeyDirectory::open(&target.0).unwrap();
        let expected = match stage {
            Stage::Installed => KeyFileError::CommitUncertain,
            Stage::DirectorySynced => KeyFileError::PreservationReviewRequired,
            _ => KeyFileError::Io,
        };
        e(
            s.preserve_recovery_file_with(&residue, &p, &mut t, "saved", &mut |at| {
                if at == stage {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            }),
            expected,
        );
        assert_eq!(stdfs::read(source.0.join(&residue)).unwrap(), bytes);
        if matches!(stage, Stage::Installed | Stage::DirectorySynced) {
            assert_eq!(stdfs::read(target.0.join("saved")).unwrap(), bytes);
        } else {
            assert!(!target.0.join("saved").exists());
            assert_eq!(t.recovery_inventory().unwrap().entries.len(), 1);
            e(t.create("other", &p), KeyFileError::PendingRecovery);
        }
    }
}

#[test]
fn preservation_detects_source_changes_before_and_after_copy_without_rolling_them_back() {
    let (bytes, p) = fixture();
    for stage in [Stage::BeforeInstall, Stage::DirectorySynced] {
        let source = Area::new();
        let target = Area::new();
        let residue = residue_name(1);
        source.put(&residue, &bytes);
        let mut s = KeyDirectory::open(&source.0).unwrap();
        let mut t = KeyDirectory::open(&target.0).unwrap();
        let expected = if stage == Stage::BeforeInstall {
            KeyFileError::RecoveryChanged
        } else {
            KeyFileError::PreservationReviewRequired
        };
        e(
            s.preserve_recovery_file_with(&residue, &p, &mut t, "saved", &mut |at| {
                if at == stage {
                    stdfs::write(source.0.join(&residue), b"public changed source").unwrap();
                }
                Ok(())
            }),
            expected,
        );
        assert_eq!(
            stdfs::read(source.0.join(&residue)).unwrap(),
            b"public changed source"
        );
        if stage == Stage::BeforeInstall {
            assert!(!target.0.join("saved").exists());
        } else {
            assert_eq!(stdfs::read(target.0.join("saved")).unwrap(), bytes);
        }
    }
}

#[test]
fn preservation_process_kill_keeps_original_residue_and_releases_both_locks() {
    if let Ok(path) = std::env::var("LNGNB_PUBLIC_PRESERVATION_KILL_SOURCE") {
        let source = PathBuf::from(path);
        let target = PathBuf::from(std::env::var("LNGNB_PUBLIC_PRESERVATION_KILL_TARGET").unwrap());
        for path in [&source, &target] {
            assert!(path.starts_with(std::env::temp_dir()));
            assert!(
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("lngnb-keytest-")
            );
            assert_eq!(
                stdfs::read(path.join("fixture-marker")).unwrap(),
                b"public preservation fixture"
            );
        }
        let stage = std::env::var("LNGNB_PUBLIC_PRESERVATION_KILL_STAGE").unwrap();
        let (_, p) = fixture();
        let mut s = KeyDirectory::open(&source).unwrap();
        let mut t = KeyDirectory::open(&target).unwrap();
        let _ = s.preserve_recovery_file_with(&residue_name(1), &p, &mut t, "saved", &mut |at| {
            if format!("{at:?}") == stage {
                println!("READY");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        });
        panic!("preservation kill point not reached");
    }
    let (bytes, p) = fixture();
    for stage in ["FileSynced", "Installed", "DirectorySynced"] {
        let source = Area::new();
        let target = Area::new();
        source.put(&residue_name(1), &bytes);
        for a in [&source, &target] {
            a.put("fixture-marker", b"public preservation fixture");
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "keyfile::files::tests::preservation_process_kill_keeps_original_residue_and_releases_both_locks", "--nocapture"])
            .env("LNGNB_PUBLIC_PRESERVATION_KILL_SOURCE", &source.0)
            .env("LNGNB_PUBLIC_PRESERVATION_KILL_TARGET", &target.0)
            .env("LNGNB_PUBLIC_PRESERVATION_KILL_STAGE", stage)
            .stdout(Stdio::piped()).spawn().unwrap();
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
        let mut s = KeyDirectory::open(&source.0).unwrap();
        let mut t = KeyDirectory::open(&target.0).unwrap();
        assert_eq!(stdfs::read(source.0.join(residue_name(1))).unwrap(), bytes);
        assert!(s.recovery_inventory().unwrap().has_residues());
        if stage == "FileSynced" {
            assert!(!target.0.join("saved").exists());
            assert_eq!(t.recovery_inventory().unwrap().entries.len(), 1);
            e(t.create("other", &p), KeyFileError::PendingRecovery);
        } else {
            assert_eq!(stdfs::read(target.0.join("saved")).unwrap(), bytes);
            assert_eq!(
                t.load("saved", &p).unwrap().public_key(),
                unlock(&bytes, &p).unwrap().public_key()
            );
        }
        e(s.create("other", &p), KeyFileError::PendingRecovery);
    }
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

#[test]
fn restoration_requires_explicit_identity_and_keeps_every_residue_and_change_stop() {
    let a = Area::new();
    let (bytes, p) = fixture();
    let residue = residue_name(1);
    a.put(&residue, &bytes);
    a.put(".lngnb-key-unknown", b"public unknown residue");
    a.put("existing", b"public unrelated file");
    let before = fingerprint(&stdfs::metadata(a.0.join(&residue)).unwrap());
    let public = unlock(&bytes, &p).unwrap().public_key();
    let mut d = KeyDirectory::open(&a.0).unwrap();
    assert_eq!(
        d.restore_recovery_file(&residue, &p, "restored", &public)
            .unwrap(),
        public
    );
    assert_eq!(stdfs::read(a.0.join("restored")).unwrap(), bytes);
    assert_eq!(
        stdfs::metadata(a.0.join("restored")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(d.load("restored", &p).unwrap().public_key(), public);
    assert_eq!(
        before,
        fingerprint(&stdfs::metadata(a.0.join(&residue)).unwrap())
    );
    assert_eq!(
        stdfs::read(a.0.join(".lngnb-key-unknown")).unwrap(),
        b"public unknown residue"
    );
    assert_eq!(
        stdfs::read(a.0.join("existing")).unwrap(),
        b"public unrelated file"
    );
    assert_eq!(d.recovery_inventory().unwrap().entries.len(), 1);
    e(d.create("new", &p), KeyFileError::PendingRecovery);
    e(
        d.change_passphrase("restored", &p, &p),
        KeyFileError::PendingRecovery,
    );
    e(
        d.restore_recovery_file(&residue, &p, "restored", &public),
        KeyFileError::Exists,
    );
}

#[test]
fn restoration_rejects_wrong_identity_authentication_unsafe_sources_and_existing_targets() {
    let a = Area::new();
    let (bytes, p) = fixture();
    let residue = residue_name(1);
    a.put(&residue, &bytes);
    let public = unlock(&bytes, &p).unwrap().public_key();
    let mut wrong = public;
    wrong[0] ^= 1;
    let mut d = KeyDirectory::open(&a.0).unwrap();
    e(
        d.restore_recovery_file(&residue, &p, "restored", &wrong),
        KeyFileError::UnexpectedPublicKey,
    );
    e(
        d.restore_recovery_file(&residue, "public wrong password", "restored", &public),
        KeyError::AuthenticationFailed.into(),
    );
    for (r, n) in [
        ("ordinary", "restored"),
        (&residue, "../escape"),
        (&residue, ".lngnb-key-reserved"),
    ] {
        e(
            d.restore_recovery_file(r, &p, n, &public),
            KeyFileError::UnsafePath,
        );
    }
    a.put(&residue_name(2), b"public incomplete ciphertext");
    e(
        d.restore_recovery_file(&residue_name(2), &p, "restored", &public),
        KeyError::InvalidFormat.into(),
    );
    symlink(&residue, a.0.join(residue_name(3))).unwrap();
    e(
        d.restore_recovery_file(&residue_name(3), &p, "restored", &public),
        KeyFileError::UnsafePath,
    );
    a.put("existing", b"public existing target");
    symlink("absent", a.0.join("dangling")).unwrap();
    stdfs::create_dir(a.0.join("directory")).unwrap();
    for n in ["existing", "dangling", "directory"] {
        e(
            d.restore_recovery_file(&residue, &p, n, &public),
            KeyFileError::Exists,
        );
    }
    assert!(!a.0.join("restored").exists());
    assert_eq!(a.pending().len(), 3); // 拒否で新しい一時暗号文を作らない。
    assert_eq!(
        stdfs::read(a.0.join("existing")).unwrap(),
        b"public existing target"
    );
    assert_eq!(stdfs::read(a.0.join(&residue)).unwrap(), bytes);
}

#[test]
fn restoration_failure_stages_preserve_inputs_and_distinguish_durability() {
    let (bytes, p) = fixture();
    let public = unlock(&bytes, &p).unwrap().public_key();
    for stage in [
        Stage::TempCreated,
        Stage::Written,
        Stage::FileSynced,
        Stage::Validated,
        Stage::BeforeInstall,
        Stage::Installed,
        Stage::DirectorySynced,
    ] {
        let a = Area::new();
        let residue = residue_name(1);
        a.put(&residue, &bytes);
        let mut d = KeyDirectory::open(&a.0).unwrap();
        e(
            d.restore_recovery_file_with(&residue, &p, "restored", &public, &mut |at| {
                if at == stage {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            }),
            match stage {
                Stage::Installed => KeyFileError::CommitUncertain,
                Stage::DirectorySynced => KeyFileError::RestorationReviewRequired,
                _ => KeyFileError::Io,
            },
        );
        assert_eq!(stdfs::read(a.0.join(&residue)).unwrap(), bytes);
        if matches!(stage, Stage::Installed | Stage::DirectorySynced) {
            assert_eq!(stdfs::read(a.0.join("restored")).unwrap(), bytes);
            assert_eq!(a.pending().len(), 1);
        } else {
            assert!(!a.0.join("restored").exists());
            assert_eq!(a.pending().len(), 2);
        }
        e(d.create("new", &p), KeyFileError::PendingRecovery);
    }
}

#[test]
fn restoration_detects_source_changes_and_target_race_without_rollback_or_overwrite() {
    let (bytes, p) = fixture();
    let public = unlock(&bytes, &p).unwrap().public_key();
    for (stage, target_race) in [
        (Stage::BeforeInstall, false),
        (Stage::DirectorySynced, false),
        (Stage::BeforeInstall, true),
    ] {
        let a = Area::new();
        let residue = residue_name(1);
        a.put(&residue, &bytes);
        let mut d = KeyDirectory::open(&a.0).unwrap();
        e(
            d.restore_recovery_file_with(&residue, &p, "restored", &public, &mut |at| {
                if at == stage {
                    if target_race {
                        a.put("restored", b"public racing target");
                    } else {
                        stdfs::write(a.0.join(&residue), b"public changed source").unwrap();
                    }
                }
                Ok(())
            }),
            if target_race {
                KeyFileError::Exists
            } else if stage == Stage::BeforeInstall {
                KeyFileError::RecoveryChanged
            } else {
                KeyFileError::RestorationReviewRequired
            },
        );
        if target_race {
            assert_eq!(
                stdfs::read(a.0.join("restored")).unwrap(),
                b"public racing target"
            );
            assert_eq!(stdfs::read(a.0.join(&residue)).unwrap(), bytes);
        } else {
            assert_eq!(
                stdfs::read(a.0.join(&residue)).unwrap(),
                b"public changed source"
            );
            if stage == Stage::DirectorySynced {
                assert_eq!(stdfs::read(a.0.join("restored")).unwrap(), bytes);
            } else {
                assert!(!a.0.join("restored").exists());
            }
        }
    }
}

#[test]
fn restoration_process_kill_keeps_residue_and_releases_lock() {
    let (bytes, p) = fixture();
    let public = unlock(&bytes, &p).unwrap().public_key();
    if let Ok(path) = std::env::var("LNGNB_PUBLIC_RESTORATION_KILL_AREA") {
        let path = PathBuf::from(path);
        assert!(path.starts_with(std::env::temp_dir()));
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("lngnb-keytest-")
        );
        assert_eq!(
            stdfs::read(path.join("fixture-marker")).unwrap(),
            b"public restoration fixture"
        );
        let stage = std::env::var("LNGNB_PUBLIC_RESTORATION_KILL_STAGE").unwrap();
        let mut d = KeyDirectory::open(&path).unwrap();
        let _ =
            d.restore_recovery_file_with(&residue_name(1), &p, "restored", &public, &mut |at| {
                if format!("{at:?}") == stage {
                    println!("READY");
                    std::io::stdout().flush().unwrap();
                    loop {
                        std::thread::park();
                    }
                }
                Ok(())
            });
        panic!("restoration kill point not reached");
    }
    for stage in ["FileSynced", "Installed", "DirectorySynced"] {
        let a = Area::new();
        a.put(&residue_name(1), &bytes);
        a.put("fixture-marker", b"public restoration fixture");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "keyfile::files::tests::restoration_process_kill_keeps_residue_and_releases_lock",
                "--nocapture",
            ])
            .env("LNGNB_PUBLIC_RESTORATION_KILL_AREA", &a.0)
            .env("LNGNB_PUBLIC_RESTORATION_KILL_STAGE", stage)
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
        assert_eq!(stdfs::read(a.0.join(residue_name(1))).unwrap(), bytes);
        if stage == "FileSynced" {
            assert!(!a.0.join("restored").exists());
            assert_eq!(a.pending().len(), 2);
        } else {
            assert_eq!(stdfs::read(a.0.join("restored")).unwrap(), bytes);
            assert_eq!(d.load("restored", &p).unwrap().public_key(), public);
            assert_eq!(a.pending().len(), 1);
        }
        e(
            d.change_passphrase("restored", &p, &p),
            KeyFileError::PendingRecovery,
        );
    }
}

#[test]
fn preserved_copy_can_be_used_after_reopen_without_clearing_or_rewriting_source_recovery() {
    let source = Area::new();
    let destination = Area::new();
    let (bytes, old) = fixture();
    let new = "public preserved copy new password only";
    let public = unlock(&bytes, &old).unwrap().public_key();
    let current = unlock(&bytes, &old).unwrap().encrypt(new).unwrap();
    let residue = residue_name(1);
    source.put("publisher", &current);
    source.put(&residue, &bytes);
    source.put(".lngnb-key-unknown", b"public unclassified residue");
    let snapshot: Vec<_> = ["publisher", &residue, ".lngnb-key-unknown"]
        .iter()
        .map(|name| {
            let path = source.0.join(name);
            (
                path.clone(),
                stdfs::read(&path).unwrap(),
                fingerprint(&stdfs::metadata(path).unwrap()),
            )
        })
        .collect();
    let directory_before = fingerprint(&stdfs::metadata(&source.0).unwrap());
    {
        let mut s = KeyDirectory::open(&source.0).unwrap();
        let mut d = KeyDirectory::open(&destination.0).unwrap();
        assert_eq!(
            s.preserve_recovery_file(&residue, &old, &mut d, "publisher")
                .unwrap(),
            public
        );
    }
    // 再openを境に、選択した領域でだけ通常操作の条件を確認する。
    let mut s = KeyDirectory::open(&source.0).unwrap();
    let mut d = KeyDirectory::open(&destination.0).unwrap();
    assert!(s.recovery_inventory().unwrap().has_residues());
    assert!(!d.recovery_inventory().unwrap().has_residues());
    assert_eq!(d.load("publisher", &old).unwrap().public_key(), public);
    e(
        d.change_passphrase("publisher", "public wrong password", new),
        KeyError::AuthenticationFailed.into(),
    );
    assert_eq!(stdfs::read(destination.0.join("publisher")).unwrap(), bytes);
    assert_eq!(d.change_passphrase("publisher", &old, new).unwrap(), public);
    assert_eq!(d.load("publisher", new).unwrap().public_key(), public);
    e(
        d.load("publisher", &old),
        KeyError::AuthenticationFailed.into(),
    );
    assert_ne!(stdfs::read(destination.0.join("publisher")).unwrap(), bytes);
    assert_eq!(
        stdfs::metadata(destination.0.join("publisher"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(!d.recovery_inventory().unwrap().has_residues());
    // コピー先の更新は元暗号文の失効や、元領域の停止解除ではない。
    assert_eq!(s.check_recovery_file(&residue, &old).unwrap(), public);
    assert_eq!(s.load("publisher", new).unwrap().public_key(), public);
    e(
        s.change_passphrase("publisher", new, &old),
        KeyFileError::PendingRecovery,
    );
    for (path, original, metadata) in snapshot {
        assert_eq!(stdfs::read(&path).unwrap(), original);
        assert_eq!(fingerprint(&stdfs::metadata(path).unwrap()), metadata);
    }
    assert_eq!(
        fingerprint(&stdfs::metadata(&source.0).unwrap()),
        directory_before
    );
    // 新しい領域でも残存物ができれば通常変更を再び止める。
    destination.put(
        ".lngnb-key-unclassified",
        b"public destination recovery marker",
    );
    e(
        d.change_passphrase("publisher", new, &old),
        KeyFileError::PendingRecovery,
    );
    assert_eq!(d.load("publisher", new).unwrap().public_key(), public);
}
