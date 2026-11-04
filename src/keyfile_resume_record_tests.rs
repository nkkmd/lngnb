//! 公開A14/隔離領域だけ。合成した過去履歴を過去の保存成功の証明にしない。
use super::super::cleanup_start::resume_record::ResumeStage as S;
use super::*;
use crate::cbor::{self, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

fn m(v: Vec<(&str, Value)>) -> Value {
    Value::Map(v.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn b<const N: usize>(v: [u8; N]) -> Value {
    Value::Bytes(v.to_vec())
}
fn t(v: &str) -> Value {
    Value::Text(v.into())
}
fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    let Value::Map(v) = v else { panic!() };
    &v.iter().find(|(k, _)| k == key).unwrap().1
}
fn set(v: &mut Value, key: &str, value: Value) {
    let Value::Map(v) = v else { panic!() };
    v.iter_mut().find(|(k, _)| k == key).unwrap().1 = value;
}
fn iv(v: KeyFileIdentity) -> Value {
    m(vec![
        ("dev", b(v.dev.to_be_bytes())),
        ("ino", b(v.ino.to_be_bytes())),
        ("length", b(v.length.to_be_bytes())),
        ("nlink", b(v.nlink.to_be_bytes())),
        ("uid", b(v.uid.to_be_bytes())),
        ("mode", b(v.mode.to_be_bytes())),
        ("mtime_seconds", Value::Int(v.mtime_seconds)),
        ("ctime_seconds", Value::Int(v.ctime_seconds)),
        ("mtime_nanoseconds", Value::Int(v.mtime_nanoseconds)),
        ("ctime_nanoseconds", Value::Int(v.ctime_nanoseconds)),
    ])
}
fn dv(v: KeyDirectoryIdentity) -> Value {
    m(vec![
        ("dev", b(v.dev.to_be_bytes())),
        ("ino", b(v.ino.to_be_bytes())),
        ("uid", b(v.uid.to_be_bytes())),
    ])
}
fn identity(path: &Path) -> KeyFileIdentity {
    KeyFileIdentity::from_metadata(&stdfs::metadata(path).unwrap())
}
fn public() -> [u8; 32] {
    super::super::super::tests::unhex(
        super::super::super::tests::a13()["public_key_hex"]
            .as_str()
            .unwrap(),
    )
    .try_into()
    .unwrap()
}
fn events(v: &Value) -> &[Value] {
    let Value::Array(a) = field(v, "events") else {
        panic!()
    };
    a
}

struct Fixture {
    a: Area,
    areas: Vec<Area>,
    source: Option<KeyDirectory>,
    backups: Vec<KeyDirectory>,
    expected: KeyResumeExpected,
    key: Vec<u8>,
    pass: String,
    names: Vec<String>,
    ids: Vec<[u8; 32]>,
    indices: Vec<usize>,
    operation: [u8; 32],
    old: Vec<u8>,
    marker: Vec<u8>,
    guard: Vec<u8>,
}
impl Fixture {
    fn new(separate: bool, count: usize) -> Self {
        let a = Area::new();
        let mut areas = vec![Area::new()];
        if separate {
            areas.push(Area::new());
        }
        let (key, pass) = fixture();
        a.put("publisher", &key);
        areas[0].put("saved", &key);
        let mut source = KeyDirectory::open(&a.0).unwrap();
        let KeyRecoveryHold::Held { area_id } = source.initialize_recovery_hold().unwrap() else {
            panic!()
        };
        let initial = source.initialize_key_state(&area_id).unwrap();
        let mut value =
            cbor::decode(&stdfs::read(a.0.join(initial_state::STATE)).unwrap()).unwrap();
        let mut all = events(&value).to_vec();
        let mut names = Vec::new();
        let mut ids = Vec::new();
        let mut indices = Vec::new();
        let pool: Vec<_> = (0x70..0x79)
            .map(|n| [n; 32])
            .filter(|v| *v != initial.operation_id)
            .collect();
        for n in 0..count {
            let name = format!("past{n}");
            let index = usize::from(separate);
            areas[index].put(&name, &key);
            let target = format!(".lngnb-key-{n:064x}");
            a.put(&target, &key);
            let old_id = identity(&a.0.join(&target));
            stdfs::remove_file(a.0.join(&target)).unwrap();
            let directory =
                KeyDirectoryIdentity::from_metadata(&stdfs::metadata(&areas[index].0).unwrap());
            let uid = rustix::process::geteuid().as_raw();
            let mut start = common(2 * n + 2, pool[2 * n], "residue_cleanup_started", uid);
            let Value::Map(v) = &mut start else { panic!() };
            v.extend([
                (
                    "target".into(),
                    m(vec![
                        ("name", t(&target)),
                        ("identity", iv(old_id)),
                        (
                            "ciphertext_sha256",
                            b(<[u8; 32]>::from(Sha256::digest(&key))),
                        ),
                        ("public_key", b(public())),
                    ]),
                ),
                (
                    "preserved".into(),
                    m(vec![
                        ("directory", dv(directory)),
                        ("name", t(&name)),
                        ("identity", iv(identity(&areas[index].0.join(&name)))),
                    ]),
                ),
            ]);
            let mut complete = common(2 * n + 3, pool[2 * n + 1], "residue_cleanup_completed", uid);
            let Value::Map(v) = &mut complete else {
                panic!()
            };
            v.extend([
                ("started_operation_id".into(), b(pool[2 * n])),
                ("disposition".into(), t("confirmed_absent_on_recovery")),
            ]);
            all.extend([start, complete]);
            names.push(name);
            ids.push(pool[2 * n + 1]);
            indices.push(index);
        }
        set(&mut value, "events", Value::Array(all));
        let old = cbor::encode(&value).unwrap();
        stdfs::write(a.0.join(initial_state::STATE), &old).unwrap();
        let state = source.key_state_history(&area_id).unwrap();
        let expected = KeyResumeExpected {
            state,
            current: identity(&a.0.join("publisher")),
            ciphertext_sha256: Sha256::digest(&key).into(),
            public_key: public(),
            preserved_directory: KeyDirectoryIdentity::from_metadata(
                &stdfs::metadata(&areas[0].0).unwrap(),
            ),
            preserved: identity(&areas[0].0.join("saved")),
            guard: identity(&a.0.join(recovery_hold::GUARD)),
        };
        let backups = areas
            .iter()
            .map(|a| KeyDirectory::open(&a.0).unwrap())
            .collect();
        let marker = stdfs::read(a.0.join(recovery_hold::MARKER)).unwrap();
        let guard = stdfs::read(a.0.join(recovery_hold::GUARD)).unwrap();
        let operation = if initial.operation_id == [0x79; 32] {
            [0x7a; 32]
        } else {
            [0x79; 32]
        };
        Self {
            a,
            areas,
            source: Some(source),
            backups,
            expected,
            key,
            pass,
            names,
            ids,
            indices,
            operation,
            old,
            marker,
            guard,
        }
    }
    fn proofs(&self) -> Vec<KeyResumePreservation<'_>> {
        self.ids
            .iter()
            .enumerate()
            .map(|(i, id)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: self.indices[i],
                name: &self.names[i],
                passphrase: &self.pass,
            })
            .collect()
    }
    fn prepare(&mut self) -> Result<PreparedKeyResume<'_>> {
        self.prepare_hook(&mut |_| Ok(()))
    }
    fn prepare_hook(
        &mut self,
        hook: &mut impl FnMut(S) -> Result<()>,
    ) -> Result<PreparedKeyResume<'_>> {
        let proofs: Vec<_> = self
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: self.indices[i],
                name: self.names[i].as_str(),
                passphrase: self.pass.as_str(),
            })
            .collect();
        self.source.as_mut().unwrap().prepare_key_resume_with(
            "publisher",
            &self.pass,
            &mut self.backups,
            0,
            "saved",
            &proofs,
            &self.expected,
            self.operation,
            42,
            hook,
        )
    }
    fn reopen(&mut self) {
        self.source.take();
        self.backups.clear();
        self.source = Some(KeyDirectory::open(&self.a.0).unwrap());
        self.backups = self
            .areas
            .iter()
            .map(|a| KeyDirectory::open(&a.0).unwrap())
            .collect();
    }
    fn retained(&mut self) {
        assert_eq!(stdfs::read(self.a.0.join("publisher")).unwrap(), self.key);
        assert_eq!(
            stdfs::read(self.a.0.join(recovery_hold::MARKER)).unwrap(),
            self.marker
        );
        assert_eq!(
            stdfs::read(self.a.0.join(recovery_hold::GUARD)).unwrap(),
            self.guard
        );
        assert_eq!(
            stdfs::read(self.areas[0].0.join("saved")).unwrap(),
            self.key
        );
        for (i, n) in self.names.iter().enumerate() {
            assert_eq!(
                stdfs::read(self.areas[self.indices[i]].0.join(n)).unwrap(),
                self.key
            );
        }
        e(
            self.source.as_mut().unwrap().create("later", &self.pass),
            KeyFileError::PendingRecovery,
        );
        e(
            self.source
                .as_mut()
                .unwrap()
                .change_passphrase("publisher", &self.pass, &self.pass),
            KeyFileError::PendingRecovery,
        );
    }
    fn independent(&self, intent: KeyResumeIntent) {
        let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
        let proofs:Vec<_>=self.ids.iter().enumerate().map(|(i,id)|serde_json::json!({"id":hex(id),"directory":self.indices[i],"name":self.names[i]})).collect();
        let input = serde_json::json!({"source":self.a.0,"backups":self.areas.iter().map(|a|&a.0).collect::<Vec<_>>(),"proofs":proofs,
            "old":hex(&self.old),"new":hex(&stdfs::read(self.a.0.join(initial_state::STATE)).unwrap()),"operation":hex(&intent.operation_id),"hash":hex(&intent.after.snapshot_hash)});
        let mut child =
            Command::new(std::env::var_os("LNGNB_REFERENCE_PYTHON").expect("reference required"))
                .args(["tests/key_resume_reference.py", "--recorded"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        assert!(
            child.wait_with_output().unwrap().status.success(),
            "independent resume append check failed (details suppressed)"
        );
    }
}
fn common(n: usize, id: [u8; 32], kind: &str, uid: u32) -> Value {
    m(vec![
        ("sequence", Value::Int(n as i64)),
        ("operation_id", b(id)),
        ("kind", t(kind)),
        ("actor_uid", b(uid.to_be_bytes())),
        ("recorded_unix_seconds", Value::Int(41)),
        ("rules", t("lngnb-key-operations-1")),
    ])
}

#[test]
fn resume_record_shared_separate_and_empty_history_hold_all_handles_and_stop() {
    for (separate, count) in [(false, 2), (true, 2), (false, 0)] {
        let mut f = Fixture::new(separate, count);
        let paths: Vec<_> = std::iter::once(f.a.0.clone())
            .chain(f.areas.iter().map(|a| a.0.clone()))
            .collect();
        let p = f.prepare().unwrap();
        for path in &paths {
            e(KeyDirectory::open(path), KeyFileError::Busy);
        }
        drop(p);
        assert_eq!(
            stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
            f.old
        );
        let before = f.expected.state;
        let p = f.prepare().unwrap();
        let intent = p.intent();
        assert_eq!(intent.before, before);
        assert!(matches!(intent.after.state, KeyHistoryState::Ready { .. }));
        assert_eq!(p.record().unwrap(), intent.after);
        f.independent(intent);
        f.reopen();
        f.retained();
        assert_eq!(
            f.source
                .as_mut()
                .unwrap()
                .key_state_history(&intent.before.initial.area_id)
                .unwrap(),
            intent.after
        );
        assert!(
            f.source
                .as_mut()
                .unwrap()
                .recover_initial_key_state(&intent.before.initial)
                .is_err()
        );
        assert!(f.prepare().is_err());
        assert_eq!(
            f.source
                .as_mut()
                .unwrap()
                .load("publisher", &f.pass)
                .unwrap()
                .public_key(),
            public()
        );
    }
    let mut f = Fixture::new(false, 0);
    let p = f
        .source
        .as_mut()
        .unwrap()
        .prepare_key_resume(
            "publisher",
            &f.pass,
            &mut f.backups,
            0,
            "saved",
            &[],
            &f.expected,
        )
        .unwrap();
    assert_ne!(
        p.intent().operation_id,
        f.expected.state.initial.operation_id
    );
    drop(p);
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        f.old
    );
}

#[test]
fn resume_record_qualification_failures_never_write_history() {
    for point in [
        S::CurrentSynced,
        S::PreservationSynced(0),
        S::PreservationSynced(1),
        S::PreservationSynced(2),
        S::DirectoriesSynced,
        S::ControlsSynced,
        S::Qualified,
    ] {
        let mut f = Fixture::new(true, 2);
        e(
            f.prepare_hook(&mut |s| {
                if s == point {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            }),
            KeyFileError::Io,
        );
        assert_eq!(
            stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
            f.old
        );
        f.retained();
        assert_eq!(stdfs::read_dir(&f.a.0).unwrap().count(), 4);
    }
}

#[test]
fn resume_record_rejects_all_expected_selection_and_authentication_mismatches() {
    let mut f = Fixture::new(true, 2);
    let original = f.expected;
    for n in 0..9 {
        f.expected = original;
        match n {
            0 => f.expected.state.generation += 1,
            1 => f.expected.state.snapshot_hash[0] ^= 1,
            2 => f.expected.state.initial.area_id[0] ^= 1,
            3 => f.expected.current.ino += 1,
            4 => f.expected.preserved.ino += 1,
            5 => f.expected.guard.ino += 1,
            6 => f.expected.preserved_directory.ino += 1,
            7 => f.expected.ciphertext_sha256[0] ^= 1,
            _ => f.expected.public_key[0] ^= 1,
        }
        assert!(f.prepare().is_err());
        assert_eq!(
            stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
            f.old
        );
    }
    f.expected = original;
    for n in 0..7 {
        let mut proofs = f.proofs();
        match n {
            0 => {
                proofs.pop();
            }
            1 => proofs.swap(0, 1),
            2 => proofs[1].completed_operation_id = proofs[0].completed_operation_id,
            3 => proofs[1].passphrase = "wrong public password",
            4 => proofs[1].name = "wrong",
            5 => proofs[1].directory_index = 999,
            _ => proofs[0].name = "../unsafe",
        }
        // Separate immutable input copies from mutable fd borrows.
        let ids: Vec<_> = proofs
            .iter()
            .map(|p| {
                (
                    p.completed_operation_id,
                    p.directory_index,
                    p.name.to_owned(),
                    p.passphrase.to_owned(),
                )
            })
            .collect();
        drop(proofs);
        let inputs: Vec<_> = ids
            .iter()
            .map(|(id, i, n, p)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: *i,
                name: n,
                passphrase: p,
            })
            .collect();
        assert!(
            f.source
                .as_mut()
                .unwrap()
                .prepare_key_resume(
                    "publisher",
                    &f.pass,
                    &mut f.backups,
                    0,
                    "saved",
                    &inputs,
                    &original
                )
                .is_err()
        );
    }
    let inputs: Vec<_> = f
        .ids
        .iter()
        .enumerate()
        .map(|(i, id)| KeyResumePreservation {
            completed_operation_id: *id,
            directory_index: f.indices[i],
            name: &f.names[i],
            passphrase: &f.pass,
        })
        .collect();
    assert!(
        f.source
            .as_mut()
            .unwrap()
            .prepare_key_resume(
                "publisher",
                "wrong public password",
                &mut f.backups,
                0,
                "saved",
                &inputs,
                &original
            )
            .is_err()
    );
    assert!(
        f.source
            .as_mut()
            .unwrap()
            .prepare_key_resume(
                "publisher",
                &f.pass,
                &mut f.backups,
                999,
                "saved",
                &inputs,
                &original
            )
            .is_err()
    );
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        f.old
    );
    f.retained();
    let mut g = Fixture::new(false, 2);
    let reencrypted = unlock(&g.key, &g.pass).unwrap().encrypt(&g.pass).unwrap();
    assert_ne!(reencrypted, g.key);
    assert_eq!(
        unlock(&reencrypted, &g.pass).unwrap().public_key(),
        public()
    );
    stdfs::write(g.areas[0].0.join("saved"), &reencrypted).unwrap();
    g.expected.preserved = identity(&g.areas[0].0.join("saved"));
    e(g.prepare(), KeyFileError::PreservationMismatch);
    assert_eq!(stdfs::read(g.a.0.join("publisher")).unwrap(), g.key);
}

#[test]
fn resume_record_unknown_residues_capacity_races_and_safe_metadata_are_rejected() {
    let mut f = Fixture::new(false, 2);
    f.a.put(".lngnb-key-unknown", b"preserved unknown");
    assert!(f.prepare().is_err());
    assert_eq!(
        stdfs::read(f.a.0.join(".lngnb-key-unknown")).unwrap(),
        b"preserved unknown"
    );
    stdfs::remove_file(f.a.0.join(".lngnb-key-unknown")).unwrap();
    std::os::unix::fs::symlink("absent", f.a.0.join(".lngnb-key-dangling")).unwrap();
    assert!(f.prepare().is_err());
    stdfs::remove_file(f.a.0.join(".lngnb-key-dangling")).unwrap();
    // 件数だけのfixture。10,000回の個別fsyncを製品資格の代わりにしない。
    for n in 0..(SCAN_LIMIT - 4) {
        stdfs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(f.a.0.join(format!("capacity-{n}")))
            .unwrap();
    }
    e(f.prepare(), KeyFileError::ScanLimit);
    stdfs::remove_file(f.a.0.join("capacity-0")).unwrap();
    let root = f.a.0.clone();
    e(
        f.prepare().unwrap().record_with(&mut |s| {
            if s == S::BeforeCreate {
                stdfs::write(root.join("race-entry"), b"").unwrap();
            }
            Ok(())
        }),
        KeyFileError::ScanLimit,
    );
    stdfs::remove_file(f.a.0.join("race-entry")).unwrap();
    let p = f.prepare().unwrap();
    let intent = p.intent();
    p.record().unwrap();
    f.independent(intent);
    f.retained();
    let mut f = Fixture::new(false, 2);
    stdfs::hard_link(f.areas[0].0.join("past0"), f.areas[0].0.join("alias")).unwrap();
    assert!(f.prepare().is_err());
    assert_eq!(stdfs::read(f.areas[0].0.join("alias")).unwrap(), f.key);
    let mut f = Fixture::new(false, 2);
    stdfs::set_permissions(
        f.areas[0].0.join("past1"),
        stdfs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(f.prepare().is_err());
}

#[test]
fn resume_record_every_append_interruption_preserves_guard_and_refuses_automatic_retry() {
    for point in [
        S::Created,
        S::Written,
        S::FileSynced,
        S::Prepared,
        S::BeforeExchange,
        S::Exchanged,
        S::StateSynced,
        S::BeforeCleanup,
        S::OldSnapshotRemoved,
        S::CleanupSynced,
    ] {
        let mut f = Fixture::new(true, 2);
        let p = f.prepare().unwrap();
        let intent = p.intent();
        let error = if matches!(
            point,
            S::StateSynced | S::BeforeCleanup | S::OldSnapshotRemoved | S::CleanupSynced
        ) {
            KeyFileError::RecoveryStateCleanupUncertain
        } else {
            KeyFileError::RecoveryStateUncertain
        };
        e(
            p.record_with(&mut |s| {
                if s == point {
                    Err(KeyFileError::Io)
                } else {
                    Ok(())
                }
            }),
            error,
        );
        f.reopen();
        f.retained();
        assert!(f.prepare().is_err());
        let raw = stdfs::read(f.a.0.join(initial_state::STATE)).unwrap();
        if matches!(
            point,
            S::Exchanged
                | S::StateSynced
                | S::BeforeCleanup
                | S::OldSnapshotRemoved
                | S::CleanupSynced
        ) {
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(&raw)),
                intent.after.snapshot_hash
            );
        } else {
            assert_eq!(raw, f.old);
        }
    }
}

#[test]
fn resume_record_detects_same_bytes_new_inodes_before_exchange_and_cleanup() {
    for point in [S::BeforeExchange, S::BeforeCleanup] {
        for which in 0..6 {
            let mut f = Fixture::new(true, 2);
            let path = match which {
                0 => f.a.0.join("publisher"),
                1 => f.areas[0].0.join("saved"),
                2 => f.areas[1].0.join("past1"),
                3 => f.a.0.join(recovery_hold::MARKER),
                4 => f.a.0.join(recovery_hold::GUARD),
                _ => f.a.0.join(initial_state::STATE),
            };
            let p = f.prepare().unwrap();
            let result = p.record_with(&mut |s| {
                if s == point {
                    let raw = stdfs::read(&path).unwrap();
                    let retained = path.with_extension("retained");
                    stdfs::rename(&path, retained).unwrap();
                    stdfs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(&path)
                        .unwrap()
                        .write_all(&raw)
                        .unwrap();
                }
                Ok(())
            });
            assert!(result.is_err());
            f.retained();
        }
    }
    let mut f = Fixture::new(false, 2);
    let root = f.a.0.clone();
    e(
        f.prepare().unwrap().record_with(&mut |s| {
            if s == S::BeforeCreate {
                stdfs::write(root.join(".lngnb-key-new"), b"keep").unwrap();
            }
            Ok(())
        }),
        KeyFileError::PendingRecovery,
    );
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        f.old
    );
    f.retained();
    let mut f = Fixture::new(true, 2);
    let paths: Vec<_> = std::iter::once(f.a.0.clone())
        .chain(f.areas.iter().map(|a| a.0.clone()))
        .collect();
    let moved: Vec<_> = paths.iter().map(|p| p.with_extension("moved")).collect();
    let p = f.prepare().unwrap();
    let intent = p.intent();
    for (original, new) in paths.iter().zip(&moved) {
        stdfs::rename(original, new).unwrap();
        stdfs::DirBuilder::new()
            .mode(0o700)
            .create(original)
            .unwrap();
        stdfs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(original.join("keep"))
            .unwrap()
            .write_all(b"replacement untouched")
            .unwrap();
    }
    p.record().unwrap();
    assert_eq!(stdfs::read(moved[0].join("publisher")).unwrap(), f.key);
    for original in &paths {
        assert_eq!(
            stdfs::read(original.join("keep")).unwrap(),
            b"replacement untouched"
        );
        assert_eq!(stdfs::read_dir(original).unwrap().count(), 1);
    }
    f.source.take();
    f.backups.clear();
    for (original, new) in paths.iter().zip(&moved) {
        stdfs::remove_dir_all(original).unwrap();
        stdfs::rename(new, original).unwrap();
    }
    f.reopen();
    f.retained();
    f.independent(intent);
}

struct ChildContext {
    source: KeyDirectory,
    backups: Vec<KeyDirectory>,
    expected: KeyResumeExpected,
    manifest: Vec<([u8; 32], usize, String)>,
    operation: [u8; 32],
    pass: String,
}
fn child_context() -> Option<ChildContext> {
    let source = std::env::var_os("LNGNB_PUBLIC_RESUME_SOURCE")?;
    let paths: Vec<PathBuf> =
        serde_json::from_str(&std::env::var("LNGNB_PUBLIC_RESUME_BACKUPS").unwrap()).unwrap();
    let manifest: Vec<(String, usize, String)> =
        serde_json::from_str(&std::env::var("LNGNB_PUBLIC_RESUME_PROOFS").unwrap()).unwrap();
    let proofs = manifest
        .into_iter()
        .map(|(id, i, n)| {
            (
                data_encoding::HEXLOWER
                    .decode(id.as_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                i,
                n,
            )
        })
        .collect();
    let mut dir = KeyDirectory::open(Path::new(&source)).unwrap();
    let backups = paths
        .iter()
        .map(|p| KeyDirectory::open(p).unwrap())
        .collect();
    let marker = stdfs::read(Path::new(&source).join(recovery_hold::MARKER)).unwrap();
    let area = marker[21..53].try_into().unwrap();
    let key = stdfs::read(Path::new(&source).join("publisher")).unwrap();
    let expected = KeyResumeExpected {
        state: dir.key_state_history(&area).unwrap(),
        current: identity(&Path::new(&source).join("publisher")),
        ciphertext_sha256: Sha256::digest(&key).into(),
        public_key: public(),
        preserved_directory: KeyDirectoryIdentity::from_metadata(
            &stdfs::metadata(&paths[0]).unwrap(),
        ),
        preserved: identity(&paths[0].join("saved")),
        guard: identity(&Path::new(&source).join(recovery_hold::GUARD)),
    };
    let operation = data_encoding::HEXLOWER
        .decode(
            std::env::var("LNGNB_PUBLIC_RESUME_OPERATION")
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    Some(ChildContext {
        source: dir,
        backups,
        expected,
        manifest: proofs,
        operation,
        pass: fixture().1,
    })
}
fn child_command(f: &Fixture, name: &str) -> Command {
    let manifest: Vec<_> = f
        .ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            (
                data_encoding::HEXLOWER.encode(id),
                f.indices[i],
                &f.names[i],
            )
        })
        .collect();
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", name, "--nocapture"])
        .env("LNGNB_PUBLIC_RESUME_SOURCE", &f.a.0)
        .env(
            "LNGNB_PUBLIC_RESUME_BACKUPS",
            serde_json::to_string(&f.areas.iter().map(|a| &a.0).collect::<Vec<_>>()).unwrap(),
        )
        .env(
            "LNGNB_PUBLIC_RESUME_PROOFS",
            serde_json::to_string(&manifest).unwrap(),
        )
        .env(
            "LNGNB_PUBLIC_RESUME_OPERATION",
            data_encoding::HEXLOWER.encode(&f.operation),
        );
    c
}

#[test]
fn resume_record_process_kill_preserves_guard_and_blocks_retry() {
    if let Some(ChildContext {
        mut source,
        mut backups,
        expected,
        manifest,
        operation,
        pass,
    }) = child_context()
    {
        let proofs: Vec<_> = manifest
            .iter()
            .map(|(id, i, n)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: *i,
                name: n,
                passphrase: &pass,
            })
            .collect();
        let point = std::env::var("LNGNB_PUBLIC_RESUME_POINT").unwrap();
        let p = source
            .prepare_key_resume_with(
                "publisher",
                &pass,
                &mut backups,
                0,
                "saved",
                &proofs,
                &expected,
                operation,
                42,
                &mut |_| Ok(()),
            )
            .unwrap();
        let _ = p.record_with(&mut |s| {
            if format!("{s:?}") == point {
                println!("READY");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        });
        panic!("kill point not reached");
    }
    for point in ["Created", "Prepared", "Exchanged", "OldSnapshotRemoved"] {
        let mut f = Fixture::new(true, 2);
        f.source.take();
        f.backups.clear();
        let mut c = child_command(
            &f,
            "keyfile::files::tests::resume_record_tests::resume_record_process_kill_preserves_guard_and_blocks_retry",
        );
        let mut child = c
            .env("LNGNB_PUBLIC_RESUME_POINT", point)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line.trim() == "READY" {
                break;
            }
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        f.reopen();
        f.retained();
        assert!(f.prepare().is_err());
    }
}

#[test]
fn resume_record_fd_limit_refuses_without_writing() {
    if let Some(ChildContext {
        mut source,
        mut backups,
        expected,
        manifest,
        operation,
        pass,
    }) = child_context()
    {
        assert!(
            Command::new("prlimit")
                .args(["--pid", &std::process::id().to_string(), "--nofile=32:32"])
                .status()
                .unwrap()
                .success()
        );
        let mut reserve = Vec::new();
        loop {
            match stdfs::File::open("/dev/null") {
                Ok(f) => reserve.push(f),
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(24));
                    break;
                }
            }
        }
        reserve.pop();
        let proofs: Vec<_> = manifest
            .iter()
            .map(|(id, i, n)| KeyResumePreservation {
                completed_operation_id: *id,
                directory_index: *i,
                name: n,
                passphrase: &pass,
            })
            .collect();
        let result = source.prepare_key_resume_with(
            "publisher",
            &pass,
            &mut backups,
            0,
            "saved",
            &proofs,
            &expected,
            operation,
            42,
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
        drop(result);
        drop(reserve);
        return;
    }
    let mut f = Fixture::new(true, 2);
    f.source.take();
    f.backups.clear();
    let output=child_command(&f,"keyfile::files::tests::resume_record_tests::resume_record_fd_limit_refuses_without_writing").output().unwrap();
    assert!(
        output.status.success(),
        "isolated fd shortage probe failed (details suppressed)"
    );
    f.reopen();
    f.retained();
    assert_eq!(
        stdfs::read(f.a.0.join(initial_state::STATE)).unwrap(),
        f.old
    );
}

#[path = "keyfile_resume_recovery_tests.rs"]
mod recovery_tests;
