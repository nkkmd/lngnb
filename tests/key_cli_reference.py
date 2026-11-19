"""R34/A11: 実CLIをPTYで駆動する。公開試験passphraseのみ、実運用へ流用禁止。"""
import fcntl
import io
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64
import hashlib

BINARY = sys.argv[1]
OLD = b"public CLI old example only"
NEW = "public CLI new e\u0301 é あ example only".encode()
ROTATED = b"public CLI rotated example only"
ROTATED_AGAIN = b"public CLI rotated again example only"

def decode_key(path, password):
    raw = path.read_bytes()
    stream = io.BytesIO(raw)
    obj = cbor2.load(stream)
    assert stream.read() == b"" and cbor2.dumps(obj, canonical=True) == raw
    header = {k: v for k, v in obj.items() if k != "ciphertext"}
    assert obj["format"] == "lngnb-keyfile-1"
    kdf = obj["kdf"]
    assert (kdf["name"], kdf["version"], kdf["memory_kib"], kdf["iterations"], kdf["parallelism"]) == ("argon2id", 19, 65536, 3, 1)
    derived = Argon2id(salt=kdf["salt"], length=32, iterations=3, lanes=1, memory_cost=65536).derive(password)
    seed = ChaCha20Poly1305(derived).decrypt(obj["cipher"]["nonce"], obj["ciphertext"], b"lngnb:keyfile:1\x00" + cbor2.dumps(header, canonical=True))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert public == obj["public_key"]
    ident = b"ky1_" + base64.b32encode(hashlib.sha256(b"lngnb:key:ed25519:1\x00" + public).digest()).lower().rstrip(b"=")
    return seed, obj, ident

def invoke(directory, action, payloads, expected=0, cancel=None, closed_output=False, residue=None, backup=None, restoration=None, extra=(), history_stage=None):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    before[3] |= termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG
    termios.tcsetattr(slave, termios.TCSANOW, before)
    before = termios.tcgetattr(slave)
    def setup():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    sink = open("/dev/full", "wb") if closed_output else subprocess.PIPE
    selection = ["--residue", residue] if residue is not None else ["--name", "publisher"]
    if backup is not None:
        selection += ["--backup-dir", str(backup[0]), "--backup-name", backup[1]]
    if restoration is not None:
        selection += ["--restore-name", restoration[0], "--expect-key-id", restoration[1]]
    child = subprocess.Popen([BINARY, "key", action] + ([history_stage] if history_stage else [])
                             + ["--key-dir", str(directory)] + selection + list(extra),
                             stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.PIPE,
                             pass_fds=(slave,), preexec_fn=setup)
    captured = bytearray()
    def prompt(n):
        deadline = time.monotonic() + 20
        while captured.count(b": ") < n:
            assert time.monotonic() < deadline and child.poll() is None, "CLI prompt missing"
            if select.select([master], [], [], 0.1)[0]:
                captured.extend(os.read(master, 4096))
        assert not termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG)
    try:
        for n, payload in enumerate(payloads, 1):
            prompt(n)
            os.write(master, payload + b"\n")
        if cancel is not None:
            prompt(len(payloads) + 1)
            os.write(master, b"public cancelled CLI input")
            os.kill(child.pid, cancel)
        out, err = child.communicate(timeout=120 if history_stage else 30)
        out = out or b""
        assert child.returncode == expected, "CLI exit mismatch: " + str(child.returncode) + ": " + err.decode(errors="replace")
        assert termios.tcgetattr(slave) == before, "CLI did not restore terminal"
        while select.select([master], [], [], 0)[0]:
            captured.extend(os.read(master, 4096))
        assert not select.select([slave], [], [], 0)[0], "CLI left pending input"
        for secret in (OLD, NEW, ROTATED, ROTATED_AGAIN, b"public cancelled CLI input", b"public wrong example only"):
            assert secret not in bytes(captured) + out + err, "CLI exposed public test secret"
        if expected != 0:
            assert not out, "failure emitted success output"
        return out, err
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        os.close(master)
        os.close(slave)
        if closed_output:
            sink.close()

def history_cases(root):
    for scenario in ("normal", "cancel", "output"):
        directory = root / scenario
        backup = root / (scenario + "-backup")
        receipt = (root / (scenario + "-receipt")).read_text().strip()
        path = directory / "publisher"
        guard = directory / ".lngnb-key-hold"
        original = path.read_bytes()
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        args = ["--resume", receipt]
        def history(stage, passwords, **kwargs):
            return invoke(directory, "history-passphrase", passwords, backup=(backup, "saved"),
                          extra=args, history_stage=stage, **kwargs)
        if scenario == "cancel":
            history("update", [OLD], expected=130, cancel=signal.SIGTERM)
            assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
        if scenario == "output":
            history("update", [OLD, NEW, NEW], expected=1, closed_output=True)
            assert path.read_bytes() == original
            assert set(p.name for p in directory.iterdir()) - before.keys() == {guard.name}
            assert {name: (directory / name).read_bytes() for name in before} == before
            history("update", [OLD, NEW, NEW], expected=1)
            assert guard.exists() and path.read_bytes() == original
        else:
            out, _ = history("update", [OLD, NEW, NEW])
            started, prepared, completed, result = out.decode().splitlines()
            assert result == "key_passphrase_change_guard_removed"
            assert not guard.exists()
            assert decode_key(path, NEW)[0] == decode_key(backup / "saved", OLD)[0]
            changed = path.read_bytes()
            args.extend(["--start", started, "--prepared", prepared, "--completed", completed])
            history("release", [OLD, NEW], expected=1, closed_output=True)
            out, _ = history("release", [OLD, NEW])
            assert out == b"key_passphrase_change_guard_absence_confirmed\n"
            assert not guard.exists() and path.read_bytes() == changed
            rotation_args = ["--previous-completed", completed]
            def rotation(stage, passwords, extras=(), **kwargs):
                return invoke(directory, "history-passphrase-rotation", passwords,
                              backup=(backup, "rotation-copy"), extra=rotation_args + list(extras),
                              history_stage=stage, **kwargs)
            rotation("preserve", [NEW])
            assert (backup / "rotation-copy").read_bytes() == changed
            rotation("preserve", [NEW], expected=1)
            rotation("verify-preserved", [NEW])
            rotation("prepare", [NEW, ROTATED, ROTATED], expected=1)
            assert not guard.exists() and path.read_bytes() == changed
            resume_id = receipt.split(" operation_id=")[1]
            rotation_args.extend(["--preservation", resume_id, str(backup), "saved"])
            out, _ = rotation("prepare", [NEW, ROTATED, ROTATED, OLD])
            started, prepared, status = out.decode().splitlines()
            assert status == "key_passphrase_rotation_prepared_guard_retained"
            assert guard.exists() and path.read_bytes() == changed
            rotation("recover-start", [], extras=["--start", started, "--prepared", prepared], expected=2)
            rotation("recover-prepared", [NEW, ROTATED, OLD],
                     extras=["--start", started, "--prepared", prepared])
            rotation_args.extend(["--start", started, "--prepared", prepared])
            rotation("exchange", [NEW, ROTATED, OLD])
            rotation("exchange", [NEW, ROTATED, OLD])
            out, _ = rotation("complete", [NEW, ROTATED, OLD])
            rotated, status = out.decode().splitlines()
            assert status == "key_passphrase_rotation_completion_confirmed_guard_retained"
            assert guard.exists() and decode_key(path, ROTATED)[0] == decode_key(backup / "saved", OLD)[0]
            rotation_args.extend(["--completed", rotated])
            rotation("recover-completed", [NEW, ROTATED, OLD])
            out, _ = rotation("release", [NEW, ROTATED, OLD])
            assert out == b"key_passphrase_rotation_guard_removed\n"
            out, _ = rotation("release", [NEW, ROTATED, OLD])
            assert out == b"key_passphrase_rotation_guard_absence_confirmed\n"
            assert not guard.exists() and (backup / "rotation-copy").read_bytes() == changed
            if scenario == "normal":
                repeat_rotation(directory, backup, completed, rotated, resume_id)
        assert (backup / "saved").read_bytes() == original

def repeat_rotation(directory, backup, first_completed, rotated, resume_id):
    path = directory / "publisher"
    guard = directory / ".lngnb-key-hold"
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    copies = {p.name: p.read_bytes() for p in backup.iterdir()}
    previous_id = rotated.rsplit(" operation_id=", 1)[1]
    first_proof = ["--preservation", resume_id, str(backup), "saved"]
    previous_proof = ["--preservation", previous_id, str(backup), "rotation-copy"]
    new_copy = "repeat-rotation-copy"

    def run(stage, passwords, *, previous=rotated, copy=new_copy, extras=(), **kwargs):
        return invoke(directory, "history-passphrase-rotation", passwords,
                      backup=(backup, copy), history_stage=stage,
                      extra=["--previous-completed", previous, *extras], **kwargs)

    run("preserve", [ROTATED], previous=first_completed, expected=1)
    run("verify-preserved", [ROTATED], copy="rotation-copy", expected=1)
    assert {p.name: p.read_bytes() for p in backup.iterdir()} == copies
    run("preserve", [ROTATED])
    copies[new_copy] = before["publisher"]
    passwords = [ROTATED, ROTATED_AGAIN, OLD, NEW]
    run("prepare", [ROTATED, ROTATED_AGAIN, ROTATED_AGAIN, OLD],
        extras=first_proof, expected=1)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    assert {p.name: p.read_bytes() for p in backup.iterdir()} == copies

    proofs = first_proof + previous_proof
    out, _ = run("prepare", [ROTATED, ROTATED_AGAIN, ROTATED_AGAIN, OLD, NEW], extras=proofs)
    started, prepared, status = out.decode().splitlines()
    assert status == "key_passphrase_rotation_prepared_guard_retained"
    assert guard.exists() and path.read_bytes() == before["publisher"]
    receipts = proofs + ["--start", started, "--prepared", prepared]
    run("recover-prepared", passwords, extras=receipts)
    run("exchange", passwords, extras=receipts)
    out, _ = run("complete", passwords, extras=receipts)
    completed, status = out.decode().splitlines()
    assert status == "key_passphrase_rotation_completion_confirmed_guard_retained"
    assert guard.exists()
    receipts += ["--completed", completed]
    run("release", passwords, extras=receipts, expected=1, closed_output=True)
    out, _ = run("release", passwords, extras=receipts)
    assert out == b"key_passphrase_rotation_guard_absence_confirmed\n"
    assert not guard.exists()
    assert {p.name: p.read_bytes() for p in backup.iterdir()} == copies
    updated_seed, _, updated_id = decode_key(path, ROTATED_AGAIN)
    original_seed, _, original_id = decode_key(backup / "saved", OLD)
    assert (updated_seed, updated_id) == (original_seed, original_id)


def cleanup_case(root):
    directory = root / "cleanup"
    backup = root / "cleanup-backup"
    area, snapshot = (root / "cleanup-receipt").read_text().split()
    residue = ".lngnb-key-" + "ab" * 32
    original = (directory / residue).read_bytes()
    key_id = decode_key(directory / residue, OLD)[2].decode()
    args = ["--expect-area-id", area, "--snapshot-hash", snapshot, "--expect-key-id", key_id]
    before = {p.name: p.read_bytes() for p in directory.iterdir()}

    def start(**kwargs):
        return invoke(directory, "cleanup-start", [OLD], residue=residue,
                      backup=(backup, "saved"), extra=args, **kwargs)

    saved = backup / "saved"
    saved.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    start(expected=1)
    saved.write_bytes(original)
    start(expected=1, closed_output=True)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    out, _ = start()
    intent, status = out.decode().splitlines()
    assert intent.startswith("key_cleanup_start_intent area_id=" + area)
    assert "before_hash=" + snapshot in intent
    assert status == "key_cleanup_start_saved"
    start(expected=1)
    after = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert after.keys() == before.keys()
    assert {name for name in before if before[name] != after[name]} == {".lngnb-key-state"}
    assert saved.read_bytes() == original

    def recover(receipt, expected=0):
        return invoke(directory, "recover-cleanup-start", [OLD], expected=expected,
                      residue=residue, backup=(backup, "saved"),
                      extra=["--expect-key-id", key_id, "--start", receipt])

    recover(intent.replace(snapshot, "00" * 32), expected=1)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    state = directory / ".lngnb-key-state"
    pending = directory / (".lngnb-key-state-update-" + intent.split(" operation_id=")[1])
    # 完全な旧固定と新候補、および交換直後の配置を再現する。
    for fixed, temporary in ((before[state.name], after[state.name]),
                             (after[state.name], before[state.name])):
        state.write_bytes(fixed)
        pending.touch(mode=0o600, exist_ok=False)
        pending.write_bytes(temporary)
        assert recover(intent)[0] == b"key_cleanup_start_confirmed\n"
        assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    assert recover(intent)[0] == b"key_cleanup_start_confirmed\n"
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    assert saved.read_bytes() == original


    def complete(receipt, **kwargs):
        return invoke(directory, "cleanup-complete-absent", [OLD], residue=residue,
                      backup=(backup, "saved"),
                      extra=["--expect-key-id", key_id, "--start", receipt], **kwargs)

    complete(intent, expected=1)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    (directory / residue).unlink()
    absent = {name: data for name, data in after.items() if name != residue}
    complete(intent.replace(snapshot, "00" * 32), expected=1)
    complete(intent, expected=1, closed_output=True)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == absent
    out, _ = complete(intent)
    completion, status = out.decode().splitlines()
    assert completion.startswith("key_cleanup_completion_intent area_id=" + area)
    assert completion.endswith("disposition=confirmed_absent_on_recovery")
    assert status == "key_cleanup_absence_confirmed"
    complete(intent, expected=1)
    final = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert final.keys() == absent.keys()
    assert {name for name in absent if absent[name] != final[name]} == {state.name}
    assert saved.read_bytes() == original


    def recover_completion(receipt, expected=0):
        return invoke(directory, "recover-cleanup-completion", [OLD], expected=expected,
                      residue=residue, backup=(backup, "saved"),
                      extra=["--expect-key-id", key_id, "--completion", receipt])

    recover_completion(completion.replace("before_hash=" + completion.split("before_hash=")[1][:64],
                                          "before_hash=" + "00" * 32), expected=1)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == final
    pending = directory / (".lngnb-key-state-update-" + completion.split(" operation_id=")[1].split()[0])
    for fixed, temporary in ((absent[state.name], final[state.name]),
                             (final[state.name], absent[state.name])):
        state.write_bytes(fixed)
        pending.touch(mode=0o600, exist_ok=False)
        pending.write_bytes(temporary)
        assert recover_completion(completion)[0] == b"key_cleanup_completion_confirmed\n"
        assert {p.name: p.read_bytes() for p in directory.iterdir()} == final
    assert recover_completion(completion)[0] == b"key_cleanup_completion_confirmed\n"
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == final
    assert saved.read_bytes() == original


    target = directory / residue
    target.touch(mode=0o600, exist_ok=False)
    target.write_bytes(original)
    next_snapshot = hashlib.sha256(final[state.name]).hexdigest()
    args[3] = next_snapshot
    next_intent = start()[0].decode().splitlines()[0]
    active = {p.name: p.read_bytes() for p in directory.iterdir()}

    def remove(**kwargs):
        return invoke(directory, "cleanup-remove", [OLD], residue=residue,
                      backup=(backup, "saved"),
                      extra=["--expect-key-id", key_id, "--start", next_intent], **kwargs)

    remove(expected=1, closed_output=True)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == active
    requested, removed, status = remove()[0].decode().splitlines()
    assert requested == "key_cleanup_removal_requested"
    assert removed.endswith("disposition=removed_present")
    assert status == "key_cleanup_removal_recorded"
    assert recover_completion(removed)[0] == b"key_cleanup_completion_confirmed\n"
    after_removal = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert after_removal.keys() == active.keys() - {residue}
    assert {name for name in after_removal if after_removal[name] != active[name]} == {state.name}
    assert saved.read_bytes() == original


def resume_record_case(root):
    directory = root / "resume-record"
    backup = root / "resume-record-backup"
    area, snapshot = (root / "resume-record-receipt").read_text().split()
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    key_id = decode_key(directory / "publisher", OLD)[2].decode()

    def record(snapshot_hash=snapshot, **kwargs):
        return invoke(directory, "history-passphrase", [OLD], history_stage="resume-record",
                      backup=(backup, "saved"), extra=[
                          "--expect-area-id", area, "--snapshot-hash", snapshot_hash,
                          "--expect-key-id", key_id,
                      ], **kwargs)

    record("00" * 32, expected=1)
    record(expected=1, closed_output=True)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    receipt, status = record()[0].decode().splitlines()
    assert area in receipt and snapshot in receipt
    assert status == "key_resume_recorded_guard_retained"
    record(expected=1)
    after = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert before.keys() == after.keys()
    assert {name for name in before if before[name] != after[name]} == {".lngnb-key-state"}
    assert (backup / "saved").read_bytes() == before["publisher"]

    def recover(password=OLD, **kwargs):
        return invoke(directory, "history-passphrase", [password], history_stage="recover-resume-record",
                      backup=(backup, "saved"), extra=["--resume", receipt], **kwargs)

    recover(b"public wrong example only", expected=1)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    def release(passwords=(OLD,), *, receipt_line=receipt, backup_dir=backup, **kwargs):
        return invoke(directory, "history-passphrase", passwords, history_stage="release-resume",
                      backup=(backup_dir, "saved"), extra=["--resume", receipt_line], **kwargs)

    state = directory / ".lngnb-key-state"
    operation_id = receipt.split(" operation_id=")[1]
    pending = directory / (".lngnb-key-state-update-" + operation_id)
    for fixed, candidate in ((before[state.name], after[state.name]),
                             (after[state.name], before[state.name])):
        state.write_bytes(fixed)
        pending.touch(mode=0o600, exist_ok=False)
        pending.write_bytes(candidate)
        unfinished = {p.name: p.read_bytes() for p in directory.iterdir()}
        release(expected=1)
        assert {p.name: p.read_bytes() for p in directory.iterdir()} == unfinished
        assert recover()[0] == b"key_resume_record_confirmed_guard_retained\n"
        assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    assert recover()[0] == b"key_resume_record_confirmed_guard_retained\n"
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    assert (backup / "saved").read_bytes() == before["publisher"]

    wrong_receipt = receipt.rsplit(" operation_id=", 1)[0] + " operation_id=" + "00" * 32
    release((), receipt_line=wrong_receipt, expected=1)
    release((b"public wrong example only",), expected=1)
    other = root / "resume-record-unrecorded-backup"
    other.mkdir(mode=0o700)
    other_saved = other / "saved"
    other_saved.touch(mode=0o600)
    other_saved.write_bytes(before["publisher"])
    release(backup_dir=other, expected=1)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == after
    assert (backup / "saved").read_bytes() == other_saved.read_bytes() == before["publisher"]

    assert release()[0] == b"key_resume_guard_removed\n"
    released = {name: data for name, data in after.items() if name != ".lngnb-key-hold"}
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == released
    assert release()[0] == b"key_resume_guard_absence_confirmed\n"
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == released
    assert (backup / "saved").read_bytes() == before["publisher"]

    out, _ = invoke(directory, "history-passphrase", [OLD, NEW, NEW],
                    history_stage="update", backup=(backup, "saved"),
                    extra=["--resume", receipt])
    started, prepared, completed, result = out.decode().splitlines()
    assert started.startswith("key_passphrase_change_started ")
    assert prepared.startswith("key_passphrase_change_prepared ")
    assert completed.startswith("key_passphrase_change_completed ")
    assert result == "key_passphrase_change_guard_removed"
    assert not (directory / ".lngnb-key-hold").exists()
    assert (backup / "saved").read_bytes() == before["publisher"]
    updated_seed, _, updated_id = decode_key(directory / "publisher", NEW)
    original_seed, _, original_id = decode_key(backup / "saved", OLD)
    assert (updated_seed, updated_id) == (original_seed, original_id)


if len(sys.argv) == 3:
    history_cases(Path(sys.argv[2]))
    cleanup_case(Path(sys.argv[2]))
    resume_record_case(Path(sys.argv[2]))
    print("HISTORY_KEY_CLI_CASES_OK")
    sys.exit(0)

with tempfile.TemporaryDirectory(prefix="lngnb-cli-public-test-") as root:
    directory = Path(root) / "keys"
    directory.mkdir(mode=0o700)
    path = directory / "publisher"
    out, _ = invoke(directory, "create", [OLD, OLD])
    seed, first, ident = decode_key(path, OLD)
    assert ident in out and path.stat().st_mode & 0o7777 == 0o600
    assert not (Path(root) / "lngnb-data").exists()
    original = path.read_bytes()
    # 再作成を拒否し、正常鍵を上書きしない。
    invoke(directory, "create", [OLD, OLD], 1)
    assert path.read_bytes() == original
    out, _ = invoke(directory, "check", [OLD])
    assert ident in out and path.read_bytes() == original
    invoke(directory, "check", [b"public wrong example only"], 1)
    invoke(directory, "change-passphrase", [b"public wrong example only"], 1)
    invoke(directory, "change-passphrase", [OLD, NEW, OLD], 1)
    assert path.read_bytes() == original
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGTSTP):
        invoke(directory, "change-passphrase", [OLD], 130, cancel=sig)
        assert path.read_bytes() == original
    invoke(directory, "change-passphrase", [OLD, NEW], 130, cancel=signal.SIGTERM)
    assert path.read_bytes() == original
    out, _ = invoke(directory, "change-passphrase", [OLD, NEW, NEW])
    seed2, second, ident2 = decode_key(path, NEW)
    assert seed == seed2 and ident == ident2 and ident in out
    assert first["kdf"]["salt"] != second["kdf"]["salt"] and first["cipher"]["nonce"] != second["cipher"]["nonce"]
    invoke(directory, "check", [OLD], 1)
    invoke(directory, "check", [NEW])
    updated = path.read_bytes()
    # 残存物は採用/削除せず、現在名のcheckだけを許す。
    residue = directory / ".lngnb-key-public-test-residue"
    residue.write_bytes(b"public residue fixture")
    os.chmod(residue, 0o600)
    invoke(directory, "change-passphrase", [NEW, OLD, OLD], 1)
    invoke(directory, "check", [NEW])
    assert residue.read_bytes() == b"public residue fixture" and path.read_bytes() == updated
    # 一覧は制御端末なしで実行可能。形式/認証未検査と復旧未完了を明示する。
    recovery = directory / (".lngnb-key-" + "ab" * 32)
    recovery.write_bytes(original)
    os.chmod(recovery, 0o600)
    unsafe_residue = directory / (".lngnb-key-" + "cd" * 32)
    unsafe_residue.symlink_to("publisher")
    incomplete = directory / (".lngnb-key-" + "ef" * 32)
    incomplete.write_bytes(b"public incomplete keyfile")
    os.chmod(incomplete, 0o600)
    def recovery_status(sink=None):
        return subprocess.run([BINARY, "key", "recovery-status", "--key-dir", str(directory)],
                              stdin=subprocess.DEVNULL, stdout=sink or subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True, timeout=10)
    status = recovery_status()
    assert status.returncode == 0 and not status.stderr
    assert b"pending_recovery: true" in status.stdout and b"unrecognized_entries: 1" in status.stdout
    assert recovery.name.encode() in status.stdout and residue.name.encode() not in status.stdout
    assert b"bounded_read_complete_unauthenticated" in status.stdout and b"key_id:" not in status.stdout
    assert b"status: unsafe_key_path" in status.stdout
    assert "復旧完了ではありません".encode() in status.stdout
    out, _ = invoke(directory, "check-residue", [OLD], residue=recovery.name)
    assert ident in out and "元の対象名・新旧・更新確定・削除可否は未確認".encode() in out
    invoke(directory, "check-residue", [NEW], 1, residue=recovery.name)
    invoke(directory, "check-residue", [OLD], 1, residue=unsafe_residue.name)
    invoke(directory, "check-residue", [OLD], 1, residue=incomplete.name)
    invoke(directory, "check-residue", [], 130, cancel=signal.SIGTERM, residue=recovery.name)
    invoke(directory, "check-residue", [OLD], 1, closed_output=True, residue=recovery.name)
    with open("/dev/full", "wb") as sink:
        failed_status = recovery_status(sink)
        assert failed_status.returncode == 1
    # 診断や認証成功後も現在鍵/残存暗号文・変更停止を保持する。
    assert recovery.read_bytes() == original and path.read_bytes() == updated
    assert unsafe_residue.is_symlink() and incomplete.read_bytes() == b"public incomplete keyfile"
    invoke(directory, "change-passphrase", [NEW, OLD, OLD], 1)
    # 認証した暗号文だけを明示先へ保全。元ファイル/変更停止はそのまま。
    backup_dir = Path(root) / "backup"
    backup_dir.mkdir(mode=0o700)
    invoke(directory, "preserve-residue", [NEW], 1, residue=recovery.name, backup=(backup_dir, "saved"))
    invoke(directory, "preserve-residue", [], 130, cancel=signal.SIGTERM, residue=recovery.name, backup=(backup_dir, "saved"))
    assert list(backup_dir.iterdir()) == []
    invoke(directory, "preserve-residue", [OLD], 1, residue=unsafe_residue.name, backup=(backup_dir, "saved"))
    invoke(directory, "preserve-residue", [OLD], 1, residue=incomplete.name, backup=(backup_dir, "saved"))
    assert list(backup_dir.iterdir()) == []
    out, _ = invoke(directory, "preserve-residue", [OLD], residue=recovery.name, backup=(backup_dir, "saved"))
    saved = backup_dir / "saved"
    assert ident in out and "同じbytesを保存".encode() in out
    assert saved.read_bytes() == original and saved.stat().st_mode & 0o7777 == 0o600
    assert decode_key(saved, OLD)[0] == seed
    invoke(directory, "preserve-residue", [OLD], 1, residue=recovery.name, backup=(backup_dir, "saved"))
    assert saved.read_bytes() == original
    _, err = invoke(directory, "preserve-residue", [OLD], 1, closed_output=True, residue=recovery.name, backup=(backup_dir, "saved-output"))
    assert "保全先への暗号文保存は完了".encode() in err
    assert decode_key(backup_dir / "saved-output", OLD)[0] == seed
    same_dir = subprocess.run([BINARY, "key", "preserve-residue", "--key-dir", str(directory), "--residue", recovery.name,
                               "--backup-dir", str(directory), "--backup-name", "saved"],
                              stdin=subprocess.DEVNULL, capture_output=True, start_new_session=True, timeout=10)
    assert same_dir.returncode == 1 and not same_dir.stdout and b"key_directory_busy" in same_dir.stderr
    (backup_dir / ".lngnb-key-public-pending").write_bytes(b"public pending backup")
    invoke(directory, "preserve-residue", [OLD], 1, residue=recovery.name, backup=(backup_dir, "blocked"))
    assert not (backup_dir / "blocked").exists()
    assert recovery.read_bytes() == original and path.read_bytes() == updated
    assert b"pending_recovery: true" in recovery_status().stdout
    # 元領域は保持したまま、別領域で保全済み鍵の通常操作へ進む。
    working = Path(root) / "working"
    working.mkdir(mode=0o700)
    source_entries = set(directory.iterdir())
    invoke(directory, "preserve-residue", [OLD], residue=recovery.name, backup=(working, "publisher"))
    working_key = working / "publisher"
    assert working_key.read_bytes() == original
    out, _ = invoke(working, "check", [OLD])
    assert ident in out  # 実手順では控え等の期待IDと利用者が照合する。
    invoke(working, "change-passphrase", [NEW], 1)
    invoke(working, "change-passphrase", [OLD], 130, cancel=signal.SIGTERM)
    assert working_key.read_bytes() == original and set(working.iterdir()) == {working_key}
    out, _ = invoke(working, "change-passphrase", [OLD, NEW, NEW])
    working_seed, working_header, working_ident = decode_key(working_key, NEW)
    assert working_seed == seed and working_ident == ident and ident in out
    assert working_header["kdf"]["salt"] != first["kdf"]["salt"]
    assert working_header["cipher"]["nonce"] != first["cipher"]["nonce"]
    assert working_key.stat().st_mode & 0o7777 == 0o600
    invoke(working, "check", [OLD], 1)
    out, _ = invoke(working, "check", [NEW])
    assert ident in out
    assert set(directory.iterdir()) == source_entries
    assert recovery.read_bytes() == original and path.read_bytes() == updated
    assert residue.read_bytes() == b"public residue fixture" and incomplete.read_bytes() == b"public incomplete keyfile"
    assert unsafe_residue.is_symlink() and b"pending_recovery: true" in recovery_status().stdout
    invoke(directory, "change-passphrase", [NEW, OLD, OLD], 1)
    # 新しいパスフレーズは元の残存暗号文を失効させない。
    out, _ = invoke(directory, "check-residue", [OLD], residue=recovery.name)
    assert ident in out
    pending_work = working / ".lngnb-key-public-pending"
    pending_work.write_bytes(b"public working recovery fixture")
    os.chmod(pending_work, 0o600)
    working_updated = working_key.read_bytes()
    invoke(working, "change-passphrase", [NEW, OLD, OLD], 1)
    assert working_key.read_bytes() == working_updated
    # 残存元/復元先/期待鍵IDを明示し、全残存物を維持したまま空き名へ復元する。
    entries_before = set(directory.iterdir())
    wrong_ident = b"ky1_" + base64.b32encode(hashlib.sha256(b"public wrong key identity").digest()).lower().rstrip(b"=")
    invoke(directory, "restore-residue", [OLD], 1, residue=recovery.name, restoration=("restored", wrong_ident.decode()))
    invoke(directory, "restore-residue", [NEW], 1, residue=recovery.name, restoration=("restored", ident.decode()))
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGTSTP):
        invoke(directory, "restore-residue", [], 130, cancel=sig, residue=recovery.name, restoration=("restored", ident.decode()))
    for source in (unsafe_residue, incomplete):
        invoke(directory, "restore-residue", [OLD], 1, residue=source.name, restoration=("restored", ident.decode()))
    assert set(directory.iterdir()) == entries_before
    out, _ = invoke(directory, "restore-residue", [OLD], residue=recovery.name, restoration=("restored", ident.decode()))
    restored = directory / "restored"
    assert ident in out and "変更停止も解除していません".encode() in out
    assert restored.read_bytes() == original and restored.stat().st_mode & 0o7777 == 0o600
    restored_seed, _, restored_ident = decode_key(restored, OLD)
    assert restored_seed == seed and restored_ident == ident
    # 別のパスフレーズを使う現在鍵や、既存通常名/危険linkを置換しない。
    for target in ("restored", "publisher"):
        invoke(directory, "restore-residue", [OLD], 1, residue=recovery.name, restoration=(target, ident.decode()))
    dangling = directory / "dangling"
    dangling.symlink_to("absent")
    invoke(directory, "restore-residue", [OLD], 1, residue=recovery.name, restoration=("dangling", ident.decode()))
    assert dangling.is_symlink()
    _, err = invoke(directory, "restore-residue", [OLD], 1, closed_output=True, residue=recovery.name, restoration=("restored-output", ident.decode()))
    assert "復元先への暗号文保存は完了".encode() in err
    assert decode_key(directory / "restored-output", OLD)[0] == seed
    no_tty_restore = subprocess.run([BINARY, "key", "restore-residue", "--key-dir", str(directory), "--residue", recovery.name,
                                    "--restore-name", "no-terminal", "--expect-key-id", ident.decode()],
                                   input=OLD + b"\n", capture_output=True, start_new_session=True, timeout=10)
    assert no_tty_restore.returncode == 1 and not no_tty_restore.stdout and OLD not in no_tty_restore.stderr
    assert not (directory / "no-terminal").exists()
    assert recovery.read_bytes() == original and path.read_bytes() == updated
    assert residue.read_bytes() == b"public residue fixture" and incomplete.read_bytes() == b"public incomplete keyfile"
    assert unsafe_residue.is_symlink() and b"pending_recovery: true" in recovery_status().stdout
    invoke(directory, "change-passphrase", [NEW, OLD, OLD], 1)
    recovery.unlink()  # 製品操作でなく、試験所有のfixtureだけを明示破棄。
    unsafe_residue.unlink()
    incomplete.unlink()
    residue.unlink()  # 試験所有のfixtureだけを明示破棄。
    _, err = invoke(directory, "change-passphrase", [NEW, OLD, OLD], 1, closed_output=True)
    assert "鍵ファイル操作は完了".encode() in err
    assert decode_key(path, OLD)[0] == seed
    # 新規作成中の取消し・出力失敗も、生成前/確定後を区別する。
    other = Path(root) / "other"
    other.mkdir(mode=0o700)
    invoke(other, "create", [], 130, cancel=signal.SIGTERM)
    invoke(other, "create", [OLD], 130, cancel=signal.SIGINT)
    assert list(other.iterdir()) == []
    invoke(other, "create", [OLD, OLD], 1, closed_output=True)
    assert decode_key(other / "publisher", OLD)[2] != ident
    # stdinに試験値があっても制御端末なしでは拒否。
    no_tty = subprocess.run([BINARY, "key", "check", "--key-dir", str(directory), "--name", "publisher"],
                            input=OLD + b"\n", capture_output=True, start_new_session=True, timeout=10)
    assert no_tty.returncode == 1 and not no_tty.stdout and OLD not in no_tty.stderr
    assert path.read_bytes() != updated
print("KEY_CLI_CASES_OK")
