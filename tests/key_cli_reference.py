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

def invoke(directory, action, payloads, expected=0, cancel=None, closed_output=False, residue=None, backup=None):
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
    child = subprocess.Popen([BINARY, "key", action, "--key-dir", str(directory)] + selection,
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
        out, err = child.communicate(timeout=30)
        out = out or b""
        assert child.returncode == expected, "CLI exit mismatch: " + str(child.returncode)
        assert termios.tcgetattr(slave) == before, "CLI did not restore terminal"
        while select.select([master], [], [], 0)[0]:
            captured.extend(os.read(master, 4096))
        assert not select.select([slave], [], [], 0)[0], "CLI left pending input"
        for secret in (OLD, NEW, b"public cancelled CLI input", b"public wrong example only"):
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
