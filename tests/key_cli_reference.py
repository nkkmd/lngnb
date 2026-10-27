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

def invoke(directory, action, payloads, expected=0, cancel=None, closed_output=False):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    before[3] |= termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG
    termios.tcsetattr(slave, termios.TCSANOW, before)
    before = termios.tcgetattr(slave)
    def setup():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    sink = open("/dev/full", "wb") if closed_output else subprocess.PIPE
    child = subprocess.Popen([BINARY, "key", action, "--key-dir", str(directory), "--name", "publisher"],
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
