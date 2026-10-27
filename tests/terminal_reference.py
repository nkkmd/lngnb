"""R34/A11: Linux PTYの独立検査。すべて公開試験入力。実運用秘密は渡さない。"""
import fcntl
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time

BINARY = sys.argv[1]
FILTER = sys.argv[2] if len(sys.argv) > 2 else "controlling_terminal_input_is_private_and_restored"
CASES = {
    "unicode": [" public e\u0301 é あ \n".encode()],
    "editing": [b"remove\x15e\xcc\x81\x7fx\n"],
    "boundary": [("あ" * 341 + "x\n").encode()],
    "confirm": [b"public confirmation test\n", b"public confirmation test\n"],
    "mismatch": [b"public confirmation test\n", b"public wrong confirmation\n"],
    "cancel": [b"public discarded input\x03"],
    "eof-key": [b"public discarded input\x04"],
    "empty": [b"\n"],
    "invalid-utf8": [b"\xff\n"],
    "overflow": [b"x" * 1025 + b"\npublic leftover input\n"],
    "hangup": [],
    "background": [],
    "signal-hup": [],
    "signal-int": [],
    "signal-quit": [],
    "signal-term": [],
    "signal-tstp": [],
    "signal-confirm": [b"public confirmation test\n"],
    "signal-idle": [],
    "signal-idle-after": [b"public completed input\n"],
    "signal-empty": [],
    "interruptible-unicode": [" public e\u0301 é あ \n".encode()],
    "interruptible-confirm": [b"public confirmation test\n", b"public confirmation test\n"],
}

def run_case(case, payloads):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    # ECHONLが元からONでも入力中は落とし、終了後は元のONへ戻す。
    before[3] |= termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG
    termios.tcsetattr(slave, termios.TCSANOW, before)
    before = termios.tcgetattr(slave)

    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        if case == "background":
            import signal
            helper = os.fork()
            if helper == 0:
                os.setpgid(0, 0)
                os.kill(os.getpid(), signal.SIGSTOP)
                os._exit(0)
            try:
                os.waitpid(helper, os.WUNTRACED)
                os.tcsetpgrp(slave, helper)
            finally:
                os.kill(helper, signal.SIGKILL)
                os.waitpid(helper, 0)
        # hangupをread/restoreのI/Oエラーとして観測する（通常終了の保証にしない）。
        if case == "hangup":
            import signal
            signal.signal(signal.SIGHUP, signal.SIG_IGN)

    env = dict(os.environ, LNGNB_PUBLIC_TERMINAL_CASE=case)
    child = subprocess.Popen([BINARY, "--exact", FILTER, "--nocapture"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             pass_fds=(slave,), preexec_fn=controlling_terminal, env=env)
    captured = bytearray()
    deadline = time.monotonic() + 15

    def wait_prompt(number):
        while captured.count(b": ") < number:
            if time.monotonic() > deadline:
                raise AssertionError("PTY prompt deadline: " + case)
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                captured.extend(os.read(master, 4096))
            if child.poll() is not None:
                raise AssertionError("PTY child ended before prompt: " + case)
        attrs = termios.tcgetattr(slave)
        if case == "signal-idle" or (case == "signal-idle-after" and number == 2):
            assert attrs == before, case
        else:
            assert not attrs[3] & (termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG), case

    try:
        if case != "background":
            wait_prompt(1)
        if case == "hangup":
            os.close(master)
            master = None
        else:
            for n, payload in enumerate(payloads, 1):
                if n > 1:
                    wait_prompt(n)
                os.write(master, payload)
            if case.startswith("signal-"):
                if case in ("signal-confirm", "signal-idle-after"):
                    wait_prompt(2)
                if case not in ("signal-idle", "signal-idle-after", "signal-empty"):
                    os.write(master, b"public discarded input")
                sig = {"signal-hup": signal.SIGHUP, "signal-int": signal.SIGINT,
                       "signal-quit": signal.SIGQUIT, "signal-tstp": signal.SIGTSTP}.get(case, signal.SIGTERM)
                os.kill(child.pid, sig)
        out, err = child.communicate(timeout=15)
        if case in ("signal-idle", "signal-idle-after"):
            assert child.returncode == -signal.SIGTERM, "idle signal default lost: " + case
        else:
            assert child.returncode == 0 and b"TERMINAL_CHECK_OK" in out, "PTY result: " + case
        if case != "hangup":
            assert termios.tcgetattr(slave) == before, "TTY settings not restored: " + case
            while select.select([master], [], [], 0)[0]:
                captured.extend(os.read(master, 4096))
            # read_line終了後の余剰入力が端末/シェル側へ残らないこと。
            assert not select.select([slave], [], [], 0)[0], "pending terminal input: " + case
        visible = bytes(captured) + out + err
        for marker in [b"public discarded input", b"public confirmation test", b"public wrong confirmation",
                       b"public leftover input", b"public completed input", " public e\u0301 é あ ".encode(), b"x" * 64]:
            assert marker not in visible, "secret echoed or logged: " + case
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if master is not None:
            os.close(master)
        os.close(slave)

if len(sys.argv) > 2:
    run_case("flush-failure", [b"public discarded input\npublic leftover input\n"])
    print("PTY_CASES_OK=1")
    sys.exit(0)
for name, lines in CASES.items():
    run_case(name, lines)
# stdinに値があっても、制御端末のない新規sessionでは代替入力しない。
for mode in ("no-terminal", "signal-no-terminal"):
    no_tty = subprocess.run([BINARY, "--exact", FILTER, "--nocapture"],
                            input=b"public stdin must not be used\n", capture_output=True, timeout=15,
                            start_new_session=True,
                            env=dict(os.environ, LNGNB_PUBLIC_TERMINAL_CASE=mode))
    assert no_tty.returncode == 0 and b"TERMINAL_CHECK_OK" in no_tty.stdout
    assert b"public stdin must not be used" not in no_tty.stdout + no_tty.stderr
print("PTY_CASES_OK=25")
