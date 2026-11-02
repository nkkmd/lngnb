"""Linux socket識別方式の試験専用probe。製品の削除資格を返さない。

Linux UAPIの値/構造だけを用い、kernel実装コードは複製しない。
根拠: torvalds/linux net/unix/diag.c, net/core/sock_diag.c,
include/uapi/linux/unix_diag.h, include/uapi/asm-generic/socket.h。
namespaceの変更・全socket列挙・要求先socketへの接続・削除は行わない。
"""
import errno
import json
import os
import platform
import select
import socket
import struct
import subprocess
import sys

HEADER = struct.Struct("=IHHII")
REQUEST = struct.Struct("=BBHIIIII")
MESSAGE = struct.Struct("=BBBBIII")
ATTRIBUTE = struct.Struct("=HH")
SO_COOKIE = 57
SO_NETNS_COOKIE = 71
SOCK_DIAG_BY_FAMILY = 20
NLMSG_ERROR = 2
LIMIT = 4096


def require(condition):
    if not condition:
        raise ValueError("socket_identity_probe_rejected")


def cookie(sock, option):
    raw = sock.getsockopt(socket.SOL_SOCKET, option, 8)
    require(len(raw) == 8)
    value, = struct.unpack("=Q", raw)
    require(0 < value < (1 << 64) - 1)
    return value


def request(inode, identity, sequence):
    # u32へ切り詰めない。全1のcookieは検査省略を意味するので使用禁止。
    require(0 < inode <= 0xFFFFFFFF and 0 < identity < (1 << 64) - 1)
    body = REQUEST.pack(socket.AF_UNIX, 0, 0, 0xFFFFFFFF, inode, 2,
                        identity & 0xFFFFFFFF, identity >> 32)
    return HEADER.pack(HEADER.size + len(body), SOCK_DIAG_BY_FAMILY,
                       1, sequence, 0) + body


def decode(data, flags, sender, port, sent, inode, identity):
    require(flags == 0 and sender == (0, 0) and HEADER.size <= len(data) <= LIMIT)
    length, kind, nlflags, sequence, pid = HEADER.unpack_from(data)
    expected_sequence = HEADER.unpack_from(sent)[3]
    require(length == len(data) and nlflags == 0 and sequence == expected_sequence
            and pid == port)
    body = data[HEADER.size:]
    if kind == NLMSG_ERROR:
        # ACK=0や一般エラーを「不存在」へ変換しない。元要求の全bytesも照合。
        require(len(body) == 4 + len(sent) and body[4:] == sent)
        error, = struct.unpack_from("=i", body)
        require(error in (-errno.ENOENT, -errno.ESTALE))
        return error, None
    require(kind == SOCK_DIAG_BY_FAMILY and len(body) >= MESSAGE.size)
    family, typ, state, pad, got_inode, low, high = MESSAGE.unpack_from(body)
    require(family == socket.AF_UNIX and typ == socket.SOCK_STREAM and pad == 0
            and got_inode == inode and low | (high << 32) == identity)
    attributes = {}
    pos = MESSAGE.size
    while pos < len(body):
        require(len(body) - pos >= ATTRIBUTE.size)
        size, tag = ATTRIBUTE.unpack_from(body, pos)
        end = pos + size
        aligned = pos + ((size + 3) & ~3)
        require(size >= ATTRIBUTE.size and end <= len(body) and aligned <= len(body)
                and tag not in attributes)
        attributes[tag] = body[pos + ATTRIBUTE.size:end]
        pos = aligned
    require(1 in attributes and len(attributes[1]) == 8)
    vfs_inode, vfs_device = struct.unpack("=II", attributes[1])
    return state, (vfs_inode, vfs_device)


def query(sock, inode, identity, sequence, expected_namespace):
    # kernel照会socket自身の所属を照合。違うnamespaceでのENOENTを流用しない。
    require(cookie(sock, SO_NETNS_COOKIE) == expected_namespace)
    sent = request(inode, identity, sequence)
    require(sock.send(sent) == len(sent))
    data, ancillary, flags, sender = sock.recvmsg(LIMIT)
    require(not ancillary)
    return decode(data, flags, sender, sock.getsockname()[0], sent, inode, identity)


def parser_checks():
    sent = request(7, 9, 11)
    payload = MESSAGE.pack(socket.AF_UNIX, socket.SOCK_STREAM, 10, 0, 7, 9, 0)
    payload += ATTRIBUTE.pack(12, 1) + struct.pack("=II", 13, 17)
    good = HEADER.pack(HEADER.size + len(payload), 20, 0, 11, 19) + payload
    require(decode(good, 0, (0, 0), 19, sent, 7, 9) == (10, (13, 17)))
    for error in (-errno.ENOENT, -errno.ESTALE):
        body = struct.pack("=i", error) + sent
        msg = HEADER.pack(16 + len(body), 2, 0, 11, 19) + body
        require(decode(msg, 0, (0, 0), 19, sent, 7, 9) == (error, None))
    invalid = [(good[:n], 0, (0, 0), 19, sent, 7, 9) for n in range(len(good))]
    invalid += [(good + b"\0", 0, (0, 0), 19, sent, 7, 9),
                (good, socket.MSG_TRUNC, (0, 0), 19, sent, 7, 9),
                (good, socket.MSG_CTRUNC, (0, 0), 19, sent, 7, 9),
                (good, 0, (1, 0), 19, sent, 7, 9),
                (good, 0, (0, 1), 19, sent, 7, 9),
                (good, 0, (0, 0), 20, sent, 7, 9),
                (good, 0, (0, 0), 19, request(7, 9, 12), 7, 9),
                (good, 0, (0, 0), 19, sent, 8, 9),
                (good, 0, (0, 0), 19, sent, 7, 10)]
    for offset, value in [(4, 3), (6, 2), (16, 2), (17, 2), (19, 1),
                          (32, 0), (34, 2)]:
        mutated = bytearray(good)
        mutated[offset] = value
        invalid.append((bytes(mutated), 0, (0, 0), 19, sent, 7, 9))
    for error in (0, -errno.EPERM, -errno.EIO, -errno.EINVAL):
        body = struct.pack("=i", error) + sent
        msg = HEADER.pack(16 + len(body), 2, 0, 11, 19) + body
        invalid.append((msg, 0, (0, 0), 19, sent, 7, 9))
    for malformed_payload in (payload + payload[MESSAGE.size:],
                              payload[:MESSAGE.size], payload + b"x"):
        msg = HEADER.pack(16 + len(malformed_payload), 20, 0, 11, 19) + malformed_payload
        invalid.append((msg, 0, (0, 0), 19, sent, 7, 9))
    bad_error = struct.pack("=i", -errno.ENOENT) + request(8, 9, 11)
    invalid.append((HEADER.pack(16 + len(bad_error), 2, 0, 11, 19) + bad_error,
                    0, (0, 0), 19, sent, 7, 9))
    for args in invalid:
        try:
            decode(*args)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed_diagnostic_accepted")
    for inode, identity in [(0, 9), (1 << 32, 9), (7, 0), (7, (1 << 64) - 1)]:
        try:
            request(inode, identity, 11)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid_identity_accepted")


def hold(fd):
    # exec後にも残した実fd。親がcloseしても子が保持する間は照会できるか検査。
    with socket.socket(fileno=fd) as retained:
        require(cookie(retained, SO_COOKIE) > 0)
        print("ready", flush=True)
        require(sys.stdin.buffer.read(1) == b"x")


def probe(root):
    require(platform.system() == "Linux" and platform.machine() == "x86_64")
    area = os.path.join(root, "identity-probe")
    os.mkdir(area, 0o700)  # 既存先へ書かず、使い捨てfixtureだけを新規作成。
    directory = os.open(area, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    try:
        path = f"/proc/self/fd/{directory}/probe.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as original:
            original.bind(path)
            os.chmod(path, 0o600)
            original.listen(1)
            original.setblocking(False)
            inode = os.fstat(original.fileno()).st_ino  # sockfs、pathname inodeではない。
            identity = cookie(original, SO_COOKIE)
            namespace = cookie(original, SO_NETNS_COOKIE)
            before = os.stat(path, follow_symlinks=False)
            require((os.fstat(original.fileno()).st_dev, inode) !=
                    (before.st_dev, before.st_ino))
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as diag:
                diag.settimeout(10)  # 速度依存の発火試験ではなく、失敗時の待機上限。
                diag.bind((0, 0))
                diag.connect((0, 0))
                state, vfs = query(diag, inode, identity, 1, namespace)
                # VFS属性はu32。低32bit一致を完全identityの証明にしない。
                require(state == 10 and vfs == (before.st_ino & 0xFFFFFFFF,
                        (os.major(before.st_dev) << 20) | os.minor(before.st_dev)))
                wrong = identity ^ 1
                if wrong in (0, (1 << 64) - 1):
                    wrong = identity ^ 2
                require(query(diag, inode, wrong, 2, namespace) == (-errno.ESTALE, None))
                retained = original.dup()
                try:
                    require(cookie(retained, SO_COOKIE) == identity)
                    require(cookie(retained, SO_NETNS_COOKIE) == namespace)
                    original.close()
                    require(query(diag, inode, identity, 3, namespace)[0] == 10)
                    child = subprocess.Popen(
                        [sys.executable, __file__, "--hold", str(retained.fileno())],
                        pass_fds=(retained.fileno(),), stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    require(select.select([child.stdout], [], [], 10)[0])
                    require(child.stdout.readline() == b"ready\n")
                finally:
                    retained.close()
                require(query(diag, inode, identity, 4, namespace)[0] == 10)
                out, err = child.communicate(b"x", timeout=10)
                require(child.returncode == 0 and out == b"" and err == b"")
                require(query(diag, inode, identity, 5, namespace) == (-errno.ENOENT, None))
                # namespace不一致は照会前に拒否し、不在へ読み替えない。
                try:
                    query(diag, inode, identity, 6, namespace ^ 1)
                except ValueError:
                    pass
                else:
                    raise AssertionError("namespace_mismatch_accepted")
            after = os.stat(path, follow_symlinks=False)
            require((before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
                     before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                     after.st_mtime_ns, after.st_ctime_ns))
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
        os.close(directory)
    print("socket_identity_probe_passed")


def check_origin(expected, closed):
    # Rustが明示的に新規bindしたfd/根拠を、別のsyscall経路で照合する。
    require(platform.system() == "Linux" and platform.machine() == "x86_64")
    with open("/proc/sys/kernel/random/boot_id", "rb") as boot:
        require(boot.read(38) == expected["boot_id"].encode("ascii") + b"\n")
    ns = os.stat("/proc/thread-self/ns/net")
    require([ns.st_dev, ns.st_ino] == expected["namespace"])
    directory = os.stat(expected["directory_path"])
    require([directory.st_dev, directory.st_ino, directory.st_uid] == expected["directory"])
    require(expected["name"] == "admin.sock")
    m = os.stat(os.path.join(expected["directory_path"], expected["name"]),
                follow_symlinks=False)
    require([m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_mode & 0o7777,
             m.st_nlink, m.st_size, m.st_mtime_ns // 1000000000,
             m.st_mtime_ns % 1000000000, m.st_ctime_ns // 1000000000,
             m.st_ctime_ns % 1000000000] == expected["path"])
    inode, identity = expected["socket_inode"], expected["socket_cookie"]
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as diag:
        diag.settimeout(10)
        diag.bind((0, 0))
        diag.connect((0, 0))
        namespace = cookie(diag, SO_NETNS_COOKIE)
        if closed:
            require(query(diag, inode, identity, 1, namespace) == (-errno.ENOENT, None))
        else:
            with socket.socket(fileno=os.dup(0)) as original:
                require(os.fstat(original.fileno()).st_dev == expected["socket_device"])
                require(os.fstat(original.fileno()).st_ino == inode)
                require(cookie(original, SO_COOKIE) == identity)
                require(cookie(original, SO_NETNS_COOKIE) == namespace)
                require(query(diag, inode, identity, 1, namespace)[0] == 10)
                require(select.select([original], [], [], 0)[0] == [])
    print("socket_origin_reference_passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--hold":
        hold(int(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] in ("--check-origin", "--check-closed-origin"):
        parser_checks()
        check_origin(json.loads(sys.argv[2]), sys.argv[1] == "--check-closed-origin")
    else:
        parser_checks()
        if sys.argv[1:] == ["--parser-only"]:
            print("socket_identity_parser_passed")
        else:
            require(len(sys.argv) == 2)
            probe(sys.argv[1])
