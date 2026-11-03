"""§5.100: independent fixed CBOR/hash/prefix checks. Public test values only."""
import hashlib
import json
import sys
import os
from pathlib import Path

import cbor2


def identity():
    return {
        "dev": (2**64-1).to_bytes(8, "big"),
        "ino": (2**63).to_bytes(8, "big"),
        "length": (4096).to_bytes(8, "big"),
        "nlink": (1).to_bytes(8, "big"),
        "uid": (3).to_bytes(4, "big"),
        "mode": (0o100600).to_bytes(4, "big"),
        "mtime_seconds": -(2**63), "ctime_seconds": 2**63-1,
        "mtime_nanoseconds": 0, "ctime_nanoseconds": 999999999,
    }


def common(n, kind):
    return {"sequence": n, "operation_id": n.to_bytes(32, "big"),
            "kind": kind, "actor_uid": (2**32-1).to_bytes(4, "big"),
            "recorded_unix_seconds": 2**63-1 if n % 2 == 0 else 0,
            "rules": "lngnb-key-operations-1"}


def snapshot(count):
    source = (b"lngnb:key-recovery:1\0" + b"\x42"*32
              + (1).to_bytes(8, "big") + (2).to_bytes(8, "big")
              + (3).to_bytes(4, "big"))
    events = [{"sequence": 1, "operation_id": (1).to_bytes(32, "big"),
               "kind": "initial_hold_confirmed"}]
    for n in range(2, count+1):
        if n % 2 == 0:
            event = common(n, "residue_cleanup_started")
            event["target"] = {
                "name": ".lngnb-key-" + "a"*64, "identity": identity(),
                "ciphertext_sha256": b"\x11"*32, "public_key": b"\x22"*32,
            }
            event["preserved"] = {
                "name": "b"*128, "identity": identity(),
                "directory": {"dev": (2**64-1).to_bytes(8, "big"),
                              "ino": (2**63).to_bytes(8, "big"),
                              "uid": (3).to_bytes(4, "big")},
            }
            event["preserved"]["identity"]["ino"] = (2**63+1).to_bytes(8, "big")
        else:
            event = common(n, "residue_cleanup_completed")
            event["started_operation_id"] = (n-1).to_bytes(32, "big")
            event["disposition"] = "confirmed_absent_on_recovery"
        events.append(event)
    return {"format": "lngnb-key-state-1", "area_id": b"\x42"*32,
            "source_marker": source, "events": events}


def encode(value):
    return cbor2.dumps(value, canonical=True)


def main():
    cases = json.load(sys.stdin)
    assert [c["count"] for c in cases] == [1, 2, 3, 24, 256, 1023]
    initial = encode(snapshot(1))
    root = hashlib.sha256(initial).hexdigest()
    maximum = common(1024, "residue_cleanup_completed")
    maximum.update(recorded_unix_seconds=2**63-1,
                   started_operation_id=bytes(32),
                   disposition="confirmed_absent_on_recovery")
    max_length = len(encode(maximum))
    assert max_length == 264
    assert root == "161597de563dacd25992b52daf83e55b9c9d5f4a1ce79a4442ca8a01ed7c9e03"
    for case in cases:
        expected = snapshot(case["count"])
        raw = bytes.fromhex(case["snapshot"])
        assert encode(expected) == raw
        assert cbor2.loads(raw) == expected
        assert hashlib.sha256(raw).hexdigest() == case["hash"]
        assert case["root"] == root
        assert case["completion_bytes"] == max_length
        # 各開始prefixで最大完了一件を実際に符号化し、配列header拡大も検査。
        for n in range(2, case["count"]+1, 2):
            prefix = dict(expected, events=expected["events"][:n] + [maximum])
            assert n+1 <= 1024 and len(encode(prefix)) <= 1048576
    print(json.dumps({"checked": len(cases)}))


def started():
    case = json.load(sys.stdin)
    source, backup = Path(case["source"]), Path(case["backup"])
    old_raw, new_raw = bytes.fromhex(case["old"]), bytes.fromhex(case["new"])
    old, new = cbor2.loads(old_raw), cbor2.loads(new_raw)
    assert encode(old) == old_raw and encode(new) == new_raw
    assert set(old) == set(new) == {"format", "area_id", "source_marker", "events"}
    for key in ("format", "area_id", "source_marker"):
        assert old[key] == new[key]
    assert new["events"][:-1] == old["events"]
    assert hashlib.sha256(new_raw).hexdigest() == case["hash"]
    def directory(m):
        return {"dev": m.st_dev.to_bytes(8, "big"), "ino": m.st_ino.to_bytes(8, "big"),
                "uid": m.st_uid.to_bytes(4, "big")}
    def file(m):
        return dict(directory(m), length=m.st_size.to_bytes(8, "big"),
                    nlink=m.st_nlink.to_bytes(8, "big"), mode=m.st_mode.to_bytes(4, "big"),
                    mtime_seconds=m.st_mtime_ns//10**9, mtime_nanoseconds=m.st_mtime_ns % 10**9,
                    ctime_seconds=m.st_ctime_ns//10**9, ctime_nanoseconds=m.st_ctime_ns % 10**9)
    original = (source / case["target"]).read_bytes()
    assert original == (backup / case["preserved"]).read_bytes()
    expected = {
        "sequence": len(old["events"])+1, "operation_id": bytes.fromhex(case["operation"]),
        "kind": "residue_cleanup_started", "actor_uid": os.geteuid().to_bytes(4, "big"),
        "recorded_unix_seconds": 42, "rules": "lngnb-key-operations-1",
        "target": {"name": case["target"], "identity": file((source / case["target"]).stat()),
                   "ciphertext_sha256": hashlib.sha256(original).digest(),
                   "public_key": bytes.fromhex(case["public_key"])},
        "preserved": {"directory": directory(backup.stat()), "name": case["preserved"],
                      "identity": file((backup / case["preserved"]).stat())},
    }
    assert new["events"][-1] == expected
    initial = dict(new, events=new["events"][:1])
    marker = (source / ".lngnb-key-control").read_bytes()
    assert marker == b"lngnb:key-recovery:2\0" + new["source_marker"][21:] + hashlib.sha256(encode(initial)).digest()
    assert (source / ".lngnb-key-hold").read_bytes() == b"lngnb:key-hold:1\0" + new["area_id"]
    print(json.dumps({"checked": 1}))


def completed():
    import stat
    case = json.load(sys.stdin)
    source, backup = Path(case["source"]), Path(case["backup"])
    old_raw, new_raw = bytes.fromhex(case["old"]), bytes.fromhex(case["new"])
    old, new = cbor2.loads(old_raw), cbor2.loads(new_raw)
    assert encode(old) == old_raw and encode(new) == new_raw
    assert set(old) == set(new) == {"format", "area_id", "source_marker", "events"}
    for key in ("format", "area_id", "source_marker"):
        assert old[key] == new[key]
    start = old["events"][-1]
    assert start["kind"] == "residue_cleanup_started"
    assert start["operation_id"] == bytes.fromhex(case["started"])
    assert start["target"]["name"] == case["target"]
    try:
        os.lstat(source / case["target"])
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("target must be absent, including dangling links")
    m = os.stat(backup / case["preserved"], follow_symlinks=False)
    assert stat.S_ISREG(m.st_mode) and m.st_mode == 0o100600 and m.st_nlink == 1
    expected_identity = {
        "dev": m.st_dev.to_bytes(8, "big"), "ino": m.st_ino.to_bytes(8, "big"),
        "uid": m.st_uid.to_bytes(4, "big"), "mode": m.st_mode.to_bytes(4, "big"),
        "length": m.st_size.to_bytes(8, "big"), "nlink": m.st_nlink.to_bytes(8, "big"),
        "mtime_seconds": m.st_mtime_ns//10**9, "mtime_nanoseconds": m.st_mtime_ns % 10**9,
        "ctime_seconds": m.st_ctime_ns//10**9, "ctime_nanoseconds": m.st_ctime_ns % 10**9,
    }
    directory = backup.stat()
    assert start["preserved"] == {
        "name": case["preserved"], "identity": expected_identity,
        "directory": {"dev": directory.st_dev.to_bytes(8, "big"),
                      "ino": directory.st_ino.to_bytes(8, "big"), "uid": directory.st_uid.to_bytes(4, "big")}}
    ciphertext = (backup / case["preserved"]).read_bytes()
    assert hashlib.sha256(ciphertext).digest() == start["target"]["ciphertext_sha256"]
    assert len(ciphertext) == int.from_bytes(start["target"]["identity"]["length"], "big")
    assert cbor2.loads(ciphertext)["public_key"] == start["target"]["public_key"]
    event = {"sequence": len(old["events"])+1, "operation_id": bytes.fromhex(case["operation"]),
             "kind": "residue_cleanup_completed", "actor_uid": os.geteuid().to_bytes(4, "big"),
             "recorded_unix_seconds": 43, "rules": "lngnb-key-operations-1",
             "started_operation_id": bytes.fromhex(case["started"]), "disposition": case["disposition"]}
    assert event["operation_id"] not in [e["operation_id"] for e in old["events"]]
    expected = dict(old, events=old["events"]+[event])
    assert encode(expected) == new_raw and new == expected
    assert hashlib.sha256(new_raw).hexdigest() == case["hash"]
    initial = dict(new, events=new["events"][:1])
    marker = (source / ".lngnb-key-control").read_bytes()
    assert marker == b"lngnb:key-recovery:2\0" + new["source_marker"][21:] + hashlib.sha256(encode(initial)).digest()
    assert (source / ".lngnb-key-hold").read_bytes() == b"lngnb:key-hold:1\0" + new["area_id"]
    # 公開固定例。別の小さなCBOR実装で算出したhashをcbor2と製品側で照合。
    fixed = dict(event, sequence=3, actor_uid=b"\0"*4, operation_id=b"\x77"*32,
                 started_operation_id=b"\x73"*32)
    hashes = {"removed_present": (241, "2716e430130e27ce54acda271e51c53143ce7287b253ad14ef5326e6bbaac703"),
              "confirmed_absent_on_recovery": (255, "a1231286fd5a965175db59eef08021f22664680a6da1a27edacd557a80f0a1dc")}
    for disposition, (length, digest) in hashes.items():
        raw = encode(dict(fixed, disposition=disposition))
        assert len(raw) == length and hashlib.sha256(raw).hexdigest() == digest
    print(json.dumps({"checked": 1}))


if __name__ == "__main__":
    if sys.argv[1:] == ["--started"]:
        started()
    elif sys.argv[1:] == ["--completed"]:
        completed()
    else:
        main()
