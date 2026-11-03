"""§5.100: independent fixed CBOR/hash/prefix checks. Public test values only."""
import hashlib
import json
import sys

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


if __name__ == "__main__":
    main()
