"""§5.108: independently construct full canonical resume snapshots; public values only."""
import hashlib
import json
import sys
import os
import stat
from pathlib import Path
import cbor2
from key_history_reference import snapshot, identity, common, encode


def resumed_snapshot(count):
    value = snapshot(count - 1)
    def file(dev, ino, length):
        return dict(identity(), dev=dev.to_bytes(8, "big"), ino=ino.to_bytes(8, "big"),
                    length=length.to_bytes(8, "big"))
    event = dict(common(count, "key_changes_resumed"), actor_uid=(3).to_bytes(4, "big"),
                 reason="reviewed_current_key_and_preservations",
                 current={"name": "publisher", "identity": file(1, 2**64-1, 4096),
                          "ciphertext_sha256": b"\x33"*32, "public_key": b"\x44"*32},
                 preserved={"name": "saved", "identity": file(2**64-1, 2**63, 4096),
                            "directory": {"dev": (2**64-1).to_bytes(8, "big"),
                                          "ino": (2**63).to_bytes(8, "big"), "uid": (3).to_bytes(4, "big")}},
                 guard_identity=file(1, 2**64-2, 49),
                 cleanup_operations=[n.to_bytes(32, "big") for n in range(3, count, 2)])
    value["events"].append(event)
    return value


def main():
    cases = json.load(sys.stdin)
    assert [v["count"] for v in cases] == [2, 4, 24, 256, 1024]
    root = hashlib.sha256(encode(snapshot(1))).hexdigest()
    fixed = {
        2: (1193, "84fe2145b9ad4e05544d158029fecb3c4db1ac80e742e3dcaf6537c7c0669101",
            "ba3fafdf78300e14e3f38b23798b8a75f99b572aa72bb7edbb8c27397cfaf8ed"),
        4: (2370, "59d88fbe114ca4af87099134541b4811690baa53062fb4a1d2b0eb050ecbb799",
            "e91197917345ad6a7a9ed5520d18edcf7e7badee971885b669ba8ca0df7f68d5"),
    }
    for case in cases:
        expected = resumed_snapshot(case["count"])
        raw = bytes.fromhex(case["snapshot"])
        assert encode(expected) == raw
        assert hashlib.sha256(raw).hexdigest() == case["hash"]
        assert case["root"] == root
        assert expected["events"][:-1] == snapshot(case["count"]-1)["events"]
        assert len(raw) <= 1048576
        if case["count"] in fixed:
            length, digest, event_digest = fixed[case["count"]]
            assert len(raw) == length and hashlib.sha256(raw).hexdigest() == digest
            assert hashlib.sha256(encode(expected["events"][-1])).hexdigest() == event_digest
    print(json.dumps({"checked": len(cases)}))


def recorded(released=False):
    """Current filesystem bytes/identities and full prefix; product performs AEAD authentication."""
    case = json.load(sys.stdin)
    source = Path(case["source"])
    backups = [Path(p) for p in case["backups"]]
    old_raw, new_raw = bytes.fromhex(case["old"]), bytes.fromhex(case["new"])
    old, new = cbor2.loads(old_raw), cbor2.loads(new_raw)
    assert encode(old) == old_raw and encode(new) == new_raw
    assert new["events"][:-1] == old["events"]
    for key in ("format", "area_id", "source_marker"):
        assert new[key] == old[key]
    def directory(path):
        m = path.stat()
        return {"dev": m.st_dev.to_bytes(8, "big"), "ino": m.st_ino.to_bytes(8, "big"), "uid": m.st_uid.to_bytes(4, "big")}
    def file(path):
        m = path.stat(follow_symlinks=False)
        assert stat.S_ISREG(m.st_mode) and m.st_mode == 0o100600 and m.st_nlink == 1
        return {"dev": m.st_dev.to_bytes(8, "big"), "ino": m.st_ino.to_bytes(8, "big"), "uid": m.st_uid.to_bytes(4, "big"),
                "mode": m.st_mode.to_bytes(4, "big"), "length": m.st_size.to_bytes(8, "big"), "nlink": m.st_nlink.to_bytes(8, "big"),
                "mtime_seconds": m.st_mtime_ns//10**9, "mtime_nanoseconds": m.st_mtime_ns % 10**9,
                "ctime_seconds": m.st_ctime_ns//10**9, "ctime_nanoseconds": m.st_ctime_ns % 10**9}
    key = (source / "publisher").read_bytes()
    assert key == (backups[0] / "saved").read_bytes()
    completed = [e for e in old["events"] if e["kind"] == "residue_cleanup_completed"]
    assert len(completed) == len(case["proofs"])
    for event, proof in zip(completed, case["proofs"]):
        assert event["operation_id"] == bytes.fromhex(proof["id"])
        start = next(e for e in old["events"] if e["operation_id"] == event["started_operation_id"])
        path = backups[proof["directory"]] / proof["name"]
        assert start["preserved"] == {"name": proof["name"], "directory": directory(backups[proof["directory"]]), "identity": file(path)}
        ciphertext = path.read_bytes()
        assert hashlib.sha256(ciphertext).digest() == start["target"]["ciphertext_sha256"]
        assert cbor2.loads(ciphertext)["public_key"] == start["target"]["public_key"]
        try:
            os.lstat(source / start["target"]["name"])
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("old residue must be absent")
    guard = source / ".lngnb-key-hold"
    if released:
        try:
            os.lstat(guard)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("recorded guard name must be absent")
        guard_identity = cbor2.loads(bytes.fromhex(case["guard"]))
    else:
        guard_identity = file(guard)
        assert guard.read_bytes() == b"lngnb:key-hold:1\0" + new["area_id"]
    event = dict(common(len(old["events"])+1, "key_changes_resumed"),
                 operation_id=bytes.fromhex(case["operation"]), actor_uid=os.geteuid().to_bytes(4, "big"), recorded_unix_seconds=42,
                 reason="reviewed_current_key_and_preservations",
                 current={"name": "publisher", "identity": file(source / "publisher"), "ciphertext_sha256": hashlib.sha256(key).digest(), "public_key": cbor2.loads(key)["public_key"]},
                 preserved={"name": "saved", "directory": directory(backups[0]), "identity": file(backups[0] / "saved")},
                 guard_identity=guard_identity, cleanup_operations=[e["operation_id"] for e in completed])
    assert encode(dict(old, events=old["events"]+[event])) == new_raw
    assert hashlib.sha256(new_raw).hexdigest() == case["hash"]
    root = hashlib.sha256(encode(dict(new, events=new["events"][:1]))).digest()
    assert (source / ".lngnb-key-control").read_bytes() == b"lngnb:key-recovery:2\0" + new["source_marker"][21:] + root
    print(json.dumps({"checked": 1}))


if __name__ == "__main__":
    if sys.argv[1:] == ["--recorded"]:
        recorded()
    elif sys.argv[1:] == ["--released"]:
        recorded(released=True)
    else:
        main()
