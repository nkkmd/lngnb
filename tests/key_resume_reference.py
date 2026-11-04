"""§5.108: independently construct full canonical resume snapshots; public values only."""
import hashlib
import json
import sys
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


if __name__ == "__main__":
    main()
