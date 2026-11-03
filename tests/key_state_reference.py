"""§5.97 initial snapshot: independent CBOR/hash check; public fixtures only."""
import hashlib
import json
import sys

import cbor2


def main():
    cases = json.load(sys.stdin)
    assert 1 <= len(cases) <= 8
    for case in cases:
        source = bytes.fromhex(case["source"])
        snapshot = bytes.fromhex(case["snapshot"])
        marker = bytes.fromhex(case["marker"])
        area = bytes.fromhex(case["area"])
        operation = bytes.fromhex(case["operation"])
        assert len(source) == 73 and source[:21] == b"lngnb:key-recovery:1\0"
        assert len(area) == len(operation) == 32 and source[21:53] == area
        assert 0 < len(snapshot) <= 1048576
        expected = {
            "format": "lngnb-key-state-1",
            "area_id": area,
            "source_marker": source,
            "events": [{"sequence": 1, "operation_id": operation,
                        "kind": "initial_hold_confirmed"}],
        }
        assert cbor2.loads(snapshot) == expected
        assert cbor2.dumps(expected, canonical=True) == snapshot
        expected_marker = (b"lngnb:key-recovery:2\0" + source[21:]
                           + hashlib.sha256(snapshot).digest())
        assert len(marker) == 105 and marker == expected_marker
    print(json.dumps({"checked": len(cases)}))


if __name__ == "__main__":
    main()
