"""A2/A13/R03〜06: 製品と異なる実装でCBOR・ハッシュ・pure Ed25519を照合。
公開試験seed専用。実運用の鍵入力手段ではない。完全なリレー実装ではない。
"""
import base64
import hashlib
import importlib.metadata
import json
import sys

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

assert importlib.metadata.version("cbor2") == "5.6.5"
assert importlib.metadata.version("cryptography") == "46.0.3"
DS = b"lngnb:signature:library-core-1\0"
DR = b"lngnb:record:library-core-1\0"
DK = b"lngnb:key:ed25519:1\0"
ids = []
for case in json.load(sys.stdin):
    body_bytes = bytes.fromhex(case["body"])
    body = cbor2.loads(body_bytes)
    assert cbor2.dumps(body, canonical=True) == body_bytes
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(case["seed"]))
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signature = key.sign(DS + body_bytes)
    envelope = {"body": body, "signature": {
        "key_id": hashlib.sha256(DK + public).digest(), "algorithm": "ed25519",
        "public_key_bytes": public, "signature_bytes": signature}}
    encoded = cbor2.dumps(envelope, canonical=True)
    assert encoded == bytes.fromhex(case["envelope"])
    key.public_key().verify(signature, DS + body_bytes)
    try:
        key.public_key().verify(signature, DS + body_bytes + b"\0")
    except InvalidSignature:
        pass
    else:
        raise AssertionError("modified message accepted")
    if "initial_creation" in case:
        creation = case["initial_creation"]
        genesis_bytes = bytes.fromhex(creation["genesis"])
        genesis = cbor2.loads(genesis_bytes)
        assert body["knowledge_id"] == genesis["body"]["knowledge_id"]
        assert genesis["body"]["publisher_public_key"] == public
        if body["record_kind"] == "revision":
            payload = bytes.fromhex(creation["payload"])
            assert body["genesis_record_id"] == hashlib.sha256(DR + genesis_bytes).digest()
            assert body["parents"] == []
            assert body["payload"]["blob_id"] == hashlib.sha256(b"lngnb:blob:1\0" + payload).digest()
            assert body["payload"]["byte_length"] == len(payload)
            assert body["payload"]["media_type"] == ""
            assert body["metadata"]["titles"] == {"ja": "e\u0301 é"}
            assert body["metadata"]["information_type"] == {"namespace": "lngnb", "code": 0}
            assert body["metadata"]["resource_type"] == "lngnb:unspecified"
            assert "languages" not in body["metadata"] and "origins" not in body
        else:
            assert body["record_kind"] == "genesis"
    if "revision_creation" in case:
        creation = case["revision_creation"]
        genesis_bytes = bytes.fromhex(creation["genesis"])
        genesis = cbor2.loads(genesis_bytes)
        assert cbor2.dumps(genesis, canonical=True) == genesis_bytes
        assert genesis["body"]["record_kind"] == "genesis"
        assert genesis["body"]["publisher_public_key"] == public
        key.public_key().verify(genesis["signature"]["signature_bytes"],
                                DS + cbor2.dumps(genesis["body"], canonical=True))
        genesis_id = hashlib.sha256(DR + genesis_bytes).digest()
        parent_ids = []
        for parent_hex in creation["parents"]:
            parent_bytes = bytes.fromhex(parent_hex)
            parent = cbor2.loads(parent_bytes)
            assert cbor2.dumps(parent, canonical=True) == parent_bytes
            parent_body = parent["body"]
            assert parent_body["profile_id"] == genesis["body"]["profile_id"]
            assert parent_body["record_kind"] == "revision"
            assert parent_body["knowledge_id"] == genesis["body"]["knowledge_id"]
            assert parent_body["genesis_record_id"] == genesis_id
            assert parent["signature"]["public_key_bytes"] == public
            key.public_key().verify(parent["signature"]["signature_bytes"],
                                    DS + cbor2.dumps(parent_body, canonical=True))
            parent_ids.append(hashlib.sha256(DR + parent_bytes).digest())
        assert len(set(parent_ids)) == len(parent_ids)
        assert body["record_kind"] == "revision"
        assert body["knowledge_id"] == genesis["body"]["knowledge_id"]
        assert body["genesis_record_id"] == genesis_id
        assert body["parents"] == sorted(parent_ids)
        payload = bytes.fromhex(creation["payload"])
        assert body["payload"]["blob_id"] == hashlib.sha256(b"lngnb:blob:1\0" + payload).digest()
        assert body["payload"]["byte_length"] == len(payload)
        assert body["payload"]["media_type"] == "application/octet-stream"
        assert body["metadata"]["titles"] == {"ja": "e\u0301 é"}
        assert body["metadata"]["information_type"] == {"namespace": "lngnb", "code": 0}
        assert body["metadata"]["resource_type"] == "lngnb:unspecified"
        assert "origins" not in body
    if "derived_creation" in case:
        creation = case["derived_creation"]

        def checked_record(raw_hex):
            raw = bytes.fromhex(raw_hex)
            record = cbor2.loads(raw)
            assert cbor2.dumps(record, canonical=True) == raw
            sig = record["signature"]
            pub = sig["public_key_bytes"]
            assert sig["algorithm"] == "ed25519"
            assert sig["key_id"] == hashlib.sha256(DK + pub).digest()
            Ed25519PublicKey.from_public_bytes(pub).verify(
                sig["signature_bytes"], DS + cbor2.dumps(record["body"], canonical=True))
            assert record["body"]["profile_id"] == "lngnb-library-core-1"
            return record, hashlib.sha256(DR + raw).digest()

        genesis, genesis_id = checked_record(creation["genesis"])
        assert genesis["body"]["record_kind"] == "genesis"
        assert genesis["body"]["publisher_public_key"] == public
        assert genesis["signature"]["public_key_bytes"] == public
        assert body["knowledge_id"] == genesis["body"]["knowledge_id"]
        expected_origins = []
        assert 1 <= len(creation["sources"]) <= 128
        for source in creation["sources"]:
            sg, sg_id = checked_record(source["genesis"])
            sr, sr_id = checked_record(source["revision"])
            assert sg["body"]["record_kind"] == "genesis"
            assert sr["body"]["record_kind"] == "revision"
            assert sg["body"]["publisher_public_key"] == sg["signature"]["public_key_bytes"]
            assert sr["signature"]["public_key_bytes"] == sg["body"]["publisher_public_key"]
            assert sr["body"]["knowledge_id"] == sg["body"]["knowledge_id"]
            assert sr["body"]["genesis_record_id"] == sg_id
            assert body["knowledge_id"] != sg["body"]["knowledge_id"]
            expected_origins.append({"knowledge_id": sg["body"]["knowledge_id"],
                                     "genesis_record_id": sg_id, "revision_record_id": sr_id})
        expected_origins.sort(key=lambda ref: cbor2.dumps(ref, canonical=True))
        assert len({cbor2.dumps(ref, canonical=True) for ref in expected_origins}) == len(expected_origins)
        if body["record_kind"] == "revision":
            assert body["genesis_record_id"] == genesis_id
            assert body["parents"] == []
            assert body["origins"] == expected_origins
            payload = bytes.fromhex(creation["payload"])
            assert body["payload"] == {
                "blob_id": hashlib.sha256(b"lngnb:blob:1\0" + payload).digest(),
                "byte_length": len(payload), "media_type": "application/octet-stream"}
            assert body["metadata"] == {"titles": {"ja": "e\u0301 é"},
                                        "information_type": {"namespace": "lngnb", "code": 0},
                                        "resource_type": "lngnb:unspecified"}
        else:
            assert body == genesis["body"]
            assert "origins" not in body
    digest = hashlib.sha256(DR + encoded).digest()
    ids.append("rc1_" + base64.b32encode(digest).decode("ascii").lower().rstrip("="))
json.dump(ids, sys.stdout)
