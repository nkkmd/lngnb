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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
    digest = hashlib.sha256(DR + encoded).digest()
    ids.append("rc1_" + base64.b32encode(digest).decode("ascii").lower().rstrip("="))
json.dump(ids, sys.stdout)
