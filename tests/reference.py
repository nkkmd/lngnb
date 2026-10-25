"""A13/R03/R05/R06: 製品と異なる実装でCBOR・ハッシュ・pure Ed25519を照合。
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
    digest = hashlib.sha256(DR + encoded).digest()
    ids.append("rc1_" + base64.b32encode(digest).decode("ascii").lower().rstrip("="))
json.dump(ids, sys.stdout)
