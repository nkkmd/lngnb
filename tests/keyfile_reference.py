"""R34/A11: 公開試験鍵専用。RustCryptoと異なるOpenSSLで双方向照合。実運用禁止。"""
import json
import os
import sys
import cbor2
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN = b"lngnb:keyfile:1\x00"
PUBLIC_TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)

def derive(password, salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=1, memory_cost=65536).derive(password.encode("utf-8"))

def encode(value):
    # 本スキーマのtext keyではcanonical=Trueの順序がA1と一致する。
    return cbor2.dumps(value, canonical=True)

results = []
for case in json.load(sys.stdin):
    raw = bytes.fromhex(case["encrypted"])
    data = cbor2.loads(raw)
    assert encode(data) == raw
    ciphertext = data.pop("ciphertext")
    seed = ChaCha20Poly1305(derive(case["passphrase"], data["kdf"]["salt"])).decrypt(
        data["cipher"]["nonce"], ciphertext, DOMAIN + encode(data)
    )
    assert seed == PUBLIC_TEST_SEED
    key = Ed25519PrivateKey.from_private_bytes(seed)
    assert key.public_key().public_bytes_raw() == data["public_key"]
    record = cbor2.loads(bytes.fromhex(case["record"]))
    message = b"lngnb:signature:library-core-1\x00" + encode(record["body"])
    assert key.sign(message) == record["signature"]["signature_bytes"]
    key.public_key().verify(record["signature"]["signature_bytes"], message)
    data["kdf"]["salt"] = os.urandom(16)
    data["cipher"]["nonce"] = os.urandom(12)
    data["ciphertext"] = ChaCha20Poly1305(derive("independent public test passphrase", data["kdf"]["salt"])).encrypt(
        data["cipher"]["nonce"], seed, DOMAIN + encode(data)
    )
    results.append(encode(data).hex())
json.dump({"checked": len(results), "reencrypted": results}, sys.stdout)
