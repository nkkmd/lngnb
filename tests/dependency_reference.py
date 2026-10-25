"""R07/R08/R10/R26: 局所検査済みDAGの管理用評価を独立に照合する。

製品のKahn法とは別の再帰DFSを使う小規模試験専用oracle。
RecordのbytesからID・署名・依存を読み直す。pin・公開・キュー・循環や
未対応形式の検査器ではない。公開試験鍵だけを入力し、実運用へ流用しない。
"""
import hashlib
import importlib.metadata
import json
import sys

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

assert importlib.metadata.version("cbor2") == "5.6.5"
assert importlib.metadata.version("cryptography") == "46.0.3"


def evaluate(case):
    nodes = {}
    for raw in case["records"]:
        raw = bytes.fromhex(raw)
        envelope = cbor2.loads(raw)
        assert cbor2.dumps(envelope, canonical=True) == raw
        body, signature = envelope["body"], envelope["signature"]
        assert body["profile_id"] == "lngnb-library-core-1"
        assert body["record_kind"] in ("genesis", "revision")
        public = signature["public_key_bytes"]
        assert signature["algorithm"] == "ed25519"
        assert signature["key_id"] == hashlib.sha256(
            b"lngnb:key:ed25519:1\0" + public).digest()
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature["signature_bytes"], b"lngnb:signature:library-core-1\0"
            + cbor2.dumps(body, canonical=True))
        if body["record_kind"] == "genesis":
            assert body["publisher_public_key"] == public
        rid = hashlib.sha256(b"lngnb:record:library-core-1\0" + raw).hexdigest()
        assert rid not in nodes
        nodes[rid] = (body, public)
    # 小規模DAGだけを対象とする。製品の形式上限・履歴長上限ではない。
    assert len(nodes) <= 200
    blobs = {}
    for raw in case["retained"]:
        raw = bytes.fromhex(raw)
        bid = hashlib.sha256(b"lngnb:blob:1\0" + raw).hexdigest()
        blobs[bid] = len(raw)
    unavailable = set(case.get("unavailable", []))
    failures = case.get("failures", {})
    assert all(r in ("transfer_hash_mismatch", "transfer_failed")
               for r in failures.values())
    known = set(case.get("known", []))
    assert known <= nodes.keys()
    results, visiting = {}, set()

    def visit(rid):
        if rid in results:
            return results[rid]
        assert rid not in visiting, "oracleは循環を対象としない"
        visiting.add(rid)
        body, public = nodes[rid]
        out = dict(id=rid, validation="valid", payload=None,
                   payload_reason=None, reason=None, related=None)

        def finish(validation="valid", reason=None, related=None):
            out.update(validation=validation, reason=reason, related=related)
            visiting.remove(rid)
            results[rid] = out
            return out

        if body["record_kind"] == "genesis":
            return finish()
        payload = body["payload"]
        bid = payload["blob_id"].hex()
        if bid in blobs and bid not in unavailable:
            if blobs[bid] == payload["byte_length"]:
                out["payload"] = "verified"
            else:
                out.update(payload="unavailable",
                           payload_reason="declared_length_mismatch")
        elif rid in known:
            out.update(payload="unavailable", payload_reason="evidence_unavailable")
        elif bid in unavailable:
            out.update(payload="unavailable", payload_reason="storage_corruption")
        elif bid in failures:
            out.update(payload="unavailable", payload_reason=failures[bid])
        else:
            out["payload"] = "missing"
        gid = body["genesis_record_id"].hex()
        if gid not in nodes:
            return finish("pending", "missing_genesis", gid)
        genesis, genesis_public = nodes[gid]
        if (genesis["record_kind"] != "genesis"
                or genesis["knowledge_id"] != body["knowledge_id"]):
            return finish("invalid", "genesis_mismatch", gid)
        if public != genesis_public:
            return finish("invalid", "wrong_publisher", gid)
        parents = sorted(p.hex() for p in body["parents"])
        parent_results = {}
        for pid in parents:
            if pid not in nodes:
                continue
            parent = nodes[pid][0]
            if (parent["record_kind"] != "revision"
                    or parent["knowledge_id"] != body["knowledge_id"]
                    or parent["genesis_record_id"].hex() != gid):
                return finish("invalid", "invalid_parent", pid)
            parent_results[pid] = visit(pid)
            if parent_results[pid]["validation"] == "invalid":
                return finish("invalid", "invalid_parent", pid)
        for pid in parents:
            if pid not in nodes:
                return finish("pending", "missing_parent", pid)
            if parent_results[pid]["validation"] == "pending":
                reason = ("evidence_unavailable"
                          if parent_results[pid]["reason"] == "evidence_unavailable"
                          else "revalidation_in_progress")
                return finish("pending", reason, pid)
        if out["payload_reason"] == "declared_length_mismatch":
            return finish("invalid", "declared_length_mismatch", bid)
        if out["payload_reason"] == "evidence_unavailable":
            return finish("pending", "evidence_unavailable", bid)
        return finish()

    return [visit(rid) for rid in sorted(nodes)]


json.dump([evaluate(case) for case in json.load(sys.stdin)], sys.stdout)
