"""R01/R24/R30/R34: 実作成CLIをPTY・SQLite・独立暗号ライブラリで照合。公開試験値のみ。"""
import base64
import fcntl
import hashlib
import os
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import termios
import time
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BINARY, ROOT = sys.argv[1], Path(sys.argv[2])
SPEC = Path("docs/specification-v1.0.0.md").read_text()
import json
A14 = json.loads(SPEC.split("## 付録A14 ", 1)[1].split("```json\n",1)[1].split("\n```",1)[0])
PASS = bytes.fromhex(A14["passphrase_utf8_hex"])
KEY = cbor2.loads(bytes.fromhex(A14["keyfile_cbor_hex"]))["public_key"]
def ident(prefix, domain, raw):
    return prefix + base64.b32encode(hashlib.sha256(domain + raw).digest()).decode().lower().rstrip("=")
KEY_ID = ident("ky1_", b"lngnb:key:ed25519:1\0", KEY)
BODY = b"public document\x00\xff\r\n"
META = {"titles":{"JA":"e\u0301 é"}, "languages":["JA","EN"], "tags":["資料","A"]}
(ROOT/"body").write_bytes(BODY)
(ROOT/"metadata").write_bytes(cbor2.dumps(META, canonical=True))
original_key = (ROOT/"keys/publisher").read_bytes()
def db(name):
    return sqlite3.connect(ROOT/name/"database.sqlite", timeout=1)
def snapshot(name):
    with db(name) as c:
        return tuple((table, c.execute('SELECT * FROM "'+table+'" ORDER BY rowid').fetchall()) for (table,) in c.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall())
def count_state(name):
    with db(name) as c:
        return c.execute("SELECT state FROM storage_state").fetchone()[0], c.execute("SELECT count(*) FROM records").fetchone()[0], c.execute("SELECT count(*) FROM blobs").fetchone()[0]
def assert_preserved_after_retry(name):
    protected={"records","blobs","blob_objects","manual_blob_holds","known_invalid","temporary_blob_holds","blob_cleanup_plans","blob_cleanup_runs"}
    old=dict(snapshot(name));files={p.name:p.read_bytes() for p in (ROOT/name/"blobs").iterdir()}
    invoke(name,expected=3)
    new=dict(snapshot(name))
    for table in protected:assert new[table]==old[table],"protected data changed"
    assert new["history"][:len(old["history"])]==old["history"],"past history changed"
    assert count_state(name)[0]=="running"
    assert {p.name:p.read_bytes() for p in (ROOT/name/"blobs").iterdir()}==files
def args(name, extra=(), key_id=KEY_ID, payload=None, metadata=None, selection=None):
    command = [BINARY,"document","create","--data-dir",str(ROOT/name),"--key-dir",str(ROOT/"keys"),"--name","publisher","--expect-key-id",key_id,"--payload",str(payload or ROOT/"body"),"--metadata",str(metadata or ROOT/"metadata")]+list(extra)
    if selection is not None:
        command[2] = "revise"
        command += list(selection)
    return command
def invoke(name, password=PASS, expected=0, cancel=None, full=False, extra=(), key_id=KEY_ID, payload=None, metadata=None, before_password=None, after_password=None, no_prompt=False, selection=None):
    master,slave=pty.openpty()
    before=termios.tcgetattr(slave);before[3]|=termios.ECHO|termios.ECHONL|termios.ICANON|termios.ISIG
    termios.tcsetattr(slave,termios.TCSANOW,before);before=termios.tcgetattr(slave)
    def setup():
        os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
    sink=open("/dev/full","wb") if full else subprocess.PIPE
    child=subprocess.Popen(args(name,extra,key_id,payload,metadata,selection),stdin=subprocess.DEVNULL,stdout=sink,stderr=subprocess.PIPE,pass_fds=(slave,),preexec_fn=setup)
    captured=bytearray()
    try:
        if not no_prompt:
            deadline=time.monotonic()+30
            while b": " not in captured:
                assert time.monotonic()<deadline and child.poll() is None,"creation prompt missing"
                if select.select([master],[],[],0.05)[0]:captured.extend(os.read(master,4096))
            assert not termios.tcgetattr(slave)[3] & (termios.ECHO|termios.ECHONL|termios.ICANON|termios.ISIG)
            if before_password:before_password()
            if cancel:os.kill(child.pid,cancel)
            else:os.write(master,password+b"\n")
            if after_password:after_password(child)
        out,err=child.communicate(timeout=60);out=out or b""
        assert child.returncode==expected,(name,child.returncode,err.decode())
        # SIGKILL試験は署名・端末復元後の保存段階だけで停止する。
        assert termios.tcgetattr(slave)==before,"terminal not restored"
        assert not select.select([slave],[],[],0)[0],"pending input"
        while select.select([master],[],[],0)[0]:captured.extend(os.read(master,4096))
        assert PASS not in out+err+captured and b"public wrong password" not in out+err+captured,"secret output"
        if expected!=0:assert out==b"","failure printed success"
        return out,err
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=5)
        os.close(master);os.close(slave)
        if full:sink.close()
def verify(name, outputs, expected_body=BODY):
    with db(name) as c:
        rows=c.execute("SELECT id,bytes FROM records ORDER BY id").fetchall()
        assert len(rows)==2*len(outputs)
        records={}
        for rid,raw in rows:
            obj=cbor2.loads(raw);assert cbor2.dumps(obj,canonical=True)==raw
            assert hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest()==rid
            sig=obj["signature"];assert sig["public_key_bytes"]==KEY
            assert sig["key_id"]==hashlib.sha256(b"lngnb:key:ed25519:1\0"+KEY).digest()
            Ed25519PublicKey.from_public_bytes(KEY).verify(sig["signature_bytes"],b"lngnb:signature:library-core-1\0"+cbor2.dumps(obj["body"],canonical=True))
            assert PASS not in raw
            records[rid]=obj["body"]
        for out in outputs:
            fields=dict(line.decode().split(": ",1) for line in out.splitlines() if b"_id: " in line)
            def rawid(s):return base64.b32decode(s.split("_",1)[1].upper()+"====")
            gen=records[rawid(fields["genesis_id"])];rev=records[rawid(fields["revision_id"])]
            assert gen["record_kind"]=="genesis" and gen["publisher_public_key"]==KEY
            assert gen["knowledge_id"]==rev["knowledge_id"]==rawid(fields["knowledge_id"])
            assert rev["genesis_record_id"]==rawid(fields["genesis_id"]) and rev["parents"]==[]
            blob=rev["payload"];bid=hashlib.sha256(b"lngnb:blob:1\0"+expected_body).digest()
            assert blob["blob_id"]==bid and blob["byte_length"]==len(expected_body)
            assert (ROOT/name/"blobs"/bid.hex()).read_bytes()==expected_body
            assert rev["metadata"]["titles"]=={"ja":"e\u0301 é"}
            assert rev["metadata"]["languages"]==["en","ja"]
        assert c.execute("SELECT state FROM storage_state").fetchone()==("clean",)
        assert c.execute("SELECT dirty FROM evaluation_state").fetchone()==(1,)  # 保存後の新規版評価は別
    assert not any(p.name=="publisher" for p in (ROOT/name).rglob("*"))

out,_=invoke("ok")
out2,_=invoke("ok")  # 起動台帳の再検査・前回入力epoch変更後の再起動
verify("ok",[out,out2]);assert out!=out2
# 認証中に元pathを差し替えても、読込み済み本文だけを署名・保存する。
out,_=invoke("binary",before_password=lambda:(ROOT/"body").write_bytes(b"changed path"))
verify("binary",[out]);(ROOT/"body").write_bytes(BODY)
(ROOT/"empty-body").write_bytes(b"")
out,_=invoke("empty",payload=ROOT/"empty-body",extra=["--max-payload-bytes","0"]);verify("empty",[out],b"")
for i,sig in enumerate([signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM,signal.SIGTSTP]):
    name="cancel"+str(i);old=snapshot(name);invoke(name,expected=130,cancel=sig);assert snapshot(name)==old
for name,password,kid in [("wrong",b"public wrong password",KEY_ID),("wrong-id",PASS,"ky1_"+"a"*52)]:
    old=snapshot(name);invoke(name,password=password,key_id=kid,expected=1);assert snapshot(name)==old
(ROOT/"invalid-meta").write_bytes(cbor2.dumps({"titles":{"JA":"a","ja":"b"}},canonical=True))
old=snapshot("bad-meta");invoke("bad-meta",metadata=ROOT/"invalid-meta",expected=1);assert snapshot("bad-meta")==old
old=snapshot("bad-media");invoke("bad-media",extra=["--media-type","Text/Plain"],expected=1);assert snapshot("bad-media")==old
old=snapshot("limit");invoke("limit",extra=["--max-payload-bytes","0"],expected=1,no_prompt=True);assert snapshot("limit")==old
os.symlink(ROOT/"body",ROOT/"linked-body")
old=snapshot("link");invoke("link",payload=ROOT/"linked-body",expected=1,no_prompt=True);assert snapshot("link")==old
residue=ROOT/"keys"/(".lngnb-key-"+"a"*64);residue.write_bytes(original_key);residue.chmod(0o600)
old=snapshot("residue");invoke("residue",expected=1,no_prompt=True);assert snapshot("residue")==old;residue.unlink()
# stdinを秘密入力の代替にせず、制御端末なしで拒否する。
old=snapshot("no-tty")
r=subprocess.run(args("no-tty"),input=PASS+b"\n",stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
assert r.returncode==1 and r.stdout==b"" and PASS not in r.stderr;assert snapshot("no-tty")==old
invoke("missing-data",expected=3);assert not (ROOT/"missing-data").exists()
with open(ROOT/"busy/lock","rb") as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);old=snapshot("busy");invoke("busy",expected=3);assert snapshot("busy")==old
# SQL拒否は実CLIの各保存段階へ注入し、一部保存と正常停止失敗を区別する。
with db("blob-sql") as c:c.executescript("CREATE TRIGGER fail_blob BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT,'test'); END;")
invoke("blob-sql",expected=3);assert count_state("blob-sql")==("running",0,0)
assert len(list((ROOT/"blob-sql/blobs").iterdir()))==1  # DB確定前の孤立実体を保全
with db("genesis-sql") as c:c.executescript("CREATE TRIGGER fail_genesis BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'test'); END;")
invoke("genesis-sql",expected=3);assert count_state("genesis-sql")==("running",0,1)
with db("sql") as c:c.executescript("CREATE TRIGGER fail_revision BEFORE INSERT ON records WHEN (SELECT count(*) FROM records)=1 BEGIN SELECT RAISE(ABORT,'test'); END;")
invoke("sql",expected=3);assert count_state("sql")==("running",1,1)
assert_preserved_after_retry("sql")
with db("finish") as c:c.executescript("CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON storage_state WHEN NEW.state='clean' BEGIN SELECT RAISE(ABORT,'test'); END;")
invoke("finish",expected=3);assert count_state("finish")==("running",2,1)
out,err=invoke("output",expected=1,full=True);assert "保存と正常終了は完了" in err.decode();assert count_state("output")==("clean",2,1)
# Revision挿入中に外側からSIGKILL。確定済み本文/Genesisを保持し、次回も手動待ち。
with db("kill") as c:c.executescript("CREATE TRIGGER slow_revision BEFORE INSERT ON records WHEN (SELECT count(*) FROM records)=1 BEGIN SELECT sum(x) FROM (WITH RECURSIVE cnt(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM cnt WHERE x<100000000) SELECT x FROM cnt); END;")
def kill_after_genesis(child):
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if count_state("kill")==("running",1,1):child.kill();return
        assert child.poll() is None,"child exited before kill point";time.sleep(0.01)
    raise AssertionError("kill point not reached")
invoke("kill",expected=-signal.SIGKILL,after_password=kill_after_genesis)
assert count_state("kill")==("running",1,1)
assert_preserved_after_retry("kill")
assert (ROOT/"keys/publisher").read_bytes()==original_key
assert (ROOT/"body").read_bytes()==BODY and cbor2.loads((ROOT/"metadata").read_bytes())==META
# R07: 同一Knowledgeの明示改訂。元Recordをファイルへ書くのは試験側の操作。
def fields(out):
    return dict(line.decode().split(": ",1) for line in out.splitlines() if b"_id: " in line)
def rawid(text):
    return base64.b32decode(text.split("_",1)[1].upper()+"====")
def saved(name):
    with db(name) as c:
        return dict(c.execute("SELECT id,bytes FROM records"))
def export(name, rid, filename):
    path = ROOT/filename
    path.write_bytes(saved(name)[rawid(rid)])
    return str(path)
base = fields(out2)
gen = export("ok", base["genesis_id"], "revision-genesis")
parent = export("ok", base["revision_id"], "revision-parent")
old_records = saved("ok")
(ROOT/"revision-meta").write_bytes(cbor2.dumps({},canonical=True))
(ROOT/"revision-body").write_bytes(b"branch a")
selection = ["--genesis",gen,"--parent",parent]
def revision(name="ok", parents=None, **kwargs):
    return invoke(name, payload=ROOT/"revision-body", metadata=ROOT/"revision-meta",
                  selection=selection if parents is None else ["--genesis",gen]+sum((["--parent",p] for p in parents),[]), **kwargs)
def checked_revision(out, payload, parent_ids):
    f = fields(out)
    assert f["knowledge_id"] == base["knowledge_id"] and f["genesis_id"] == base["genesis_id"]
    raw = saved("ok")[rawid(f["revision_id"])];record = cbor2.loads(raw);body = record["body"]
    assert cbor2.dumps(record,canonical=True)==raw
    assert hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest()==rawid(f["revision_id"])
    sig=record["signature"]
    assert sig["public_key_bytes"]==KEY and sig["key_id"]==hashlib.sha256(b"lngnb:key:ed25519:1\0"+KEY).digest()
    Ed25519PublicKey.from_public_bytes(KEY).verify(sig["signature_bytes"],b"lngnb:signature:library-core-1\0"+cbor2.dumps(body,canonical=True))
    assert body["knowledge_id"]==rawid(base["knowledge_id"]) and body["genesis_record_id"]==rawid(base["genesis_id"])
    assert body["parents"]==sorted(rawid(r) for r in parent_ids)
    assert "origins" not in body
    assert body["metadata"]=={"information_type":{"namespace":"lngnb","code":0},"resource_type":"lngnb:unspecified"}
    bid=hashlib.sha256(b"lngnb:blob:1\0"+payload).digest()
    assert body["payload"]=={"blob_id":bid,"byte_length":len(payload),"media_type":""}
    assert (ROOT/"ok/blobs"/bid.hex()).read_bytes()==payload
    assert count_state("ok")[0]=="clean"
    assert all(saved("ok")[rid]==raw for rid,raw in old_records.items())
    return f["revision_id"]
a,_=revision();aid=checked_revision(a,b"branch a",[base["revision_id"]]);ap=export("ok",aid,"branch-a")
(ROOT/"revision-body").write_bytes(b"branch b")
b,_=revision();bid=checked_revision(b,b"branch b",[base["revision_id"]]);bp=export("ok",bid,"branch-b")
(ROOT/"revision-body").write_bytes(b"merge")
m,_=revision(parents=[bp,ap]);mid=checked_revision(m,b"merge",[aid,bid])
state=count_state("ok");again,_=revision(parents=[ap,bp]);assert fields(again)["revision_id"]==mid and count_state("ok")==state
(ROOT/"revision-body").write_bytes(b"another initial")
empty=["--genesis",gen,"--no-parents"]
e,_=invoke("ok",payload=ROOT/"revision-body",metadata=ROOT/"revision-meta",selection=empty)
checked_revision(e,b"another initial",[])
# 書込み前拒否では全論理DB不変。取消し・鍵・入力・明示親の異常を区別する。
for sig in [signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM,signal.SIGTSTP]:
    old=snapshot("ok");revision(expected=130,cancel=sig);assert snapshot("ok")==old
for kwargs in [{"password":b"public wrong password"},{"key_id":"ky1_"+"a"*52}]:
    old=snapshot("ok");revision(expected=1,**kwargs);assert snapshot("ok")==old
for chosen in [["--genesis",parent,"--parent",parent], ["--genesis",gen,"--parent",gen],
               ["--genesis",gen,"--parent",parent,"--parent",parent]]:
    old=snapshot("ok");invoke("ok",selection=chosen,expected=1,no_prompt=True);assert snapshot("ok")==old
# 別Knowledgeの親、局所署名不正、予算不足、危険link、親未選択。
other_id=next(ident("rc1_", b"lngnb:record:library-core-1\0", raw) for raw in old_records.values() if cbor2.loads(raw)["body"]["record_kind"]=="revision" and cbor2.loads(raw)["body"]["knowledge_id"]!=rawid(base["knowledge_id"]))
other=export("ok",other_id,"other-parent")
old=snapshot("ok");revision(parents=[other],expected=1,no_prompt=True);assert snapshot("ok")==old
(ROOT/"bad-record").write_bytes(b"not cbor")
old=snapshot("ok");revision(parents=[str(ROOT/"bad-record")],expected=1,no_prompt=True);assert snapshot("ok")==old
old=snapshot("ok");revision(extra=["--max-payload-bytes","0"],expected=1,no_prompt=True);assert snapshot("ok")==old
os.symlink(parent,ROOT/"linked-parent")
old=snapshot("ok");revision(parents=[str(ROOT/"linked-parent")],expected=1,no_prompt=True);assert snapshot("ok")==old
r=subprocess.run(args("ok",selection=["--genesis",gen]),capture_output=True)
assert r.returncode==2 and r.stdout==b""
# 一Record上限と、複数の有効Recordの合計16 MiB予算を署名前に適用する。
(ROOT/"oversize-parent").write_bytes(b"x"*2097153)
old=snapshot("ok");revision(parents=[str(ROOT/"oversize-parent")],expected=1,no_prompt=True);assert snapshot("ok")==old
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
A13=json.loads(SPEC.split("## 付録A13 ",1)[1].split("```json\n",1)[1].split("\n```",1)[0])
signing=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(A13["seed_hex"]))
large_parents=[]
for n in range(65):
    body=cbor2.loads(Path(parent).read_bytes())["body"]
    body["metadata"]={"information_type":{"namespace":"lngnb","code":0},"resource_type":"lngnb:unspecified","extensions":{"padding":"x"*260000}}
    body["payload"]["byte_length"]=n
    encoded=cbor2.dumps(body,canonical=True)
    record={"body":body,"signature":{"algorithm":"ed25519","public_key_bytes":KEY,
            "key_id":hashlib.sha256(b"lngnb:key:ed25519:1\0"+KEY).digest(),
            "signature_bytes":signing.sign(b"lngnb:signature:library-core-1\0"+encoded)}}
    path=ROOT/("large-parent-"+str(n));path.write_bytes(cbor2.dumps(record,canonical=True));large_parents.append(str(path))
assert sum(Path(p).stat().st_size for p in large_parents)>16*1024*1024
old=snapshot("ok");revision(parents=large_parents,expected=1,no_prompt=True);assert snapshot("ok")==old
# 元pathの後の差替えで署名対象を変えない。
parent_bytes=Path(parent).read_bytes()
(ROOT/"revision-body").write_bytes(b"stable input")
v,_=revision(before_password=lambda:Path(parent).write_bytes(b"changed path"))
checked_revision(v,b"stable input",[base["revision_id"]]);Path(parent).write_bytes(parent_bytes)
# 保存先に元版がなければ、新しい本文/Recordを保存せず保全停止する。
for name in ["revision-missing","revision-sql","revision-finish","revision-output"]:
    r=subprocess.run([BINARY,"data","init","--data-dir",str(ROOT/name)],capture_output=True);assert r.returncode==0
revision("revision-missing",expected=3);assert count_state("revision-missing")==("running",0,0)
# 元版のある領域へ複製するのは、全保存fileを持つ停止中fixtureの明示コピーだけ。
import shutil
for name in ["revision-sql","revision-finish","revision-output"]:
    shutil.rmtree(ROOT/name);shutil.copytree(ROOT/"ok",ROOT/name)
with db("revision-sql") as c:c.executescript("CREATE TRIGGER fail_new_revision BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'test'); END;")
old=saved("revision-sql");(ROOT/"revision-body").write_bytes(b"sql failure")
revision("revision-sql",expected=3);assert saved("revision-sql")==old and count_state("revision-sql")[0]=="running"
with db("revision-finish") as c:c.executescript("CREATE TRIGGER fail_revision_finish BEFORE UPDATE OF state ON storage_state WHEN NEW.state='clean' BEGIN SELECT RAISE(ABORT,'test'); END;")
old=saved("revision-finish");revision("revision-finish",expected=3)
assert len(saved("revision-finish"))==len(old)+1 and count_state("revision-finish")[0]=="running"
_,err=revision("revision-output",expected=1,full=True);assert "保存と正常終了は完了" in err.decode();assert count_state("revision-output")[0]=="clean"
# 後続の無関係操作で手動待ちを解除しない。一次bytes・鍵・元入力を保持する。
old=saved("revision-sql");revision("revision-sql",expected=3);assert saved("revision-sql")==old and count_state("revision-sql")[0]=="running"
assert (ROOT/"keys/publisher").read_bytes()==original_key
assert Path(parent).read_bytes()==parent_bytes and saved("ok")[rawid(base["genesis_id"])]==Path(gen).read_bytes()
print("DOCUMENT_CLI_CASES_OK")
