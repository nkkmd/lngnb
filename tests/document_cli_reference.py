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
def args(name, extra=(), key_id=KEY_ID, payload=None, metadata=None, selection=None, origins=None):
    command = [BINARY,"document","create","--data-dir",str(ROOT/name),"--key-dir",str(ROOT/"keys"),"--name","publisher","--expect-key-id",key_id,"--payload",str(payload or ROOT/"body"),"--metadata",str(metadata or ROOT/"metadata")]+list(extra)
    if selection is not None:
        command[2] = "revise"
        command += list(selection)
    if origins is not None:
        command[2] = "derive"
        command += sum((["--origin-genesis",g,"--origin-revision",r] for g,r in origins),[])
    return command
def invoke(name, password=PASS, expected=0, cancel=None, full=False, extra=(), key_id=KEY_ID, payload=None, metadata=None, before_password=None, after_password=None, no_prompt=False, selection=None, origins=None):
    master,slave=pty.openpty()
    before=termios.tcgetattr(slave);before[3]|=termios.ECHO|termios.ECHONL|termios.ICANON|termios.ISIG
    termios.tcsetattr(slave,termios.TCSANOW,before);before=termios.tcgetattr(slave)
    def setup():
        os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
    sink=open("/dev/full","wb") if full else subprocess.PIPE
    child=subprocess.Popen(args(name,extra,key_id,payload,metadata,selection,origins),stdin=subprocess.DEVNULL,stdout=sink,stderr=subprocess.PIPE,pass_fds=(slave,),preexec_fn=setup)
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
# R07: 明示由来から新Knowledge。元版の祖先/本文/保存は派生の必須依存ではない。
def init(name):
    r=subprocess.run([BINARY,"data","init","--data-dir",str(ROOT/name)],capture_output=True)
    assert r.returncode==0,(name,r.stderr)
for name in ["derived","derived-next","derived-sql","derived-finish","derived-output"]:init(name)
def derive(name="derived", sources=None, **kwargs):
    return invoke(name,payload=ROOT/"revision-body",metadata=ROOT/"revision-meta",
                  origins=[(gen,parent)] if sources is None else sources,**kwargs)
def fixture(body, signer, public, filename):
    encoded=cbor2.dumps(body,canonical=True)
    obj={"body":body,"signature":{"algorithm":"ed25519","public_key_bytes":public,
         "key_id":hashlib.sha256(b"lngnb:key:ed25519:1\0"+public).digest(),
         "signature_bytes":signer.sign(b"lngnb:signature:library-core-1\0"+encoded)}}
    raw=cbor2.dumps(obj,canonical=True);path=ROOT/filename;path.write_bytes(raw)
    return str(path),hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest()
# 公開試験seedのみ。異なる元発行鍵・欠落親/本文・既存由来を持つ元版。
from cryptography.hazmat.primitives import serialization
foreign=Ed25519PrivateKey.from_private_bytes(bytes([1])*32)
foreign_public=foreign.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
gbody=cbor2.loads(Path(gen).read_bytes())["body"]
gbody["knowledge_id"]=bytes([3])*32;gbody["publisher_public_key"]=foreign_public
fg,fgid=fixture(gbody,foreign,foreign_public,"foreign-genesis")
rbody=cbor2.loads(parent_bytes)["body"]
rbody["knowledge_id"]=gbody["knowledge_id"];rbody["genesis_record_id"]=fgid
rbody["parents"]=[bytes([9])*32]
rbody["origins"]=[{"knowledge_id":bytes([8])*32}]
fr,frid=fixture(rbody,foreign,foreign_public,"foreign-revision")
def ref(g,r):
    gb=cbor2.loads(Path(g).read_bytes())["body"]
    return {"knowledge_id":gb["knowledge_id"],
            "genesis_record_id":hashlib.sha256(b"lngnb:record:library-core-1\0"+Path(g).read_bytes()).digest(),
            "revision_record_id":hashlib.sha256(b"lngnb:record:library-core-1\0"+Path(r).read_bytes()).digest()}
def checked_derived(name,out,sources):
    f=fields(out);rows=saved(name);bodies={}
    for field in ["genesis_id","revision_id"]:
        raw=rows[rawid(f[field])];obj=cbor2.loads(raw);body=obj["body"];sig=obj["signature"]
        assert cbor2.dumps(obj,canonical=True)==raw
        assert hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest()==rawid(f[field])
        assert sig["public_key_bytes"]==KEY and sig["key_id"]==hashlib.sha256(b"lngnb:key:ed25519:1\0"+KEY).digest()
        Ed25519PublicKey.from_public_bytes(KEY).verify(sig["signature_bytes"],b"lngnb:signature:library-core-1\0"+cbor2.dumps(body,canonical=True))
        bodies[field]=body
    g=bodies["genesis_id"];r=bodies["revision_id"]
    expected=sorted([ref(g,r) for g,r in sources],key=lambda v:cbor2.dumps(v,canonical=True))
    assert g["record_kind"]=="genesis" and g["publisher_public_key"]==KEY
    assert g["knowledge_id"]==r["knowledge_id"]==rawid(f["knowledge_id"])
    assert all(r["knowledge_id"]!=v["knowledge_id"] for v in expected)
    assert r["genesis_record_id"]==rawid(f["genesis_id"]) and r["parents"]==[]
    assert r["origins"]==expected and "origins" not in g
    assert r["metadata"]=={"information_type":{"namespace":"lngnb","code":0},"resource_type":"lngnb:unspecified"}
    payload=(ROOT/"revision-body").read_bytes();bid=hashlib.sha256(b"lngnb:blob:1\0"+payload).digest()
    assert r["payload"]=={"blob_id":bid,"byte_length":len(payload),"media_type":""}
    assert (ROOT/name/"blobs"/bid.hex()).read_bytes()==payload and count_state(name)[0]=="clean"
    return f
sources=[(fg,fr),(gen,parent)];source_bytes={p:Path(p).read_bytes() for pair in sources for p in pair}
source_state=snapshot("ok")
(ROOT/"revision-body").write_bytes(b"explicit derived body")
d,_=derive(sources=sources);df=checked_derived("derived",d,sources)
assert len(saved("derived"))==2 and not any(ref(g,r)["revision_record_id"] in saved("derived") for g,r in sources)
d2,_=derive(sources=list(reversed(sources)));df2=checked_derived("derived",d2,sources)
assert df2["knowledge_id"]!=df["knowledge_id"] and len(saved("derived"))==4
# 派生の派生も直接選んだ版だけを由来とし、元版のoriginsを継承しない。
dg=export("derived",df["genesis_id"],"derived-genesis");dr=export("derived",df["revision_id"],"derived-revision")
d3,_=derive("derived-next",sources=[(dg,dr)]);checked_derived("derived-next",d3,[(dg,dr)])
# 入力拒否・取消しは保存前。元発行鍵とは別でもよいが、派生先の期待鍵は必須。
for sig in [signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM,signal.SIGTSTP]:
    old=snapshot("derived");derive(cancel=sig,expected=130);assert snapshot("derived")==old
for kwargs in [{"password":b"public wrong password"},{"key_id":"ky1_"+"a"*52}]:
    old=snapshot("derived");derive(expected=1,**kwargs);assert snapshot("derived")==old
mismatch_body=cbor2.loads(parent_bytes)["body"]
wrong_publisher,_=fixture(mismatch_body,foreign,foreign_public,"wrong-publisher")
for chosen in [[(gen,wrong_publisher)],[(parent,parent)],[(gen,gen)],[(gen,fr)],[(fg,parent)],[(gen,parent),(gen,parent)],
               [(gen,str(ROOT/"bad-record"))],[(gen,str(ROOT/"linked-parent"))],[(gen,str(ROOT/"oversize-parent"))]]:
    old=snapshot("derived");derive(sources=chosen,expected=1,no_prompt=True);assert snapshot("derived")==old
old=snapshot("derived");derive(extra=["--max-payload-bytes","0"],expected=1,no_prompt=True);assert snapshot("derived")==old
old=snapshot("derived");_,err=derive(sources=[(gen,p) for p in large_parents],expected=1,no_prompt=True)
assert b"record_input_limit" in err and snapshot("derived")==old
# 128組を実CLIでも受理し、本文不保持を参照失敗へ読み替えない。
maximum=[]
for n in range(128):
    body=cbor2.loads(parent_bytes)["body"];body["payload"]["byte_length"]=n
    path,_=fixture(body,signing,KEY,"small-origin-"+str(n));maximum.append((gen,path))
maximum_out,_=derive(sources=maximum);checked_derived("derived",maximum_out,maximum)
# 読込み後のsource path差替えを署名対象へ反映しない。
d4,_=derive(before_password=lambda:Path(parent).write_bytes(b"changed path"))
Path(parent).write_bytes(parent_bytes);checked_derived("derived",d4,[(gen,parent)])
# 共通保存の独立確定と保全停止。由来を保存先へ自動取込みしない。
with db("derived-sql") as c:c.executescript("CREATE TRIGGER fail_derived BEFORE INSERT ON records WHEN (SELECT count(*) FROM records)=1 BEGIN SELECT RAISE(ABORT,'test'); END;")
derive("derived-sql",expected=3);assert count_state("derived-sql")==("running",1,1)
old=saved("derived-sql");derive("derived-sql",expected=3);assert saved("derived-sql")==old and count_state("derived-sql")[0]=="running"
with db("derived-finish") as c:c.executescript("CREATE TRIGGER fail_derived_finish BEFORE UPDATE OF state ON storage_state WHEN NEW.state='clean' BEGIN SELECT RAISE(ABORT,'test'); END;")
derive("derived-finish",expected=3);assert count_state("derived-finish")==("running",2,1)
_,err=derive("derived-output",expected=1,full=True)
assert "保存と正常終了は完了" in err.decode() and count_state("derived-output")==("clean",2,1)
assert snapshot("ok")==source_state and all(Path(p).read_bytes()==raw for p,raw in source_bytes.items())
assert (ROOT/"keys/publisher").read_bytes()==original_key
# R04/R07: 鍵・端末なしの完全固定指定。署名中の親/由来だけを独立照合する。
def text_id(prefix, raw):
    return prefix+base64.b32encode(raw).decode("ascii").lower().rstrip("=")
def fixed_in(name, rid=None):
    for raw in saved(name).values():
        body=cbor2.loads(raw)["body"]
        revision=text_id("rc1_",hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest())
        if body["record_kind"]=="revision" and (rid is None or rid==revision):
            return {"knowledge_id":text_id("kn1_",body["knowledge_id"]),"genesis_id":text_id("rc1_",body["genesis_record_id"]),"revision_id":revision}
    raise AssertionError("revision fixture absent")
def inspect_args(name, fixed, extra=()):
    return [BINARY,"document","inspect","--data-dir",str(ROOT/name),
            "--knowledge-id",fixed["knowledge_id"],"--genesis-id",fixed["genesis_id"],
            "--revision-id",fixed["revision_id"]]+list(extra)
def inspect(name, fixed, expected=0, state="clean", full=False, extra=()):
    sink=open("/dev/full","wb") if full else subprocess.PIPE
    try:
        result=subprocess.run(inspect_args(name,fixed,extra),stdin=subprocess.DEVNULL,stdout=sink,
                              stderr=subprocess.PIPE,start_new_session=True,timeout=60)
    finally:
        if full:sink.close()
    out=result.stdout or b"";err=result.stderr
    assert result.returncode==expected,(name,result.returncode,err.decode())
    assert PASS not in out+err and b"PRIVATE METADATA" not in out+err
    if expected!=0:
        assert out==b"";return err
    assert err==b""
    raw=saved(name)[rawid(fixed["revision_id"])];record=cbor2.loads(raw);body=record["body"];sig=record["signature"]
    assert hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest()==rawid(fixed["revision_id"])
    assert cbor2.dumps(record,canonical=True)==raw
    Ed25519PublicKey.from_public_bytes(sig["public_key_bytes"]).verify(sig["signature_bytes"],b"lngnb:signature:library-core-1\0"+cbor2.dumps(body,canonical=True))
    expected_fields={"startup_state":state,"knowledge_id":text_id("kn1_",body["knowledge_id"]),
                     "genesis_id":text_id("rc1_",body["genesis_record_id"]),"revision_id":fixed["revision_id"],
                     "publisher_key_id":text_id("ky1_",hashlib.sha256(b"lngnb:key:ed25519:1\0"+sig["public_key_bytes"]).digest()),
                     "parents":str(len(body["parents"])),"origins":"unspecified" if "origins" not in body else str(len(body["origins"]))}
    expected_fields.update({"parent["+str(n)+"]":text_id("rc1_",p) for n,p in enumerate(body["parents"])})
    for n,origin in enumerate(body.get("origins",[])):
        expected_fields["origin["+str(n)+"].knowledge_id"]=text_id("kn1_",origin["knowledge_id"])
        for name,key in [("genesis_id","genesis_record_id"),("revision_id","revision_record_id")]:
            expected_fields["origin["+str(n)+"]."+name]=text_id("rc1_",origin[key]) if key in origin else "unspecified"
    lines=out.decode().splitlines()
    assert dict(line.split(": ",1) for line in lines[1:-1])==expected_fields
    assert "署名内参照" in lines[0] and "全祖先評価" in lines[-1] and "解除しません" in lines[-1]
    assert len(out)<100000 and b"record_validation:" not in out
    return out
# 初版・二分岐・merge・別初版・派生・派生の派生を明示IDで開く。全論理DB不変。
for name,rid in [("ok",base["revision_id"]),("ok",aid),("ok",bid),("ok",mid),("ok",fields(e)["revision_id"]),
                 ("derived",df["revision_id"]),("derived",df2["revision_id"]),("derived-next",fields(d3)["revision_id"])]:
    old=snapshot(name);inspect(name,fixed_in(name,rid));assert snapshot(name)==old
# 正常な保存APIで作った、Genesis/256親/本文/128由来を未保持のfixture。
for raw in saved("inspect-declarations").values():
    body=cbor2.loads(raw)["body"];rid=text_id("rc1_",hashlib.sha256(b"lngnb:record:library-core-1\0"+raw).digest())
    old=snapshot("inspect-declarations");inspect("inspect-declarations",fixed_in("inspect-declarations",rid))
    assert snapshot("inspect-declarations")==old
assert count_state("inspect-declarations")==("clean",2,0)
# 既存の手動待ちを読取り成功・出力失敗・照合失敗で解除しない。
for name in ["revision-finish","derived-finish"]:
    fixed=fixed_in(name);old=snapshot(name);inspect(name,fixed,state="manual_review_required");assert snapshot(name)==old
    err=inspect(name,fixed,expected=1,full=True);assert "読取り確認は終了" in err.decode() and snapshot(name)==old
fixed=fixed_in("ok",base["revision_id"])
for changed in [{"knowledge_id":"kn1_"+"a"*52},{"genesis_id":"rc1_"+"a"*52},
                {"revision_id":"rc1_"+"a"*52},{"revision_id":base["genesis_id"]},
                {"revision_id":other_id}]:
    old=snapshot("ok");inspect("ok",dict(fixed,**changed),expected=1);assert snapshot("ok")==old
old=snapshot("derived-finish");inspect("derived-finish",dict(fixed,revision_id="rc1_"+"a"*52),expected=1);assert snapshot("derived-finish")==old
# 不正引数は接触前。lock競合・不存在・危険pathでIPC/直接保存へ切り替えない。
for extra in [["--key-dir",str(ROOT/"missing-keys")],["--parent",parent],["--revision-id",fixed["revision_id"]]]:
    old=snapshot("ok");inspect("ok",fixed,expected=2,extra=extra);assert snapshot("ok")==old
inspect("inspect-missing",fixed,expected=1);assert not (ROOT/"inspect-missing").exists()
os.symlink(ROOT/"ok",ROOT/"inspect-linked")
old=snapshot("ok");inspect("inspect-linked",fixed,expected=1);assert snapshot("ok")==old
with open(ROOT/"ok/lock","rb") as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);inspect("ok",fixed,expected=1)
assert snapshot("ok")==old
# 停止中fixtureの明示コピーだけで未知形式・保存破損を注入する。
for name in ["inspect-old-format","inspect-corrupt"]:shutil.copytree(ROOT/"inspect-declarations",ROOT/name)
with db("inspect-old-format") as c:c.execute("PRAGMA user_version=11")
fixed_decl=fixed_in("inspect-declarations")
old=snapshot("inspect-old-format");inspect("inspect-old-format",fixed_decl,expected=1);assert snapshot("inspect-old-format")==old
with db("inspect-old-format") as c:assert c.execute("PRAGMA user_version").fetchone()==(11,)
with db("inspect-corrupt") as c:
    c.execute("DROP TRIGGER records_no_update")
    # 対象以外の破損でもopenの全局所検査を省略しない。
    c.execute("UPDATE records SET bytes=? WHERE id<>?",(b"not cbor",rawid(fixed_decl["revision_id"])))
old=snapshot("inspect-corrupt");inspect("inspect-corrupt",fixed_decl,expected=1);assert snapshot("inspect-corrupt")==old
# openが保持本文欠損を検出した停止印・履歴は残す。署名内の宣言表示とは別。
shutil.copytree(ROOT/"ok",ROOT/"inspect-blob-fault")
victim=next((ROOT/"inspect-blob-fault/blobs").iterdir());victim.unlink()
old_records=saved("inspect-blob-fault");files={p.name:p.read_bytes() for p in (ROOT/"inspect-blob-fault/blobs").iterdir()}
inspect("inspect-blob-fault",fixed,state="manual_review_required")
assert saved("inspect-blob-fault")==old_records and count_state("inspect-blob-fault")[0]=="running"
assert {p.name:p.read_bytes() for p in (ROOT/"inspect-blob-fault/blobs").iterdir()}==files
old=snapshot("inspect-blob-fault");inspect("inspect-blob-fault",fixed,state="manual_review_required");assert snapshot("inspect-blob-fault")==old
assert (ROOT/"keys/publisher").read_bytes()==original_key
print("DOCUMENT_CLI_CASES_OK")
