import os, json, time, hashlib, hmac, sqlite3, uuid, io
import httpx, jwt
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

os.makedirs("data/blobs", exist_ok=True)
SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
KEYFILE = "data/fernet.key"
if not os.path.exists(KEYFILE):
    open(KEYFILE, "wb").write(Fernet.generate_key())
F = Fernet(open(KEYFILE, "rb").read())

db = sqlite3.connect("data/dms.db", check_same_thread=False)
db.row_factory = sqlite3.Row
db.executescript("""
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, pw TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, case_id TEXT, title TEXT, version INT,
  classification TEXT, sha256 TEXT, signature TEXT, owner TEXT, created REAL, text_enc BLOB);
CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, name TEXT, category TEXT, serial TEXT,
  status TEXT, holder TEXT, case_id TEXT, created REAL);
CREATE TABLE IF NOT EXISTS custody(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT, event TEXT,
  from_holder TEXT, to_holder TEXT, note TEXT, actor TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT,
  target TEXT, ts REAL, prev TEXT, hash TEXT);
""")

PERMS = {
    "admin": {"*"},
    "officer": {"doc:w", "doc:r", "doc:restricted", "asset:w", "asset:r", "case:w", "handoff:w", "handoff:sign"},
    "clerk": {"doc:w", "doc:r", "asset:r", "case:w"},
    "prosecutor": {"doc:r", "doc:restricted", "asset:r", "handoff:w", "handoff:sign"},
    "judge": {"doc:r", "doc:restricted", "asset:r", "audit:r", "handoff:sign"},
    "auditor": {"doc:r", "asset:r", "audit:r"},
}


def pwhash(p):
    return hashlib.pbkdf2_hmac("sha256", p.encode(), b"dms-salt", 100_000).hex()


db.executescript("""
CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, title TEXT, division TEXT, priority TEXT, created REAL);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT, author TEXT, body TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS handoffs(id TEXT PRIMARY KEY, case_id TEXT, title TEXT, to_org TEXT, doc_ids TEXT,
  status TEXT, sigs TEXT, expires REAL, created REAL, created_by TEXT);
""")
for u, r in [("admin", "admin"), ("officer", "officer"), ("clerk", "clerk"), ("prosecutor", "prosecutor"),
             ("judge", "judge"), ("auditor", "auditor")]:
    db.execute("INSERT OR IGNORE INTO users VALUES(?,?,?)",
               (u, pwhash(os.getenv("DEFAULT_PASSWORD", "changeme")), r))
db.commit()


def audit(actor, action, target):
    row = db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else "0" * 64
    ts = time.time()
    h = hashlib.sha256(f"{prev}|{actor}|{action}|{target}|{ts}".encode()).hexdigest()
    db.execute("INSERT INTO audit(actor,action,target,ts,prev,hash) VALUES(?,?,?,?,?,?)",
               (actor, action, target, ts, prev, h))
    db.commit()


app = FastAPI(title="Secure Legal DMS + Police Asset Lifecycle")
bearer = HTTPBearer()


def current(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(cred.credentials, SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


def need(perm):
    def dep(u=Depends(current)):
        p = PERMS.get(u["role"], set())
        if "*" not in p and perm not in p:
            audit(u["sub"], f"DENIED {perm}", "-")
            raise HTTPException(403, "Forbidden")
        return u
    return dep


def can(u, perm):
    p = PERMS.get(u["role"], set())
    return "*" in p or perm in p


def groq(system, prompt):
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise HTTPException(503, "GROQ_API_KEY not set")
    models = [os.getenv("GROQ_MODEL")] if os.getenv("GROQ_MODEL") else \
        ["llama-3.1-8b-instant", "openai/gpt-oss-20b", "openai/gpt-oss-120b"]
    err = ""
    for m in models:
        r = httpx.post("https://api.groq.com/openai/v1/chat/completions",
                       headers={"Authorization": f"Bearer {key}"}, timeout=60,
                       json={"model": m, "temperature": 0.2,
                             "messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": prompt}]})
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        err = r.text[:200]
        if "model" not in err.lower():
            break
    raise HTTPException(502, f"Groq error: {err}")


def extract_text(name, data):
    if name.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader
            return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)[:20000]
        except Exception:
            return ""
    return data.decode("utf-8", "ignore")[:20000]


def visible(u, row):
    return row["classification"] != "restricted" or can(u, "doc:restricted")


# ---------- Auth ----------
class Login(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(b: Login):
    r = db.execute("SELECT * FROM users WHERE username=?", (b.username,)).fetchone()
    if not r or not hmac.compare_digest(r["pw"], pwhash(b.password)):
        audit(b.username, "LOGIN_FAILED", "-")
        raise HTTPException(401, "Bad credentials")
    audit(b.username, "LOGIN", "-")
    tok = jwt.encode({"sub": r["username"], "role": r["role"], "exp": time.time() + 3600}, SECRET, "HS256")
    return {"token": tok, "role": r["role"], "user": r["username"], "perms": sorted(PERMS[r["role"]])}


# ---------- Documents ----------
@app.post("/documents")
async def upload(case_id: str = Form(...), title: str = Form(...), classification: str = Form("normal"),
                 file: UploadFile = File(...), u=Depends(need("doc:w"))):
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise HTTPException(404, "Case not found - create the case first")
    data = await file.read()
    did = uuid.uuid4().hex[:12]
    ver = (db.execute("SELECT MAX(version) v FROM documents WHERE case_id=? AND title=?",
                      (case_id, title)).fetchone()["v"] or 0) + 1
    sha = hashlib.sha256(data).hexdigest()
    ts = time.time()
    sig = hmac.new(SECRET.encode(), f"{sha}|{u['sub']}|{ts}".encode(), "sha256").hexdigest()
    open(f"data/blobs/{did}.enc", "wb").write(F.encrypt(data))
    text_enc = F.encrypt(extract_text(file.filename, data).encode())
    db.execute("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?)",
               (did, case_id, title, ver, classification, sha, f"{ts}:{sig}", u["sub"], ts, text_enc))
    db.commit()
    audit(u["sub"], f"UPLOAD v{ver}", did)
    return {"id": did, "version": ver, "sha256": sha}


@app.get("/documents")
def list_docs(case_id: str | None = None, u=Depends(need("doc:r"))):
    q = "SELECT id,case_id,title,version,classification,sha256,owner,created FROM documents"
    rows = db.execute(q + (" WHERE case_id=?" if case_id else ""), (case_id,) if case_id else ()).fetchall()
    return [dict(r) for r in rows if visible(u, r)]


def get_doc(u, did):
    r = db.execute("SELECT * FROM documents WHERE id=?", (did,)).fetchone()
    if not r or not visible(u, r):
        raise HTTPException(404, "Not found")
    return r


@app.get("/documents/{did}/verify")
def verify(did: str, u=Depends(need("doc:r"))):
    r = get_doc(u, did)
    data = F.decrypt(open(f"data/blobs/{did}.enc", "rb").read())
    ok_hash = hashlib.sha256(data).hexdigest() == r["sha256"]
    ts, sig = r["signature"].split(":")
    exp = hmac.new(SECRET.encode(), f"{r['sha256']}|{r['owner']}|{ts}".encode(), "sha256").hexdigest()
    audit(u["sub"], "VERIFY", did)
    return {"hash_intact": ok_hash, "signature_valid": hmac.compare_digest(sig, exp)}


@app.get("/documents/{did}/summarize")
def summarize(did: str, u=Depends(need("doc:r"))):
    r = get_doc(u, did)
    text = F.decrypt(r["text_enc"]).decode()
    audit(u["sub"], "AI_SUMMARIZE", did)
    return {"summary": groq("You summarize legal/investigation documents concisely and factually.",
                            f"Summarize in 5 bullets:\n\n{text[:8000]}")}


@app.get("/search")
def search(q: str, ask: bool = False, u=Depends(need("doc:r"))):
    terms = q.lower().split()
    hits = []
    for r in db.execute("SELECT * FROM documents").fetchall():
        if not visible(u, r):
            continue
        text = F.decrypt(r["text_enc"]).decode()
        score = sum((text + r["title"]).lower().count(t) for t in terms)
        if score:
            hits.append((score, r, text))
    hits.sort(key=lambda x: -x[0])
    hits = hits[:5]
    audit(u["sub"], f"SEARCH:{q[:40]}", "-")
    out = {"results": [{"id": r["id"], "title": r["title"], "case_id": r["case_id"], "score": s}
                       for s, r, _ in hits]}
    if ask and hits:
        ctx = "\n\n".join(f"[{r['title']}]\n{t[:3000]}" for _, r, t in hits)
        out["answer"] = groq("Answer only from the provided case documents; cite document titles.",
                             f"Question: {q}\n\nDocuments:\n{ctx}")
    return out


# ---------- Assets ----------
class AssetIn(BaseModel):
    name: str
    category: str
    serial: str
    holder: str
    case_id: str | None = None


class Transfer(BaseModel):
    to: str
    note: str = ""


class Status(BaseModel):
    status: str  # in_custody | in_use | maintenance | seized_evidence | disposed
    note: str = ""


def event(aid, ev, frm, to, note, actor):
    db.execute("INSERT INTO custody(asset_id,event,from_holder,to_holder,note,actor,ts) VALUES(?,?,?,?,?,?,?)",
               (aid, ev, frm, to, note, actor, time.time()))
    db.commit()
    audit(actor, ev, aid)


@app.post("/assets")
def add_asset(a: AssetIn, u=Depends(need("asset:w"))):
    aid = "AST-" + uuid.uuid4().hex[:8].upper()
    db.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?)",
               (aid, a.name, a.category, a.serial, "in_custody", a.holder, a.case_id, time.time()))
    event(aid, "REGISTERED", None, a.holder, "", u["sub"])
    return {"id": aid, "qr_payload": f"dms://asset/{aid}"}


def get_asset(aid):
    r = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    if not r:
        raise HTTPException(404, "Not found")
    if r["status"] == "disposed":
        raise HTTPException(409, "Asset already disposed")
    return r


@app.post("/assets/{aid}/transfer")
def transfer(aid: str, t: Transfer, u=Depends(need("asset:w"))):
    r = get_asset(aid)
    db.execute("UPDATE assets SET holder=? WHERE id=?", (t.to, aid))
    event(aid, "TRANSFERRED", r["holder"], t.to, t.note, u["sub"])
    return {"ok": True}


@app.post("/assets/{aid}/status")
def set_status(aid: str, s: Status, u=Depends(need("asset:w"))):
    get_asset(aid)
    db.execute("UPDATE assets SET status=? WHERE id=?", (s.status, aid))
    event(aid, f"STATUS:{s.status}", None, None, s.note, u["sub"])
    return {"ok": True}


@app.get("/assets")
def list_assets(u=Depends(need("asset:r"))):
    return [dict(r) for r in db.execute("SELECT * FROM assets").fetchall()]


@app.get("/assets/{aid}/history")
def history(aid: str, u=Depends(need("asset:r"))):
    return [dict(r) for r in db.execute("SELECT * FROM custody WHERE asset_id=? ORDER BY id", (aid,))]


# ---------- Audit ----------
@app.get("/audit")
def get_audit(u=Depends(need("audit:r"))):
    return [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")]


@app.get("/audit/verify")
def verify_audit(u=Depends(need("audit:r"))):
    prev = "0" * 64
    for r in db.execute("SELECT * FROM audit ORDER BY id"):
        h = hashlib.sha256(f"{prev}|{r['actor']}|{r['action']}|{r['target']}|{r['ts']}".encode()).hexdigest()
        if r["prev"] != prev or r["hash"] != h:
            return {"intact": False, "broken_at": r["id"]}
        prev = r["hash"]
    return {"intact": True}


@app.get("/audit/insights")
def insights(u=Depends(need("audit:r"))):
    rows = db.execute("SELECT actor,action,target,ts FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    log = "\n".join(f"{r['ts']:.0f} {r['actor']} {r['action']} {r['target']}" for r in rows)
    return {"analysis": groq("You are a security auditor reviewing access logs for a law-enforcement DMS.",
                             f"Flag suspicious patterns (repeated denials, odd-hour access, mass downloads):\n{log}")}


# ---------- Cases, notes, stats ----------
class CaseIn(BaseModel):
    id: str
    title: str
    division: str = ""
    priority: str = "standard"


@app.post("/cases")
def add_case(c: CaseIn, u=Depends(need("case:w"))):
    if db.execute("SELECT 1 FROM cases WHERE id=?", (c.id,)).fetchone():
        raise HTTPException(409, "Case already exists")
    db.execute("INSERT INTO cases VALUES(?,?,?,?,?)", (c.id, c.title, c.division, c.priority, time.time()))
    db.commit()
    audit(u["sub"], "CASE_CREATED", c.id)
    return {"ok": True}


@app.get("/cases")
def list_cases(u=Depends(need("doc:r"))):
    out = []
    for c in db.execute("SELECT * FROM cases ORDER BY created DESC"):
        d = dict(c)
        d["docs"] = db.execute("SELECT COUNT(*) n FROM documents WHERE case_id=?", (c["id"],)).fetchone()["n"]
        d["assets"] = db.execute("SELECT COUNT(*) n FROM assets WHERE case_id=?", (c["id"],)).fetchone()["n"]
        out.append(d)
    return out


@app.get("/stats")
def stats(u=Depends(need("doc:r"))):
    n = lambda q: db.execute(q).fetchone()[0]
    return {"documents": n("SELECT COUNT(*) FROM documents"), "cases": n("SELECT COUNT(*) FROM cases"),
            "assets": n("SELECT COUNT(*) FROM assets WHERE status!='disposed'"),
            "custody_events": n("SELECT COUNT(*) FROM custody"), "handoffs": n("SELECT COUNT(*) FROM handoffs")}


class NoteIn(BaseModel):
    body: str


@app.post("/documents/{did}/notes")
def add_note(did: str, n: NoteIn, u=Depends(need("doc:w"))):
    get_doc(u, did)
    db.execute("INSERT INTO notes(doc_id,author,body,ts) VALUES(?,?,?,?)", (did, u["sub"], n.body, time.time()))
    db.commit()
    audit(u["sub"], "NOTE_ADDED", did)
    return {"ok": True}


@app.get("/documents/{did}/notes")
def get_notes(did: str, u=Depends(need("doc:r"))):
    get_doc(u, did)
    return [dict(r) for r in db.execute("SELECT * FROM notes WHERE doc_id=? ORDER BY id", (did,))]


@app.get("/documents/{did}/text")
def doc_text(did: str, u=Depends(need("doc:r"))):
    r = get_doc(u, did)
    audit(u["sub"], "VIEW", did)
    return {"text": F.decrypt(r["text_enc"]).decode()}


@app.get("/documents/{did}/download")
def download(did: str, u=Depends(need("doc:r"))):
    from fastapi.responses import Response
    r = get_doc(u, did)
    audit(u["sub"], "DOWNLOAD", did)
    return Response(F.decrypt(open(f"data/blobs/{did}.enc", "rb").read()),
                    headers={"Content-Disposition": f'attachment; filename="{r["title"]}"'})


# ---------- Merkle proof + court certificate ----------
def merkle(leaves):
    lvl = leaves[:] or [hashlib.sha256(b"").hexdigest()]
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        lvl = [hashlib.sha256((lvl[i] + lvl[i + 1]).encode()).hexdigest() for i in range(0, len(lvl), 2)]
    return lvl[0]


@app.get("/audit/merkle")
def audit_merkle(target: str | None = None, u=Depends(need("audit:r"))):
    rows = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id")]
    return {"root": merkle([r["hash"] for r in rows]), "leaves": len(rows),
            "entries": [r for r in rows if target and r["target"] == target]}


@app.get("/documents/{did}/certificate")
def certificate(did: str, u=Depends(need("doc:r"))):
    from fastapi.responses import HTMLResponse
    r = get_doc(u, did)
    v = verify(did, u)
    ev = [dict(x) for x in db.execute("SELECT * FROM audit WHERE target=? ORDER BY id", (did,))]
    root = merkle([x["hash"] for x in db.execute("SELECT hash FROM audit ORDER BY id")])
    rows = "".join(f"<tr><td>{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(e['ts']))}</td><td>{e['actor']}</td>"
                   f"<td>{e['action']}</td><td>{e['hash'][:16]}...</td></tr>" for e in ev)
    ok = v["hash_intact"] and v["signature_valid"]
    audit(u["sub"], "CERTIFICATE", did)
    return HTMLResponse(f"""<html><body style="font-family:sans-serif;max-width:760px;margin:40px auto">
<h2>Evidence Integrity Certificate</h2><p><b>{r['title']}</b> (v{r['version']}) - case {r['case_id']}</p>
<p>SHA-256: <code>{r['sha256']}</code></p>
<p>Status: <b style="color:{'green' if ok else 'red'}">{'INTACT - hash and signature verified' if ok else 'TAMPERING DETECTED'}</b></p>
<p>Audit Merkle root: <code>{root}</code></p><h3>Custody events</h3>
<table border=1 cellpadding=6 cellspacing=0><tr><th>UTC</th><th>Actor</th><th>Action</th><th>Ledger hash</th></tr>{rows}</table>
<p style="color:#666">Issued to {u['sub']} at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC. Print to PDF to file.</p>
</body></html>""")


# ---------- Inter-agency handoffs ----------
SIGN_ROLES = ["officer", "prosecutor", "judge"]
STAGES = ["Police finalization", "Prosecution review", "Court docketing", "Defense disclosure"]


class HandoffIn(BaseModel):
    case_id: str
    title: str
    to_org: str
    doc_ids: list[str]
    hours: int = 72


def h_view(r):
    d = dict(r)
    sigs = json.loads(d["sigs"])
    d["sigs"], d["doc_ids"] = sigs, json.loads(d["doc_ids"])
    d["stage"] = len(sigs)
    d["stage_name"] = STAGES[len(sigs)]
    d["next_signer"] = SIGN_ROLES[len(sigs)] if len(sigs) < 3 else None
    if d["status"] == "active" and len(sigs) < 3 and time.time() > d["expires"]:
        d["status"] = "expired"
    return d


def h_get(hid):
    r = db.execute("SELECT * FROM handoffs WHERE id=?", (hid,)).fetchone()
    if not r:
        raise HTTPException(404, "Not found")
    return r


@app.post("/handoffs")
def new_handoff(h: HandoffIn, u=Depends(need("handoff:w"))):
    for d in h.doc_ids:
        get_doc(u, d)
    hid = "PKG-" + uuid.uuid4().hex[:8].upper()
    db.execute("INSERT INTO handoffs VALUES(?,?,?,?,?,?,?,?,?,?)",
               (hid, h.case_id, h.title, h.to_org, json.dumps(h.doc_ids), "active", "[]",
                time.time() + h.hours * 3600, time.time(), u["sub"]))
    db.commit()
    audit(u["sub"], "HANDOFF_CREATED", hid)
    return {"id": hid}


@app.get("/handoffs")
def list_handoffs(u=Depends(need("doc:r"))):
    return [h_view(r) for r in db.execute("SELECT * FROM handoffs ORDER BY created DESC")]


@app.post("/handoffs/{hid}/sign")
def sign_handoff(hid: str, u=Depends(need("handoff:sign"))):
    d = h_view(h_get(hid))
    if d["status"] != "active" or d["next_signer"] is None:
        raise HTTPException(409, f"Package is {d['status']}")
    if u["role"] != d["next_signer"]:
        raise HTTPException(403, f"Next signature must come from role: {d['next_signer']}")
    hashes = []
    for did in d["doc_ids"]:
        row = db.execute("SELECT sha256 FROM documents WHERE id=?", (did,)).fetchone()
        data = F.decrypt(open(f"data/blobs/{did}.enc", "rb").read())
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            audit(u["sub"], "HANDOFF_BLOCKED_TAMPER", hid)
            raise HTTPException(409, f"Document {did} failed integrity check")
        hashes.append(row["sha256"])
    ts = time.time()
    sig = hmac.new(SECRET.encode(), f"{hid}|{u['sub']}|{ts}|{'|'.join(hashes)}".encode(), "sha256").hexdigest()
    d["sigs"].append({"user": u["sub"], "role": u["role"], "ts": ts, "sig": sig})
    db.execute("UPDATE handoffs SET sigs=? WHERE id=?", (json.dumps(d["sigs"]), hid))
    db.commit()
    audit(u["sub"], f"HANDOFF_SIGNED:{u['role']}", hid)
    return {"stage": len(d["sigs"]), "sig": sig}


@app.post("/handoffs/{hid}/revoke")
def revoke_handoff(hid: str, u=Depends(need("handoff:w"))):
    h_get(hid)
    db.execute("UPDATE handoffs SET status='revoked' WHERE id=?", (hid,))
    db.commit()
    audit(u["sub"], "HANDOFF_REVOKED", hid)
    return {"ok": True}


# ---------- Access control admin ----------
@app.get("/rbac")
def rbac(u=Depends(need("admin"))):
    return {"perms": {k: sorted(v) for k, v in PERMS.items()},
            "users": [dict(r) for r in db.execute("SELECT username, role FROM users")]}


class RoleIn(BaseModel):
    role: str


@app.post("/users/{name}/role")
def set_role(name: str, b: RoleIn, u=Depends(need("admin"))):
    if b.role not in PERMS:
        raise HTTPException(400, "Unknown role")
    db.execute("UPDATE users SET role=? WHERE username=?", (b.role, name))
    db.commit()
    audit(u["sub"], f"ROLE_CHANGED:{b.role}", name)
    return {"ok": True}


# ---------- Frontend ----------
from fastapi.staticfiles import StaticFiles  # noqa: E402
os.makedirs("static", exist_ok=True)
app.mount("/", StaticFiles(directory="static", html=True), name="ui")