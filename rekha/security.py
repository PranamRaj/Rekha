"""Normaliser, provenance registry, tamper-evident audit chain, scope tokens, signed approval receipts."""
import hashlib, hmac, json, time, unicodedata, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from . import config

def canonical(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def sha(s): return hashlib.sha256(s.encode()).hexdigest()

# ---------- normaliser (used for TAINT matching only, never to grant trust) ----------
CONF = str.maketrans({"а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ѕ":"s","ј":"j","ԁ":"d","һ":"h",
                      "ɡ":"g","ⅼ":"l","ο":"o","ν":"v","α":"a","ι":"i","κ":"k","ɑ":"a","ɩ":"l","0":"o","1":"l"})
def normalise(s: str) -> str:
    s = unicodedata.normalize("NFKC", str(s))
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cf", "Cc", "Zs") )
    s = s.casefold().translate(CONF)
    return s

# ---------- provenance ----------
TRUSTED_SRC = {"SYSTEM_RECORD", "OPERATOR"}
UNTRUSTED_SRC = {"CUSTOMER_INPUT", "EXTERNAL"}

def register(db, session_id, source, text):
    db.c().execute("INSERT INTO registry(session_id,source,text) VALUES(?,?,?)", (session_id, source, text))

def untrusted_blob(db, session_id):
    rows = db.c().execute("SELECT text FROM registry WHERE session_id=? AND source IN ('CUSTOMER_INPUT','EXTERNAL')", (session_id,)).fetchall()
    return normalise(" ".join(r["text"] for r in rows))

def classify(db, session_id, value, trusted_values):
    """TRUSTED: exact match to system record. TAINTED: appears in untrusted content (after normalisation) or is a
    look-alike of a trusted value. UNKNOWN: neither (model rewrote it) -> fail closed."""
    if value in trusted_values: return "TRUSTED"
    nv = normalise(value)
    if nv and nv in {normalise(t) for t in trusted_values}: return "TAINTED"   # spoof of a trusted value
    if nv and nv in untrusted_blob(db, session_id): return "TAINTED"
    return "UNKNOWN"

# ---------- scope tokens ----------
class Scope:
    def __init__(self): self.key = secrets.token_bytes(32)
    def mint(self, customer_id, allowed, ticket_id, session_id, ttl=None):
        ttl = config.i("REKHA_SCOPE_TTL_SECONDS", 3600) if ttl is None else ttl
        p = canonical({"customer_id": customer_id, "allowed": sorted(allowed), "ticket_id": ticket_id,
                       "session_id": session_id, "exp": time.time() + ttl})
        return p.encode().hex() + "." + hmac.new(self.key, p.encode(), "sha256").hexdigest()
    def verify(self, token):
        try:
            h, sig = token.split("."); p = bytes.fromhex(h)
            if not hmac.compare_digest(sig, hmac.new(self.key, p, "sha256").hexdigest()): return None
            d = json.loads(p)
            return d if d["exp"] > time.time() else None
        except Exception: return None

# ---------- tamper-evident audit chain ----------
GENESIS = "0" * 64
class Audit:
    def __init__(self, db, anchor_key): self.db, self.ak = db, anchor_key
    def append(self, event: dict):
        with self.db.tx() as c:                                    # BEGIN IMMEDIATE serialises chain writers
            row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            ev = canonical(event); ts = time.time()
            h = sha(prev + ev)
            c.execute("INSERT INTO audit(ts,event,prev_hash,hash) VALUES(?,?,?,?)", (ts, ev, prev, h))
    def verify(self, anchor=None):
        prev, n = GENESIS, 0
        for r in self.db.c().execute("SELECT * FROM audit ORDER BY seq"):
            if r["prev_hash"] != prev or sha(prev + r["event"]) != r["hash"]:
                return {"ok": False, "broken_at_seq": r["seq"], "checked": n}
            prev, n = r["hash"], n + 1
        if anchor:
            if n < anchor["count"]: return {"ok": False, "broken_at_seq": "tail truncated", "checked": n}
            r = self.db.c().execute("SELECT hash FROM audit ORDER BY seq LIMIT 1 OFFSET ?", (anchor["count"] - 1,)).fetchone()
            if not r or r["hash"] != anchor["head"]: return {"ok": False, "broken_at_seq": "anchor mismatch", "checked": n}
        return {"ok": True, "checked": n, "head": prev}
    def anchor(self):
        r = self.verify(); body = {"count": r["checked"], "head": r.get("head", GENESIS)}
        sig = self.ak.sign(canonical(body).encode()).hex()
        return {**body, "sig": sig}
    def rows(self, limit=60):
        out = []
        for r in self.db.c().execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)):
            out.append({"seq": r["seq"], "ts": r["ts"], "hash": r["hash"][:12], **json.loads(r["event"])})
        return out

# ---------- approval receipts ----------
APPROVERS = config.approvers()          # from REKHA_APPROVERS; demo token table, not real auth
RUBBER_STAMP_SECONDS = config.f("REKHA_RUBBER_STAMP_SECONDS", 2.0)
class ApprovalService:
    """Only component holding the Ed25519 signing key. Authenticates the human approver."""
    def __init__(self, ttl=None):
        self.key = Ed25519PrivateKey.generate(); self.pub = self.key.public_key()
        self.ttl = config.i("REKHA_RECEIPT_TTL_SECONDS", 300) if ttl is None else ttl
    def issue(self, review: dict, approver_token: str, fast: bool):
        approver = APPROVERS.get(approver_token)
        if not approver: raise PermissionError("unknown approver")
        payload = {"review_id": review["review_id"], "tool": review["tool"], "args": review["args"], "resource_id": review["resource_id"],
                   "resource_version": review["resource_version"], "policy_version": review["policy_version"],
                   "session_id": review["session_id"], "agent_id": "support-agent-1", "approver_id": approver,
                   "nonce": secrets.token_hex(12), "expires_at": time.time() + self.ttl}
        digest = sha(canonical(payload))
        return {"payload": payload, "sig": self.key.sign(digest.encode()).hex()}

def verify_receipt(pub, receipt, tool, args, resource_id, current_version):
    p = receipt.get("payload", {})
    try: pub.verify(bytes.fromhex(receipt["sig"]), sha(canonical(p)).encode())
    except (InvalidSignature, KeyError, ValueError): return False, "R1 bad signature"
    if p.get("tool") != tool or canonical(p.get("args")) != canonical(args) or p.get("resource_id") != resource_id:
        return False, "R2 receipt does not match the action (tool/args/resource changed)"
    if p.get("expires_at", 0) < time.time(): return False, "R3 receipt expired"
    if p.get("resource_version") != current_version: return False, "R4 record changed since approval"
    return True, "ok"
