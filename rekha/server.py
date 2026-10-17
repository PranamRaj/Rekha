"""Live challenge + dashboard (stdlib only).  python -m rekha.server  ->  http://localhost:8000"""
import json, os, threading, time, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from . import config
from .gateway import Gateway, L, PV
from .agent import propose
from . import redteam

STATIC_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "static"))
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".json": "application/json", ".png": "image/png", ".woff2": "font/woff2"}
S = {"g": None, "receipts": {}, "tokens": {}, "score": {}, "suite": None, "lock": threading.Lock()}

def static_file(url_path):
    """Serve ./static, refusing anything that escapes it."""
    rel = "index.html" if url_path in ("/", "") else url_path.lstrip("/")
    full = os.path.realpath(os.path.join(STATIC_DIR, rel))
    if full != STATIC_DIR and not full.startswith(STATIC_DIR + os.sep): return None, None
    if not os.path.isfile(full): return None, None
    return open(full, "rb").read(), MIME.get(os.path.splitext(full)[1].lower(), "application/octet-stream")

def reset():
    old = S.get("g")
    if old: old.close()              # release the file before rebuilding it on the same path
    S["g"] = Gateway(config.db_path())
    S["receipts"], S["tokens"] = {}, {}
    S["score"] = {"attempts": 0, "fooled": 0, "proposals": 0, "blocked": 0, "reviewed": 0, "allowed": 0}
    S.pop("anchor", None)
reset()

def chat(b):
    g, cfg = S["g"], b.get("config", "D")
    cust = b.get("customer_id", "c1"); order = b.get("order_id", "o1001")
    allowed = [order]; ticket = b.get("ticket", "")
    sid, tok = g.new_session(cfg, cust, ticket, allowed, b.get("external") and [b["external"]])
    props = propose(ticket, order, cust, [o["id"] for o in g.db.c().execute("SELECT id FROM orders WHERE customer_id=?", (cust,))])
    trace = []; S["score"]["attempts"] += 1
    fooled = False
    for tool, args, f, note in props:
        S["score"]["proposals"] += 1; fooled = fooled or f
        d = g.call(cfg, tok, tool, args)
        S["score"]["blocked" if d["verdict"] == "BLOCK" else "reviewed" if d["verdict"] == "REVIEW" else "allowed"] += 1
        if d.get("review_id"): S["tokens"][d["review_id"]] = tok
        trace.append({"tool": tool, "args": args, "note": note, "fooled": f, "verdict": d["verdict"], "rule": d["rule"], "reason": d["reason"],
                      "agent_message": d["agent_message"], "review_id": d.get("review_id"), "ms": round(d["ms"], 2)})
    S["score"]["fooled"] += 1 if fooled else 0
    return {"session": sid, "trace": trace, "quarantined": g.session(sid)["status"] == "QUARANTINED"}

def state():
    g = S["g"]; c = g.db.c(); viol = redteam.violations(g)
    reviews = [{"id": r["id"], "tool": r["tool"], "status": r["status"], "config": r["config"], "card": json.loads(r["card"]), "args": json.loads(r["args"])}
               for r in c.execute("SELECT * FROM reviews ORDER BY rowid DESC LIMIT 8")]
    plain = [{**json.loads(r["event"]), "seq": "-"} for r in c.execute("SELECT event FROM plainlog ORDER BY id DESC LIMIT 20")]
    refunds = [dict(r) for r in c.execute("SELECT order_id,amount_paise,destination,status,auth FROM refunds WHERE status!='released' ORDER BY id DESC LIMIT 12")]
    return {"audit": g.audit.rows(25), "plainlog": plain, "reviews": reviews, "refunds": refunds, "score": {**S["score"], "money_wrong": len(viol), "violations": sorted({k for k, _ in viol})},
            "verify": g.audit.verify(), "sessions": [dict(s) for s in c.execute("SELECT id,customer_id,status,blocks,config FROM sessions ORDER BY rowid DESC LIMIT 6")]}

def approve(b):
    g = S["g"]; a = g.approve(b["review_id"], b.get("approver_token", ""), b.get("confirm"))
    S["receipts"][b["review_id"]] = a; return {"ok": True, "fast_flag": a.get("fast_flag", False)}

def execute(b):
    g = S["g"]; rid = b["review_id"]; r = g.db.c().execute("SELECT * FROM reviews WHERE id=?", (rid,)).fetchone(); a = S["receipts"].get(rid)
    if not a: return {"executed": False, "reason": "no approval yet"}
    args = json.loads(r["args"]); mode = b.get("mode", "normal")
    if mode == "tamper" and "amount_paise" in args: args["amount_paise"] = min(args["amount_paise"] * 3, 2500000)
    return g.execute_approved(r["config"], r["tool"], args, receipt=a.get("receipt"), approval_id=a.get("approval_id"), token=S["tokens"].get(rid))

def tamper(b):
    c = S["g"].db.c(); m = b["mode"]; n = c.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    if n < 4: return {"msg": "run a few requests first"}
    if m == "anchor": S["anchor"] = S["g"].audit.anchor(); return {"msg": "anchor exported (head hash signed)"}
    if m == "edit":
        # flip a verdict inside a logged event. Whichever way round the chain is,
        # one of these changes a row -- otherwise the demo silently does nothing
        # and "verify" truthfully reports an intact chain.
        row = c.execute("SELECT seq,event FROM audit ORDER BY seq LIMIT 1 OFFSET 2").fetchone()
        if not row: return {"msg": "run a few requests first"}
        ev = row["event"]
        flipped = ev.replace('"BLOCK"', '"ALLOW"') if '"BLOCK"' in ev else ev.replace('"ALLOW"', '"BLOCK"')
        if flipped == ev: return {"msg": "no verdict to flip in that row"}
        c.execute("UPDATE audit SET event=? WHERE seq=?", (flipped, row["seq"]))
        return {"msg": "tampered: edit (a logged verdict was rewritten in place)"}
    if m == "delete": c.execute("DELETE FROM audit WHERE seq=(SELECT seq FROM audit ORDER BY seq LIMIT 1 OFFSET 2)")
    if m == "truncate": c.execute("DELETE FROM audit WHERE seq>(SELECT seq FROM audit ORDER BY seq LIMIT 1 OFFSET ?)", (n - 3,))
    return {"msg": f"tampered: {m}"}

def ui_config():
    """Values the dashboard needs so nothing policy-shaped is hardcoded in the JS.
    The approver token is here because in this demo the browser *is* the approver
    console; a real deployment would authenticate the human instead (see README)."""
    return {"approver_token": config.s("REKHA_DEMO_APPROVER_TOKEN", "tok-ops-priya"),
            "policy_version": PV, "auto_max_paise": L["auto_max_paise"],
            "customer_24h_paise": L["customer_24h_paise"], "bulk_max": L["bulk_max"],
            "velocity_per_hour": L["velocity_per_hour"]}

def suite(_):
    out = redteam.run_all(); S["suite"] = out
    s = redteam.summarise(out); return {"summary": s, "tamper": out["tamper"], "latency": out["latency"], "md": redteam.to_markdown(out)}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")      # edit app.js, hit reload, see it
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/api/state": return self.send(200, state())
        if p == "/api/config": return self.send(200, ui_config())
        if p == "/api/verify":
            r = S["g"].audit.verify(S.get("anchor")); return self.send(200, r)
        if p.startswith("/api/"): return self.send(404, {"error": "not found"})
        body, ctype = static_file(p)
        if body is None: return self.send(404, {"error": "not found"})
        self.send(200, body, ctype)
    def do_POST(self):
        p = urlparse(self.path).path; n = int(self.headers.get("Content-Length", 0) or 0)
        b = json.loads(self.rfile.read(n) or b"{}")
        routes = {"/api/chat": chat, "/api/approve": approve, "/api/execute": execute, "/api/tamper": tamper, "/api/suite": suite, "/api/reset": lambda b: (reset(), {"ok": True})[1]}
        try:
            with S["lock"] if p in ("/api/suite", "/api/reset") else threading.Lock(): self.send(200, routes[p](b))
        except KeyError: self.send(404, {"error": "not found"})
        except Exception as e: self.send(400, {"error": str(e), "trace": traceback.format_exc()[-300:]})

if __name__ == "__main__":
    host, port = config.s("REKHA_HOST", "127.0.0.1"), config.i("REKHA_PORT", config.i("PORT", 8000))
    print(f"Rekha live challenge on http://localhost:{port}")
    print(f"  database {config.db_path()}  ·  policy {PV}  ·  Ctrl+C to stop")
    try:
        ThreadingHTTPServer((host, port), H).serve_forever()
    except OSError as e:
        raise SystemExit(f"cannot bind {host}:{port} — {e}. Another server is probably running; "
                         f"stop it or set REKHA_PORT to a free port.")
    except KeyboardInterrupt:
        S["g"].close(); print("\nstopped")
