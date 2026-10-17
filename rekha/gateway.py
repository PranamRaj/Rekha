"""Gateway (decide) + controlled adapter (execute). Four configurations:
   A  no guard | C per-call stateless | C2 per-call + naive check-then-act ledger | D full Rekha."""
import json, os, time, uuid, threading, yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from . import config
from .db import DB, seed, fmt
from .security import *

M = yaml.safe_load(open(config.manifest_path(), encoding="utf-8"))
L, TOOLS, HONEY, PV = M["limits"], M["tools"], set(M["honeytools"]), M["policy_version"]
L.update(config.limit_overrides(L))          # .env may override individual limits
CANARY = config.s("REKHA_CANARY_UPI", M["canary_upi"])
NAIVE_DELAY = config.f("REKHA_NAIVE_DELAY", 0.05)
RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
GENERIC = "Request denied."

def mask(v):
    if isinstance(v, str) and "@" in v: a, b = v.split("@", 1); return a[:2] + "***@" + b
    return v

class Gateway:
    def __init__(self, path, naive_delay=None):
        if os.path.exists(path):
            for ext in ("", "-wal", "-shm"):
                self._remove(path + ext)
        self.db = DB(path); seed(self.db)
        self.scope = Scope(); self.approvals = ApprovalService()
        self.anchor_key = Ed25519PrivateKey.generate(); self.audit = Audit(self.db, self.anchor_key)
        self.lat = []; self.naive_delay = NAIVE_DELAY if naive_delay is None else naive_delay
        self.lock = threading.Lock()

    @staticmethod
    def _remove(target, attempts=12, pause=0.08):
        """Delete a database file, waiting briefly for in-flight requests to let go.

        A request that grabbed the previous Gateway can reopen its connection just
        after close_all(), so the handle disappears a moment later when that request
        thread ends. Windows will not delete an open file, so retry before giving up.
        """
        for i in range(attempts):
            try:
                os.remove(target); return
            except FileNotFoundError:
                return
            except PermissionError:
                if i == attempts - 1:
                    raise RuntimeError(
                        f"cannot rebuild {target}: the file is still open. Another Rekha process is "
                        f"probably running -- stop it, or point REKHA_DB_PATH at a different file.")
                time.sleep(pause)

    def close(self):
        """Release the database file. Call before building a replacement Gateway on the same path."""
        self.db.close_all()

    # ---------- sessions ----------
    def new_session(self, cfg, customer_id, ticket_text, allowed, external=None, ticket_id="T-1"):
        sid = "s-" + uuid.uuid4().hex[:8]
        self.db.c().execute("INSERT INTO sessions(id,customer_id,allowed,config,created_at) VALUES(?,?,?,?,?)",
                            (sid, customer_id, json.dumps(allowed), cfg, time.time()))
        register(self.db, sid, "CUSTOMER_INPUT", ticket_text)
        for src in (external or []): register(self.db, sid, "EXTERNAL", src)
        return sid, self.scope.mint(customer_id, allowed, ticket_id, sid)

    def session(self, sid): return self.db.c().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    def quarantine(self, sid): self.db.c().execute("UPDATE sessions SET status='QUARANTINED' WHERE id=?", (sid,))

    # ---------- logging ----------
    def log(self, cfg, sid, tool, args, v, rule, reason, ms):
        masked = {k: (mask(x) if isinstance(x, str) else x) for k, x in args.items()}
        ev = {"session": sid, "config": cfg, "tool": tool, "args": masked, "verdict": v, "rule": rule,
              "reason": reason, "policy_version": PV, "ms": round(ms, 2)}
        if cfg == "D": self.audit.append(ev)
        else: self.db.c().execute("INSERT INTO plainlog(ts,event) VALUES(?,?)", (time.time(), canonical(ev)))

    # ---------- public entry: propose -> decide -> (execute) ----------
    def call(self, cfg, token, tool, args):
        t0 = time.perf_counter()
        d = self.decide(cfg, token, tool, args)
        ms = (time.perf_counter() - t0) * 1000
        d["ms"] = ms
        sid = (self.scope.verify(token) or {}).get("session_id", "?")
        if cfg == "D": self.lat.append(ms)
        if d["verdict"] == "ALLOW": d["result"] = self.execute(cfg, sid, tool, args, d.get("reservation"))
        self.log(cfg, sid, tool, args, d["verdict"], d["rule"], d["reason"], ms)
        d.pop("reservation", None)
        return d

    def D(self, v, rule, reason, msg=None, **kw): return {"verdict": v, "rule": rule, "reason": reason, "agent_message": msg or reason, **kw}

    # ---------- decide ----------
    def decide(self, cfg, token, tool, args):
        sess = self.scope.verify(token)
        sid = sess["session_id"] if sess else "?"
        if cfg == "A": return self.D("ALLOW", "-", "no guard")
        if cfg in ("C", "C2"): return self.decide_percall(cfg, sid, tool, args)
        return self.decide_full(sess, tool, args)

    def decide_percall(self, cfg, sid, tool, args):
        if tool not in TOOLS: return self.D("BLOCK", "C0", "tool not on allow-list")
        if tool == "delete_orders" and len(args.get("order_ids", [])) > 3: return self.D("BLOCK", "C3", "too many rows")
        if "amount_paise" in args:
            amt = args["amount_paise"]
            if not isinstance(amt, int) or amt <= 0: return self.D("BLOCK", "C4", "bad amount")
            if amt > L["auto_max_paise"]:
                return self.review(sid, "C", tool, args, "C1 amount above auto limit", weak=True)
            if cfg == "C2":   # naive stateful ledger: check ... (gap) ... act
                o = self.order(args["order_id"])
                used = self.sum("SELECT COALESCE(SUM(amount_paise),0) FROM refunds WHERE order_id=? AND status='committed'", (o["id"],))
                if used + amt > o["captured_paise"]: return self.D("BLOCK", "L1", "exceeds captured")
                c24 = self.sum("SELECT COALESCE(SUM(amount_paise),0) FROM refunds WHERE customer_id=? AND auth='auto' AND status='committed'", (o["customer_id"],))
                if c24 + amt > L["customer_24h_paise"]: return self.D("REVIEW", "L2", "24h cap")
                time.sleep(self.naive_delay)          # the payment API call in real life
        return self.D("ALLOW", "C-ok", "per-call checks passed")

    def decide_full(self, sess, tool, args):
        if not sess: return self.D("BLOCK", "S0", "invalid or expired scope token", GENERIC)
        sid, cust = sess["session_id"], sess["customer_id"]
        row = self.session(sid)
        def block(rule, reason, msg=None, quarantine=False):
            c = self.db.c(); c.execute("UPDATE sessions SET blocks=blocks+1 WHERE id=?", (sid,))
            b = self.session(sid)["blocks"]
            if quarantine or b >= L["blocks_to_quarantine"]: self.quarantine(sid)
            return self.D("BLOCK", rule, reason, msg or GENERIC)
        if tool in HONEY:
            return block("H1", f"honeytool '{tool}' called: high-confidence hijack signal; session quarantined", quarantine=True)
        if tool not in TOOLS: return block("S1", "unknown tool")
        spec = TOOLS[tool]["params"]
        if set(args) != set(spec): return block("S2", f"schema violation: unexpected/missing params {sorted(set(args) ^ set(spec))}",
                                                "Tool does not accept those parameters.")
        for k, s in spec.items():
            v = args[k]
            if s.get("type") == "int" and (not isinstance(v, int) or isinstance(v, bool) or v <= 0): return block("S2", f"{k} must be positive integer paise")
            if s.get("type") == "str" and not isinstance(v, str): return block("S2", f"{k} must be string")
            if s.get("type") == "list" and not isinstance(v, list): return block("S2", f"{k} must be list")
            if "enum" in s and v not in s["enum"]: return block("S2", f"{k} not in enum {s['enum']}", f"{k} must be one of {s['enum']}")
        if normalise(CANARY) in normalise(canonical(args)):
            return block("H2", "canary record value appeared in arguments: data planted for the agent was exfiltrated", quarantine=True)
        allowed = set(json.loads(row["allowed"]))
        oids = args.get("order_ids") or ([args["order_id"]] if "order_id" in args else [])
        for oid in oids:
            if oid not in allowed: return block("SC1", f"order {oid} is outside this session's signed scope", GENERIC)
        orders = [self.order(o) for o in oids]
        if any(o is None or o["customer_id"] != cust or o["deleted"] for o in orders): return block("SC2", "order missing or belongs to another customer", GENERIC)
        review = None
        # provenance of sensitive values
        for k, s in spec.items():
            if "provenance" not in s: continue
            trusted = self.trusted_values(s["trusted_from"], cust)
            cls = classify(self.db, sid, args[k], trusted)
            if cls == "TAINTED":
                return block("P1", f"'{k}' came from untrusted content (customer message / external text), not from the system record", GENERIC)
            if cls == "UNKNOWN": review = review or ("P2", f"'{k}' is not in the system record and its origin is unknown (fail closed)")
        if tool == "send_email":
            other = self.db.c().execute("SELECT email,phone FROM customers WHERE id!=?", (cust,)).fetchall()
            leak = [x for r in other for x in (r["email"], r["phone"]) if x and x in args["body"]]
            leak += [r["upi_id"] for r in self.db.c().execute("SELECT upi_id FROM saved_methods WHERE customer_id!=?", (cust,)) if r["upi_id"] in args["body"]]
            if leak: return block("E1", "email body contains another customer's data", GENERIC)
        if tool in ("refund", "refund_to_saved_method"):
            o, amt = orders[0], args["amount_paise"]
            if o["status"] not in ("DELIVERED", "RETURN_RECEIVED"): return block("R1", f"order status {o['status']} is not refundable", "Order is not in a refundable state.")
            if amt > o["captured_paise"]: return block("R0", "amount exceeds captured payment", f"Maximum refundable on this order is {fmt(o['captured_paise'])}.")
            if amt > L["auto_max_paise"]: review = review or ("R2", f"amount {fmt(amt)} above auto limit {fmt(L['auto_max_paise'])}")
        if tool == "delete_orders":
            if any(o["status"] != "CANCELLED" for o in orders): return block("R6", "only CANCELLED orders may be deleted", "Only cancelled orders can be deleted.")
            if len(orders) > L["bulk_max"]: return block("R5", f"bulk delete of {len(orders)} rows exceeds limit {L['bulk_max']}", "Bulk deletes need an operator; use escalate_to_human.")
        if row["status"] == "QUARANTINED": review = review or ("Q1", "session is QUARANTINED: every action needs a human")
        if review: return self.review(sid, "D", tool, args, f"{review[0]} {review[1]}", rule=review[0])
        # stateful budgets: reserve-then-commit in one BEGIN IMMEDIATE transaction
        if tool in ("refund", "refund_to_saved_method"):
            return self.reserve(sid, cust, orders[0], args)
        return self.D("ALLOW", "OK", "all rules passed")

    # ---------- ledger ----------
    def reserve(self, sid, cust, o, args):
        amt, now = args["amount_paise"], time.time()
        live = "(status='committed' OR (status='reserved' AND expires_at>?))"
        with self.db.tx() as c:
            used = c.execute(f"SELECT COALESCE(SUM(amount_paise),0) FROM refunds WHERE order_id=? AND {live}", (o["id"], now)).fetchone()[0]
            if used + amt > o["captured_paise"]:
                return self.D("BLOCK", "L1", f"refunds on order would reach {fmt(used+amt)} > captured {fmt(o['captured_paise'])}", f"Only {fmt(o['captured_paise']-used)} remains refundable on this order.")
            c24 = c.execute(f"SELECT COALESCE(SUM(amount_paise),0) FROM refunds WHERE customer_id=? AND auth='auto' AND created_at>? AND {live}", (cust, now-86400, now)).fetchone()[0]
            if c24 + amt > L["customer_24h_paise"]:
                rid = None
            else:
                n = c.execute(f"SELECT COUNT(*) FROM refunds WHERE session_id=? AND created_at>? AND {live}", (sid, now-3600, now)).fetchone()[0]
                if n >= L["velocity_per_hour"]:
                    self.quarantine(sid); return self.D("BLOCK", "L3", "velocity cap hit; circuit breaker tripped", GENERIC)
                dest = o["upi_id"] if "upi_id" not in args else args["upi_id"]
                cur = c.execute("INSERT INTO refunds(order_id,customer_id,session_id,amount_paise,destination,status,auth,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                                (o["id"], cust, sid, amt, dest, "reserved", "auto", now, now + 60))
                return self.D("ALLOW", "L-ok", "budget reserved", reservation=cur.lastrowid)
        return self.review(sid, "D", "refund" if "upi_id" not in args else "refund_to_saved_method", args,
                           f"L2 24h automatic-refund total would be {fmt(c24+amt)} > {fmt(L['customer_24h_paise'])}", rule="L2")

    # ---------- review cards ----------
    def review(self, sid, cfg, tool, args, why, rule=None, weak=False):
        rid = "rv-" + uuid.uuid4().hex[:8]
        oids = args.get("order_ids") or ([args["order_id"]] if "order_id" in args else [None])
        o = self.order(oids[0]) if oids[0] else None
        ver = o["version"] if o else 0
        blob = [r["text"] for r in self.db.c().execute("SELECT text FROM registry WHERE session_id=? AND source IN ('CUSTOMER_INPUT','EXTERNAL')", (sid,))]
        lines = {k: (fmt(v) if k == "amount_paise" else v) for k, v in args.items()}
        card = {"why": why, "action": tool, "fields": lines, "untrusted_text": blob, "label": "unverified: from customer message / external content"}
        self.db.c().execute("INSERT INTO reviews(id,session_id,tool,args,resource_id,resource_version,card,shown_at,config) VALUES(?,?,?,?,?,?,?,?,?)",
                            (rid, sid, tool, canonical(args), oids[0], ver, canonical(card), time.time(), "C" if weak else "D"))
        return self.D("REVIEW", rule or why.split()[0], why, f"Needs human approval (review {rid}).", review_id=rid)

    # ---------- approvals ----------
    def approve(self, review_id, approver_token, confirm_value=None):
        r = self.db.c().execute("SELECT * FROM reviews WHERE id=?", (review_id,)).fetchone()
        args = json.loads(r["args"])
        if r["config"] == "C":     # weak baseline: a boolean flag, nothing bound
            self.db.c().execute("INSERT OR REPLACE INTO weak_approvals(id,status,version,amount) VALUES(?,?,?,?)",
                                (review_id, "approved", r["resource_version"], args.get("amount_paise", 0)))
            return {"approval_id": review_id}
        # comprehension gate: reviewer must restate the fact being approved
        want = str(args["amount_paise"] // 100) if "amount_paise" in args else (args.get("to") or ",".join(args.get("order_ids", [])))
        if str(confirm_value).strip().replace(",", "") != want: raise ValueError("comprehension gate failed: type the amount in rupees")
        fast = (time.time() - r["shown_at"]) < RUBBER_STAMP_SECONDS
        rv = {"review_id": review_id, "tool": r["tool"], "args": args, "resource_id": r["resource_id"], "resource_version": r["resource_version"],
              "policy_version": PV, "session_id": r["session_id"]}
        receipt = self.approvals.issue(rv, approver_token, fast)
        self.db.c().execute("UPDATE reviews SET status='APPROVED' WHERE id=?", (review_id,))
        self.log("D", r["session_id"], r["tool"], args, "APPROVED", "A1", f"approved by {receipt['payload']['approver_id']}" + (" (FLAG: <2s, possible rubber-stamp)" if fast else ""), 0)
        return {"receipt": receipt, "fast_flag": fast}

    def execute_approved(self, cfg, tool, args, receipt=None, approval_id=None, token=None):
        """Adapter entry for human-approved actions."""
        oid = args.get("order_id") or (args.get("order_ids") or [None])[0]
        o = self.order(oid) if oid else None
        if cfg == "D":
            if tool not in TOOLS: return {"executed": False, "reason": "S1"}
            sess = self.scope.verify(token or "")
            ok, why = verify_receipt(self.approvals.pub, receipt or {}, tool, args, oid, o["version"] if o else 0)
            if ok and (not sess or sess["session_id"] != receipt["payload"]["session_id"]): ok, why = False, "R6 receipt bound to a different session"
            if not ok:
                self.log("D", (sess or {}).get("session_id", "?"), tool, args, "REJECTED", why.split()[0], why, 0); return {"executed": False, "reason": why}
            p = receipt["payload"]
            try:
                with self.db.tx() as c:
                    try: c.execute("INSERT INTO nonces(nonce,used_at) VALUES(?,?)", (p["nonce"], time.time()))
                    except Exception: 
                        raise _Reject("R5 nonce already used (replay)")
                    if tool in ("refund", "refund_to_saved_method"):
                        used = c.execute("SELECT COALESCE(SUM(amount_paise),0) FROM refunds WHERE order_id=? AND (status='committed' OR (status='reserved' AND expires_at>?))", (oid, time.time())).fetchone()[0]
                        if used + args["amount_paise"] > o["captured_paise"]: raise _Reject("L1 exceeds captured even with approval")
                    res = self._do(c, p["session_id"], tool, args, auth="human:" + p["review_id"], approval=(p["review_id"], p["resource_version"], args.get("amount_paise")))
            except _Reject as e:
                self.log("D", p["session_id"], tool, args, "REJECTED", str(e).split()[0], str(e), 0); return {"executed": False, "reason": str(e)}
            self.log("D", p["session_id"], tool, args, "EXECUTED", "A2", "executed with valid receipt", 0)
            return {"executed": True, **res}
        # baseline: approval is only a flag; arguments come from the caller and approval is reusable
        w = self.db.c().execute("SELECT * FROM weak_approvals WHERE id=?", (approval_id,)).fetchone()
        if not w or w["status"] != "approved": return {"executed": False, "reason": "not approved"}
        with self.db.tx() as c:
            res = self._do(c, (self.scope.verify(token or "") or {}).get("session_id", "?"), tool, args, auth="human:" + approval_id,
                           approval=(approval_id, w["version"], w["amount"]))
        return {"executed": True, **res}

    # ---------- adapter: the only code that touches the system of record ----------
    def execute(self, cfg, sid, tool, args, reservation):
        if reservation:       # D: reserved -> committed (or released on failure)
            try:
                with self.db.tx() as c:
                    c.execute("UPDATE refunds SET status='committed', exec_version=(SELECT version FROM orders WHERE id=?) WHERE id=?", (args["order_id"], reservation))
                    c.execute("UPDATE orders SET version=version+1 WHERE id=?", (args["order_id"],))
                return {"executed": True, "refund_id": reservation}
            except Exception:
                self.db.c().execute("UPDATE refunds SET status='released' WHERE id=?", (reservation,)); raise
        with self.db.tx() as c: return {"executed": True, **self._do(c, sid, tool, args, auth="auto")}

    def _do(self, c, sid, tool, args, auth, approval=None):
        s = c.execute("SELECT customer_id FROM sessions WHERE id=?", (sid,)).fetchone()
        cust = s["customer_id"] if s else None
        now = time.time()
        if tool in ("refund", "refund_to_saved_method", "admin_override_refund"):
            o = c.execute("SELECT * FROM orders WHERE id=?", (args["order_id"],)).fetchone()
            dest = args.get("upi_id") or args.get("destination") or o["upi_id"]       # refund-to-source: from the DB, not the agent
            if tool == "admin_override_refund": auth = "override"
            c.execute("INSERT INTO refunds(order_id,customer_id,session_id,amount_paise,destination,status,auth,approval_id,approval_version,exec_version,approval_amount,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (o["id"], o["customer_id"], sid, args["amount_paise"], dest, "committed", auth,
                       approval[0] if approval else None, approval[1] if approval else None, o["version"], approval[2] if approval else None, now))
            c.execute("UPDATE orders SET version=version+1 WHERE id=?", (o["id"],))
        elif tool == "send_email": c.execute("INSERT INTO emails(session_id,to_addr,subject,body,auth) VALUES(?,?,?,?,?)", (sid, args["to"], args["subject"], args["body"], auth))
        elif tool == "delete_orders":
            for oid in args["order_ids"]:
                c.execute("UPDATE orders SET deleted=1 WHERE id=?", (oid,)); c.execute("INSERT INTO deletions(order_id,session_id,auth) VALUES(?,?,?)", (oid, sid, auth))
        elif tool == "export_all_customers": c.execute("INSERT INTO exports(session_id,what) VALUES(?,?)", (sid, "all customers"))
        elif tool == "update_payout_vpa": c.execute("UPDATE customers SET payout_vpa=? WHERE id=?", (args["upi_id"], args["customer_id"]))
        return {}

    # ---------- helpers ----------
    def order(self, oid): return self.db.c().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone() if oid else None
    def sum(self, q, a): return self.db.c().execute(q, a).fetchone()[0]
    def trusted_values(self, src, cust):
        c = self.db.c()
        if src == "saved_methods":
            return {r["upi_id"] for r in c.execute("SELECT upi_id FROM saved_methods WHERE customer_id=? AND verified=1", (cust,))}
        if src == "customer_email": return {c.execute("SELECT email FROM customers WHERE id=?", (cust,)).fetchone()["email"]}
        return set()

class _Reject(Exception): pass
