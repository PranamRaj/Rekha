"""SQLite layer. WAL + busy_timeout; writers use BEGIN IMMEDIATE (one writer at a time)."""
import sqlite3, threading, time, contextlib, weakref

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers(id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, payout_vpa TEXT);
CREATE TABLE IF NOT EXISTS saved_methods(customer_id TEXT, upi_id TEXT, verified INT DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, customer_id TEXT, status TEXT, captured_paise INT,
  upi_id TEXT, version INT DEFAULT 1, deleted INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS refunds(id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT, customer_id TEXT, session_id TEXT,
  amount_paise INT, destination TEXT, status TEXT, auth TEXT, approval_id TEXT, approval_version INT, exec_version INT,
  approval_amount INT, created_at REAL, expires_at REAL);
CREATE TABLE IF NOT EXISTS emails(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, to_addr TEXT, subject TEXT, body TEXT, auth TEXT);
CREATE TABLE IF NOT EXISTS exports(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, what TEXT);
CREATE TABLE IF NOT EXISTS deletions(id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT, session_id TEXT, auth TEXT);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, customer_id TEXT, allowed TEXT, status TEXT DEFAULT 'ACTIVE',
  blocks INT DEFAULT 0, config TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS registry(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, source TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY, session_id TEXT, tool TEXT, args TEXT, resource_id TEXT,
  resource_version INT, card TEXT, status TEXT DEFAULT 'PENDING', shown_at REAL, approval_amount INT, config TEXT);
CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, used_at REAL);
CREATE TABLE IF NOT EXISTS weak_approvals(id TEXT PRIMARY KEY, status TEXT, version INT, amount INT, used INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, event TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS plainlog(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, event TEXT);
"""

class _Conn:
    """Holds one thread's connection so it can be closed deterministically.

    sqlite3.Connection cannot be weak-referenced, so DB registers weakrefs to these
    holders instead. Two things then close a connection: this object being released
    when its thread dies (one request thread each, under ThreadingHTTPServer), and
    an explicit close_all(). Registering the connections directly in a plain list
    would pin them past their thread's death and leak a file handle per request.
    """
    __slots__ = ("conn", "__weakref__")

    def __init__(self, conn): self.conn = conn

    def close(self):
        conn, self.conn = self.conn, None
        if conn is not None:
            try: conn.close()
            except Exception: pass

    def __del__(self): self.close()


class DB:
    def __init__(self, path):
        self.path, self.local = path, threading.local()
        self._holders, self._clock = [], threading.Lock()
        c = self.c(); c.executescript(SCHEMA)

    def c(self):
        h = getattr(self.local, "h", None)
        if h is None or h.conn is None:
            conn = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL"); conn.execute("PRAGMA busy_timeout=15000")
            conn.execute("PRAGMA synchronous=OFF")
            h = _Conn(conn); self.local.h = h
            with self._clock:
                self._holders = [r for r in self._holders if r() is not None]   # drop dead threads
                self._holders.append(weakref.ref(h))
        return h.conn

    def close_all(self):
        """Close every thread's connection and release the file.

        Connections are cached per thread, so a server with N live request threads
        holds N handles on the database. Windows refuses to delete an open file
        (POSIX allows it), so without this the live server cannot rebuild its own
        database -- which is what /api/reset does. Safe to call from any thread:
        connections are opened with check_same_thread=False.
        """
        with self._clock:
            holders = [r() for r in self._holders]
            self._holders.clear()
        for h in holders:
            if h is not None: h.close()
        self.local = threading.local()

    @contextlib.contextmanager
    def tx(self):
        c = self.c(); c.execute("BEGIN IMMEDIATE")
        try:
            yield c; c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK"); raise

def rs(x): return int(round(x * 100))
def fmt(p): return f"₹{p/100:,.0f}" if p % 100 == 0 else f"₹{p/100:,.2f}"

def seed(db):
    c = db.c()
    c.executescript("""
    INSERT INTO customers VALUES('c1','Asha','asha@example.com','+91-98000-11111',NULL);
    INSERT INTO customers VALUES('c2','Ravi','ravi@example.com','+91-98000-22222',NULL);
    INSERT INTO saved_methods VALUES('c1','asha@okhdfc',1),('c1','asha.work@okicici',1),('c2','ravi@oksbi',1);
    """)
    O = [  # id, customer, status, captured Rs, original upi
      ("o1001","c1","DELIVERED",25000,"asha@okhdfc"), ("o1002","c1","DELIVERED",20000,"asha@okhdfc"),
      ("o1003","c1","PROCESSING",8000,"asha@okhdfc"), ("o1004","c1","CANCELLED",1000,"asha@okhdfc"),
      ("o1005","c1","CANCELLED",1200,"asha@okhdfc"), ("o1006","c1","CANCELLED",900,"asha@okhdfc"),
      ("o1007","c1","DELIVERED",8000,"asha@okhdfc"), ("o1008","c1","RETURN_RECEIVED",3000,"asha@okhdfc"),
      ("o2001","c2","DELIVERED",30000,"ravi@oksbi"), ("o2002","c2","DELIVERED",5000,"ravi@oksbi")]
    for o in O: c.execute("INSERT INTO orders(id,customer_id,status,captured_paise,upi_id) VALUES(?,?,?,?,?)", (o[0],o[1],o[2],rs(o[3]),o[4]))
