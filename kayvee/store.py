"""SQLite persistence: cases, evidence, tamper-evident chain of custody, analyses, notes, history, notifications, IOCs, reports."""
import sqlite3, threading, json, time, hashlib, os

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, case_no TEXT UNIQUE, title TEXT, description TEXT, status TEXT, priority TEXT, analyst TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, case_id INTEGER, filename TEXT, stored_path TEXT, size INTEGER, sha256 TEXT, source TEXT, acquired_at REAL,
  acquired_by TEXT, notes TEXT, last_verified_at REAL, last_verify_status TEXT, meta TEXT);
CREATE TABLE IF NOT EXISTS custody(id INTEGER PRIMARY KEY, evidence_id INTEGER, ts REAL, actor TEXT, action TEXT, details TEXT, prev_hash TEXT, entry_hash TEXT);
CREATE TABLE IF NOT EXISTS analyses(id INTEGER PRIMARY KEY, evidence_id INTEGER, case_id INTEGER, created REAL, status TEXT, error TEXT, summary TEXT, result_path TEXT, packet_count INTEGER);
CREATE TABLE IF NOT EXISTS packets(analysis_id INTEGER, no INTEGER, ts REAL, src TEXT, dst TEXT, proto TEXT, sport INTEGER, dport INTEGER, len INTEGER, info TEXT);
CREATE INDEX IF NOT EXISTS ix_pk ON packets(analysis_id, no);
CREATE INDEX IF NOT EXISTS ix_pk_src ON packets(analysis_id, src);
CREATE INDEX IF NOT EXISTS ix_pk_dst ON packets(analysis_id, dst);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, case_id INTEGER, analysis_id INTEGER, ref TEXT, author TEXT, text TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, case_id INTEGER, evidence_id INTEGER, analysis_id INTEGER, details TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, ts REAL, level TEXT, title TEXT, body TEXT, ref_type TEXT, ref_id TEXT, analysis_id INTEGER, read INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS iocs(id INTEGER PRIMARY KEY, type TEXT, value TEXT, source TEXT, severity TEXT, description TEXT, added REAL, UNIQUE(type, value));
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, case_id INTEGER, analysis_id INTEGER, format TEXT, filename TEXT, path TEXT, sha256 TEXT, size INTEGER, created REAL, analyst TEXT);
CREATE TABLE IF NOT EXISTS alert_status(analysis_id INTEGER, alert_id TEXT, status TEXT, updated REAL, by TEXT, PRIMARY KEY(analysis_id, alert_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""
GENESIS = "0" * 64


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)

    # -- generic
    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        r = self.q(sql, args)
        return r[0] if r else None

    def x(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).lastrowid

    def many(self, sql, rows):
        with self.lock:
            self.db.execute("BEGIN")
            try:
                self.db.executemany(sql, rows)
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    # -- settings
    def get_setting(self, key, default=None):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(r["value"]) if r else default

    def set_setting(self, key, value):
        self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

    # -- history / notifications
    def log(self, actor, action, details="", case_id=None, evidence_id=None, analysis_id=None):
        return self.x("INSERT INTO history(ts,actor,action,case_id,evidence_id,analysis_id,details) VALUES(?,?,?,?,?,?,?)", (time.time(), actor, action, case_id, evidence_id, analysis_id, details))

    def notify(self, level, title, body="", ref_type="", ref_id="", analysis_id=None):
        return self.x("INSERT INTO notifications(ts,level,title,body,ref_type,ref_id,analysis_id) VALUES(?,?,?,?,?,?,?)", (time.time(), level, title, body, ref_type, str(ref_id), analysis_id))

    # -- chain of custody (each entry hashes the previous one => any edit/removal is detectable)
    @staticmethod
    def _entry_hash(prev, ev, ts, actor, action, details):
        return hashlib.sha256(json.dumps([prev, ev, round(ts, 6), actor, action, details], separators=(",", ":")).encode()).hexdigest()

    def custody_add(self, evidence_id, actor, action, details=""):
        with self.lock:
            last = self.one("SELECT entry_hash FROM custody WHERE evidence_id=? ORDER BY id DESC LIMIT 1", (evidence_id,))
            prev, ts = (last["entry_hash"] if last else GENESIS), time.time()
            h = self._entry_hash(prev, evidence_id, ts, actor, action, details)
            return self.x("INSERT INTO custody(evidence_id,ts,actor,action,details,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?)", (evidence_id, ts, actor, action, details, prev, h))

    def custody_verify(self, evidence_id):
        rows = self.q("SELECT * FROM custody WHERE evidence_id=? ORDER BY id", (evidence_id,))
        prev = GENESIS
        for r in rows:
            if r["prev_hash"] != prev or self._entry_hash(prev, r["evidence_id"], r["ts"], r["actor"], r["action"], r["details"]) != r["entry_hash"]:
                return {"ok": False, "entries": len(rows), "broken_at": r["id"]}
            prev = r["entry_hash"]
        return {"ok": True, "entries": len(rows), "broken_at": None}

    # -- IOCs
    def iocs(self):
        return self.q("SELECT type,value,source,severity,description FROM iocs")
