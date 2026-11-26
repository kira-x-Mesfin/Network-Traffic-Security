"""
storage.py - SQLite persistence layer for Network Traffic Security.
Stores connections, security alerts and blocked IPs. Thread-safe.
"""
import sqlite3
import threading
import time


class Storage:
    def __init__(self, path="ntsec.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()

    def init(self):
        with self.lock:
            c = self.conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, src TEXT, dst TEXT, proto TEXT,
                sport INTEGER, dport INTEGER, length INTEGER,
                blocked INTEGER DEFAULT 0)""")
            c.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, severity TEXT, rule TEXT,
                src TEXT, dst TEXT, detail TEXT,
                recommendation TEXT, status TEXT DEFAULT 'new')""")
            c.execute("""CREATE TABLE IF NOT EXISTS blocked (
                ip TEXT PRIMARY KEY, ts REAL, reason TEXT)""")
            self.conn.commit()

    # ---- connections -------------------------------------------------
    def log_connection(self, ts, src, dst, proto, sport, dport, length, blocked=False):
        with self.lock:
            self.conn.execute(
                "INSERT INTO connections (ts,src,dst,proto,sport,dport,length,blocked)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (ts, src, dst, proto, sport, dport, length, int(blocked)))
            # keep the table bounded so the dashboard stays fast
            self.conn.execute(
                "DELETE FROM connections WHERE id < "
                "(SELECT COALESCE(MAX(id),0) FROM connections) - 20000")
            self.conn.commit()

    def totals(self):
        with self.lock:
            r = self.conn.execute(
                "SELECT COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes,"
                " SUM(blocked) AS blocked FROM connections").fetchone()
            a = self.conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()
            return {"packets": r["packets"], "bytes": r["bytes"],
                    "blocked": r["blocked"] or 0, "alerts": a["n"]}

    def protocol_counts(self):
        with self.lock:
            return [{"proto": row["proto"], "n": row["n"]} for row in self.conn.execute(
                "SELECT proto, COUNT(*) AS n FROM connections"
                " GROUP BY proto ORDER BY n DESC")]

    def traffic_timeline(self, minutes=30):
        cutoff = time.time() - minutes * 60
        with self.lock:
            rows = self.conn.execute(
                "SELECT CAST(ts/60 AS INT) AS bucket, SUM(length) AS bytes,"
                " COUNT(*) AS packets FROM connections WHERE ts >= ?"
                " GROUP BY bucket ORDER BY bucket", (cutoff,)).fetchall()
        return [{"t": r["bucket"] * 60, "bytes": r["bytes"], "packets": r["packets"]}
                for r in rows]

    def top_talkers(self, limit=10):
        with self.lock:
            return [{"ip": r["ip"], "bytes": r["b"]} for r in self.conn.execute(
                "SELECT src AS ip, SUM(length) AS b FROM connections"
                " GROUP BY src ORDER BY b DESC LIMIT ?", (limit,))]

    def recent_connections(self, limit=25):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT ts,src,dst,proto,sport,dport,length,blocked"
                " FROM connections ORDER BY id DESC LIMIT ?", (limit,))]

    # ---- alerts ------------------------------------------------------
    def log_alert(self, severity, rule, src, dst, detail, recommendation):
        with self.lock:
            self.conn.execute(
                "INSERT INTO alerts (ts,severity,rule,src,dst,detail,recommendation)"
                " VALUES (?,?,?,?,?,?,?)",
                (time.time(), severity, rule, src, dst, detail, recommendation))
            self.conn.execute(
                "DELETE FROM alerts WHERE id < "
                "(SELECT COALESCE(MAX(id),0) FROM alerts) - 5000")
            self.conn.commit()

    def recent_alerts(self, limit=20):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]

    def alerts_by_severity(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity").fetchall()
        order = ["Low", "Medium", "High", "Critical"]
        m = {r["severity"]: r["n"] for r in rows}
        return [{"severity": s, "n": m.get(s, 0)} for s in order]

    # ---- blocking ----------------------------------------------------
    def block_ip(self, ip, reason="manual block"):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO blocked (ip, ts, reason) VALUES (?,?,?)",
                (ip, time.time(), reason))
            self.conn.commit()

    def unblock_ip(self, ip):
        with self.lock:
            self.conn.execute("DELETE FROM blocked WHERE ip=?", (ip,))
            self.conn.commit()

    def is_blocked(self, ip):
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM blocked WHERE ip=?", (ip,)).fetchone() is not None

    def blocked_ips(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT ip, reason FROM blocked ORDER BY ts DESC")]
