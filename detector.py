"""
detector.py - Rule-based threat detection engine.
Detects port scans, DoS floods, suspicious ports and known-bad hosts.
Every alert carries a severity (Low/Medium/High/Critical) and a
defensive remediation recommendation.
"""
import time
from collections import defaultdict, deque


class ThreatDetector:
    SUSPICIOUS_PORTS = {
        21: "FTP - cleartext credentials",
        23: "Telnet - cleartext remote shell",
        445: "SMB - lateral movement / WannaCry class",
        3389: "RDP - brute-force target",
        5900: "VNC - remote desktop exposure",
    }
    KNOWN_BAD = {
        "203.0.113.66": "Known botnet command-and-control (threat intel feed)",
        "198.51.100.23": "Listed on public blocklist (example feed)",
    }
    WINDOW = 10          # seconds for sliding detection windows
    ALERT_COOLDOWN = 60  # seconds before the same rule may re-alert on a key

    def __init__(self, storage):
        self.storage = storage
        self.ports_seen = defaultdict(set)   # (src, dst) -> set of dst ports
        self.pkt_times = defaultdict(deque)  # src -> deque of packet timestamps
        self.last_alert = {}                 # (rule, key) -> last alert ts

    # ------------------------------------------------------------------
    def observe(self, ts, src, dst, proto, sport, dport, length):
        if self.storage.is_blocked(src):
            self.storage.log_connection(ts, src, dst, proto, sport, dport,
                                        length, blocked=True)
            return

        self.storage.log_connection(ts, src, dst, proto, sport, dport, length)
        self._trim(src, ts)
        self.pkt_times[src].append(ts)
        self.ports_seen[(src, dst)].add(dport)

        self._check_port_scan(ts, src, dst)
        self._check_dos(ts, src)
        self._check_suspicious_port(ts, src, dst, sport, dport)
        self._check_known_bad(ts, src, dst)
        self._check_oversize(ts, src, dst, length)

    # ------------------------------------------------------------------
    def _trim(self, src, ts):
        q = self.pkt_times[src]
        while q and q[0] < ts - self.WINDOW:
            q.popleft()

    def _alert(self, rule, key, ts, severity, src, dst, detail, recommendation):
        if ts - self.last_alert.get((rule, key), -1e9) < self.ALERT_COOLDOWN:
            return
        self.last_alert[(rule, key)] = ts
        self.storage.log_alert(severity, rule, src, dst, detail, recommendation)

    def _check_port_scan(self, ts, src, dst):
        n = len(self.ports_seen[(src, dst)])
        if n >= 60:
            self._alert("port_scan", (src, dst), ts, "Critical", src, dst,
                f"{n} distinct ports touched on {dst} within {self.WINDOW}s - full sweep",
                "Drop traffic from this host at the perimeter firewall and "
                "investigate the source machine for scanning tools.")
        elif n >= 15:
            self._alert("port_scan", (src, dst), ts, "High", src, dst,
                f"{n} distinct ports touched on {dst} within {self.WINDOW}s",
                "Rate-limit or block the source IP; verify whether an "
                "approved vulnerability scanner is running.")

    def _check_dos(self, ts, src):
        n = len(self.pkt_times[src])
        if n >= 1500:
            self._alert("dos_flood", src, ts, "Critical", src, "multiple",
                f"{n} packets from {src} in {self.WINDOW}s - volumetric flood",
                "Enable upstream rate limiting / DDoS mitigation; "
                "null-route the source if it persists.")
        elif n >= 300:
            self._alert("dos_flood", src, ts, "High", src, "multiple",
                f"{n} packets from {src} in {self.WINDOW}s - possible DoS",
                "Apply per-source rate limiting and inspect the traffic "
                "profile to distinguish attack from misconfiguration.")

    def _check_suspicious_port(self, ts, src, dst, sport, dport):
        port = dport if dport in self.SUSPICIOUS_PORTS else sport
        if port not in self.SUSPICIOUS_PORTS:
            return
        reason = self.SUSPICIOUS_PORTS[port]
        self._alert("suspicious_port", (src, port), ts, "Medium", src, dst,
            f"Connection involving {port}/TCP ({reason})",
            f"Confirm {port} exposure is intentional; restrict it with a "
            "firewall rule or VPN, and prefer encrypted alternatives.")

    def _check_known_bad(self, ts, src, dst):
        bad_src = self.KNOWN_BAD.get(src)
        bad_dst = self.KNOWN_BAD.get(dst)
        if bad_src:
            self._alert("threat_intel", src, ts, "Critical", src, dst,
                f"Source {src} matches threat intel: {bad_src}",
                "Block immediately at the edge, then hunt for prior "
                "beaconing in DNS and proxy logs.")
        elif bad_dst:
            self._alert("threat_intel", dst, ts, "Critical", src, dst,
                f"Destination {dst} matches threat intel: {bad_dst}",
                "Isolate the internal host; check for data exfiltration "
                "and rotate any credentials it used.")

    def _check_oversize(self, ts, src, dst, length):
        if length >= 9000:
            self._alert("oversize_packet", (src, dst), ts, "Low", src, dst,
                f"Jumbo/oversize frame of {length} bytes (possible tunneling or fragmentation abuse)",
                "Verify MTU consistency; inspect payload for GRE/IPIP "
                "tunneling attempts.")
