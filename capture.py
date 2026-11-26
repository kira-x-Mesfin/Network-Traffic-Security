"""
capture.py - Packet acquisition layer.

Two modes:
  live      - real capture with Scapy (requires root/admin + Npcap/libpcap).
  simulate  - built-in synthetic traffic generator with injected attacks,
              useful for demos and lab validation on authorized networks.

Only run live capture on networks you are explicitly authorized to monitor.
"""
import random
import threading
import time


class PacketCapture:
    def __init__(self, detector):
        self.detector = detector
        self._stop = threading.Event()
        self._thread = None
        self.packets_seen = 0

    # ------------------------------------------------------------------
    def start(self, interface=None, simulate=False):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, args=(interface, simulate), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    def _run(self, interface, simulate):
        if not simulate:
            try:
                self._live(interface)
                return
            except Exception as exc:  # e.g. no Npcap / no permission
                print(f"[capture] live mode unavailable ({exc}); "
                      f"falling back to simulation.")
        self._simulate()

    def _live(self, interface):
        from scapy.all import sniff, IP, TCP, UDP  # noqa: F401

        def handle(pkt):
            if self._stop.is_set():
                return True
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            sport = dport = None
            proto_num = ip.proto
            if pkt.haslayer(TCP):
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            proto = self._app_proto(proto_num, sport, dport)
            self.packets_seen += 1
            self.detector.observe(time.time(), ip.src, ip.dst, proto,
                                  sport, dport, len(pkt))
            return self._stop.is_set()

        kwargs = {"prn": handle, "store": False, "stop_filter": handle}
        if interface:
            kwargs["iface"] = interface
        sniff(**kwargs)

    @staticmethod
    def _app_proto(proto_num, sport, dport):
        ports = {sport, dport}
        if 53 in ports:
            return "DNS"
        if proto_num == 6 and ports & {80, 8080, 8000, 443}:
            return "HTTP"
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))

    # ------------------------------------------------------------------
    # Synthetic traffic generator (authorized lab testing / demos)
    # ------------------------------------------------------------------
    INTERNAL = ["192.168.1.10", "192.168.1.11", "192.168.1.23", "192.168.1.42"]
    EXTERNAL = ["93.184.216.34", "142.250.72.46", "1.1.1.1", "8.8.8.8",
                "20.190.160.14", "104.21.5.19"]
    NORMAL_PORTS = [443, 443, 443, 80, 53, 8080, 123]

    def _rand_conn(self, src, dst, proto=None, dport=None, length=None):
        proto = proto or random.choice(["TCP", "TCP", "UDP", "HTTP", "DNS"])
        if proto in ("DNS",) and dport is None:
            dport = 53
        elif proto == "HTTP" and dport is None:
            dport = random.choice([80, 443, 8080])
        else:
            dport = dport or random.choice(self.NORMAL_PORTS)
        self.packets_seen += 1
        self.detector.observe(time.time(), src, dst, proto,
                              random.randint(1024, 65000), dport,
                              length or random.randint(60, 1500))

    def _inject_port_scan(self):
        src = random.choice(self.EXTERNAL)
        dst = random.choice(self.INTERNAL)
        for p in range(1, 80):
            self._rand_conn(src, dst, "TCP", dport=p, length=64)

    def _inject_dos(self):
        src = random.choice(self.EXTERNAL)
        for _ in range(900):
            self._rand_conn(src, random.choice(self.INTERNAL),
                            "UDP", dport=random.randint(1000, 60000), length=200)

    def _inject_suspicious(self):
        src = random.choice(self.EXTERNAL)
        dst = random.choice(self.INTERNAL)
        self._rand_conn(src, dst, "TCP", dport=random.choice([23, 3389, 445]))
        self._rand_conn("203.0.113.66", dst, "TCP", dport=4444)

    def _simulate(self):
        while not self._stop.is_set():
            for _ in range(random.randint(6, 20)):
                if random.random() < 0.5:
                    self._rand_conn(random.choice(self.INTERNAL),
                                    random.choice(self.EXTERNAL))
                else:
                    self._rand_conn(random.choice(self.EXTERNAL),
                                    random.choice(self.INTERNAL))
            roll = random.random()
            if roll < 0.12:
                self._inject_port_scan()
            elif roll < 0.20:
                self._inject_dos()
            elif roll < 0.30:
                self._inject_suspicious()
            time.sleep(1)
