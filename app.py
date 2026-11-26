"""
app.py - Network Traffic Security platform (Flask API + dashboard server).

Run only on networks you are authorized to monitor.
    python app.py            -> http://127.0.0.1:5000

API:
    POST /api/start          {"interface": "eth0"|null, "mode": "live"|"simulate"}
    POST /api/stop
    GET  /api/overview       dashboard data (stats, charts, alerts, connections)
    POST /api/block          {"ip": "x.x.x.x"}
    DELETE /api/unblock/<ip>
"""
from flask import Flask, jsonify, render_template, request

from storage import Storage
from detector import ThreatDetector
from capture import PacketCapture

app = Flask(__name__)
storage = Storage("ntsec.db")
storage.init()
detector = ThreatDetector(storage)
capture = PacketCapture(detector)
STATE = {"running": False, "mode": "simulate"}


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/start", methods=["POST"])
def start():
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode", "simulate")
    interface = body.get("interface") or None
    capture.start(interface=interface, simulate=(mode == "simulate"))
    STATE.update(running=True, mode=mode)
    return jsonify({"status": "started", "mode": mode,
                    "interface": interface})


@app.route("/api/stop", methods=["POST"])
def stop():
    capture.stop()
    STATE["running"] = False
    return jsonify({"status": "stopped"})


@app.route("/api/block", methods=["POST"])
def block():
    ip = (request.get_json(force=True, silent=True) or {}).get("ip", "").strip()
    if ip:
        storage.block_ip(ip, reason="manual block from dashboard")
    return jsonify({"blocked": ip})


@app.route("/api/unblock/<ip>", methods=["DELETE"])
def unblock(ip):
    storage.unblock_ip(ip)
    return jsonify({"unblocked": ip})


@app.route("/api/overview")
def overview():
    return jsonify({
        "running": capture.is_running(),
        "mode": STATE["mode"],
        "packets_seen": capture.packets_seen,
        "totals": storage.totals(),
        "protocols": storage.protocol_counts(),
        "timeline": storage.traffic_timeline(minutes=30),
        "top_talkers": storage.top_talkers(8),
        "alerts": storage.recent_alerts(20),
        "alerts_by_severity": storage.alerts_by_severity(),
        "connections": storage.recent_connections(25),
        "blocked": storage.blocked_ips(),
    })


if __name__ == "__main__":
    print("Network Traffic Security - authorized monitoring only.")
    app.run(host="127.0.0.1", port=5000, threaded=True)
