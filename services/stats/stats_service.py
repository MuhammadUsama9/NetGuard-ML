import os
import time
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

LOGGER_URL = os.environ.get("LOGGER_URL", "http://logger:5001")
ALERT_URL  = os.environ.get("ALERT_URL",  "http://alerts:5002")

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def _get(url: str, params: dict = None) -> dict:
    try:
        r = requests.get(url, params=params, timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "stats"})


@app.route("/stats", methods=["GET"])
def stats():
    summary = _get(f"{LOGGER_URL}/logs/summary")
    alerts  = _get(f"{ALERT_URL}/alerts/count")

    return jsonify({
        "total_packets":    summary.get("total", 0),
        "malicious":        summary.get("malicious", 0),
        "benign":           summary.get("benign", 0),
        "threat_rate":      summary.get("threat_rate", 0.0),
        "active_alerts":    alerts.get("count", 0),
        "hourly":           summary.get("hourly", {}),
        "timestamp":        time.time(),
    })


@app.route("/traffic-over-time", methods=["GET"])
def traffic_over_time():
    hours = request.args.get("hours", 24)
    data  = _get(f"{LOGGER_URL}/logs/traffic-over-time", {"hours": hours})
    return jsonify(data)


@app.route("/recent-logs", methods=["GET"])
def recent_logs():
    limit = request.args.get("limit", 20)
    data  = _get(f"{LOGGER_URL}/logs/recent", {"limit": limit})
    return jsonify(data)


@app.route("/alerts-history", methods=["GET"])
def alerts_history():
    limit = request.args.get("limit", 20)
    data  = _get(f"{ALERT_URL}/alerts/history", {"limit": limit})
    return jsonify(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
