import time
import collections
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "netguard-secret-key"
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Keep last 100 alerts in memory for new client connections
alert_history: collections.deque = collections.deque(maxlen=100)
alert_count = 0

# ─────────────────────────────────────────────────────────────
# HTTP Routes
# ─────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "alerts", "total_alerts": alert_count})


@app.route("/alert", methods=["POST"])
def receive_alert():
    global alert_count
    data = request.get_json(force=True)
    alert_count += 1
    payload = {
        "id": alert_count,
        "timestamp": data.get("timestamp", time.time()),
        "label": data.get("label", "MALICIOUS"),
        "probability": data.get("probability", 1.0),
        "features": data.get("features", {}),
        "source_ip": data.get("source_ip", "unknown"),
    }
    alert_history.append(payload)
    # Broadcast to all connected WebSocket clients
    socketio.emit("new_alert", payload)
    return jsonify({"status": "broadcast", "alert_id": alert_count}), 201


@app.route("/alerts/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 50))
    alerts = list(alert_history)[-limit:]
    return jsonify({"alerts": alerts[::-1], "total": alert_count})


@app.route("/alerts/count", methods=["GET"])
def count():
    return jsonify({"count": alert_count})

# ─────────────────────────────────────────────────────────────
# WebSocket Events
# ─────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    # Send recent history to newly connected clients
    emit("history", {"alerts": list(alert_history)[-20:]})


@socketio.on("disconnect")
def on_disconnect():
    pass


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5002, debug=False, allow_unsafe_werkzeug=True)
