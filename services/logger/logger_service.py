import os
import sqlite3
import time
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get("DB_PATH", "/data/netguard.db")

# ─────────────────────────────────────────────────────────────
# DB Init
# ─────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       REAL    NOT NULL,
            label           TEXT    NOT NULL,
            probability     REAL    NOT NULL,
            packet_length   REAL,
            inter_arrival   REAL,
            protocol_tcp    INTEGER,
            protocol_udp    INTEGER,
            source_port     INTEGER,
            dest_port       INTEGER,
            source_ip       TEXT,
            raw_features    TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()

# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "logger"})


@app.route("/log", methods=["POST"])
def log_event():
    data = request.get_json(force=True)
    features = data.get("features", {})
    conn = get_db()
    conn.execute("""
        INSERT INTO events
            (timestamp, label, probability,
             packet_length, inter_arrival, protocol_tcp, protocol_udp,
             source_port, dest_port, source_ip, raw_features)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        data.get("timestamp", time.time()),
        data.get("label", "UNKNOWN"),
        data.get("probability", 0.0),
        features.get("packet_length"),
        features.get("inter_arrival_time"),
        features.get("protocol_tcp"),
        features.get("protocol_udp"),
        features.get("source_port"),
        features.get("dest_port"),
        data.get("source_ip"),
        json.dumps(features),
    ))
    conn.commit()
    conn.close()
    return jsonify({"status": "logged"}), 201


@app.route("/logs", methods=["GET"])
def get_logs():
    page  = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    label = request.args.get("label")   # optional filter
    offset = (page - 1) * limit

    conn = get_db()
    query  = "SELECT * FROM events"
    params: list = []

    if label:
        query += " WHERE label = ?"
        params.append(label.upper())

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    rows = conn.execute(query, params).fetchall()

    count_q = "SELECT COUNT(*) FROM events"
    if label:
        count_q += " WHERE label = ?"
        total = conn.execute(count_q, [label.upper()]).fetchone()[0]
    else:
        total = conn.execute(count_q).fetchone()[0]

    conn.close()
    return jsonify({
        "logs": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
    })


@app.route("/logs/summary", methods=["GET"])
def summary():
    conn = get_db()
    total     = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    malicious = conn.execute("SELECT COUNT(*) FROM events WHERE label='MALICIOUS'").fetchone()[0]
    benign    = total - malicious

    # Hourly breakdown for last 24 hours
    cutoff = time.time() - 86400
    hourly_rows = conn.execute("""
        SELECT
            CAST((timestamp - ?) / 3600 AS INTEGER) AS hour_bucket,
            label,
            COUNT(*) AS cnt
        FROM events
        WHERE timestamp >= ?
        GROUP BY hour_bucket, label
        ORDER BY hour_bucket
    """, (cutoff, cutoff)).fetchall()
    conn.close()

    hourly = {}
    for row in hourly_rows:
        b = row["hour_bucket"]
        if b not in hourly:
            hourly[b] = {"BENIGN": 0, "MALICIOUS": 0}
        hourly[b][row["label"]] = row["cnt"]

    return jsonify({
        "total": total,
        "malicious": malicious,
        "benign": benign,
        "threat_rate": round(malicious / total * 100, 2) if total else 0,
        "hourly": hourly,
    })


@app.route("/logs/recent", methods=["GET"])
def recent():
    limit = int(request.args.get("limit", 20))
    conn  = get_db()
    rows  = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify({"logs": [dict(r) for r in rows]})


@app.route("/logs/traffic-over-time", methods=["GET"])
def traffic_over_time():
    """Returns data bucketed by hour for the last 24 hours."""
    hours = int(request.args.get("hours", 24))
    cutoff = time.time() - (hours * 3600)
    conn = get_db()
    rows = conn.execute("""
        SELECT
            CAST((timestamp - ?) / 3600 AS INTEGER) AS bucket,
            label,
            COUNT(*) AS cnt
        FROM events
        WHERE timestamp >= ?
        GROUP BY bucket, label
        ORDER BY bucket ASC
    """, (cutoff, cutoff)).fetchall()
    conn.close()

    buckets: dict = {}
    for row in rows:
        b = str(row["bucket"])
        if b not in buckets:
            buckets[b] = {"BENIGN": 0, "MALICIOUS": 0}
        buckets[b][row["label"]] = row["cnt"]

    return jsonify({"buckets": buckets, "hours": hours})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
