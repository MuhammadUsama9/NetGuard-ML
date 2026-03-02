import os
import time
import logging
import requests
import numpy as np
import torch
from flask import Flask, request, jsonify
from flask_cors import CORS
from model import TrafficClassifierMLP

# ─────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netguard-api")

app = Flask(__name__)
CORS(app)

LOGGER_URL = os.environ.get("LOGGER_URL", "http://logger:5001")
ALERT_URL  = os.environ.get("ALERT_URL",  "http://alerts:5002")

# ─────────────────────────────────────────────────────────────
# Model Loading
# ─────────────────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = None
model_loaded = False

def load_model():
    global model, model_loaded
    m = TrafficClassifierMLP(input_dim=6, hidden_dim=64, dropout_rate=0.2).to(device)
    try:
        checkpoint = torch.load(
            os.path.join(os.path.dirname(__file__), "best_model.pth"),
            map_location=device,
            weights_only=True,
        )
        m.load_state_dict(checkpoint["model_state_dict"])
        m.eval()
        model = m
        model_loaded = True
        logger.info("✅ Model loaded successfully.")
    except FileNotFoundError:
        logger.error("❌ best_model.pth not found!")
        model_loaded = False

load_model()

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def _preprocess(features: list[float]) -> torch.Tensor:
    arr = np.array(features, dtype=np.float32)
    arr[0] = np.clip(arr[0], 20, 1500)   # packet_length
    arr[1] = np.clip(arr[1], 0, None)    # inter_arrival_time
    return torch.tensor(arr, dtype=torch.float32).unsqueeze(0).to(device)


def _infer(tensor: torch.Tensor) -> tuple[float, str]:
    with torch.no_grad():
        output = model(tensor)
        probability = torch.sigmoid(output).item()
    label = "MALICIOUS" if probability > 0.5 else "BENIGN"
    return round(probability, 6), label


def _forward_to_services(payload: dict, is_malicious: bool):
    """Fire-and-forget log + alert to downstream services."""
    try:
        requests.post(f"{LOGGER_URL}/log", json=payload, timeout=1)
    except Exception:
        pass
    if is_malicious:
        try:
            requests.post(f"{ALERT_URL}/alert", json=payload, timeout=1)
        except Exception:
            pass


def _extract_features(data: dict) -> list[float]:
    keys = ["packet_length", "inter_arrival_time",
            "protocol_tcp", "protocol_udp",
            "source_port", "dest_port"]
    return [float(data[k]) for k in keys]

# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model_loaded,
        "device": str(device),
    })


@app.route("/predict", methods=["POST"])
def predict():
    if not model_loaded:
        return jsonify({"error": "Model not loaded"}), 503

    data = request.get_json(force=True)
    try:
        features = _extract_features(data)
    except (KeyError, TypeError, ValueError) as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    tensor = _preprocess(features)
    probability, label = _infer(tensor)

    payload = {
        "timestamp": time.time(),
        "features": {
            "packet_length":      features[0],
            "inter_arrival_time": features[1],
            "protocol_tcp":       features[2],
            "protocol_udp":       features[3],
            "source_port":        features[4],
            "dest_port":          features[5],
        },
        "probability": probability,
        "label": label,
        "source_ip": request.remote_addr,
    }
    _forward_to_services(payload, is_malicious=(label == "MALICIOUS"))

    return jsonify({"prediction": label, "probability": probability, "label": label})


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    if not model_loaded:
        return jsonify({"error": "Model not loaded"}), 503

    data = request.get_json(force=True)
    flows = data.get("flows", [])
    if not flows:
        return jsonify({"error": "No flows provided"}), 400

    results = []
    for flow in flows:
        try:
            features = _extract_features(flow)
            tensor = _preprocess(features)
            probability, label = _infer(tensor)
            payload = {
                "timestamp": time.time(),
                "features": {k: v for k, v in zip(
                    ["packet_length","inter_arrival_time","protocol_tcp",
                     "protocol_udp","source_port","dest_port"], features)},
                "probability": probability,
                "label": label,
                "source_ip": request.remote_addr,
            }
            _forward_to_services(payload, is_malicious=(label == "MALICIOUS"))
            results.append({"prediction": label, "probability": probability})
        except Exception as e:
            results.append({"error": str(e)})

    return jsonify({"results": results, "total": len(results)})


@app.route("/model/info", methods=["GET"])
def model_info():
    return jsonify({
        "architecture": "TrafficClassifierMLP",
        "input_dim": 6,
        "hidden_dim": 64,
        "dropout_rate": 0.2,
        "features": [
            "packet_length", "inter_arrival_time",
            "protocol_tcp", "protocol_udp",
            "source_port", "dest_port"
        ],
        "classes": ["BENIGN", "MALICIOUS"],
        "threshold": 0.5,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
