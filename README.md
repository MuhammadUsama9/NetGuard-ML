# NetGuard-ML

An intelligent network traffic analysis pipeline to detect malicious activity (e.g., DDoS, Scans) using PyTorch MLPs and a full Microservices Architecture.

This project implements a custom synthetic dataset, an MLP classifier, wandb experiment tracking, code-level profiling, and a sleek real-time monitoring dashboard powered by Docker.

## Features
- **AI-Powered Detection**: PyTorch MLP neural network trained to classify network flows as BENIGN or MALICIOUS based on features like packet length, inter-arrival time, protocols, and ports.
- **Real-time Dashboard**: A beautiful, responsive web interface that tracks traffic statistics, displays real-time malicious alerts via WebSockets, and shows interactive traffic charts.
- **Live Traffic Sniffing**: Captures raw network packets in real-time, extracts features, and runs them through the ML model.
- **Microservices Architecture**: Completely containerized with Docker for seamless deployment, horizontal scalability, and organized separation of concerns (API, Logger, Alerts, Stats, Sniffer, Frontend).

---

## 🚀 Getting Started (Docker & Dashboard)

The easiest way to run NetGuard-ML is by using Docker Compose. This will spin up the entire ecosystem, including the live sniffer, ML API, storage services, and the Web Dashboard.

### Prerequisites
- Docker & Docker Compose installed

### Launching the System
```bash
# Clone the repository and navigate into it
docker-compose up -d --build
```
Once the containers are running, access the dashboard at: **http://localhost:3000**

### Services & Ports
- **Frontend Dashboard:** `:3000`
- **ML Inference API:** `:5000`
- **Traffic Logger (SQLite):** `:5001`
- **WebSocket Alerts:** `:5002`
- **Statistics API:** `:5003`

---

## 🧠 Local Development & Model Training

If you'd like to adjust the model architecture, test the dataset, or train the AI yourself locally (without Docker):

### Installation
```bash
pip install -r requirements.txt
```

### Running Tests
Verify the dataset generation logic:
```bash
pytest test_data.py
```

### Training The Model
Train the MLP and track experiments with Weights & Biases:
```bash
python train.py --lr 0.001 --batch_size 64 --epochs 20 --seed 42 --num_samples 20000
```
This will automatically save the best performing model weights to `best_model.pth`.

### Running Local Inference (Simulation)
Simulate network traffic predictions using the loaded model and synthesized data:
```bash
python inference.py
```

### Running Local Live Sniffer
You can hook directly into your PC's real network card using Scapy to sniff and assess live traffic using your AI model locally (without Docker):
```bash
python live_inference.py
```
*Note: Depending on your OS, you may need to run this command as Administrator/root.*
