import torch
import numpy as np
from model import TrafficClassifierMLP

def predict_single_flow(packet_length, inter_arrival_time, protocol_tcp, protocol_udp, source_port, dest_port):
    """
    Loads the trained model and predicts whether a single network flow is benign or malicious (DDoS).
    """
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # Initialize the model and load the trained weights
    model = TrafficClassifierMLP(input_dim=6, hidden_dim=64, dropout_rate=0.2).to(device)
    
    try:
        # Load weights
        checkpoint = torch.load("best_model.pth", map_location=device, weights_only=True)
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
    except FileNotFoundError:
        print("Error: 'best_model.pth' not found. Please run 'python train.py' first.")
        return

    # Prepare the feature tensor
    features = np.array([packet_length, inter_arrival_time, protocol_tcp, protocol_udp, source_port, dest_port])
    # Clip just like we did in training
    features[0] = np.clip(features[0], 20, 1500)
    features[1] = np.clip(features[1], 0, None)
    
    # Needs to be a batch of size 1 (hence unsqueeze)
    feature_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(device)
    
    # Make prediction
    with torch.no_grad():
        output = model(feature_tensor)
        probability = torch.sigmoid(output).item()
        
    print(f"Malicious Probability: {probability:.2%}")
    if probability > 0.5:
        print("🚨 ALERT: Traffic flagged as MALICIOUS (Potential DDoS).")
    else:
        print("✅ Traffic appears BENIGN.")

if __name__ == "__main__":
    print("--- NetGuard-ML Inference ---")
    
    print("\n[Test 1] Standard HTTP Traffic:")
    print("Simulating a normal sized packet (1200 bytes) arriving at a web server (Port 443)...")
    predict_single_flow(
        packet_length=1200, 
        inter_arrival_time=0.5, 
        protocol_tcp=1, protocol_udp=0, 
        source_port=54321, dest_port=443
    )
    
    print("\n[Test 2] Suspected UDP Flood (DDoS Attack):")
    print("Simulating tiny packets (64 bytes) arriving continuously (0.0001s spacing)...")
    predict_single_flow(
        packet_length=64, 
        inter_arrival_time=0.0001, 
        protocol_tcp=0, protocol_udp=1, 
        source_port=50000, dest_port=80
    )
