import torch
import numpy as np
import time
from scapy.all import sniff, IP, TCP, UDP
from model import TrafficClassifierMLP

# Global variables to track state
last_packet_time = None
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = None

def load_ai_model():
    """Initializes and loads the trained PyTorch weights."""
    global model
    model = TrafficClassifierMLP(input_dim=6, hidden_dim=64, dropout_rate=0.2).to(device)
    try:
        checkpoint = torch.load("best_model.pth", map_location=device, weights_only=True)
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        print("✅ AI Model Loaded Successfully. Listening for live traffic...")
    except FileNotFoundError:
        print("❌ Error: 'best_model.pth' not found. Please run 'python train.py' first.")
        exit(1)

def process_live_packet(packet):
    """
    Callback function executed by Scapy every time a real packet is sniffed.
    Extracts the 6 required features and passes them to the PyTorch model.
    """
    global last_packet_time, model
    
    # We only care about IP packets that contain TCP or UDP payloads
    if not packet.haslayer(IP):
        return
        
    if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
        return

    # 1. Packet Length
    packet_length = len(packet)
    
    # 2. Inter-arrival time (Time since last packet)
    current_time = time.time()
    if last_packet_time is None:
        inter_arrival_time = 0.0
    else:
        inter_arrival_time = current_time - last_packet_time
    last_packet_time = current_time

    # 3 & 4. Protocol Flags
    protocol_tcp = 1 if packet.haslayer(TCP) else 0
    protocol_udp = 1 if packet.haslayer(UDP) else 0

    # 5 & 6. Source and Destination Ports
    if protocol_tcp:
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
    else:
        source_port = packet[UDP].sport
        dest_port = packet[UDP].dport

    # Prepare features for the ML model
    features = np.array([packet_length, inter_arrival_time, protocol_tcp, protocol_udp, source_port, dest_port])
    
    # Clean/Clip data exactly like training
    features[0] = np.clip(features[0], 20, 1500)
    features[1] = np.clip(features[1], 0, None)
    
    # Convert to PyTorch Tensor (batch size 1)
    feature_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(device)
    
    # AI Inference
    with torch.no_grad():
        output = model(feature_tensor)
        probability = torch.sigmoid(output).item()
        
    # Print results to terminal
    proto_name = "TCP" if protocol_tcp else "UDP"
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    report = f"[{proto_name}] {src_ip}:{source_port} -> {dst_ip}:{dest_port} | Len: {packet_length} | "
    
    if probability > 0.5:
        print(f"🚨 BOOM! MALICIOUS (Prob: {probability:.1%}) | {report}")
    else:
        # To avoid extreme terminal spam, we'll only print benign packets with low probability occasionally
        # or we explicitly print them in gray/dim text. We'll just print them here:
        print(f"✅ Benign (Prob: {probability:.1%}) | {report}")

if __name__ == "__main__":
    print("--- NetGuard-ML Live Sniffer ---")
    print("Warning: This requires Administrator/Root privileges to hook into the network card!")
    
    load_ai_model()
    
    try:
        # Start sniffing. `store=False` ensures we don't eat all our RAM by saving packets.
        # It calls `process_live_packet` for every single packet it sees.
        sniff(prn=process_live_packet, store=False)
    except PermissionError:
        print("\n❌ Permission Denied! You must run this command Prompt as Administrator!")
    except Exception as e:
        print(f"\n❌ Error sniffing network: {e}")
