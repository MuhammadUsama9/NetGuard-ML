import os
import time
import random
import logging
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("sniffer")

API_URL = os.environ.get("API_URL", "http://api:5000/predict")
last_packet_time = None
time_lock = threading.Lock()

def send_to_api(payload):
    try:
        requests.post(API_URL, json=payload, timeout=2)
    except Exception as e:
        pass # Ignore errors so we don't spam logs if API is down

def process_packet(packet):
    global last_packet_time
    
    if not packet.haslayer(IP): return
    if not (packet.haslayer(TCP) or packet.haslayer(UDP)): return

    packet_length = len(packet)
    current_time = time.time()
    
    with time_lock:
        inter_arrival_time = 0.0 if last_packet_time is None else current_time - last_packet_time
        last_packet_time = current_time

    protocol_tcp = 1 if packet.haslayer(TCP) else 0
    protocol_udp = 1 if packet.haslayer(UDP) else 0

    if protocol_tcp:
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
    else:
        source_port = packet[UDP].sport
        dest_port = packet[UDP].dport

    payload = {
        "packet_length": packet_length,
        "inter_arrival_time": inter_arrival_time,
        "protocol_tcp": protocol_tcp,
        "protocol_udp": protocol_udp,
        "source_port": source_port,
        "dest_port": dest_port
    }
    
    send_to_api(payload)

def generate_background_traffic():
    """Generates continuous simulated traffic so the dashboard always shows activity."""
    global last_packet_time
    logger.info("Starting background traffic generator...")
    
    while True:
        time.sleep(random.uniform(0.5, 3.0)) # Random delay
        
        # 10% chance of generating a malicious-looking packet
        is_malicious = random.random() < 0.10
        
        if is_malicious:
            packet_length = random.randint(20, 100)
            inter_arrival_time = random.uniform(0.0001, 0.01)
            protocol_tcp = 0 if random.random() > 0.5 else 1
            protocol_udp = 1 - protocol_tcp
            source_port = random.randint(1024, 65535)
            dest_port = random.choice([22, 80, 443, 8080, 3306])
        else:
            packet_length = random.randint(200, 1500)
            inter_arrival_time = random.uniform(0.1, 2.0)
            protocol_tcp = 1 if random.random() > 0.2 else 0
            protocol_udp = 1 - protocol_tcp
            source_port = random.choice([80, 443, 22, 53]) if random.random() > 0.5 else random.randint(1024, 65535)
            dest_port = random.randint(1024, 65535) if source_port in [80, 443, 22, 53] else random.choice([80, 443, 53])

        current_time = time.time()
        with time_lock:
            last_packet_time = current_time
            
        payload = {
            "packet_length": packet_length,
            "inter_arrival_time": inter_arrival_time,
            "protocol_tcp": protocol_tcp,
            "protocol_udp": protocol_udp,
            "source_port": source_port,
            "dest_port": dest_port
        }
        send_to_api(payload)

if __name__ == "__main__":
    logger.info(f"Starting NetGuard sniffer... Forwarding to {API_URL}")
    
    # Start the background traffic generator thread
    traffic_thread = threading.Thread(target=generate_background_traffic, daemon=True)
    traffic_thread.start()
    
    # Start actual packet sniffing
    try:
        sniff(prn=process_packet, store=False, filter="not port 5000 and not port 5001 and not port 5002 and not port 5003 and not port 3000")
    except Exception as e:
        logger.error(f"Sniffer encountered an error: {e}")
        # Keep alive for the simulated thread
        while True:
            time.sleep(10)
