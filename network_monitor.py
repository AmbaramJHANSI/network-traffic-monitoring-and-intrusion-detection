# network_monitor.py
# Network Traffic Monitoring and Intrusion Detection
# Beginner-friendly IDS using Python and Scapy

from scapy.all import sniff
from collections import defaultdict
from datetime import datetime
import os

# Directory to store logs
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# File to save packet logs
PACKET_LOG = os.path.join(LOG_DIR, "packet_logs.txt")
ALERT_LOG = os.path.join(LOG_DIR, "alerts.txt")

# Dictionary to track packets per IP (for basic anomaly detection)
packet_count = defaultdict(int)
ALERT_THRESHOLD = 20  # Example threshold for suspicious activity

def log_packet(info):
    """Log packet information to file"""
    with open(PACKET_LOG, "a") as f:
        f.write(f"{info}\n")
    print(info)

def log_alert(alert):
    """Log alerts to file"""
    with open(ALERT_LOG, "a") as f:
        f.write(f"{alert}\n")
    print(alert)

def detect_suspicious(ip):
    """Basic intrusion detection: alert if packets exceed threshold"""
    packet_count[ip] += 1
    if packet_count[ip] == ALERT_THRESHOLD:
        alert = f"[ALERT] Possible suspicious activity from {ip} at {datetime.now()}"
        log_alert(alert)

def process_packet(packet):
    """Process each captured packet"""
    src_ip = packet[0][1].src if packet.haslayer("IP") else "N/A"
    dst_ip = packet[0][1].dst if packet.haslayer("IP") else "N/A"
    protocol = packet.proto if hasattr(packet, "proto") else "N/A"
    length = len(packet)

    log_info = f"[PACKET] {datetime.now()} | Source: {src_ip} → Destination: {dst_ip} | Protocol: {protocol} | Length: {length}"
    log_packet(log_info)

    if src_ip != "N/A":
        detect_suspicious(src_ip)

def main():
    print("[INFO] Starting network traffic monitoring...")
    print(f"[INFO] Logs will be saved in '{LOG_DIR}/'")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
