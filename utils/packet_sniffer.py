from scapy.all import sniff, IP, TCP, UDP, get_if_list
import pandas as pd
import numpy as np
import joblib
import time
from collections import defaultdict, deque
import sqlite3
import ipaddress
import socket
import requests
from typing import Optional, Dict, Any

# Load model and preprocessor
model = joblib.load("model/model.pkl")
scaler = joblib.load("model/preprocessor.pkl")
features = joblib.load("model/features.pkl")

# Protocol mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP", 
    17: "UDP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    587: "SMTP_SUBMISSION",
    465: "SMTPS"
}

# Private IP ranges
PRIVATE_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12", 
    "192.168.0.0/16",
    "127.0.0.0/8",  # Loopback
    "169.254.0.0/16",  # Link-local
    "224.0.0.0/4",  # Multicast
    "240.0.0.0/4"   # Reserved
]

# Cache for GeoIP lookups to avoid repeated API calls
geoip_cache = {}

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for private_range in PRIVATE_RANGES:
            if ip in ipaddress.ip_network(private_range):
                return True
        return False
    except ValueError:
        return False

def get_protocol_name(proto_num: int) -> str:
    """Map protocol number to protocol name."""
    return PROTOCOL_MAP.get(proto_num, f"Protocol_{proto_num}")

def get_country_from_ip(ip_str: str) -> str:
    """Get country information for an IP address using free GeoIP service."""
    if ip_str in geoip_cache:
        return geoip_cache[ip_str]
    
    try:
        # Use free ipapi.co service (no API key required, rate limited)
        response = requests.get(f"http://ip-api.com/json/{ip_str}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country = data.get('country', 'Unknown')
                geoip_cache[ip_str] = country
                return country
    except Exception as e:
        print(f"GeoIP lookup failed for {ip_str}: {e}")
    
    geoip_cache[ip_str] = "Unknown"
    return "Unknown"

def determine_flow_direction(src_ip: str, dst_ip: str) -> str:
    """Determine if flow is internal-to-external or external-to-internal."""
    src_internal = is_private_ip(src_ip)
    dst_internal = is_private_ip(dst_ip)
    
    if src_internal and not dst_internal:
        return "Internal-to-External"
    elif not src_internal and dst_internal:
        return "External-to-Internal"
    elif src_internal and dst_internal:
        return "Internal-to-Internal"
    else:
        return "External-to-External"

def get_derived_features(src_ip: str, dst_ip: str, proto_num: int) -> Dict[str, Any]:
    """Get all derived features for a flow."""
    return {
        'direction': determine_flow_direction(src_ip, dst_ip),
        'protocol_name': get_protocol_name(proto_num),
        'is_internal_src': is_private_ip(src_ip),
        'is_internal_dst': is_private_ip(dst_ip),
        'country': get_country_from_ip(dst_ip) if not is_private_ip(dst_ip) else "Internal"
    }

# Store flow data
flows = defaultdict(lambda: {
    'start_time': 0, 'fwd_packets': 0, 'bwd_packets': 0,
    'fwd_bytes': 0, 'bwd_bytes': 0, 'fwd_packet_lengths': [],
    'bwd_packet_lengths': [], 'fwd_iat': [], 'bwd_iat': []
})

# Real-time packet timestamps (for last 60 seconds)
packet_timestamps = deque(maxlen=10000)  # holds timestamps of recent packets

# Live flows: (src_ip, dst_ip, proto) -> {'packets': int, 'bytes': int, 'last_seen': float, 'derived_features': dict}
live_flows = defaultdict(lambda: {
    'packets': 0, 
    'bytes': 0, 
    'last_seen': 0, 
    'proto': '',
    'src_port': 0,
    'dst_port': 0,
    'derived_features': {}
})

def get_packets_per_second(window=60):
    now = time.time()
    count = sum(1 for t in packet_timestamps if now - t <= window)
    return count / window if window > 0 else 0

def get_live_flows(window=10):
    now = time.time()
    result = []
    for (src, dst, proto), info in live_flows.items():
        if now - info['last_seen'] <= window:
            result.append({
                'src_ip': src,
                'dst_ip': dst,
                'proto': proto,
                'packets': info['packets'],
                'bytes': info['bytes'],
                'last_seen': info['last_seen'],
                'src_port': info['src_port'],
                'dst_port': info['dst_port'],
                'direction': info['derived_features'].get('direction', 'Unknown'),
                'protocol_name': info['derived_features'].get('protocol_name', 'Unknown'),
                'is_internal_src': info['derived_features'].get('is_internal_src', False),
                'is_internal_dst': info['derived_features'].get('is_internal_dst', False),
                'country': info['derived_features'].get('country', 'Unknown')
            })
    return result

def extract_features(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        flow_id = (src_ip, dst_ip, proto)
        
        # Initialize flow
        if flows[flow_id]['start_time'] == 0:
            flows[flow_id]['start_time'] = time.time()
        
        # Update flow statistics
        pkt_len = len(packet)
        if packet[IP].src == src_ip:  # Forward direction
            flows[flow_id]['fwd_packets'] += 1
            flows[flow_id]['fwd_bytes'] += pkt_len
            flows[flow_id]['fwd_packet_lengths'].append(pkt_len)
            if len(flows[flow_id]['fwd_packet_lengths']) > 1:
                flows[flow_id]['fwd_iat'].append(time.time() - flows[flow_id]['last_fwd_time'])
        else:  # Backward direction
            flows[flow_id]['bwd_packets'] += 1
            flows[flow_id]['bwd_bytes'] += pkt_len
            flows[flow_id]['bwd_packet_lengths'].append(pkt_len)
            if len(flows[flow_id]['bwd_packet_lengths']) > 1:
                flows[flow_id]['bwd_iat'].append(time.time() - flows[flow_id]['last_bwd_time'])
        
        flows[flow_id]['last_fwd_time'] = time.time()
        flows[flow_id]['last_bwd_time'] = time.time()
        
        # Compute features
        flow_duration = time.time() - flows[flow_id]['start_time']
        fwd_pkt_len_mean = np.mean(flows[flow_id]['fwd_packet_lengths']) if flows[flow_id]['fwd_packet_lengths'] else 0
        bwd_pkt_len_mean = np.mean(flows[flow_id]['bwd_packet_lengths']) if flows[flow_id]['bwd_packet_lengths'] else 0
        flow_bytes_s = (flows[flow_id]['fwd_bytes'] + flows[flow_id]['bwd_bytes']) / flow_duration if flow_duration > 0 else 0
        flow_packets_s = (flows[flow_id]['fwd_packets'] + flows[flow_id]['bwd_packets']) / flow_duration if flow_duration > 0 else 0
        fwd_iat_total = sum(flows[flow_id]['fwd_iat']) if flows[flow_id]['fwd_iat'] else 0
        bwd_iat_total = sum(flows[flow_id]['bwd_iat']) if flows[flow_id]['bwd_iat'] else 0
        
        feature_vector = [
            flow_duration, flows[flow_id]['fwd_packets'], flows[flow_id]['bwd_packets'],
            flows[flow_id]['fwd_bytes'], flows[flow_id]['bwd_bytes'],
            fwd_pkt_len_mean, bwd_pkt_len_mean, flow_bytes_s, flow_packets_s,
            fwd_iat_total, bwd_iat_total
        ]
        
        return flow_id, feature_vector
    return None, None

def predict_packet(flow_id, feature_vector):
    feature_df = pd.DataFrame([feature_vector], columns=features)
    feature_vector_scaled = scaler.transform(feature_df)
    prediction = model.predict(feature_vector_scaled)[0]
    confidence = model.predict_proba(feature_vector_scaled)[0][prediction]
    
    if prediction == 1:  # Attack detected
        src_ip, dst_ip, proto_num = flow_id
        derived_features = get_derived_features(src_ip, dst_ip, proto_num)
        
        with sqlite3.connect("nids.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO alerts 
                   (timestamp, src_ip, dst_ip, prediction, confidence, 
                    direction, protocol_name, is_internal_src, is_internal_dst, country) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip, "Attack", confidence,
                 derived_features['direction'], derived_features['protocol_name'],
                 derived_features['is_internal_src'], derived_features['is_internal_dst'],
                 derived_features['country'])
            )
            conn.commit()

def packet_callback(packet):
    # Add timestamp for real-time traffic chart
    packet_timestamps.append(time.time())
    # Update live flows
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = str(packet[IP].proto)
        flow_key = (src_ip, dst_ip, proto)
        pkt_len = len(packet)
        
        # Extract port information
        src_port = dst_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        live_flows[flow_key]['packets'] += 1
        live_flows[flow_key]['bytes'] += pkt_len
        live_flows[flow_key]['last_seen'] = time.time()
        live_flows[flow_key]['proto'] = proto
        live_flows[flow_key]['src_port'] = src_port
        live_flows[flow_key]['dst_port'] = dst_port
        live_flows[flow_key]['derived_features'] = get_derived_features(src_ip, dst_ip, packet[IP].proto)
        
    flow_id, features = extract_features(packet)
    if features:
        predict_packet(flow_id, features)

def start_sniffer(interface=None):
    if interface is None:
        interfaces = get_if_list()
        # Prefer the first non-loopback interface
        interface = next((i for i in interfaces if 'loopback' not in i.lower() and i.lower() != 'lo'), interfaces[0])
        print(f"[INFO] Auto-selected interface: {interface}")
    else:
        print(f"[INFO] Using specified interface: {interface}")
    print("Starting packet sniffer...")
    sniff(iface=interface, prn=packet_callback, store=0)