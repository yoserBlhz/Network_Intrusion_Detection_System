import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
import sqlite3
from datetime import datetime, timedelta
from scapy.all import *
import os
from typing import Dict, List, Tuple, Any, Optional
import warnings
import time
from utils.alert_generator import alert_generator
from utils.ml_rule_generator import MLRuleGenerator
warnings.filterwarnings('ignore')

# Suspicious protocol/port combinations
SUSPICIOUS_COMBINATIONS = {
    (6, 53): "TCP on DNS port (53) - Suspicious",
    (17, 80): "UDP on HTTP port (80) - Suspicious", 
    (17, 443): "UDP on HTTPS port (443) - Suspicious",
    (6, 22): "TCP on SSH port (22) - Monitor",
    (6, 3389): "TCP on RDP port (3389) - Monitor",
    (6, 23): "TCP on Telnet port (23) - Suspicious",
    (6, 21): "TCP on FTP port (21) - Monitor",
    (17, 53): "UDP on DNS port (53) - Normal",
    (6, 80): "TCP on HTTP port (80) - Normal",
    (6, 443): "TCP on HTTPS port (443) - Normal"
}

class NetworkAnalyzer:
    def __init__(self, db_path="nids.db"):
        self.db_path = db_path
        self.suspicious_flows = []
        self.pcap_dir = "suspicious_pcaps"
        os.makedirs(self.pcap_dir, exist_ok=True)
        self.ml_rule_generator = MLRuleGenerator(db_path)
        
    def get_live_flows_for_analysis(self, hours=24) -> List[Dict]:
        """Get live flows data formatted for analysis."""
        from utils.packet_sniffer import live_flows
        live_flows_data = []
        current_time = time.time()
        for (src_ip, dst_ip, proto), info in live_flows.items():
            # Only include flows from the last N hours
            if current_time - info['last_seen'] <= hours * 3600:
                # Try to get proto_num as int
                try:
                    proto_num = int(proto)
                except Exception:
                    proto_num = 0
                
                # Use dst_port as the primary port for analysis
                dst_port = info.get('dst_port', 0)
                src_port = info.get('src_port', 0)
                port = dst_port if dst_port > 0 else src_port
                
                live_flows_data.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol_name': info['derived_features'].get('protocol_name', 'Unknown'),
                    'direction': info['derived_features'].get('direction', 'Unknown'),
                    'is_internal_src': info['derived_features'].get('is_internal_src', False),
                    'is_internal_dst': info['derived_features'].get('is_internal_dst', False),
                    'country': info['derived_features'].get('country', 'Unknown'),
                    'bytes': info['bytes'],
                    'packets': info['packets'],
                    'last_seen': info['last_seen'],
                    'first_seen': info.get('first_seen', info['last_seen']),
                    'dst_port': dst_port,
                    'src_port': src_port,
                    'port': port,  # Add port field for compatibility
                    'proto_num': proto_num,
                    'protocol': info['derived_features'].get('protocol_name', 'Unknown')  # Add protocol field for compatibility
                })
        return live_flows_data

    def get_live_flows_df_for_analysis(self, hours=24) -> pd.DataFrame:
        """Get live flows as a DataFrame, ensuring all required fields and no NaN values."""
        flows = self.get_live_flows_for_analysis(hours)
        df = pd.DataFrame(flows)
        # Ensure all required columns are present
        required_columns = [
            'src_ip', 'dst_ip', 'protocol_name', 'direction', 'is_internal_src', 'is_internal_dst', 'country',
            'bytes', 'packets', 'last_seen', 'first_seen', 'dst_port', 'src_port', 'port', 'proto_num', 'protocol'
        ]
        for col in required_columns:
            if col not in df.columns:
                if col in ['is_internal_src', 'is_internal_dst']:
                    df[col] = False
                elif col in ['bytes', 'packets', 'last_seen', 'first_seen', 'dst_port', 'src_port', 'port', 'proto_num']:
                    df[col] = 0
                else:
                    df[col] = ''
        # Fill NaN values
        df.fillna({
            'src_ip': '', 'dst_ip': '', 'protocol_name': '', 'direction': '', 'country': '', 'protocol': '',
            'is_internal_src': False, 'is_internal_dst': False,
            'bytes': 0, 'packets': 0, 'last_seen': 0, 'first_seen': 0, 'dst_port': 0, 'src_port': 0, 'port': 0, 'proto_num': 0
        }, inplace=True)
        return df

    def get_flow_data(self, hours=24) -> pd.DataFrame:
        """Retrieve flow data from database and live flows for analysis."""
        from utils.packet_sniffer import live_flows
        live_flows_data = []
        current_time = time.time()
        for (src_ip, dst_ip, proto), info in live_flows.items():
            if current_time - info['last_seen'] <= hours * 3600:
                try:
                    proto_num = int(proto)
                except Exception:
                    proto_num = 0
                
                # Use dst_port as the primary port for analysis
                dst_port = info.get('dst_port', 0)
                src_port = info.get('src_port', 0)
                port = dst_port if dst_port > 0 else src_port
                
                live_flows_data.append({
                    'timestamp': pd.to_datetime(info['last_seen'], unit='s'),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol_name': info['derived_features'].get('protocol_name', 'Unknown'),
                    'direction': info['derived_features'].get('direction', 'Unknown'),
                    'is_internal_src': info['derived_features'].get('is_internal_src', False),
                    'is_internal_dst': info['derived_features'].get('is_internal_dst', False),
                    'country': info['derived_features'].get('country', 'Unknown'),
                    'bytes': info['bytes'],
                    'packets': info['packets'],
                    'hour': pd.to_datetime(info['last_seen'], unit='s').hour,
                    'date': pd.to_datetime(info['last_seen'], unit='s').date(),
                    'dst_port': dst_port,
                    'src_port': src_port,
                    'port': port,  # Add port field for compatibility
                    'proto_num': proto_num,
                    'protocol': info['derived_features'].get('protocol_name', 'Unknown')  # Add protocol field for compatibility
                })
        if not live_flows_data:
            print("No live flows available, using alerts data...")
            with sqlite3.connect(self.db_path) as conn:
                alerts_query = """
                    SELECT timestamp, src_ip, dst_ip, protocol_name, direction, 
                           is_internal_src, is_internal_dst, country
                    FROM alerts 
                    WHERE timestamp >= datetime('now', '-{} hours')
                """.format(hours)
                alerts_df = pd.read_sql_query(alerts_query, conn)
                if alerts_df.empty:
                    print("No data in database, creating sample data for testing...")
                    return self._create_sample_data(hours)
                else:
                    alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
                    alerts_df['hour'] = alerts_df['timestamp'].dt.hour
                    alerts_df['date'] = alerts_df['timestamp'].dt.date
                    alerts_df['bytes'] = np.random.randint(100, 10000, len(alerts_df))
                    alerts_df['packets'] = np.random.randint(1, 100, len(alerts_df))
                    def get_port_for_protocol(protocol):
                        port_map = {
                            'HTTP': 80, 'HTTPS': 443, 'DNS': 53, 'SSH': 22,
                            'FTP': 21, 'SMTP': 25, 'POP3': 110, 'IMAP': 143
                        }
                        return port_map.get(protocol, 0)
                    alerts_df['dst_port'] = alerts_df['protocol_name'].apply(get_port_for_protocol)
                    alerts_df['src_port'] = np.random.randint(1024, 65535, len(alerts_df))
                    alerts_df['port'] = alerts_df['dst_port']  # Add port field for compatibility
                    alerts_df['proto_num'] = alerts_df['protocol_name'].apply(lambda p: {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'DNS': 53, 'HTTP': 80, 'HTTPS': 443, 'SSH': 22, 'FTP': 21, 'SMTP': 25, 'POP3': 110, 'IMAP': 143}.get(p, 0))
                    alerts_df['protocol'] = alerts_df['protocol_name']  # Add protocol field for compatibility
                    return alerts_df
        df = pd.DataFrame(live_flows_data)
        print(f"Using {len(df)} live flows for analysis")
        return df
    
    def _create_sample_data(self, hours=24) -> pd.DataFrame:
        """Create sample data for testing when no real data is available."""
        from datetime import datetime, timedelta
        
        # Sample protocols and their typical ports
        protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'TCP', 'UDP']
        sample_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.1', '8.8.8.8', '1.1.1.1', '208.67.222.222']
        
        # Generate sample data for the last N hours
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        data = []
        current_time = start_time
        
        while current_time <= end_time:
            # Generate 5-15 flows per hour
            num_flows = np.random.randint(5, 15)
            
            for _ in range(num_flows):
                protocol = np.random.choice(protocols)
                src_ip = np.random.choice(sample_ips)
                dst_ip = np.random.choice(sample_ips)
                
                # Ensure src and dst are different
                while dst_ip == src_ip:
                    dst_ip = np.random.choice(sample_ips)
                
                # Determine if internal/external
                is_internal_src = src_ip.startswith(('192.168.', '10.'))
                is_internal_dst = dst_ip.startswith(('192.168.', '10.'))
                
                # Determine direction
                if is_internal_src and not is_internal_dst:
                    direction = 'Internal-to-External'
                elif not is_internal_src and is_internal_dst:
                    direction = 'External-to-Internal'
                elif is_internal_src and is_internal_dst:
                    direction = 'Internal-to-Internal'
                else:
                    direction = 'External-to-External'
                
                # Generate flow statistics
                bytes_transferred = np.random.randint(100, 10000)
                packets_sent = np.random.randint(1, 100)
                
                # Get port for protocol
                port_map = {
                    'HTTP': 80, 'HTTPS': 443, 'DNS': 53, 'SSH': 22,
                    'FTP': 21, 'SMTP': 25, 'POP3': 110, 'IMAP': 143
                }
                dst_port = port_map.get(protocol, np.random.randint(1024, 65535))
                
                data.append({
                    'timestamp': current_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol_name': protocol,
                    'direction': direction,
                    'is_internal_src': is_internal_src,
                    'is_internal_dst': is_internal_dst,
                    'country': 'US' if not is_internal_dst else 'Internal',
                    'bytes': bytes_transferred,
                    'packets': packets_sent,
                    'hour': current_time.hour,
                    'date': current_time.date(),
                    'dst_port': dst_port,
                    'src_port': np.random.randint(1024, 65535)
                })
            
            current_time += timedelta(hours=1)
        
        return pd.DataFrame(data)
    
    def create_protocol_heatmap(self, hours=24, save_path="static/protocol_heatmap.png"):
        """Create heatmap showing flows/bytes per hour per protocol."""
        df = self.get_flow_data(hours)
        
        if df.empty:
            print("No data available for heatmap generation")
            return None
            
        # Ensure we have the required columns
        required_columns = ['hour', 'protocol_name', 'bytes', 'packets']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Missing required columns: {missing_columns}")
            return None
        
        # Filter out rows with missing data
        df = df.dropna(subset=['hour', 'protocol_name', 'bytes', 'packets'])
        
        if df.empty:
            print("No valid data after filtering")
            return None
            
        # Group by hour and protocol
        heatmap_data = df.groupby(['hour', 'protocol_name']).agg({
            'bytes': 'sum',
            'packets': 'sum'
        }).reset_index()
        
        if heatmap_data.empty:
            print("No data after aggregation")
            return None
        
        # Pivot for heatmap
        bytes_pivot = heatmap_data.pivot(index='hour', columns='protocol_name', values='bytes').fillna(0)
        packets_pivot = heatmap_data.pivot(index='hour', columns='protocol_name', values='packets').fillna(0)
        
        # Check if we have data to plot
        if bytes_pivot.empty or packets_pivot.empty:
            print("No data available for heatmap after pivoting")
            return None
        
        # Create subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Bytes heatmap
        sns.heatmap(bytes_pivot, annot=True, fmt='.0f', cmap='YlOrRd', ax=ax1)
        ax1.set_title('Bytes per Hour by Protocol')
        ax1.set_xlabel('Protocol')
        ax1.set_ylabel('Hour of Day')
        
        # Packets heatmap
        sns.heatmap(packets_pivot, annot=True, fmt='.0f', cmap='Blues', ax=ax2)
        ax2.set_title('Packets per Hour by Protocol')
        ax2.set_xlabel('Protocol')
        ax2.set_ylabel('Hour of Day')
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return save_path
    
    def get_top_source_ips(self, hours=24, top_n=10) -> Dict[str, pd.DataFrame]:
        """Get top source IPs by different metrics."""
        df = self.get_flow_data(hours)
        
        if df.empty:
            return {}
            
        # Group by source IP
        ip_stats = df.groupby('src_ip').agg({
            'bytes': 'sum',
            'packets': 'sum',
            'dst_ip': 'nunique'
        }).reset_index()
        
        ip_stats.columns = ['src_ip', 'total_bytes', 'total_packets', 'distinct_destinations']
        
        # Get top 10 by each metric
        top_by_bytes = ip_stats.nlargest(top_n, 'total_bytes')
        top_by_packets = ip_stats.nlargest(top_n, 'total_packets')
        top_by_destinations = ip_stats.nlargest(top_n, 'distinct_destinations')
        
        return {
            'by_bytes': top_by_bytes,
            'by_packets': top_by_packets,
            'by_destinations': top_by_destinations
        }
    
    def detect_suspicious_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect suspicious flows using both rule-based and ML-generated rules."""
        if df.empty:
            return pd.DataFrame()
        
        suspicious_flows = []
        
        for _, flow in df.iterrows():
            suspicion_reasons = []
            ml_triggered_rules = []
            
            # Apply existing rule-based detection
            flow_dict = flow.to_dict()
            
            # Handle missing fields gracefully for live flows data
            proto_num = flow.get('proto_num', None)
            port = flow.get('port', None)
            src_port = flow.get('src_port', 0)
            dst_port = flow.get('dst_port', 0)
            proto = flow.get('proto', '')
            
            # If proto_num is missing, try to derive from proto string
            if proto_num is None and proto:
                try:
                    proto_num = int(proto)
                except (ValueError, TypeError):
                    proto_num = 0
            
            # If port is missing, use dst_port as the primary port
            if port is None:
                port = dst_port if dst_port > 0 else src_port
            
            # Check for suspicious protocols/ports
            if proto_num == 23:  # Telnet
                suspicion_reasons.append("Telnet usage detected")
            elif proto_num == 22 and port == 22:  # SSH
                suspicion_reasons.append("SSH access detected")
            elif proto_num == 6 and port == 3389:  # RDP
                suspicion_reasons.append("RDP access detected")
            elif proto_num == 17 and port == 53:  # DNS
                if flow['packets'] > 1000:  # High DNS activity
                    suspicion_reasons.append("Potential DNS tunneling")
            
            # Check for unusual packet/byte patterns
            if flow['packets'] > 10000:  # Very high packet count
                suspicion_reasons.append("Unusually high packet count")
            elif flow['bytes'] > 1000000:  # Very high byte count
                suspicion_reasons.append("Unusually high byte count")
            
            # Check for unusual port activity
            if port and port > 49152:  # Dynamic ports
                if flow['packets'] > 1000:
                    suspicion_reasons.append("High activity on dynamic port")
            
            # Apply ML-generated rules
            try:
                ml_triggers = self.ml_rule_generator.apply_ml_rules(flow_dict)
                if ml_triggers:
                    ml_triggered_rules = ml_triggers
                    for trigger in ml_triggers:
                        suspicion_reasons.append(f"ML Rule: {trigger['description']}")
            except Exception as e:
                print(f"Error applying ML rules: {e}")
            
            # If suspicious, add to results
            if suspicion_reasons or ml_triggered_rules:
                suspicious_flow = {
                    'src_ip': flow['src_ip'],
                    'dst_ip': flow['dst_ip'],
                    'protocol': flow.get('protocol', flow.get('protocol_name', 'Unknown')),
                    'port': port if port is not None else 0,
                    'proto_num': proto_num if proto_num is not None else 0,
                    'packets': flow['packets'],
                    'bytes': flow['bytes'],
                    'timestamp': flow.get('timestamp', flow.get('last_seen', datetime.now().isoformat())),
                    'suspicion_reason': '; '.join(suspicion_reasons),
                    'direction': flow.get('direction', 'Unknown'),
                    'country': flow.get('country', 'Unknown'),
                    'ml_triggered_rules': ml_triggered_rules,
                    'ml_rule_count': len(ml_triggered_rules)
                }
                suspicious_flows.append(suspicious_flow)
        
        return pd.DataFrame(suspicious_flows)
    
    def save_suspicious_pcap(self, suspicious_flows: pd.DataFrame, 
                           live_capture_func=None, duration=60):
        """Save suspicious flows to PCAP files."""
        if suspicious_flows.empty:
            print("No suspicious flows to save")
            return []
        
        saved_files = []
        
        for _, flow in suspicious_flows.iterrows():
            timestamp = flow['timestamp']
            if isinstance(timestamp, str):
                timestamp = pd.to_datetime(timestamp)
            
            filename = f"suspicious_{flow['src_ip']}_{flow['dst_ip']}_{flow['protocol']}_{timestamp.strftime('%Y%m%d_%H%M%S')}.pcap"
            filepath = os.path.join(self.pcap_dir, filename)
            
            # Create a simple PCAP with dummy packets for demonstration
            # In real implementation, you'd extract actual packets from live capture
            packets = []
            
            # Create dummy packets based on protocol
            if flow['protocol'] == 'TCP':
                pkt = IP(src=flow['src_ip'], dst=flow['dst_ip'])/TCP(sport=RandShort(), dport=flow['port'])
            elif flow['protocol'] == 'UDP':
                pkt = IP(src=flow['src_ip'], dst=flow['dst_ip'])/UDP(sport=RandShort(), dport=flow['port'])
            else:
                pkt = IP(src=flow['src_ip'], dst=flow['dst_ip'])
            
            packets.append(pkt)
            
            # Save to PCAP
            wrpcap(filepath, packets)
            saved_files.append({
                'filepath': filepath,
                'flow_info': flow.to_dict()
            })
            
            print(f"Saved suspicious flow to {filepath}")
        
        return saved_files
    
    def generate_analysis_report(self, hours=24) -> Dict[str, Any]:
        """Generate comprehensive network analysis report."""
        df = self.get_flow_data(hours)
        
        if df.empty:
            return {"error": "No data available for analysis"}
        
        # Generate heatmap
        heatmap_path = self.create_protocol_heatmap(hours)
        
        # Get top IPs
        top_ips = self.get_top_source_ips(hours)
        
        # Detect suspicious flows
        suspicious_flows = self.detect_suspicious_flows(df)
        
        # Save suspicious PCAPs
        saved_pcaps = self.save_suspicious_pcap(suspicious_flows)
        
        # Generate summary statistics
        summary_stats = {
            'total_flows': len(df),
            'unique_src_ips': df['src_ip'].nunique(),
            'unique_dst_ips': df['dst_ip'].nunique(),
            'protocols_detected': df['protocol_name'].value_counts().to_dict(),
            'suspicious_flows_count': len(suspicious_flows),
            'internal_to_external_flows': len(df[df['direction'] == 'Internal-to-External']),
            'external_to_internal_flows': len(df[df['direction'] == 'External-to-Internal']),
            'total_bytes': df['bytes'].sum(),
            'total_packets': df['packets'].sum()
        }
        
        return {
            'summary_stats': summary_stats,
            'heatmap_path': heatmap_path,
            'top_ips': top_ips,
            'suspicious_flows': suspicious_flows.to_dict('records'),
            'saved_pcaps': saved_pcaps,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def get_top_source_ips_from_df(self, df: pd.DataFrame, top_n=10) -> Dict[str, pd.DataFrame]:
        """Get top source IPs by different metrics from DataFrame."""
        if df.empty:
            return {}
            
        # Group by source IP
        ip_stats = df.groupby('src_ip').agg({
            'bytes': 'sum',
            'packets': 'sum',
            'dst_ip': 'nunique'
        }).reset_index()
        
        ip_stats.columns = ['src_ip', 'total_bytes', 'total_packets', 'distinct_destinations']
        
        # Get top 10 by each metric
        top_by_bytes = ip_stats.nlargest(top_n, 'total_bytes')
        top_by_packets = ip_stats.nlargest(top_n, 'total_packets')
        top_by_destinations = ip_stats.nlargest(top_n, 'distinct_destinations')
        
        return {
            'by_bytes': top_by_bytes,
            'by_packets': top_by_packets,
            'by_destinations': top_by_destinations
        }

    def create_protocol_heatmap_from_df(self, df: pd.DataFrame, save_path="static/protocol_heatmap.png"):
        """Create heatmap showing flows/bytes per hour per protocol from DataFrame."""
        if df.empty:
            print("No data available for heatmap generation")
            return None
            
        # Ensure we have the required columns
        required_columns = ['hour', 'protocol_name', 'bytes', 'packets']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Missing required columns: {missing_columns}")
            return None
        
        # Filter out rows with missing data
        df = df.dropna(subset=['hour', 'protocol_name', 'bytes', 'packets'])
        
        if df.empty:
            print("No valid data after filtering")
            return None
            
        # Group by hour and protocol
        heatmap_data = df.groupby(['hour', 'protocol_name']).agg({
            'bytes': 'sum',
            'packets': 'sum'
        }).reset_index()
        
        if heatmap_data.empty:
            print("No data after aggregation")
            return None
        
        # Pivot for heatmap
        bytes_pivot = heatmap_data.pivot(index='hour', columns='protocol_name', values='bytes').fillna(0)
        packets_pivot = heatmap_data.pivot(index='hour', columns='protocol_name', values='packets').fillna(0)
        
        # Check if we have data to plot
        if bytes_pivot.empty or packets_pivot.empty:
            print("No data available for heatmap after pivoting")
            return None
        
        # Create subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Bytes heatmap
        sns.heatmap(bytes_pivot, annot=True, fmt='.0f', cmap='YlOrRd', ax=ax1)
        ax1.set_title('Bytes per Hour by Protocol (Live Flows)')
        ax1.set_xlabel('Protocol')
        ax1.set_ylabel('Hour of Day')
        
        # Packets heatmap
        sns.heatmap(packets_pivot, annot=True, fmt='.0f', cmap='Blues', ax=ax2)
        ax2.set_title('Packets per Hour by Protocol (Live Flows)')
        ax2.set_xlabel('Protocol')
        ax2.set_ylabel('Hour of Day')
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return save_path

# Global analyzer instance
analyzer = NetworkAnalyzer() 