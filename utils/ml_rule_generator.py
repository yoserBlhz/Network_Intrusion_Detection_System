import pandas as pd
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
import joblib
import sqlite3
from typing import List, Dict, Any, Tuple
import json
import os
from datetime import datetime, timedelta
import ipaddress
import re

class MLRuleGenerator:
    def __init__(self, db_path: str = "nids.db"):
        self.db_path = db_path
        self.rules_file = "ml_generated_rules.json"
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        
    def extract_features_from_flows(self, flows_data: List[Dict]) -> pd.DataFrame:
        """Extract features from flow data for ML analysis."""
        if not flows_data:
            return pd.DataFrame()
            
        df = pd.DataFrame(flows_data)
        
        # Basic flow features
        features = {
            'flow_duration': df['last_seen'] - df['first_seen'],
            'packets_per_second': df['packets'] / (df['last_seen'] - df['first_seen'] + 1),
            'bytes_per_packet': df['bytes'] / (df['packets'] + 1),
            'packet_size_variance': df['bytes'] / (df['packets'] + 1),  # Simplified variance
            'protocol_numeric': df['proto_num'],
            'port_numeric': df['port'],
            'is_internal_src': df['is_internal_src'].astype(int),
            'is_internal_dst': df['is_internal_dst'].astype(int),
        }
        
        # Add derived features
        features['internal_to_external'] = ((df['is_internal_src'] == 1) & (df['is_internal_dst'] == 0)).astype(int)
        features['external_to_internal'] = ((df['is_internal_src'] == 0) & (df['is_internal_dst'] == 1)).astype(int)
        features['internal_to_internal'] = ((df['is_internal_src'] == 1) & (df['is_internal_dst'] == 1)).astype(int)
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['last_seen'], unit='s')
        features['hour_of_day'] = df['timestamp'].dt.hour
        features['day_of_week'] = df['timestamp'].dt.dayofweek
        
        return pd.DataFrame(features)
    
    def detect_anomalous_patterns(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        """Detect anomalous patterns using isolation forest."""
        if features_df.empty:
            return {}
            
        # Scale features
        scaled_features = self.scaler.fit_transform(features_df.fillna(0))
        
        # Detect anomalies
        anomaly_scores = self.isolation_forest.fit_predict(scaled_features)
        anomaly_indices = np.where(anomaly_scores == -1)[0]
        
        # Analyze anomalous patterns
        anomalous_features = features_df.iloc[anomaly_indices]
        
        patterns = {
            'anomaly_count': len(anomaly_indices),
            'total_flows': len(features_df),
            'anomaly_ratio': len(anomaly_indices) / len(features_df),
            'anomalous_protocols': anomalous_features['protocol_numeric'].value_counts().to_dict(),
            'anomalous_ports': anomalous_features['port_numeric'].value_counts().head(10).to_dict(),
            'anomalous_directions': {
                'internal_to_external': int(anomalous_features['internal_to_external'].sum()),
                'external_to_internal': int(anomalous_features['external_to_internal'].sum()),
                'internal_to_internal': int(anomalous_features['internal_to_internal'].sum())
            },
            'anomalous_hours': anomalous_features['hour_of_day'].value_counts().to_dict(),
            'avg_anomalous_duration': float(anomalous_features['flow_duration'].mean()),
            'avg_anomalous_packets_per_sec': float(anomalous_features['packets_per_second'].mean()),
            'avg_anomalous_bytes_per_packet': float(anomalous_features['bytes_per_packet'].mean())
        }
        
        return patterns
    
    def cluster_suspicious_flows(self, flows_data: List[Dict], n_clusters: int = 5) -> Dict[str, Any]:
        """Cluster suspicious flows to identify patterns."""
        if not flows_data:
            return {}
            
        features_df = self.extract_features_from_flows(flows_data)
        if features_df.empty:
            return {}
        
        # Scale features for clustering
        scaled_features = self.scaler.fit_transform(features_df.fillna(0))
        
        # Perform clustering
        kmeans = KMeans(n_clusters=min(n_clusters, len(features_df)), random_state=42)
        cluster_labels = kmeans.fit_predict(scaled_features)
        
        # Analyze clusters
        features_df['cluster'] = cluster_labels
        cluster_analysis = {}
        
        for cluster_id in range(len(features_df['cluster'].unique())):
            cluster_data = features_df[features_df['cluster'] == cluster_id]
            
            cluster_analysis[f'cluster_{cluster_id}'] = {
                'size': len(cluster_data),
                'avg_duration': float(cluster_data['flow_duration'].mean()),
                'avg_packets_per_sec': float(cluster_data['packets_per_second'].mean()),
                'avg_bytes_per_packet': float(cluster_data['bytes_per_packet'].mean()),
                'common_protocols': cluster_data['protocol_numeric'].value_counts().head(3).to_dict(),
                'common_ports': cluster_data['port_numeric'].value_counts().head(5).to_dict(),
                'direction_pattern': {
                    'internal_to_external': int(cluster_data['internal_to_external'].sum()),
                    'external_to_internal': int(cluster_data['external_to_internal'].sum()),
                    'internal_to_internal': int(cluster_data['internal_to_internal'].sum())
                },
                'peak_hours': cluster_data['hour_of_day'].value_counts().head(3).to_dict()
            }
        
        return cluster_analysis
    
    def generate_protocol_rules(self, flows_data: List[Dict]) -> List[Dict]:
        """Generate protocol-based detection rules."""
        if not flows_data:
            return []
            
        df = pd.DataFrame(flows_data)
        protocol_stats = df.groupby('proto_num').agg({
            'packets': ['mean', 'std', 'count'],
            'bytes': ['mean', 'std'],
            'port': ['nunique'],
            'src_ip': ['nunique'],
            'dst_ip': ['nunique']
        }).round(2)
        
        rules = []
        for protocol in protocol_stats.index:
            stats = protocol_stats.loc[protocol]
            
            # Calculate thresholds based on statistical analysis
            packet_mean = stats[('packets', 'mean')]
            packet_std = stats[('packets', 'std')]
            byte_mean = stats[('bytes', 'mean')]
            byte_std = stats[('bytes', 'std')]
            
            # Generate rule thresholds (mean + 2*std for anomaly detection)
            packet_threshold = packet_mean + (2 * packet_std) if not np.isnan(packet_std) else packet_mean * 3
            byte_threshold = byte_mean + (2 * byte_std) if not np.isnan(byte_std) else byte_mean * 3
            
            rule = {
                'rule_id': f'ML_PROTOCOL_{protocol}_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'rule_type': 'protocol_anomaly',
                'protocol': int(protocol),
                'protocol_name': self._get_protocol_name(int(protocol)),
                'conditions': {
                    'packets_threshold': float(packet_threshold),
                    'bytes_threshold': float(byte_threshold),
                    'unique_ports_threshold': int(stats[('port', 'nunique')] * 1.5),
                    'unique_src_ips_threshold': int(stats[('src_ip', 'nunique')] * 1.5),
                    'unique_dst_ips_threshold': int(stats[('dst_ip', 'nunique')] * 1.5)
                },
                'severity': 'MEDIUM',
                'description': f'ML-generated protocol anomaly rule for {self._get_protocol_name(int(protocol))}',
                'confidence': 0.8,
                'created_at': datetime.now().isoformat(),
                'stats': {
                    'avg_packets': float(packet_mean),
                    'avg_bytes': float(byte_mean),
                    'flow_count': int(stats[('packets', 'count')])
                }
            }
            rules.append(rule)
        
        return rules
    
    def generate_port_rules(self, flows_data: List[Dict]) -> List[Dict]:
        """Generate port-based detection rules."""
        if not flows_data:
            return []
            
        df = pd.DataFrame(flows_data)
        
        # Analyze ports with high activity
        port_stats = df.groupby('port').agg({
            'packets': ['mean', 'std', 'count'],
            'bytes': ['mean', 'std'],
            'src_ip': ['nunique'],
            'dst_ip': ['nunique'],
            'proto_num': ['nunique']
        }).round(2)
        
        # Filter for ports with significant activity
        significant_ports = port_stats[port_stats[('packets', 'count')] > 10]
        
        rules = []
        for port in significant_ports.index:
            stats = significant_ports.loc[port]
            
            # Calculate thresholds
            packet_mean = stats[('packets', 'mean')]
            packet_std = stats[('packets', 'std')]
            byte_mean = stats[('bytes', 'mean')]
            byte_std = stats[('bytes', 'std')]
            
            packet_threshold = packet_mean + (2 * packet_std) if not np.isnan(packet_std) else packet_mean * 3
            byte_threshold = byte_mean + (2 * byte_std) if not np.isnan(byte_std) else byte_mean * 3
            
            # Determine severity based on port
            severity = self._determine_port_severity(int(port))
            
            rule = {
                'rule_id': f'ML_PORT_{port}_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'rule_type': 'port_anomaly',
                'port': int(port),
                'conditions': {
                    'packets_threshold': float(packet_threshold),
                    'bytes_threshold': float(byte_threshold),
                    'unique_src_ips_threshold': int(stats[('src_ip', 'nunique')] * 1.5),
                    'unique_dst_ips_threshold': int(stats[('dst_ip', 'nunique')] * 1.5),
                    'protocols_threshold': int(stats[('proto_num', 'nunique')] * 1.5)
                },
                'severity': severity,
                'description': f'ML-generated port anomaly rule for port {port}',
                'confidence': 0.75,
                'created_at': datetime.now().isoformat(),
                'stats': {
                    'avg_packets': float(packet_mean),
                    'avg_bytes': float(byte_mean),
                    'flow_count': int(stats[('packets', 'count')])
                }
            }
            rules.append(rule)
        
        return rules
    
    def generate_temporal_rules(self, flows_data: List[Dict]) -> List[Dict]:
        """Generate time-based detection rules."""
        if not flows_data:
            return []
            
        df = pd.DataFrame(flows_data)
        df['timestamp'] = pd.to_datetime(df['last_seen'], unit='s')
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Analyze temporal patterns
        hourly_stats = df.groupby('hour').agg({
            'packets': ['mean', 'std', 'count'],
            'bytes': ['mean', 'std'],
            'src_ip': ['nunique'],
            'dst_ip': ['nunique']
        }).round(2)
        
        rules = []
        for hour in hourly_stats.index:
            stats = hourly_stats.loc[hour]
            
            # Calculate baseline for this hour
            packet_baseline = stats[('packets', 'mean')]
            byte_baseline = stats[('bytes', 'mean')]
            
            # Generate threshold (baseline + 50% for anomaly)
            packet_threshold = packet_baseline * 1.5
            byte_threshold = byte_baseline * 1.5
            
            rule = {
                'rule_id': f'ML_TEMPORAL_{hour:02d}_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'rule_type': 'temporal_anomaly',
                'hour': int(hour),
                'conditions': {
                    'packets_threshold': float(packet_threshold),
                    'bytes_threshold': float(byte_threshold),
                    'unique_src_ips_threshold': int(stats[('src_ip', 'nunique')] * 1.3),
                    'unique_dst_ips_threshold': int(stats[('dst_ip', 'nunique')] * 1.3)
                },
                'severity': 'LOW',
                'description': f'ML-generated temporal anomaly rule for hour {hour:02d}:00',
                'confidence': 0.7,
                'created_at': datetime.now().isoformat(),
                'baseline': {
                    'avg_packets': float(packet_baseline),
                    'avg_bytes': float(byte_baseline),
                    'flow_count': int(stats[('packets', 'count')])
                }
            }
            rules.append(rule)
        
        return rules
    
    def generate_behavioral_rules(self, flows_data: List[Dict]) -> List[Dict]:
        """Generate behavioral pattern rules."""
        if not flows_data:
            return []
            
        df = pd.DataFrame(flows_data)
        
        # Analyze source IP behavior
        src_ip_stats = df.groupby('src_ip').agg({
            'packets': ['sum', 'mean', 'count'],
            'bytes': ['sum', 'mean'],
            'dst_ip': ['nunique'],
            'port': ['nunique'],
            'proto_num': ['nunique']
        }).round(2)
        
        # Find IPs with unusual behavior
        high_activity_ips = src_ip_stats[
            (src_ip_stats[('packets', 'sum')] > src_ip_stats[('packets', 'sum')].quantile(0.95)) |
            (src_ip_stats[('dst_ip', 'nunique')] > src_ip_stats[('dst_ip', 'nunique')].quantile(0.95)) |
            (src_ip_stats[('port', 'nunique')] > src_ip_stats[('port', 'nunique')].quantile(0.95))
        ]
        
        rules = []
        for src_ip in high_activity_ips.index:
            stats = high_activity_ips.loc[src_ip]
            
            rule = {
                'rule_id': f'ML_BEHAVIOR_{src_ip.replace(".", "_")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'rule_type': 'behavioral_anomaly',
                'src_ip': src_ip,
                'conditions': {
                    'total_packets_threshold': float(stats[('packets', 'sum')] * 0.8),
                    'avg_packets_per_flow_threshold': float(stats[('packets', 'mean')] * 1.2),
                    'unique_destinations_threshold': int(stats[('dst_ip', 'nunique')] * 0.8),
                    'unique_ports_threshold': int(stats[('port', 'nunique')] * 0.8),
                    'unique_protocols_threshold': int(stats[('proto_num', 'nunique')] * 0.8)
                },
                'severity': 'HIGH',
                'description': f'ML-generated behavioral anomaly rule for source IP {src_ip}',
                'confidence': 0.85,
                'created_at': datetime.now().isoformat(),
                'behavior_profile': {
                    'total_packets': int(stats[('packets', 'sum')]),
                    'avg_packets_per_flow': float(stats[('packets', 'mean')]),
                    'unique_destinations': int(stats[('dst_ip', 'nunique')]),
                    'unique_ports': int(stats[('port', 'nunique')]),
                    'unique_protocols': int(stats[('proto_num', 'nunique')]),
                    'total_flows': int(stats[('packets', 'count')])
                }
            }
            rules.append(rule)
        
        return rules
    
    def analyze_historical_data(self, hours: int = 24, use_live_flows: bool = False) -> Dict[str, Any]:
        """Analyze historical flow data to generate ML-based rules. Optionally use live flows."""
        try:
            if use_live_flows:
                from utils.network_analyzer import analyzer
                flows_data = analyzer.get_live_flows_for_analysis(hours)
                if not flows_data:
                    return {'error': 'No live flow data available'}
            else:
                with sqlite3.connect(self.db_path) as conn:
                    # Get flows from the last N hours
                    cutoff_time = datetime.now() - timedelta(hours=hours)
                    cutoff_timestamp = cutoff_time.timestamp()
                    query = """
                        SELECT * FROM live_flows 
                        WHERE last_seen >= ? 
                        ORDER BY last_seen DESC
                    """
                    df = pd.read_sql_query(query, conn, params=(cutoff_timestamp,))
                    if df.empty:
                        return {'error': 'No historical data available'}
                    flows_data = df.to_dict('records')
            # Extract features and analyze patterns
            features_df = self.extract_features_from_flows(flows_data)
            anomaly_patterns = self.detect_anomalous_patterns(features_df)
            cluster_analysis = self.cluster_suspicious_flows(flows_data)
            # Generate rules
            protocol_rules = self.generate_protocol_rules(flows_data)
            port_rules = self.generate_port_rules(flows_data)
            temporal_rules = self.generate_temporal_rules(flows_data)
            behavioral_rules = self.generate_behavioral_rules(flows_data)
            # Combine all rules
            all_rules = protocol_rules + port_rules + temporal_rules + behavioral_rules
            analysis_result = {
                'analysis_timestamp': datetime.now().isoformat(),
                'data_period_hours': hours,
                'total_flows_analyzed': len(flows_data),
                'anomaly_patterns': anomaly_patterns,
                'cluster_analysis': cluster_analysis,
                'generated_rules': {
                    'protocol_rules': len(protocol_rules),
                    'port_rules': len(port_rules),
                    'temporal_rules': len(temporal_rules),
                    'behavioral_rules': len(behavioral_rules),
                    'total_rules': len(all_rules)
                },
                'rules': all_rules
            }
            # Save rules to file
            self.save_rules(all_rules)
            return analysis_result
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def save_rules(self, rules: List[Dict]) -> None:
        """Save generated rules to JSON file."""
        try:
            existing_rules = []
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    existing_rules = json.load(f)
            
            # Add new rules
            all_rules = existing_rules + rules
            
            # Save updated rules
            with open(self.rules_file, 'w') as f:
                json.dump(all_rules, f, indent=2, default=str)
                
        except Exception as e:
            print(f"Error saving rules: {e}")
    
    def load_rules(self) -> List[Dict]:
        """Load existing ML-generated rules."""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error loading rules: {e}")
            return []
    
    def apply_ml_rules(self, flow_data: Dict) -> List[Dict]:
        """Apply ML-generated rules to a single flow."""
        rules = self.load_rules()
        triggered_rules = []
        
        for rule in rules:
            if self._evaluate_rule(rule, flow_data):
                triggered_rules.append({
                    'rule_id': rule['rule_id'],
                    'rule_type': rule['rule_type'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'confidence': rule['confidence'],
                    'triggered_at': datetime.now().isoformat()
                })
        
        return triggered_rules
    
    def _evaluate_rule(self, rule: Dict, flow_data: Dict) -> bool:
        """Evaluate if a flow triggers a specific rule."""
        conditions = rule['conditions']
        
        try:
            if rule['rule_type'] == 'protocol_anomaly':
                return (flow_data['proto_num'] == rule['protocol'] and
                        flow_data['packets'] > conditions['packets_threshold'])
            
            elif rule['rule_type'] == 'port_anomaly':
                return (flow_data['port'] == rule['port'] and
                        flow_data['packets'] > conditions['packets_threshold'])
            
            elif rule['rule_type'] == 'temporal_anomaly':
                timestamp = datetime.fromtimestamp(flow_data['last_seen'])
                return (timestamp.hour == rule['hour'] and
                        flow_data['packets'] > conditions['packets_threshold'])
            
            elif rule['rule_type'] == 'behavioral_anomaly':
                return (flow_data['src_ip'] == rule['src_ip'] and
                        flow_data['packets'] > conditions['avg_packets_per_flow_threshold'])
            
            return False
            
        except Exception:
            return False
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Get protocol name from number."""
        protocol_map = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 53: 'DNS', 80: 'HTTP',
            443: 'HTTPS', 22: 'SSH', 23: 'TELNET', 3389: 'RDP'
        }
        return protocol_map.get(protocol_num, f'PROTO_{protocol_num}')
    
    def _determine_port_severity(self, port: int) -> str:
        """Determine severity based on port number."""
        high_risk_ports = {22, 23, 3389, 445, 135, 139, 1433, 3306, 5432}
        medium_risk_ports = {21, 25, 53, 80, 110, 143, 443, 993, 995}
        
        if port in high_risk_ports:
            return 'HIGH'
        elif port in medium_risk_ports:
            return 'MEDIUM'
        else:
            return 'LOW' 