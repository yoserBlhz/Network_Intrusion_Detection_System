import json
import time
from datetime import datetime
from typing import Dict, List, Any
import uuid
from dataclasses import dataclass, asdict
import sqlite3

@dataclass
class StructuredAlert:
    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    packets: int
    bytes: int
    threat_type: str
    anomaly_score: float
    severity: str
    suspicion_reason: str
    direction: str
    country: str
    port: int
    proto_num: int

class AlertGenerator:
    def __init__(self, db_path="nids.db"):
        self.db_path = db_path
        self.alert_counter = 0
        self.init_alert_table()
    
    def init_alert_table(self):
        """Initialize the structured alerts table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS structured_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    packets INTEGER,
                    bytes INTEGER,
                    threat_type TEXT,
                    anomaly_score REAL,
                    severity TEXT,
                    suspicion_reason TEXT,
                    direction TEXT,
                    country TEXT,
                    port INTEGER,
                    proto_num INTEGER,
                    created_at TEXT
                )
            """)
            conn.commit()
    
    def calculate_anomaly_score(self, flow_data: Dict[str, Any]) -> float:
        """Calculate anomaly score based on various factors."""
        score = 0.0
        
        # Base score for suspicious protocol/port combinations
        suspicion_reason = flow_data.get('suspicion_reason', '').lower()
        if 'suspicious' in suspicion_reason:
            score += 0.4
        elif 'monitor' in suspicion_reason:
            score += 0.2
        
        # Score based on protocol
        protocol = flow_data.get('protocol', '').lower()
        if protocol in ['tcp', 'udp']:
            score += 0.1
        
        # Score based on direction (external connections are riskier)
        direction = flow_data.get('direction', '')
        if 'external' in direction.lower():
            score += 0.2
        
        # Score based on country (non-internal)
        country = flow_data.get('country', '')
        if country.lower() != 'internal':
            score += 0.1
        
        # Score based on port (well-known ports are less suspicious)
        port = flow_data.get('port', 0)
        if port in [80, 443, 53]:  # Common ports
            score -= 0.1
        elif port in [22, 23, 3389]:  # Admin ports
            score += 0.2
        
        # Normalize score to 0-1 range
        return max(0.0, min(1.0, score))
    
    def determine_threat_type(self, flow_data: Dict[str, Any]) -> str:
        """Determine the type of threat based on flow characteristics."""
        suspicion_reason = flow_data.get('suspicion_reason', '').lower()
        protocol = flow_data.get('protocol', '').lower()
        port = flow_data.get('port', 0)
        
        if 'tcp on dns port' in suspicion_reason:
            return "DNS Tunneling"
        elif 'udp on http' in suspicion_reason or 'udp on https' in suspicion_reason:
            return "Protocol Anomaly"
        elif port == 23:
            return "Telnet Usage"
        elif port == 22:
            return "SSH Access"
        elif port == 3389:
            return "RDP Access"
        elif 'suspicious' in suspicion_reason:
            return "Suspicious Protocol/Port"
        elif 'monitor' in suspicion_reason:
            return "Unusual Activity"
        else:
            return "Protocol Anomaly"
    
    def determine_severity(self, anomaly_score: float, threat_type: str) -> str:
        """Determine severity level based on anomaly score and threat type."""
        if anomaly_score >= 0.7:
            return "HIGH"
        elif anomaly_score >= 0.4:
            return "MEDIUM"
        elif anomaly_score >= 0.2:
            return "LOW"
        else:
            return "INFO"
    
    def generate_structured_alert(self, flow_data: Dict[str, Any]) -> StructuredAlert:
        """Generate a structured alert for a suspicious flow."""
        # Generate unique alert ID
        alert_id = f"ALERT_{int(time.time())}_{uuid.uuid4().hex[:8].upper()}"
        
        # Calculate metrics
        anomaly_score = self.calculate_anomaly_score(flow_data)
        threat_type = self.determine_threat_type(flow_data)
        severity = self.determine_severity(anomaly_score, threat_type)
        
        # Handle timestamp conversion
        timestamp = flow_data.get('timestamp', datetime.now().isoformat())
        if hasattr(timestamp, 'isoformat'):  # If it's a pandas Timestamp or datetime object
            timestamp = timestamp.isoformat()
        elif isinstance(timestamp, (int, float)):  # If it's a Unix timestamp
            timestamp = datetime.fromtimestamp(timestamp).isoformat()
        
        # Create structured alert
        alert = StructuredAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            src_ip=flow_data.get('src_ip', ''),
            dst_ip=flow_data.get('dst_ip', ''),
            protocol=flow_data.get('protocol', ''),
            packets=flow_data.get('packets', 0),
            bytes=flow_data.get('bytes', 0),
            threat_type=threat_type,
            anomaly_score=round(anomaly_score, 3),
            severity=severity,
            suspicion_reason=flow_data.get('suspicion_reason', ''),
            direction=flow_data.get('direction', ''),
            country=flow_data.get('country', ''),
            port=flow_data.get('port', 0),
            proto_num=flow_data.get('proto_num', 0)
        )
        
        return alert
    
    def save_alert(self, alert: StructuredAlert):
        """Save alert to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO structured_alerts 
                (alert_id, timestamp, src_ip, dst_ip, protocol, packets, bytes,
                 threat_type, anomaly_score, severity, suspicion_reason, direction,
                 country, port, proto_num, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id, alert.timestamp, alert.src_ip, alert.dst_ip,
                alert.protocol, alert.packets, alert.bytes, alert.threat_type,
                alert.anomaly_score, alert.severity, alert.suspicion_reason,
                alert.direction, alert.country, alert.port, alert.proto_num,
                datetime.now().isoformat()
            ))
            conn.commit()
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve alerts from database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT alert_id, timestamp, src_ip, dst_ip, protocol, packets, bytes,
                       threat_type, anomaly_score, severity, suspicion_reason, direction,
                       country, port, proto_num, created_at
                FROM structured_alerts 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (limit,))
            
            columns = [description[0] for description in cursor.description]
            alerts = []
            for row in cursor.fetchall():
                alert_dict = dict(zip(columns, row))
                alerts.append(alert_dict)
            
            return alerts
    
    def get_alerts_by_severity(self, severity: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get alerts filtered by severity level."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM structured_alerts 
                    WHERE severity = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (severity, limit))
                
                columns = [description[0] for description in cursor.description]
                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(zip(columns, row))
                    alerts.append(alert_dict)
                
                return alerts
        except Exception as e:
            print(f"Error getting alerts by severity: {e}")
            return []
    
    def get_alerts_by_threat_type(self, threat_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts filtered by threat type."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM structured_alerts 
                    WHERE threat_type = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (threat_type, limit))
                
                columns = [description[0] for description in cursor.description]
                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(zip(columns, row))
                    alerts.append(alert_dict)
                
                return alerts
        except Exception as e:
            print(f"Error getting alerts by threat type: {e}")
            return []
    
    def get_alerts_by_protocol(self, protocol: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts filtered by protocol."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM structured_alerts 
                    WHERE protocol = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (protocol, limit))
                
                columns = [description[0] for description in cursor.description]
                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(zip(columns, row))
                    alerts.append(alert_dict)
                
                return alerts
        except Exception as e:
            print(f"Error getting alerts by protocol: {e}")
            return []
    
    def get_alerts_by_ip(self, ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts filtered by IP address (source or destination)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM structured_alerts 
                    WHERE src_ip = ? OR dst_ip = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (ip, ip, limit))
                
                columns = [description[0] for description in cursor.description]
                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(zip(columns, row))
                    alerts.append(alert_dict)
                
                return alerts
        except Exception as e:
            print(f"Error getting alerts by IP: {e}")
            return []
    
    def get_alerts_by_date_range(self, start_date: str, end_date: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts filtered by date range."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if start_date and end_date:
                    cursor.execute("""
                        SELECT * FROM structured_alerts 
                        WHERE timestamp BETWEEN ? AND ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (start_date, end_date, limit))
                elif start_date:
                    cursor.execute("""
                        SELECT * FROM structured_alerts 
                        WHERE timestamp >= ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (start_date, limit))
                elif end_date:
                    cursor.execute("""
                        SELECT * FROM structured_alerts 
                        WHERE timestamp <= ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (end_date, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM structured_alerts 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                
                columns = [description[0] for description in cursor.description]
                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(zip(columns, row))
                    alerts.append(alert_dict)
                
                return alerts
        except Exception as e:
            print(f"Error getting alerts by date range: {e}")
            return []
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM structured_alerts")
            total_alerts = cursor.fetchone()[0]
            
            # Alerts by severity
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM structured_alerts 
                GROUP BY severity
            """)
            severity_counts = dict(cursor.fetchall())
            
            # Alerts by threat type
            cursor.execute("""
                SELECT threat_type, COUNT(*) 
                FROM structured_alerts 
                GROUP BY threat_type
            """)
            threat_counts = dict(cursor.fetchall())
            
            # Recent alerts (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) 
                FROM structured_alerts 
                WHERE created_at >= datetime('now', '-24 hours')
            """)
            recent_alerts = cursor.fetchone()[0]
            
            return {
                'total_alerts': total_alerts,
                'recent_alerts_24h': recent_alerts,
                'severity_distribution': severity_counts,
                'threat_type_distribution': threat_counts
            }

# Global alert generator instance
alert_generator = AlertGenerator() 