#!/usr/bin/env python3
"""
Test script for structured alerts functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.alert_generator import alert_generator, StructuredAlert
from datetime import datetime

def test_alert_generation():
    """Test alert generation with sample suspicious flow data."""
    print("Testing structured alert generation...")
    
    # Sample suspicious flow data
    test_flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'protocol': 'TCP',
        'port': 53,
        'proto_num': 6,
        'timestamp': datetime.now().isoformat(),
        'suspicion_reason': 'TCP on DNS port (53) - Suspicious',
        'direction': 'Internal-to-External',
        'country': 'United States',
        'packets': 150,
        'bytes': 2048
    }
    
    # Generate structured alert
    alert = alert_generator.generate_structured_alert(test_flow)
    
    print(f"Generated Alert ID: {alert.alert_id}")
    print(f"Threat Type: {alert.threat_type}")
    print(f"Anomaly Score: {alert.anomaly_score}")
    print(f"Severity: {alert.severity}")
    print(f"Source IP: {alert.src_ip}")
    print(f"Destination IP: {alert.dst_ip}")
    print(f"Protocol: {alert.protocol}")
    print(f"Port: {alert.port}")
    print(f"Packets: {alert.packets}")
    print(f"Bytes: {alert.bytes}")
    print(f"Direction: {alert.direction}")
    print(f"Country: {alert.country}")
    
    # Save alert to database
    alert_generator.save_alert(alert)
    print("Alert saved to database successfully!")
    
    return alert

def test_alert_retrieval():
    """Test retrieving alerts from database."""
    print("\nTesting alert retrieval...")
    
    # Get all alerts
    alerts = alert_generator.get_alerts(limit=10)
    print(f"Retrieved {len(alerts)} alerts from database")
    
    if alerts:
        print("Sample alert data:")
        for key, value in alerts[0].items():
            print(f"  {key}: {value}")
    
    return alerts

def test_alert_statistics():
    """Test alert statistics functionality."""
    print("\nTesting alert statistics...")
    
    stats = alert_generator.get_alert_statistics()
    print("Alert Statistics:")
    print(f"  Total Alerts: {stats['total_alerts']}")
    print(f"  Recent Alerts (24h): {stats['recent_alerts_24h']}")
    print(f"  Severity Distribution: {stats['severity_distribution']}")
    print(f"  Threat Type Distribution: {stats['threat_type_distribution']}")
    
    return stats

def test_severity_filtering():
    """Test filtering alerts by severity."""
    print("\nTesting severity filtering...")
    
    # Test each severity level
    for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
        alerts = alert_generator.get_alerts_by_severity(severity, limit=5)
        print(f"  {severity} severity alerts: {len(alerts)}")
    
    return True

def main():
    """Run all tests."""
    print("=== Structured Alerts Test Suite ===\n")
    
    try:
        # Test alert generation
        alert = test_alert_generation()
        
        # Test alert retrieval
        alerts = test_alert_retrieval()
        
        # Test alert statistics
        stats = test_alert_statistics()
        
        # Test severity filtering
        test_severity_filtering()
        
        print("\n=== All tests completed successfully! ===")
        print("Structured alerts system is working correctly.")
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 