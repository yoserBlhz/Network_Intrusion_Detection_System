#!/usr/bin/env python3
"""
Test script for ML-based rule generation functionality
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:5000"

def test_ml_rule_generation():
    """Test ML rule generation functionality"""
    print("=" * 60)
    print("ML-BASED RULE GENERATION TEST")
    print("=" * 60)
    
    # Test 1: Generate ML rules
    print("\n1. Testing ML Rule Generation...")
    try:
        response = requests.get(f"{BASE_URL}/api/ml/generate_rules?hours=24")
        data = response.json()
        
        if data['success']:
            analysis = data['analysis']
            print(f"✅ Successfully generated {analysis['generated_rules']['total_rules']} ML rules")
            print(f"   - Protocol Rules: {analysis['generated_rules']['protocol_rules']}")
            print(f"   - Port Rules: {analysis['generated_rules']['port_rules']}")
            print(f"   - Temporal Rules: {analysis['generated_rules']['temporal_rules']}")
            print(f"   - Behavioral Rules: {analysis['generated_rules']['behavioral_rules']}")
            print(f"   - Total Flows Analyzed: {analysis['total_flows_analyzed']}")
            
            if analysis['anomaly_patterns']:
                patterns = analysis['anomaly_patterns']
                print(f"   - Anomaly Detection: {patterns['anomaly_count']} anomalies found")
                print(f"   - Anomaly Ratio: {patterns['anomaly_ratio']:.2%}")
        else:
            print(f"❌ Error generating rules: {data['error']}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    
    # Test 2: Get rule statistics
    print("\n2. Testing Rule Statistics...")
    try:
        response = requests.get(f"{BASE_URL}/api/ml/rule_statistics")
        data = response.json()
        
        if data['success']:
            stats = data['statistics']
            print(f"✅ Rule Statistics:")
            print(f"   - Total Rules: {stats['total_rules']}")
            print(f"   - Average Confidence: {stats['avg_confidence']:.2%}")
            print(f"   - Severity Distribution: {stats['severity_distribution']}")
        else:
            print(f"❌ Error getting statistics: {data['error']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 3: Get all rules
    print("\n3. Testing Rule Retrieval...")
    try:
        response = requests.get(f"{BASE_URL}/api/ml/rules")
        data = response.json()
        
        if data['success']:
            rules = data['rules']
            print(f"✅ Retrieved {len(rules)} rules")
            
            # Show sample rules
            for i, rule in enumerate(rules[:3]):  # Show first 3 rules
                print(f"   Rule {i+1}: {rule['rule_type']} - {rule['description']}")
                print(f"      Severity: {rule['severity']}, Confidence: {rule['confidence']:.2%}")
        else:
            print(f"❌ Error retrieving rules: {data['error']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    return True

def test_ml_rules_integration():
    """Test ML rules integration with network analysis"""
    print("\n" + "=" * 60)
    print("ML RULES INTEGRATION TEST")
    print("=" * 60)
    
    # Test live flows analysis with ML rules
    print("\n1. Testing Live Flows Analysis with ML Rules...")
    try:
        response = requests.get(f"{BASE_URL}/api/live_flows_analysis?hours=24")
        data = response.json()
        
        if data['success']:
            print(f"✅ Live analysis completed successfully")
            print(f"   - Data Source: {data['data_source']}")
            print(f"   - Flows Count: {data['flows_count']}")
            
            if 'suspicious_flows' in data and data['suspicious_flows']:
                suspicious_flows = data['suspicious_flows']
                print(f"   - Suspicious Flows: {len(suspicious_flows)}")
                
                # Check for ML rule triggers
                ml_triggered = [flow for flow in suspicious_flows if flow.get('ml_rule_count', 0) > 0]
                print(f"   - Flows with ML Rule Triggers: {len(ml_triggered)}")
                
                if ml_triggered:
                    print(f"   - Sample ML-triggered flows:")
                    for i, flow in enumerate(ml_triggered[:2]):
                        print(f"      Flow {i+1}: {flow['src_ip']} -> {flow['dst_ip']}")
                        print(f"        ML Rules: {flow['ml_rule_count']}, Reason: {flow['suspicion_reason']}")
            else:
                print(f"   - No suspicious flows detected")
        else:
            print(f"❌ Error in live analysis: {data['error']}")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Main test function"""
    print("Starting ML Rules Test Suite...")
    print(f"Target URL: {BASE_URL}")
    print(f"Timestamp: {datetime.now()}")
    
    # Wait a moment for the server to be ready
    time.sleep(2)
    
    # Run tests
    success = test_ml_rule_generation()
    
    if success:
        test_ml_rules_integration()
    
    print("\n" + "=" * 60)
    print("ML RULES TEST COMPLETED")
    print("=" * 60)
    print("\nTo view the ML Rules interface, visit:")
    print(f"{BASE_URL}/ml_rules")
    print("\nThe interface allows you to:")
    print("- Generate ML rules from historical data")
    print("- View and manage generated rules")
    print("- Apply rules to live network flows")
    print("- Monitor rule effectiveness")

if __name__ == "__main__":
    main() 