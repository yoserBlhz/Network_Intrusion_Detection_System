#!/usr/bin/env python3
"""
Test script for network analysis functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.network_analyzer import analyzer
import pandas as pd
from datetime import datetime

def test_network_analyzer():
    print("Testing Network Analyzer...")
    
    # Test flow data retrieval
    print("\n1. Testing flow data retrieval...")
    df = analyzer.get_flow_data(hours=24)
    print(f"Retrieved {len(df)} flow records")
    
    if not df.empty:
        print("Sample data:")
        print(df.head())
    
    # Test top IPs analysis
    print("\n2. Testing top IPs analysis...")
    top_ips = analyzer.get_top_source_ips(hours=24, top_n=5)
    for metric, data in top_ips.items():
        print(f"\nTop IPs by {metric}:")
        if not data.empty:
            print(data.head())
        else:
            print("No data available")
    
    # Test suspicious flow detection
    print("\n3. Testing suspicious flow detection...")
    suspicious_flows = analyzer.detect_suspicious_flows(df)
    print(f"Detected {len(suspicious_flows)} suspicious flows")
    
    if not suspicious_flows.empty:
        print("Suspicious flows:")
        print(suspicious_flows)
    
    # Test heatmap generation
    print("\n4. Testing heatmap generation...")
    try:
        heatmap_path = analyzer.create_protocol_heatmap(hours=24)
        if heatmap_path:
            print(f"Heatmap generated: {heatmap_path}")
        else:
            print("No heatmap generated (no data)")
    except Exception as e:
        print(f"Error generating heatmap: {e}")
    
    # Test full analysis report
    print("\n5. Testing full analysis report...")
    try:
        report = analyzer.generate_analysis_report(hours=24)
        if 'error' in report:
            print(f"Error: {report['error']}")
        else:
            print("Analysis report generated successfully")
            print(f"Summary stats: {report.get('summary_stats', {})}")
            print(f"Suspicious flows count: {len(report.get('suspicious_flows', []))}")
            print(f"PCAP files saved: {len(report.get('saved_pcaps', []))}")
    except Exception as e:
        print(f"Error generating report: {e}")
    
    print("\nTest completed!")

if __name__ == "__main__":
    test_network_analyzer() 