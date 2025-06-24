#!/usr/bin/env python3
"""
Test script for live flows analysis functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.network_analyzer import analyzer
import pandas as pd
from datetime import datetime

def test_live_flows_analysis():
    print("Testing Live Flows Analysis...")
    
    # Test live flows data retrieval
    print("\n1. Testing live flows data retrieval...")
    live_flows_data = analyzer.get_live_flows_for_analysis(hours=24)
    print(f"Retrieved {len(live_flows_data)} live flows")
    
    if live_flows_data:
        print("Sample live flow data:")
        print(pd.DataFrame(live_flows_data).head())
        
        # Test DataFrame conversion and analysis
        print("\n2. Testing DataFrame analysis...")
        df = pd.DataFrame(live_flows_data)
        df['timestamp'] = pd.to_datetime(df['last_seen'], unit='s')
        df['hour'] = df['timestamp'].dt.hour
        df['date'] = df['timestamp'].dt.date
        
        print(f"DataFrame shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        
        # Test top IPs analysis
        print("\n3. Testing top IPs analysis from DataFrame...")
        top_ips = analyzer.get_top_source_ips_from_df(df, top_n=5)
        for metric, data in top_ips.items():
            print(f"\nTop IPs by {metric}:")
            if not data.empty:
                print(data.head())
            else:
                print("No data available")
        
        # Test suspicious flow detection
        print("\n4. Testing suspicious flow detection...")
        suspicious_flows = analyzer.detect_suspicious_flows(df)
        print(f"Detected {len(suspicious_flows)} suspicious flows")
        
        if not suspicious_flows.empty:
            print("Suspicious flows:")
            print(suspicious_flows)
        
        # Test heatmap generation
        print("\n5. Testing heatmap generation from DataFrame...")
        try:
            heatmap_path = analyzer.create_protocol_heatmap_from_df(df)
            if heatmap_path:
                print(f"Live flows heatmap generated: {heatmap_path}")
            else:
                print("No heatmap generated (no data)")
        except Exception as e:
            print(f"Error generating heatmap: {e}")
        
    else:
        print("No live flows available - this is normal if no network traffic is being captured")
        print("Start the packet sniffer to capture live flows")

if __name__ == "__main__":
    test_live_flows_analysis() 