from flask import Flask, render_template, request, jsonify, send_file
import pandas as pd
import joblib
import sqlite3
from utils.packet_sniffer import start_sniffer, get_packets_per_second, get_live_flows, get_derived_features, get_protocol_name
from utils.db import init_db
from utils.network_analyzer import analyzer
from utils.alert_generator import alert_generator
from utils.ml_rule_generator import MLRuleGenerator
import threading
import os
import numpy as np
import time
import json
from datetime import datetime

app = Flask(__name__)

# Load model and preprocessor
model = joblib.load("model/model.pkl")
scaler = joblib.load("model/preprocessor.pkl")
features = joblib.load("model/features.pkl")

# Initialize ML rule generator
ml_rule_generator = MLRuleGenerator()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        start_time = time.time()  # Start timer
        file = request.files['file']
        if file and file.filename.endswith('.csv'):
            df = pd.read_csv(file)
            df.columns = df.columns.str.strip()
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(0, inplace=True)
            
            X = df[features]
            X_scaled = scaler.transform(X)
            predictions = model.predict(X_scaled)
            confidences = model.predict_proba(X_scaled)[:, -1]
            
            now = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_rows = []
            for i, (pred, conf) in enumerate(zip(predictions, confidences)):
                # For CSV uploads, we don't have real IP addresses, so we'll use placeholder values
                # In a real scenario, you'd extract these from the CSV data
                src_ip = df.iloc[i].get('src_ip', 'N/A') if 'src_ip' in df.columns else 'N/A'
                dst_ip = df.iloc[i].get('dst_ip', 'N/A') if 'dst_ip' in df.columns else 'N/A'
                proto = df.iloc[i].get('protocol', 6) if 'protocol' in df.columns else 6  # Default to TCP
                
                # Get derived features if we have IP addresses
                if src_ip != 'N/A' and dst_ip != 'N/A':
                    derived_features = get_derived_features(src_ip, dst_ip, proto)
                else:
                    derived_features = {
                        'direction': 'Unknown',
                        'protocol_name': get_protocol_name(proto),
                        'is_internal_src': False,
                        'is_internal_dst': False,
                        'country': 'Unknown'
                    }
                
                alert_rows.append((
                    now, src_ip, dst_ip, "Attack" if pred == 1 else "Normal", float(conf),
                    derived_features['direction'], derived_features['protocol_name'],
                    derived_features['is_internal_src'], derived_features['is_internal_dst'],
                    derived_features['country']
                ))
            
            results = [
                {"prediction": "Attack" if pred == 1 else "Normal", "confidence": float(conf)}
                for pred, conf in zip(predictions, confidences)
            ]
            # Batch insert
            for attempt in range(5):
                try:
                    with sqlite3.connect("nids.db") as conn:
                        cursor = conn.cursor()
                        cursor.executemany(
                            """INSERT INTO alerts 
                               (timestamp, src_ip, dst_ip, prediction, confidence,
                                direction, protocol_name, is_internal_src, is_internal_dst, country) 
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            alert_rows
                        )
                        conn.commit()
                    break
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e):
                        time.sleep(0.1)
                    else:
                        raise
            elapsed = time.time() - start_time  # End timer
            return jsonify({"results": results, "analysis_time": elapsed})
    return render_template('upload.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@app.route('/structured_alerts')
def structured_alerts():
    return render_template('structured_alerts.html')

@app.route('/ml_rules')
def ml_rules():
    return render_template('ml_rules.html')

@app.route('/api/traffic')
def api_traffic():
    pps = get_packets_per_second(window=10)
    return jsonify({'packets_per_second': pps})

@app.route('/api/live_flows')
def api_live_flows():
    flows = get_live_flows(window=10)
    return jsonify({'flows': flows})

@app.route('/api/heatmap')
def api_heatmap():
    hours = request.args.get('hours', 24, type=int)
    try:
        heatmap_path = analyzer.create_protocol_heatmap(hours)
        if heatmap_path:
            return jsonify({'success': True, 'heatmap_path': heatmap_path})
        else:
            return jsonify({'success': False, 'error': 'No data available for heatmap'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/top_ips')
def api_top_ips():
    hours = request.args.get('hours', 24, type=int)
    top_n = request.args.get('top_n', 10, type=int)
    try:
        top_ips = analyzer.get_top_source_ips(hours, top_n)
        return jsonify({
            'success': True,
            'by_bytes': top_ips.get('by_bytes', pd.DataFrame()).to_dict('records'),
            'by_packets': top_ips.get('by_packets', pd.DataFrame()).to_dict('records'),
            'by_destinations': top_ips.get('by_destinations', pd.DataFrame()).to_dict('records')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/suspicious_flows')
def api_suspicious_flows():
    hours = request.args.get('hours', 24, type=int)
    try:
        df = analyzer.get_flow_data(hours)
        suspicious_flows = analyzer.detect_suspicious_flows(df)
        return jsonify({
            'success': True,
            'suspicious_flows': suspicious_flows.to_dict('records'),
            'count': len(suspicious_flows)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/live_flows_analysis')
def api_live_flows_analysis():
    hours = request.args.get('hours', 24, type=int)
    try:
        # Get live flows data as DataFrame with all required fields and no NaN
        df = analyzer.get_live_flows_df_for_analysis(hours)
        live_flows_data = df.to_dict('records')
        if df.empty:
            return jsonify({
                'success': False,
                'error': 'No live flows available for analysis',
                'message': 'Start capturing network traffic to see live analysis'
            })
        # Add timestamp and hour columns for heatmap
        df['timestamp'] = pd.to_datetime(df['last_seen'], unit='s')
        df['hour'] = df['timestamp'].dt.hour
        df['date'] = df['timestamp'].dt.date
        
        # Generate analysis
        summary_stats = {
            'total_flows': int(len(df)),
            'unique_src_ips': int(df['src_ip'].nunique()),
            'unique_dst_ips': int(df['dst_ip'].nunique()),
            'protocols_detected': {k: int(v) for k, v in df['protocol_name'].value_counts().to_dict().items()},
            'total_bytes': int(df['bytes'].sum()),
            'total_packets': int(df['packets'].sum()),
            'internal_to_external_flows': int(len(df[df['direction'] == 'Internal-to-External'])),
            'external_to_internal_flows': int(len(df[df['direction'] == 'External-to-Internal'])),
            'internal_to_internal_flows': int(len(df[df['direction'] == 'Internal-to-Internal'])),
            'external_to_external_flows': int(len(df[df['direction'] == 'External-to-External']))
        }
        
        # Get top IPs
        top_ips = analyzer.get_top_source_ips_from_df(df)
        
        # Convert top_ips DataFrames to JSON-serializable format
        serializable_top_ips = {}
        for metric, data in top_ips.items():
            if not data.empty:
                serializable_top_ips[metric] = []
                for _, row in data.iterrows():
                    serializable_top_ips[metric].append({
                        'src_ip': str(row['src_ip']),
                        'total_bytes': int(row['total_bytes']),
                        'total_packets': int(row['total_packets']),
                        'distinct_destinations': int(row['distinct_destinations'])
                    })
            else:
                serializable_top_ips[metric] = []
        
        # Detect suspicious flows
        suspicious_flows = analyzer.detect_suspicious_flows(df)
        suspicious_flows_count = int(len(suspicious_flows)) if suspicious_flows is not None else 0
        
        # Convert suspicious flows to JSON-serializable format
        serializable_suspicious_flows = []
        if not suspicious_flows.empty:
            for _, row in suspicious_flows.iterrows():
                serializable_suspicious_flows.append({
                    'src_ip': str(row['src_ip']),
                    'dst_ip': str(row['dst_ip']),
                    'protocol': str(row['protocol']),
                    'port': int(row['port']),
                    'proto_num': int(row['proto_num']),
                    'timestamp': str(row['timestamp']),
                    'suspicion_reason': str(row['suspicion_reason']),
                    'direction': str(row['direction']),
                    'country': str(row['country'])
                })
        
        # Generate heatmap
        heatmap_path = analyzer.create_protocol_heatmap_from_df(df)
        
        # Save suspicious PCAPs
        saved_pcaps = analyzer.save_suspicious_pcap(suspicious_flows)
        
        return jsonify({
            'success': True,
            'summary_stats': summary_stats,
            'heatmap_path': heatmap_path,
            'top_ips': serializable_top_ips,
            'suspicious_flows': serializable_suspicious_flows,
            'suspicious_flows_count': suspicious_flows_count,
            'saved_pcaps': saved_pcaps,
            'analysis_timestamp': datetime.now().isoformat(),
            'data_source': 'live_flows',
            'flows_count': len(live_flows_data)
        })
        
    except Exception as e:
        print(f"Error in live flows analysis: {str(e)}")
        return jsonify({'success': False, 'error': f'Live analysis failed: {str(e)}'}), 500

@app.route('/api/analysis_report')
def api_analysis_report():
    hours = request.args.get('hours', 24, type=int)
    try:
        report = analyzer.generate_analysis_report(hours)
        if 'error' in report:
            return jsonify({'error': report['error']}), 400
        
        # Convert numpy types to JSON-serializable types
        if 'summary_stats' in report:
            summary_stats = report['summary_stats']
            for key, value in summary_stats.items():
                if hasattr(value, 'item'):  # numpy scalar
                    summary_stats[key] = int(value)
                elif isinstance(value, dict):
                    summary_stats[key] = {k: int(v) if hasattr(v, 'item') else v for k, v in value.items()}
        
        # Convert top_ips DataFrames to JSON-serializable format
        if 'top_ips' in report:
            serializable_top_ips = {}
            for metric, data in report['top_ips'].items():
                if not data.empty:
                    serializable_top_ips[metric] = []
                    for _, row in data.iterrows():
                        serializable_top_ips[metric].append({
                            'src_ip': str(row['src_ip']),
                            'total_bytes': int(row['total_bytes']),
                            'total_packets': int(row['total_packets']),
                            'distinct_destinations': int(row['distinct_destinations'])
                        })
                else:
                    serializable_top_ips[metric] = []
            report['top_ips'] = serializable_top_ips
        
        # Convert suspicious flows to JSON-serializable format
        if 'suspicious_flows' in report and report['suspicious_flows']:
            serializable_suspicious_flows = []
            for flow in report['suspicious_flows']:
                serializable_suspicious_flows.append({
                    'src_ip': str(flow['src_ip']),
                    'dst_ip': str(flow['dst_ip']),
                    'protocol': str(flow['protocol']),
                    'port': int(flow['port']),
                    'proto_num': int(flow['proto_num']),
                    'timestamp': str(flow['timestamp']),
                    'suspicion_reason': str(flow['suspicion_reason']),
                    'direction': str(flow['direction']),
                    'country': str(flow['country'])
                })
            report['suspicious_flows'] = serializable_suspicious_flows
        
        return jsonify(report)
    except Exception as e:
        print(f"Error in analysis report: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/download_pcap/<filename>')
def download_pcap(filename):
    pcap_path = os.path.join('suspicious_pcaps', filename)
    if os.path.exists(pcap_path):
        return send_file(pcap_path, as_attachment=True)
    else:
        return jsonify({'error': 'PCAP file not found'}), 404

@app.route('/api/list_pcaps')
def list_pcaps():
    pcap_dir = 'suspicious_pcaps'
    if os.path.exists(pcap_dir):
        files = []
        for filename in os.listdir(pcap_dir):
            if filename.endswith('.pcap'):
                filepath = os.path.join(pcap_dir, filename)
                files.append({
                    'filename': filename,
                    'size': os.path.getsize(filepath),
                    'created': os.path.getctime(filepath)
                })
        return jsonify({'files': files})
    else:
        return jsonify({'files': []})

@app.route('/api/structured_alerts')
def api_structured_alerts():
    """Get structured alerts with optional filtering."""
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity', None)
    
    try:
        if severity:
            alerts = alert_generator.get_alerts_by_severity(severity, limit)
        else:
            alerts = alert_generator.get_alerts(limit)
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alert_statistics')
def api_alert_statistics():
    """Get alert statistics."""
    try:
        stats = alert_generator.get_alert_statistics()
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts_by_severity/<severity>')
def api_alerts_by_severity(severity):
    """Get alerts filtered by severity level."""
    limit = request.args.get('limit', 50, type=int)
    
    try:
        alerts = alert_generator.get_alerts_by_severity(severity.upper(), limit)
        return jsonify({
            'success': True,
            'alerts': alerts,
            'severity': severity.upper(),
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts_by_threat_type/<threat_type>')
def api_alerts_by_threat_type(threat_type):
    """Get alerts filtered by threat type."""
    limit = request.args.get('limit', 100, type=int)
    
    try:
        alerts = alert_generator.get_alerts_by_threat_type(threat_type, limit)
        return jsonify({
            'success': True,
            'alerts': alerts,
            'threat_type': threat_type,
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts_by_protocol/<protocol>')
def api_alerts_by_protocol(protocol):
    """Get alerts filtered by protocol."""
    limit = request.args.get('limit', 100, type=int)
    
    try:
        alerts = alert_generator.get_alerts_by_protocol(protocol.upper(), limit)
        return jsonify({
            'success': True,
            'alerts': alerts,
            'protocol': protocol.upper(),
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts_by_ip/<ip>')
def api_alerts_by_ip(ip):
    """Get alerts filtered by IP address (source or destination)."""
    limit = request.args.get('limit', 100, type=int)
    
    try:
        alerts = alert_generator.get_alerts_by_ip(ip, limit)
        return jsonify({
            'success': True,
            'alerts': alerts,
            'ip': ip,
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts_by_date_range')
def api_alerts_by_date_range():
    """Get alerts filtered by date range."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = request.args.get('limit', 100, type=int)
    
    try:
        alerts = alert_generator.get_alerts_by_date_range(start_date, end_date, limit)
        return jsonify({
            'success': True,
            'alerts': alerts,
            'start_date': start_date,
            'end_date': end_date,
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/generate_rules')
def api_ml_generate_rules():
    """Generate ML-based detection rules from historical data or live flows."""
    hours = request.args.get('hours', 24, type=int)
    use_live_flows = request.args.get('use_live_flows', 'false').lower() == 'true'
    try:
        analysis_result = ml_rule_generator.analyze_historical_data(hours, use_live_flows=use_live_flows)
        if 'error' in analysis_result:
            return jsonify({'success': False, 'error': analysis_result['error']}), 400
        return jsonify({
            'success': True,
            'analysis': analysis_result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/rules')
def api_ml_rules():
    """Get all ML-generated rules."""
    try:
        rules = ml_rule_generator.load_rules()
        return jsonify({
            'success': True,
            'rules': rules,
            'count': len(rules)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/rules/<rule_type>')
def api_ml_rules_by_type(rule_type):
    """Get ML-generated rules by type."""
    try:
        all_rules = ml_rule_generator.load_rules()
        filtered_rules = [rule for rule in all_rules if rule['rule_type'] == rule_type]
        
        return jsonify({
            'success': True,
            'rules': filtered_rules,
            'rule_type': rule_type,
            'count': len(filtered_rules)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/apply_rules')
def api_ml_apply_rules():
    """Apply ML rules to current live flows."""
    try:
        # Get current live flows
        live_flows = get_live_flows(window=60)  # Last hour
        
        triggered_rules = []
        for flow in live_flows:
            flow_triggers = ml_rule_generator.apply_ml_rules(flow)
            if flow_triggers:
                triggered_rules.append({
                    'flow': {
                        'src_ip': flow['src_ip'],
                        'dst_ip': flow['dst_ip'],
                        'protocol': flow['protocol'],
                        'port': flow['port'],
                        'packets': flow['packets'],
                        'bytes': flow['bytes']
                    },
                    'triggered_rules': flow_triggers
                })
        
        return jsonify({
            'success': True,
            'triggered_rules': triggered_rules,
            'total_flows_checked': len(live_flows),
            'flows_with_triggers': len(triggered_rules)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/rule_statistics')
def api_ml_rule_statistics():
    """Get statistics about ML-generated rules."""
    try:
        rules = ml_rule_generator.load_rules()
        
        if not rules:
            return jsonify({
                'success': True,
                'statistics': {
                    'total_rules': 0,
                    'rule_types': {},
                    'severity_distribution': {},
                    'avg_confidence': 0
                }
            })
        
        # Analyze rule statistics
        rule_types = {}
        severity_dist = {}
        confidences = []
        
        for rule in rules:
            # Rule types
            rule_type = rule['rule_type']
            rule_types[rule_type] = rule_types.get(rule_type, 0) + 1
            
            # Severity distribution
            severity = rule['severity']
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
            
            # Confidence scores
            confidences.append(rule.get('confidence', 0))
        
        statistics = {
            'total_rules': len(rules),
            'rule_types': rule_types,
            'severity_distribution': severity_dist,
            'avg_confidence': sum(confidences) / len(confidences) if confidences else 0,
            'rule_breakdown': {
                'protocol_rules': rule_types.get('protocol_anomaly', 0),
                'port_rules': rule_types.get('port_anomaly', 0),
                'temporal_rules': rule_types.get('temporal_anomaly', 0),
                'behavioral_rules': rule_types.get('behavioral_anomaly', 0)
            }
        }
        
        return jsonify({
            'success': True,
            'statistics': statistics
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/delete_rules', methods=['DELETE'])
def api_ml_delete_rules():
    """Delete all ML-generated rules."""
    try:
        # Clear the rules file
        if os.path.exists(ml_rule_generator.rules_file):
            os.remove(ml_rule_generator.rules_file)
        
        return jsonify({
            'success': True,
            'message': 'All ML-generated rules have been deleted'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == "__main__":
    init_db()
    # Start packet sniffer in a separate thread on the Wi-Fi interface
    sniffer_thread = threading.Thread(target=start_sniffer, args=("\\Device\\NPF_{70D676F3-7B5C-4148-AD3F-2327E4BA45AE}",), daemon=True)
    sniffer_thread.start()
    app.run(debug=True, host="0.0.0.0")