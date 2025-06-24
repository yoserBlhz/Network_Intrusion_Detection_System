# Network Intrusion Detection System (NIDS)

A modern, extensible, and intelligent Network Intrusion Detection System for real-time monitoring, ML-based anomaly detection, and structured security alerting. Includes a full-featured web interface, analytics dashboard, and automated rule generation.

---

## 🚀 Overview

This project provides a comprehensive NIDS platform that:
- Captures and analyzes live network traffic
- Detects suspicious flows and generates structured security alerts
- Uses machine learning to generate adaptive detection rules
- Offers a rich web interface for monitoring, analytics, and management
- Supports both real-time and historical data analysis

---

## ✨ Key Features

- **Live Packet Capture & Flow Analysis**: Real-time monitoring of network traffic
- **ML-Based Rule Generation**: Automated, adaptive detection rules using Isolation Forest, clustering, and statistical analysis
- **Structured Alerts**: Detailed, real-time security alerts with severity, threat type, and anomaly scoring
- **Analytics Dashboard**: Protocol heatmaps, top IPs, suspicious flows, and PCAP downloads
- **Web Interface**: User-friendly dashboard for analysis, rule management, and alert review
- **API Access**: RESTful endpoints for integration and automation
- **PCAP Generation**: Automatic capture of suspicious flows for forensic analysis
- **Configurable & Extensible**: Easily add new rules, features, or data sources

---

## 🏗️ System Architecture

```
Live Network Traffic
        ↓
Packet Sniffer (Real-time capture)
        ↓
Flow Analysis & ML Rule Generation
        ↓
Suspicious Flow Detection
        ↓
Structured Alert Generation
        ↓
Database Storage
        ↓
Web Interface & API
```

---

## ⚡ Installation & Setup

### 1. Clone the Repository
```bash
git clone <repo-url>
cd network_intrusion_detection
```

### 2. Install Python Dependencies
```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 3. Initialize the Database
```bash
python -c "from utils.db import init_db; init_db()"
```

### 4. (Optional) Import Sample Data
Place CSVs in the `data/` directory. Use or adapt scripts to import if needed.

### 5. Run the Application
```bash
python app.py
```
The web interface will be available at [http://localhost:5000](http://localhost:5000)

---

## 🌐 Web Interface

- **Dashboard**: Overview of network activity
- **Analysis**: Live analytics, heatmaps, top IPs, suspicious flows, PCAP downloads
- **ML Rules**: Generate, view, and manage ML-based detection rules
- **Structured Alerts**: Review and filter real-time security alerts
- **Upload**: Analyze CSV data manually

---

## 🧠 ML Rule Generation

- **Automated**: Generate rules from historical or live flows
- **Rule Types**: Protocol, port, temporal, and behavioral anomaly rules
- **How to Use**:
  - Go to `/ml_rules` in the web UI
  - Select analysis period and (optionally) "Use live flows"
  - Click "Generate Rules"
  - Apply rules to live flows for real-time detection
- **API**:
  - `GET /api/ml/generate_rules?hours=24[&use_live_flows=true]`
  - `GET /api/ml/rules`, `GET /api/ml/rules/{rule_type}`
  - `GET /api/ml/apply_rules`
  - `DELETE /api/ml/delete_rules`

---

## 🚨 Structured Alerts

- **Real-Time**: Alerts generated instantly from live traffic
- **Rich Metadata**: Includes IPs, protocol, port, threat type, severity, anomaly score, and more
- **Web UI**: `/structured_alerts` for dashboard, filtering, and export
- **API**:
  - `GET /api/structured_alerts?limit=100&severity=HIGH`
  - `GET /api/alert_statistics`
  - `GET /api/alerts_by_severity/HIGH?limit=50`

---

## 📊 Analytics & Dashboard

- **Protocol Activity Heatmap**: `/analysis` page, `/api/heatmap`
- **Top Source IPs**: By bytes, packets, destinations
- **Suspicious Flows**: Highlighted with reasons and PCAP download
- **PCAP Files**: Downloadable for forensic analysis
- **API**:
  - `/api/analysis_report?hours=24`
  - `/api/heatmap?hours=24`
  - `/api/top_ips?hours=24&top_n=10`
  - `/api/suspicious_flows?hours=24`
  - `/api/download_pcap/<filename>`
  - `/api/list_pcaps`

---

## 📁 Data & Directory Structure

- `data/` — Sample and imported CSV flow data
- `model/` — ML model, preprocessor, and training scripts
- `utils/` — Core logic: packet sniffer, analyzer, ML rule generator, alert generator, DB
- `templates/` — Web UI HTML templates
- `static/` — JS, CSS, images for frontend
- `suspicious_pcaps/` — Auto-saved PCAPs of suspicious flows
- `nids.db` — SQLite database
- `requirements.txt` — Python dependencies
- `test_*.py` — Test scripts

---

## 🧪 Testing

- **ML Rules**: `python test_ml_rules.py`
- **Analysis**: `python test_analysis.py`
- **Live Analysis**: `python test_live_analysis.py`
- **Structured Alerts**: `python test_structured_alerts.py`

---

## ⚙️ Configuration & Customization

- **ML Rule Parameters**: Tune in `utils/ml_rule_generator.py`
- **Alert Scoring/Thresholds**: Adjust in `utils/alert_generator.py`
- **Analysis Features**: Extend in `utils/network_analyzer.py`
- **Web UI**: Customize in `templates/` and `static/js/`
- **Database**: Schema in `nids.db`, can be reset via `init_db()`

---

## 🔒 Security & Privacy Notes

- All analysis is local; no data leaves your machine
- PCAPs and logs may contain sensitive information—handle with care
- Consider data retention and privacy policies for your environment

---

## 🛠️ Troubleshooting & Support

- **No Data/Alerts?** Ensure the sniffer is running and traffic is present
- **Heatmap/Plots Not Showing?** Check matplotlib/seaborn installation
- **PCAP Download Fails?** Check permissions in `suspicious_pcaps/`
- **Database Issues?** Try re-initializing with `init_db()`
- **More Help?** See the markdown docs or open an issue

---

## 📜 Credits & License

- Developed by [Your Name/Team]
- Inspired by open-source NIDS and SIEM solutions
- License: MIT (or specify your license)

---

For more details, see the markdown docs in this repo:
- `ML_RULE_GENERATION.md`
- `STRUCTURED_ALERTS.md`
- `ANALYSIS_FEATURES.md`
- `LIVE_ALERTS_EXPLANATION.md`

--- 