# Structured Alerts System

## Overview

The Network Intrusion Detection System (NIDS) now includes a comprehensive structured alerts system that automatically generates detailed security alerts for suspicious network flows. Each alert contains rich metadata including threat scoring, severity assessment, and detailed flow information.

## Alert Fields

Each structured alert includes the following fields:

### Core Identification
- **Alert ID**: Unique identifier in format `ALERT_{timestamp}_{uuid}`
- **Timestamp**: When the suspicious flow was detected
- **Created At**: When the alert was generated

### Network Information
- **Source IP**: Source IP address of the suspicious flow
- **Destination IP**: Destination IP address of the suspicious flow
- **Protocol**: Network protocol (TCP, UDP, etc.)
- **Port**: Destination port number
- **Proto Num**: Protocol number (6 for TCP, 17 for UDP)

### Flow Metrics
- **Packets**: Number of packets in the flow
- **Bytes**: Total bytes transferred in the flow

### Security Assessment
- **Threat Type**: Categorized threat type based on flow characteristics
- **Anomaly Score**: Calculated risk score (0.0 to 1.0)
- **Severity**: Risk level (HIGH, MEDIUM, LOW, INFO)
- **Suspicion Reason**: Detailed explanation of why the flow is suspicious

### Context Information
- **Direction**: Flow direction (Internal-to-External, External-to-Internal, etc.)
- **Country**: Geographic location of the destination IP

## Threat Types

The system categorizes threats into the following types:

1. **DNS Tunneling**: TCP traffic on DNS port (53)
2. **Protocol Anomaly**: Unusual protocol/port combinations
3. **Telnet Usage**: Telnet traffic (port 23)
4. **SSH Access**: SSH traffic (port 22)
5. **RDP Access**: Remote Desktop Protocol (port 3389)
6. **Suspicious Protocol/Port**: Other suspicious combinations
7. **Unusual Activity**: Monitored but not immediately suspicious

## Severity Levels

Alerts are assigned severity levels based on anomaly score and threat type:

- **HIGH** (Anomaly Score ≥ 0.7): Critical threats requiring immediate attention
- **MEDIUM** (Anomaly Score ≥ 0.4): Moderate threats requiring investigation
- **LOW** (Anomaly Score ≥ 0.2): Minor threats for monitoring
- **INFO** (Anomaly Score < 0.2): Informational alerts

## Anomaly Scoring

The anomaly score is calculated based on multiple factors:

- **Suspicion Level**: Base score for suspicious protocol/port combinations
- **Protocol Risk**: Additional score for TCP/UDP protocols
- **Direction Risk**: External connections receive higher scores
- **Geographic Risk**: Non-internal destinations receive higher scores
- **Port Risk**: Admin ports (22, 23, 3389) receive higher scores, common ports (80, 443, 53) receive lower scores

## API Endpoints

### Get Structured Alerts
```
GET /api/structured_alerts?limit=100&severity=HIGH
```
- `limit`: Maximum number of alerts to return (default: 100)
- `severity`: Filter by severity level (optional)

### Get Alert Statistics
```
GET /api/alert_statistics
```
Returns summary statistics including:
- Total alerts count
- Recent alerts (last 24 hours)
- Severity distribution
- Threat type distribution

### Get Alerts by Severity
```
GET /api/alerts_by_severity/HIGH?limit=50
```
- `severity`: Severity level (HIGH, MEDIUM, LOW, INFO)
- `limit`: Maximum number of alerts to return (default: 50)

## Web Interface

### Structured Alerts Page
Access the structured alerts page at `/structured_alerts` to view:

1. **Alert Statistics Dashboard**: Shows total alerts, high/medium severity counts, and recent alerts
2. **Filtering Controls**: Filter by severity level and limit results
3. **Detailed Alerts Table**: Displays all alert fields with color-coded severity and threat types
4. **Export Functionality**: Download alerts as CSV file

### Features
- **Real-time Updates**: Statistics and alerts refresh automatically
- **Color Coding**: Severity levels and threat types are color-coded for quick identification
- **Anomaly Score Visualization**: Progress bars show anomaly scores
- **Export Capability**: Download filtered alerts as CSV
- **Responsive Design**: Works on desktop and mobile devices

## Integration with Network Analysis

The structured alerts system is automatically integrated with the network analyzer:

1. **Automatic Detection**: Suspicious flows are automatically detected during analysis
2. **Alert Generation**: Structured alerts are generated for each suspicious flow
3. **Database Storage**: Alerts are stored in the `structured_alerts` table
4. **Real-time Updates**: New alerts appear in the web interface immediately

## Database Schema

```sql
CREATE TABLE structured_alerts (
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
);
```

## Usage Examples

### Python API Usage
```python
from utils.alert_generator import alert_generator

# Get all alerts
alerts = alert_generator.get_alerts(limit=100)

# Get high severity alerts
high_alerts = alert_generator.get_alerts_by_severity('HIGH', limit=50)

# Get alert statistics
stats = alert_generator.get_alert_statistics()
```

### JavaScript Usage
```javascript
// Load alerts
fetch('/api/structured_alerts?limit=100&severity=HIGH')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('Alerts:', data.alerts);
        }
    });

// Get statistics
fetch('/api/alert_statistics')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('Statistics:', data.statistics);
        }
    });
```

## Configuration

The alert generator can be configured by modifying the scoring algorithms in `utils/alert_generator.py`:

- **Anomaly Score Calculation**: Adjust weights for different risk factors
- **Severity Thresholds**: Modify score thresholds for severity levels
- **Threat Type Classification**: Add new threat types or modify existing ones

## Monitoring and Maintenance

### Alert Cleanup
Consider implementing alert cleanup policies:
- Archive old alerts (e.g., older than 30 days)
- Delete low-severity alerts after a certain period
- Maintain alert retention policies

### Performance Optimization
- Index the database on frequently queried fields
- Implement pagination for large alert datasets
- Consider caching for alert statistics

## Security Considerations

- **Access Control**: Ensure only authorized users can access alert data
- **Data Privacy**: Be mindful of IP address and geographic data privacy
- **Logging**: Monitor access to alert data for security purposes
- **Backup**: Regularly backup the alerts database

## Troubleshooting

### Common Issues

1. **No Alerts Generated**: Check if suspicious flows are being detected
2. **Database Errors**: Verify database permissions and connectivity
3. **Performance Issues**: Consider limiting alert retrieval or implementing pagination

### Debug Mode
Enable debug logging in the alert generator to troubleshoot issues:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

Potential improvements to the structured alerts system:

1. **Machine Learning Integration**: Use ML models for more accurate threat detection
2. **Alert Correlation**: Group related alerts into incidents
3. **Automated Response**: Trigger automated responses for high-severity alerts
4. **Integration with SIEM**: Export alerts to external security systems
5. **Custom Alert Rules**: Allow users to define custom detection rules
6. **Alert Acknowledgment**: Track alert acknowledgment and resolution
7. **Escalation Procedures**: Implement alert escalation workflows 