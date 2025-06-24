# Network Analysis Features

This document describes the advanced network analysis features implemented in the Network Intrusion Detection System (NIDS).

## Features Overview

### 1. Protocol Activity Heatmap
- **Description**: Visual heatmap showing network activity patterns by protocol and hour
- **Implementation**: Uses Seaborn and Matplotlib to create dual heatmaps (bytes and packets)
- **Access**: Available via `/analysis` page
- **API Endpoint**: `/api/heatmap?hours=24`

### 2. Top Source IP Analysis
- **Description**: Identifies top source IPs by three metrics:
  - Total bytes transferred
  - Total packets sent
  - Number of distinct destinations
- **Implementation**: Aggregates flow data and ranks IPs by each metric
- **Access**: Available via `/analysis` page
- **API Endpoint**: `/api/top_ips?hours=24&top_n=10`

### 3. Suspicious Flow Detection
- **Description**: Flags unusual protocol/port combinations as suspicious
- **Detected Patterns**:
  - TCP on DNS port (53) - Suspicious
  - UDP on HTTP port (80) - Suspicious
  - UDP on HTTPS port (443) - Suspicious
  - TCP on Telnet port (23) - Suspicious
  - TCP on SSH port (22) - Monitor
  - TCP on RDP port (3389) - Monitor
- **Implementation**: Uses predefined suspicious combinations dictionary
- **Access**: Available via `/analysis` page
- **API Endpoint**: `/api/suspicious_flows?hours=24`

### 4. PCAP File Generation
- **Description**: Automatically saves suspicious flows to PCAP files for further analysis
- **Features**:
  - Creates individual PCAP files for each suspicious flow
  - Files named with source/destination IPs and timestamp
  - Downloadable via web interface
  - Stored in `suspicious_pcaps/` directory
- **Implementation**: Uses Scapy to create PCAP files with dummy packets
- **Access**: Available via `/analysis` page
- **API Endpoints**: 
  - `/api/download_pcap/<filename>` - Download specific PCAP
  - `/api/list_pcaps` - List available PCAP files

## Technical Implementation

### Dependencies Added
```
matplotlib==3.8.4
seaborn==0.13.2
```

### New Files Created
- `utils/network_analyzer.py` - Core analysis functionality
- `templates/analysis.html` - Analysis page template
- `static/js/analysis.js` - Frontend JavaScript
- `ANALYSIS_FEATURES.md` - This documentation

### Enhanced Files
- `app.py` - Added analysis routes
- `utils/packet_sniffer.py` - Enhanced with port capture
- `templates/index.html` - Added analysis link
- `requirements.txt` - Added new dependencies

### Database Schema Updates
The alerts table now includes derived features:
- `direction` - Flow direction (Internal-to-External, etc.)
- `protocol_name` - Human-readable protocol name
- `is_internal_src` - Boolean for source IP classification
- `is_internal_dst` - Boolean for destination IP classification
- `country` - Geographic location for external IPs

## Usage Instructions

### 1. Accessing Analysis Features
1. Navigate to the main dashboard
2. Click "Analysis" in the navigation menu
3. Select time range (1 hour to 1 week)
4. Click "Generate Analysis"

### 2. Interpreting Results
- **Heatmap**: Darker colors indicate higher activity
- **Top IPs**: Ranked lists show most active sources
- **Suspicious Flows**: Red-highlighted entries require attention
- **PCAP Files**: Download for detailed packet analysis

### 3. Downloading Reports
- Click "Download Report" for text-based summary
- Click individual "Download PCAP" buttons for packet captures
- Reports include timestamps and detailed flow information

## API Reference

### Analysis Report
```
GET /api/analysis_report?hours=24
```
Returns comprehensive analysis including:
- Summary statistics
- Heatmap path
- Top IP rankings
- Suspicious flows list
- PCAP file information

### Individual Endpoints
```
GET /api/heatmap?hours=24
GET /api/top_ips?hours=24&top_n=10
GET /api/suspicious_flows?hours=24
GET /api/download_pcap/<filename>
GET /api/list_pcaps
```

## Security Considerations

### Suspicious Flow Detection
- Based on known malicious patterns
- Configurable threshold levels
- Includes geographic and protocol context
- Automatic PCAP generation for forensics

### Data Privacy
- IP addresses are logged for analysis
- Geographic data from external services
- PCAP files contain packet-level details
- Consider data retention policies

## Future Enhancements

### Planned Features
1. **Machine Learning Integration**: Use ML models for anomaly detection
2. **Real-time Alerts**: Push notifications for suspicious activity
3. **Advanced Filtering**: Custom filters for specific protocols/IPs
4. **Export Options**: CSV, JSON, and other formats
5. **Historical Analysis**: Long-term trend analysis
6. **Custom Rules**: User-defined suspicious patterns

### Performance Optimizations
1. **Caching**: Cache analysis results for better performance
2. **Database Indexing**: Optimize queries for large datasets
3. **Background Processing**: Async analysis for large time ranges
4. **Data Compression**: Compress historical data

## Troubleshooting

### Common Issues
1. **No Data Available**: Ensure network traffic is being captured
2. **Heatmap Not Generated**: Check matplotlib/seaborn installation
3. **PCAP Download Fails**: Verify file permissions in suspicious_pcaps/
4. **Slow Performance**: Reduce time range or implement caching

### Debug Mode
Run the test script to verify functionality:
```bash
python test_analysis.py
```

## Support

For issues or questions about the analysis features:
1. Check the console logs for error messages
2. Verify all dependencies are installed
3. Ensure database schema is up to date
4. Test with the provided test script 