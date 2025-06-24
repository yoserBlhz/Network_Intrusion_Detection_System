// Structured Alerts JavaScript
let currentAlerts = [];

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function getSeverityColor(severity) {
    switch (severity.toUpperCase()) {
        case 'HIGH':
            return 'text-red-600 bg-red-50';
        case 'MEDIUM':
            return 'text-orange-600 bg-orange-50';
        case 'LOW':
            return 'text-yellow-600 bg-yellow-50';
        case 'INFO':
            return 'text-blue-600 bg-blue-50';
        default:
            return 'text-gray-600 bg-gray-50';
    }
}

function getThreatTypeColor(threatType) {
    const threatColors = {
        'DNS Tunneling': 'text-purple-600 bg-purple-50',
        'Protocol Anomaly': 'text-red-600 bg-red-50',
        'Telnet Usage': 'text-red-600 bg-red-50',
        'SSH Access': 'text-orange-600 bg-orange-50',
        'RDP Access': 'text-orange-600 bg-orange-50',
        'Suspicious Protocol/Port': 'text-red-600 bg-red-50',
        'Unusual Activity': 'text-yellow-600 bg-yellow-50'
    };
    return threatColors[threatType] || 'text-gray-600 bg-gray-50';
}

function updateAlertStatistics() {
    fetch('/api/alert_statistics')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const stats = data.statistics;
                document.getElementById('totalAlerts').textContent = formatNumber(stats.total_alerts);
                document.getElementById('highAlerts').textContent = formatNumber(stats.severity_distribution.HIGH || 0);
                document.getElementById('mediumAlerts').textContent = formatNumber(stats.severity_distribution.MEDIUM || 0);
                document.getElementById('recentAlerts').textContent = formatNumber(stats.recent_alerts_24h);
            }
        })
        .catch(error => {
            console.error('Error loading alert statistics:', error);
        });
}

function updateAlertsTable(alerts) {
    const tableBody = document.getElementById('structuredAlertsTable');
    
    if (alerts.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="13" class="px-4 py-2 text-center text-gray-500">No alerts found</td>
            </tr>
        `;
        return;
    }
    
    tableBody.innerHTML = alerts.map(alert => {
        const severityColor = getSeverityColor(alert.severity);
        const threatColor = getThreatTypeColor(alert.threat_type);
        const timestamp = new Date(alert.timestamp).toLocaleString();
        
        return `
            <tr class="border-b hover:bg-gray-50">
                <td class="px-4 py-2 text-sm font-mono">${alert.alert_id}</td>
                <td class="px-4 py-2 text-sm">${timestamp}</td>
                <td class="px-4 py-2 text-sm font-semibold">${alert.src_ip}</td>
                <td class="px-4 py-2 text-sm font-semibold">${alert.dst_ip}</td>
                <td class="px-4 py-2 text-sm font-mono">${alert.protocol}</td>
                <td class="px-4 py-2 text-sm">${alert.port}</td>
                <td class="px-4 py-2 text-sm">${formatNumber(alert.packets)}</td>
                <td class="px-4 py-2 text-sm">${formatBytes(alert.bytes)}</td>
                <td class="px-4 py-2 text-sm">
                    <span class="px-2 py-1 rounded text-xs font-semibold ${threatColor}">
                        ${alert.threat_type}
                    </span>
                </td>
                <td class="px-4 py-2 text-sm">
                    <div class="flex items-center">
                        <span class="font-semibold">${alert.anomaly_score}</span>
                        <div class="ml-2 w-16 bg-gray-200 rounded-full h-2">
                            <div class="bg-blue-600 h-2 rounded-full" style="width: ${alert.anomaly_score * 100}%"></div>
                        </div>
                    </div>
                </td>
                <td class="px-4 py-2 text-sm">
                    <span class="px-2 py-1 rounded text-xs font-semibold ${severityColor}">
                        ${alert.severity}
                    </span>
                </td>
                <td class="px-4 py-2 text-sm">${alert.direction}</td>
                <td class="px-4 py-2 text-sm">${alert.country}</td>
            </tr>
        `;
    }).join('');
}

function applyFilters(alerts) {
    const severityFilter = document.getElementById('severityFilter').value;
    const threatTypeFilter = document.getElementById('threatTypeFilter').value;
    const protocolFilter = document.getElementById('protocolFilter').value;
    const srcIpFilter = document.getElementById('srcIpFilter').value.toLowerCase();
    const dstIpFilter = document.getElementById('dstIpFilter').value.toLowerCase();
    const portFilter = document.getElementById('portFilter').value;
    const startDateFilter = document.getElementById('startDateFilter').value;
    const endDateFilter = document.getElementById('endDateFilter').value;
    const minScoreFilter = document.getElementById('minScoreFilter').value;
    const maxScoreFilter = document.getElementById('maxScoreFilter').value;
    const searchBox = document.getElementById('searchBox').value.toLowerCase();

    return alerts.filter(alert => {
        // Search box filter (searches across all text fields)
        if (searchBox) {
            const searchableText = [
                alert.alert_id,
                alert.src_ip,
                alert.dst_ip,
                alert.protocol,
                alert.threat_type,
                alert.severity,
                alert.direction,
                alert.country,
                alert.suspicion_reason || ''
            ].join(' ').toLowerCase();
            
            if (!searchableText.includes(searchBox)) return false;
        }
        
        // Severity filter
        if (severityFilter && alert.severity !== severityFilter) return false;
        
        // Threat type filter
        if (threatTypeFilter && alert.threat_type !== threatTypeFilter) return false;
        
        // Protocol filter
        if (protocolFilter && alert.protocol !== protocolFilter) return false;
        
        // Source IP filter
        if (srcIpFilter && !alert.src_ip.toLowerCase().includes(srcIpFilter)) return false;
        
        // Destination IP filter
        if (dstIpFilter && !alert.dst_ip.toLowerCase().includes(dstIpFilter)) return false;
        
        // Port filter
        if (portFilter && alert.port !== parseInt(portFilter)) return false;
        
        // Date range filter
        if (startDateFilter) {
            const alertDate = new Date(alert.timestamp);
            const startDate = new Date(startDateFilter);
            if (alertDate < startDate) return false;
        }
        
        if (endDateFilter) {
            const alertDate = new Date(alert.timestamp);
            const endDate = new Date(endDateFilter);
            if (alertDate > endDate) return false;
        }
        
        // Anomaly score range filter
        if (minScoreFilter && alert.anomaly_score < parseFloat(minScoreFilter)) return false;
        if (maxScoreFilter && alert.anomaly_score > parseFloat(maxScoreFilter)) return false;
        
        return true;
    });
}

async function loadAlerts() {
    const limit = document.getElementById('alertLimit').value;
    
    try {
        // Get all alerts first, then apply client-side filters
        const response = await fetch(`/api/structured_alerts?limit=${Math.max(limit, 500)}`);
        const data = await response.json();
        
        if (data.success) {
            // Apply filters to the alerts
            let filteredAlerts = applyFilters(data.alerts);
            
            // Apply limit after filtering
            filteredAlerts = filteredAlerts.slice(0, parseInt(limit));
            
            currentAlerts = filteredAlerts;
            updateAlertsTable(filteredAlerts);
            
            // Update results count
            const resultsCount = document.getElementById('resultsCount');
            if (resultsCount) {
                resultsCount.textContent = `Showing ${filteredAlerts.length} of ${data.alerts.length} alerts`;
            }
        } else {
            console.error('Error loading alerts:', data.error);
            document.getElementById('structuredAlertsTable').innerHTML = `
                <tr>
                    <td colspan="13" class="px-4 py-2 text-center text-red-500">Error loading alerts</td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('structuredAlertsTable').innerHTML = `
            <tr>
                <td colspan="13" class="px-4 py-2 text-center text-red-500">Error loading alerts</td>
            </tr>
        `;
    }
}

function clearFilters() {
    document.getElementById('severityFilter').value = '';
    document.getElementById('threatTypeFilter').value = '';
    document.getElementById('protocolFilter').value = '';
    document.getElementById('srcIpFilter').value = '';
    document.getElementById('dstIpFilter').value = '';
    document.getElementById('portFilter').value = '';
    document.getElementById('startDateFilter').value = '';
    document.getElementById('endDateFilter').value = '';
    document.getElementById('minScoreFilter').value = '';
    document.getElementById('maxScoreFilter').value = '';
    document.getElementById('alertLimit').value = '100';
    document.getElementById('searchBox').value = '';
    
    loadAlerts();
}

function refreshAlerts() {
    loadAlerts();
    updateAlertStatistics();
}

function quickFilter(type, value) {
    // Clear all filters first
    clearFilters();
    
    switch (type) {
        case 'severity':
            document.getElementById('severityFilter').value = value;
            break;
        case 'threat_type':
            document.getElementById('threatTypeFilter').value = value;
            break;
        case 'protocol':
            document.getElementById('protocolFilter').value = value;
            break;
        case 'time':
            const now = new Date();
            if (value === 'last_hour') {
                const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
                document.getElementById('startDateFilter').value = oneHourAgo.toISOString().slice(0, 16);
                document.getElementById('endDateFilter').value = now.toISOString().slice(0, 16);
            } else if (value === 'last_24h') {
                const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                document.getElementById('startDateFilter').value = oneDayAgo.toISOString().slice(0, 16);
                document.getElementById('endDateFilter').value = now.toISOString().slice(0, 16);
            }
            break;
    }
    
    // Apply the filter
    loadAlerts();
}

function exportAlerts() {
    if (currentAlerts.length === 0) {
        alert('No alerts to export');
        return;
    }
    
    // Create CSV content
    const headers = [
        'Alert ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Port',
        'Packets', 'Bytes', 'Threat Type', 'Anomaly Score', 'Severity', 'Direction', 'Country'
    ];
    
    const csvContent = [
        headers.join(','),
        ...currentAlerts.map(alert => [
            alert.alert_id,
            alert.timestamp,
            alert.src_ip,
            alert.dst_ip,
            alert.protocol,
            alert.port,
            alert.packets,
            alert.bytes,
            alert.threat_type,
            alert.anomaly_score,
            alert.severity,
            alert.direction,
            alert.country
        ].join(','))
    ].join('\n');
    
    // Create and download file
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `structured_alerts_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Auto-load alerts and statistics on page load
document.addEventListener('DOMContentLoaded', () => {
    updateAlertStatistics();
    loadAlerts();
    
    // Add search box event listener
    const searchBox = document.getElementById('searchBox');
    if (searchBox) {
        let searchTimeout;
        searchBox.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                loadAlerts();
            }, 300); // Debounce search for better performance
        });
    }
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        updateAlertStatistics();
    }, 30000);
}); 