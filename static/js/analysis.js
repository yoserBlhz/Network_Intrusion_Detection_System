// Analysis page JavaScript
let currentAnalysisData = null;

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

function updateSummaryStats(data) {
    if (data.summary_stats) {
        document.getElementById('totalFlows').textContent = formatNumber(data.summary_stats.total_flows);
        // Use suspicious_flows_count from the top level if present, else from summary_stats, else 0
        let suspiciousCount = data.suspicious_flows_count;
        if (typeof suspiciousCount === 'undefined') {
            suspiciousCount = data.summary_stats.suspicious_flows_count;
        }
        suspiciousCount = Number(suspiciousCount);
        document.getElementById('suspiciousFlows').textContent = isNaN(suspiciousCount) ? 0 : formatNumber(suspiciousCount);
        document.getElementById('totalBytes').textContent = formatBytes(data.summary_stats.total_bytes);
        document.getElementById('uniqueIPs').textContent = formatNumber(data.summary_stats.unique_src_ips);
    }
}

function updateHeatmap(data) {
    const heatmapImage = document.getElementById('heatmapImage');
    const heatmapLoading = document.getElementById('heatmapLoading');
    
    if (data.heatmap_path) {
        heatmapImage.src = data.heatmap_path + '?t=' + new Date().getTime(); // Cache busting
        heatmapImage.style.display = 'block';
        heatmapLoading.style.display = 'none';
        
        // Handle image load errors
        heatmapImage.onerror = function() {
            heatmapImage.style.display = 'none';
            heatmapLoading.textContent = 'Error loading heatmap image';
            heatmapLoading.style.display = 'block';
        };
        
        // Handle successful image load
        heatmapImage.onload = function() {
            heatmapImage.style.display = 'block';
            heatmapLoading.style.display = 'none';
        };
    } else {
        heatmapImage.style.display = 'none';
        heatmapLoading.textContent = 'No data available for heatmap';
        heatmapLoading.style.display = 'block';
    }
}

function updateTopIPs(data) {
    // Update Top IPs by Bytes
    const topIPsBytes = document.getElementById('topIPsBytes');
    if (data.top_ips && data.top_ips.by_bytes && data.top_ips.by_bytes.length > 0) {
        topIPsBytes.innerHTML = data.top_ips.by_bytes.map((ip, index) => `
            <div class="flex justify-between items-center p-2 bg-gray-50 rounded">
                <div>
                    <span class="font-semibold">${index + 1}.</span>
                    <span class="text-sm">${ip.src_ip}</span>
                </div>
                <span class="text-sm text-blue-600">${formatBytes(ip.total_bytes)}</span>
            </div>
        `).join('');
    } else {
        topIPsBytes.innerHTML = '<p class="text-gray-500">No data available</p>';
    }

    // Update Top IPs by Packets
    const topIPsPackets = document.getElementById('topIPsPackets');
    if (data.top_ips && data.top_ips.by_packets && data.top_ips.by_packets.length > 0) {
        topIPsPackets.innerHTML = data.top_ips.by_packets.map((ip, index) => `
            <div class="flex justify-between items-center p-2 bg-gray-50 rounded">
                <div>
                    <span class="font-semibold">${index + 1}.</span>
                    <span class="text-sm">${ip.src_ip}</span>
                </div>
                <span class="text-sm text-green-600">${formatNumber(ip.total_packets)}</span>
            </div>
        `).join('');
    } else {
        topIPsPackets.innerHTML = '<p class="text-gray-500">No data available</p>';
    }

    // Update Top IPs by Destinations
    const topIPsDestinations = document.getElementById('topIPsDestinations');
    if (data.top_ips && data.top_ips.by_destinations && data.top_ips.by_destinations.length > 0) {
        topIPsDestinations.innerHTML = data.top_ips.by_destinations.map((ip, index) => `
            <div class="flex justify-between items-center p-2 bg-gray-50 rounded">
                <div>
                    <span class="font-semibold">${index + 1}.</span>
                    <span class="text-sm">${ip.src_ip}</span>
                </div>
                <span class="text-sm text-purple-600">${formatNumber(ip.distinct_destinations)}</span>
            </div>
        `).join('');
    } else {
        topIPsDestinations.innerHTML = '<p class="text-gray-500">No data available</p>';
    }
}

function updateSuspiciousFlows(data) {
    const suspiciousFlowsTable = document.getElementById('suspiciousFlowsTable');
    
    if (data.suspicious_flows && data.suspicious_flows.length > 0) {
        suspiciousFlowsTable.innerHTML = data.suspicious_flows.map(flow => {
            // Determine color based on suspicion reason
            const isSuspicious = flow.suspicion_reason.toLowerCase().includes('suspicious');
            const suspicionColor = isSuspicious ? 'text-red-600' : 'text-green-600';
            const suspicionBg = isSuspicious ? 'bg-red-50' : 'bg-green-50';
            
            return `
                <tr class="border-b hover:bg-gray-50">
                    <td class="px-4 py-2 text-sm">${flow.src_ip}</td>
                    <td class="px-4 py-2 text-sm">${flow.dst_ip}</td>
                    <td class="px-4 py-2 text-sm font-mono">${flow.protocol}</td>
                    <td class="px-4 py-2 text-sm">${flow.port}</td>
                    <td class="px-4 py-2 text-sm ${suspicionColor} font-semibold">${flow.suspicion_reason}</td>
                    <td class="px-4 py-2 text-sm">${flow.direction}</td>
                    <td class="px-4 py-2 text-sm">${flow.country}</td>
                    <td class="px-4 py-2 text-sm">
                        <button onclick="downloadPcap('${flow.src_ip}_${flow.dst_ip}_${flow.protocol}')" 
                                class="bg-blue-600 text-white px-2 py-1 rounded text-xs hover:bg-blue-700">
                            Download PCAP
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } else {
        suspiciousFlowsTable.innerHTML = `
            <tr>
                <td colspan="8" class="px-4 py-2 text-center text-gray-500">No suspicious flows detected</td>
            </tr>
        `;
    }
}

function updatePcapFiles(data) {
    const pcapFiles = document.getElementById('pcapFiles');
    
    if (data.saved_pcaps && data.saved_pcaps.length > 0) {
        pcapFiles.innerHTML = data.saved_pcaps.map(pcap => `
            <div class="flex justify-between items-center p-3 bg-gray-50 rounded">
                <div>
                    <span class="font-semibold">${pcap.flow_info.src_ip} → ${pcap.flow_info.dst_ip}</span>
                    <span class="text-sm text-gray-600 ml-2">(${pcap.flow_info.protocol})</span>
                </div>
                <button onclick="downloadPcapFile('${pcap.filepath.split('/').pop()}')" 
                        class="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700">
                    Download
                </button>
            </div>
        `).join('');
    } else {
        pcapFiles.innerHTML = '<p class="text-gray-500">No PCAP files available</p>';
    }
}

async function generateAnalysis() {
    const hours = document.getElementById('timeRange').value;
    const statusElement = document.getElementById('analysisStatus');
    
    // Show loading state
    statusElement.textContent = 'Analyzing live network flows...';
    document.getElementById('heatmapLoading').textContent = 'Generating live flows analysis...';
    document.getElementById('heatmapLoading').style.display = 'block';
    document.getElementById('heatmapImage').style.display = 'none';
    
    try {
        // Try live flows analysis first
        let response = await fetch(`/api/live_flows_analysis?hours=${hours}`);
        let data = await response.json();
        
        if (!response.ok || !data.success) {
            // Fallback to regular analysis if live flows not available
            console.log("Live flows not available, falling back to regular analysis...");
            statusElement.textContent = 'Live flows not available, using historical data...';
            response = await fetch(`/api/analysis_report?hours=${hours}`);
            data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Analysis failed');
            }
            
            if (data.error) {
                throw new Error(data.error);
            }
        }
        
        currentAnalysisData = data;
        
        // Update all sections
        updateSummaryStats(data);
        updateHeatmap(data);
        updateTopIPs(data);
        updateSuspiciousFlows(data);
        updatePcapFiles(data);
        
        // Show data source info
        if (data.data_source === 'live_flows') {
            statusElement.textContent = `Live analysis complete - ${data.flows_count} flows analyzed`;
            document.getElementById('heatmapLoading').textContent = `Live analysis complete - ${data.flows_count} flows analyzed`;
        } else {
            statusElement.textContent = 'Analysis complete (using historical data)';
            document.getElementById('heatmapLoading').textContent = 'Analysis complete (using historical data)';
        }
        
    } catch (error) {
        console.error('Error:', error);
        statusElement.textContent = `Error: ${error.message}`;
        document.getElementById('heatmapLoading').textContent = `Error: ${error.message}`;
        document.getElementById('heatmapLoading').style.display = 'block';
        document.getElementById('heatmapImage').style.display = 'none';
        
        // Show error in other sections too
        document.getElementById('topIPsBytes').innerHTML = '<p class="text-red-500">Error loading data</p>';
        document.getElementById('topIPsPackets').innerHTML = '<p class="text-red-500">Error loading data</p>';
        document.getElementById('topIPsDestinations').innerHTML = '<p class="text-red-500">Error loading data</p>';
        document.getElementById('suspiciousFlowsTable').innerHTML = '<tr><td colspan="8" class="px-4 py-2 text-center text-red-500">Error loading data</td></tr>';
        document.getElementById('pcapFiles').innerHTML = '<p class="text-red-500">Error loading data</p>';
    }
}

async function downloadReport() {
    if (!currentAnalysisData) {
        alert('Please generate analysis first');
        return;
    }
    
    // Create a text report
    const report = generateTextReport(currentAnalysisData);
    
    // Create and download file
    const blob = new Blob([report], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network_analysis_report_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function generateTextReport(data) {
    let report = 'NETWORK INTRUSION DETECTION SYSTEM - ANALYSIS REPORT\n';
    report += '=' * 50 + '\n\n';
    report += `Generated: ${new Date().toLocaleString()}\n\n`;
    
    if (data.summary_stats) {
        report += 'SUMMARY STATISTICS:\n';
        report += `- Total Flows: ${data.summary_stats.total_flows}\n`;
        report += `- Suspicious Flows: ${data.summary_stats.suspicious_flows_count}\n`;
        report += `- Total Bytes: ${formatBytes(data.summary_stats.total_bytes)}\n`;
        report += `- Unique Source IPs: ${data.summary_stats.unique_src_ips}\n`;
        report += `- Unique Destination IPs: ${data.summary_stats.unique_dst_ips}\n`;
        report += `- Internal-to-External Flows: ${data.summary_stats.internal_to_external_flows}\n`;
        report += `- External-to-Internal Flows: ${data.summary_stats.external_to_internal_flows}\n\n`;
    }
    
    if (data.suspicious_flows && data.suspicious_flows.length > 0) {
        report += 'SUSPICIOUS FLOWS:\n';
        data.suspicious_flows.forEach((flow, index) => {
            report += `${index + 1}. ${flow.src_ip} → ${flow.dst_ip} (${flow.protocol}:${flow.port})\n`;
            report += `   Reason: ${flow.suspicion_reason}\n`;
            report += `   Direction: ${flow.direction}\n`;
            report += `   Country: ${flow.country}\n\n`;
        });
    }
    
    return report;
}

async function downloadPcap(filename) {
    try {
        window.open(`/api/download_pcap/${filename}`, '_blank');
    } catch (error) {
        console.error('Error downloading PCAP:', error);
        alert('Error downloading PCAP file');
    }
}

async function downloadPcapFile(filename) {
    try {
        window.open(`/api/download_pcap/${filename}`, '_blank');
    } catch (error) {
        console.error('Error downloading PCAP file:', error);
        alert('Error downloading PCAP file');
    }
}

// Auto-generate analysis on page load
document.addEventListener('DOMContentLoaded', () => {
    generateAnalysis();
}); 