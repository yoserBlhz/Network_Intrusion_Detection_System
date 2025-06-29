// ML Rules JavaScript
let currentRules = [];

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleString();
}

function getSeverityColor(severity) {
    switch (severity.toUpperCase()) {
        case 'HIGH':
            return 'text-red-600 bg-red-50';
        case 'MEDIUM':
            return 'text-orange-600 bg-orange-50';
        case 'LOW':
            return 'text-yellow-600 bg-yellow-50';
        default:
            return 'text-gray-600 bg-gray-50';
    }
}

function getRuleTypeColor(ruleType) {
    const typeColors = {
        'protocol_anomaly': 'text-blue-600 bg-blue-50',
        'port_anomaly': 'text-green-600 bg-green-50',
        'temporal_anomaly': 'text-purple-600 bg-purple-50',
        'behavioral_anomaly': 'text-red-600 bg-red-50'
    };
    return typeColors[ruleType] || 'text-gray-600 bg-gray-50';
}

function updateRuleStatistics() {
    fetch('/api/ml/rule_statistics')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const stats = data.statistics;
                document.getElementById('totalRules').textContent = formatNumber(stats.total_rules);
                document.getElementById('protocolRules').textContent = formatNumber(stats.rule_breakdown.protocol_rules);
                document.getElementById('portRules').textContent = formatNumber(stats.rule_breakdown.port_rules);
                document.getElementById('avgConfidence').textContent = (stats.avg_confidence * 100).toFixed(1) + '%';
            }
        })
        .catch(error => {
            console.error('Error loading rule statistics:', error);
        });
}

function updateRulesTable(rules) {
    const tableBody = document.getElementById('mlRulesTable');
    
    if (rules.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="px-4 py-2 text-center text-gray-500">No ML rules found</td>
            </tr>
        `;
        return;
    }
    
    tableBody.innerHTML = rules.map(rule => {
        const severityColor = getSeverityColor(rule.severity);
        const typeColor = getRuleTypeColor(rule.rule_type);
        const createdDate = formatDate(rule.created_at);
        
        // Determine target based on rule type
        let target = '';
        if (rule.rule_type === 'protocol_anomaly') {
            target = rule.protocol_name || `Protocol ${rule.protocol}`;
        } else if (rule.rule_type === 'port_anomaly') {
            target = `Port ${rule.port}`;
        } else if (rule.rule_type === 'temporal_anomaly') {
            target = `Hour ${rule.hour}:00`;
        } else if (rule.rule_type === 'behavioral_anomaly') {
            target = rule.src_ip;
        }
        
        return `
            <tr class="border-b hover:bg-gray-50">
                <td class="px-4 py-2 text-sm font-mono">${rule.rule_id}</td>
                <td class="px-4 py-2 text-sm">
                    <span class="px-2 py-1 rounded text-xs font-semibold ${typeColor}">
                        ${rule.rule_type.replace('_', ' ').toUpperCase()}
                    </span>
                </td>
                <td class="px-4 py-2 text-sm font-semibold">${target}</td>
                <td class="px-4 py-2 text-sm">
                    <span class="px-2 py-1 rounded text-xs font-semibold ${severityColor}">
                        ${rule.severity}
                    </span>
                </td>
                <td class="px-4 py-2 text-sm">
                    <div class="flex items-center">
                        <span class="font-semibold">${(rule.confidence * 100).toFixed(1)}%</span>
                        <div class="ml-2 w-16 bg-gray-200 rounded-full h-2">
                            <div class="bg-blue-600 h-2 rounded-full" style="width: ${rule.confidence * 100}%"></div>
                        </div>
                    </div>
                </td>
                <td class="px-4 py-2 text-sm">${rule.description}</td>
                <td class="px-4 py-2 text-sm">${createdDate}</td>
            </tr>
        `;
    }).join('');
}

async function generateRules() {
    const hours = document.getElementById('analysisHours').value;
    const useLiveFlows = document.getElementById('useLiveFlows').checked;
    // Show loading state
    const generateBtn = document.querySelector('button[onclick="generateRules()"]');
    const originalText = generateBtn.textContent;
    generateBtn.textContent = 'Generating...';
    generateBtn.disabled = true;
    try {
        let url = `/api/ml/generate_rules?hours=${hours}`;
        if (useLiveFlows) {
            url += '&use_live_flows=true';
        }
        const response = await fetch(url);
        const data = await response.json();
        if (data.success) {
            showAnalysisResults(data.analysis);
            loadRules(); // Refresh the rules table
            updateRuleStatistics(); // Update statistics
            alert(`Successfully generated ${data.analysis.generated_rules.total_rules} ML rules!`);
        } else {
            alert(`Error generating rules: ${data.error}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error generating rules. Please try again.');
    } finally {
        // Restore button state
        generateBtn.textContent = originalText;
        generateBtn.disabled = false;
    }
}

function showAnalysisResults(analysis) {
    const resultsDiv = document.getElementById('analysisResults');
    const contentDiv = document.getElementById('analysisContent');
    
    contentDiv.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
                <h3 class="text-lg font-semibold mb-3">Analysis Summary</h3>
                <div class="space-y-2">
                    <p><strong>Analysis Period:</strong> ${analysis.data_period_hours} hours</p>
                    <p><strong>Total Flows Analyzed:</strong> ${formatNumber(analysis.total_flows_analyzed)}</p>
                    <p><strong>Analysis Timestamp:</strong> ${formatDate(analysis.analysis_timestamp)}</p>
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-3">Generated Rules</h3>
                <div class="space-y-2">
                    <p><strong>Protocol Rules:</strong> ${analysis.generated_rules.protocol_rules}</p>
                    <p><strong>Port Rules:</strong> ${analysis.generated_rules.port_rules}</p>
                    <p><strong>Temporal Rules:</strong> ${analysis.generated_rules.temporal_rules}</p>
                    <p><strong>Behavioral Rules:</strong> ${analysis.generated_rules.behavioral_rules}</p>
                    <p><strong>Total Rules:</strong> ${analysis.generated_rules.total_rules}</p>
                </div>
            </div>
        </div>
        
        ${analysis.anomaly_patterns ? `
        <div class="mt-6">
            <h3 class="text-lg font-semibold mb-3">Anomaly Patterns Detected</h3>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-gray-50 p-3 rounded">
                    <p><strong>Anomaly Count:</strong> ${formatNumber(analysis.anomaly_patterns.anomaly_count)}</p>
                    <p><strong>Anomaly Ratio:</strong> ${(analysis.anomaly_patterns.anomaly_ratio * 100).toFixed(2)}%</p>
                </div>
                <div class="bg-gray-50 p-3 rounded">
                    <p><strong>Avg Anomalous Duration:</strong> ${analysis.anomaly_patterns.avg_anomalous_duration.toFixed(2)}s</p>
                    <p><strong>Avg Packets/Sec:</strong> ${analysis.anomaly_patterns.avg_anomalous_packets_per_sec.toFixed(2)}</p>
                </div>
                <div class="bg-gray-50 p-3 rounded">
                    <p><strong>Avg Bytes/Packet:</strong> ${analysis.anomaly_patterns.avg_anomalous_bytes_per_packet.toFixed(2)}</p>
                </div>
            </div>
        </div>
        ` : ''}
    `;
    
    resultsDiv.classList.remove('hidden');
}

async function applyRules() {
    try {
        const response = await fetch('/api/ml/apply_rules');
        const data = await response.json();
        
        if (data.success) {
            alert(`Applied ML rules to ${data.total_flows_checked} flows. Found ${data.flows_with_triggers} flows with triggered rules.`);
        } else {
            alert(`Error applying rules: ${data.error}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error applying rules. Please try again.');
    }
}

async function deleteRules() {
    if (!confirm('Are you sure you want to delete all ML-generated rules? This action cannot be undone.')) {
        return;
    }
    
    try {
        const response = await fetch('/api/ml/delete_rules', {
            method: 'DELETE'
        });
        const data = await response.json();
        
        if (data.success) {
            alert('All ML-generated rules have been deleted.');
            loadRules(); // Refresh the rules table
            updateRuleStatistics(); // Update statistics
        } else {
            alert(`Error deleting rules: ${data.error}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error deleting rules. Please try again.');
    }
}

async function loadRules() {
    const ruleTypeFilter = document.getElementById('ruleTypeFilter').value;
    
    try {
        let url = '/api/ml/rules';
        if (ruleTypeFilter) {
            url = `/api/ml/rules/${ruleTypeFilter}`;
        }
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.success) {
            currentRules = data.rules;
            updateRulesTable(currentRules);
        } else {
            console.error('Error loading rules:', data.error);
            document.getElementById('mlRulesTable').innerHTML = `
                <tr>
                    <td colspan="7" class="px-4 py-2 text-center text-red-500">Error loading rules</td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('mlRulesTable').innerHTML = `
            <tr>
                <td colspan="7" class="px-4 py-2 text-center text-red-500">Error loading rules</td>
            </tr>
        `;
    }
}

// Auto-load rules and statistics on page load
document.addEventListener('DOMContentLoaded', () => {
    updateRuleStatistics();
    loadRules();
    
    // Add filter change listener
    document.getElementById('ruleTypeFilter').addEventListener('change', loadRules);
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        updateRuleStatistics();
    }, 30000);
});
