document.addEventListener('DOMContentLoaded', () => {
    // Real-time packets per second chart
    const realtimeTrafficChartCtx = document.getElementById('realtimeTrafficChart').getContext('2d');
    const realtimeTrafficChart = new Chart(realtimeTrafficChartCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets Per Second',
                data: [],
                borderColor: 'rgba(54, 162, 235, 1)',
                fill: false
            }]
        },
        options: {
            scales: { y: { beginAtZero: true } },
            animation: false
        }
    });

    function updateRealtimeTrafficChart() {
        fetch('/api/traffic')
            .then(response => response.json())
            .then(data => {
                const now = new Date();
                const timeLabel = now.toLocaleTimeString();
                const d = realtimeTrafficChart.data;
                d.labels.push(timeLabel);
                d.datasets[0].data.push(data.packets_per_second);
                if (d.labels.length > 30) {
                    d.labels.shift();
                    d.datasets[0].data.shift();
                }
                realtimeTrafficChart.update();
            });
    }

    function updateLiveFlowsTable() {
        fetch('/api/live_flows')
            .then(response => response.json())
            .then(data => {
                const tbody = document.getElementById('live-flows-table-body');
                tbody.innerHTML = '';
                data.flows.forEach(flow => {
                    const row = document.createElement('tr');
                    const srcInternalClass = flow.is_internal_src ? 'text-green-600 font-semibold' : 'text-blue-600';
                    const dstInternalClass = flow.is_internal_dst ? 'text-green-600 font-semibold' : 'text-blue-600';
                    const directionClass = flow.direction === 'Internal-to-External' ? 'text-orange-600' : 
                                         flow.direction === 'External-to-Internal' ? 'text-red-600' : 'text-gray-600';
                    
                    row.innerHTML = `
                        <td class="border px-4 py-2 ${srcInternalClass}">${flow.src_ip}</td>
                        <td class="border px-4 py-2 ${dstInternalClass}">${flow.dst_ip}</td>
                        <td class="border px-4 py-2 font-mono">${flow.protocol_name}</td>
                        <td class="border px-4 py-2 ${directionClass}">${flow.direction}</td>
                        <td class="border px-4 py-2">${flow.packets}</td>
                        <td class="border px-4 py-2">${flow.bytes}</td>
                        <td class="border px-4 py-2">${flow.country}</td>
                        <td class="border px-4 py-2">${new Date(flow.last_seen * 1000).toLocaleTimeString()}</td>
                    `;
                    tbody.appendChild(row);
                });
            });
    }

    setInterval(updateRealtimeTrafficChart, 1000);
    setInterval(updateLiveFlowsTable, 1000);
});