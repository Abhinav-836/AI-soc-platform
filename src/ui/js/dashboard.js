// Dashboard functionality
let alertTimelineChart = null;
let severityChart = null;
let topSourcesChart = null;
let eventTypesChart = null;
let alertHistory = [];
let startTime = Date.now();

function initDashboardCharts() {
    // Alert Timeline Chart
    const timelineCtx = document.getElementById('alertTimelineChart').getContext('2d');
    alertTimelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                borderColor: '#00ff41',
                backgroundColor: 'rgba(0, 255, 65, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#00ff41' }
                }
            },
            scales: {
                y: {
                    grid: { color: '#1a1a1a' },
                    ticks: { color: '#00cc33' }
                },
                x: {
                    grid: { color: '#1a1a1a' },
                    ticks: { color: '#00cc33' }
                }
            }
        }
    });
    
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#ff3333', '#ff6600', '#ffaa00', '#00aaff'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#00ff41' }
                }
            }
        }
    });
    
    // Top Sources Chart
    const sourcesCtx = document.getElementById('topSourcesChart').getContext('2d');
    topSourcesChart = new Chart(sourcesCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Events',
                data: [],
                backgroundColor: '#00ff41',
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: '#1a1a1a' },
                    ticks: { color: '#00cc33' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#00cc33' }
                }
            }
        }
    });
    
    // Event Types Chart
    const typesCtx = document.getElementById('eventTypesChart').getContext('2d');
    eventTypesChart = new Chart(typesCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Count',
                data: [],
                backgroundColor: '#00aaff',
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: '#1a1a1a' },
                    ticks: { color: '#00cc33' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#00cc33' }
                }
            }
        }
    });
}

function updateDashboardStats(stats) {
    if (stats.detection) {
        document.getElementById('statTotalAlerts').textContent = stats.detection.alerts_generated || 0;
        document.getElementById('statCriticalAlerts').textContent = stats.detection.alerts_count || 0;
        document.getElementById('statActiveRules').textContent = stats.detection.rule_engine?.total_rules || 0;
    }
    
    if (stats.websocket) {
        document.getElementById('statConnections').textContent = stats.websocket.total_connections || 0;
    }
    
    if (stats.ml) {
        document.getElementById('statMLInferences').textContent = stats.ml.inferences || 0;
    }
}

function updateAlertTimeline(alert) {
    const now = new Date();
    const timeLabel = now.toLocaleTimeString();
    
    alertHistory.push({ time: timeLabel, count: 1 });
    
    // Keep last 30 points
    if (alertHistory.length > 30) {
        alertHistory.shift();
    }
    
    // Aggregate by time
    const timeMap = new Map();
    alertHistory.forEach(item => {
        timeMap.set(item.time, (timeMap.get(item.time) || 0) + item.count);
    });
    
    const labels = Array.from(timeMap.keys());
    const data = labels.map(l => timeMap.get(l));
    
    alertTimelineChart.data.labels = labels;
    alertTimelineChart.data.datasets[0].data = data;
    alertTimelineChart.update();
}

function updateSeverityChart(severities) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    severities.forEach(s => {
        if (counts[s] !== undefined) counts[s]++;
    });
    
    severityChart.data.datasets[0].data = [counts.critical, counts.high, counts.medium, counts.low];
    severityChart.update();
}

function updateUptime() {
    const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;
    
    document.getElementById('uptime').textContent = 
        `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

// Update uptime every second
setInterval(updateUptime, 1000);