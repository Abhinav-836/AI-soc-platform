// Alerts functionality
let currentAlerts = [];

function loadAlerts() {
    const severity = document.getElementById('alertSeverityFilter')?.value || '';
    const status = document.getElementById('alertStatusFilter')?.value || '';
    
    let url = '/api/v1/alerts?limit=100';
    if (severity) url += `&severity=${severity}`;
    if (status) url += `&status=${status}`;
    
    fetch(url)
        .then(res => res.json())
        .then(data => {
            currentAlerts = data.alerts || [];
            renderAlertsTable(currentAlerts);
            
            // Update severity chart with all alerts
            const severities = currentAlerts.map(a => a.severity);
            if (typeof updateSeverityChart === 'function') {
                updateSeverityChart(severities);
            }
        })
        .catch(err => console.error('Failed to load alerts:', err));
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    const recentTbody = document.getElementById('recentAlertsTable');
    
    if (!tbody) return;
    
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading">No alerts found</td></tr>';
        if (recentTbody) recentTbody.innerHTML = '<tr><td colspan="6" class="loading">No recent alerts</td></tr>';
        return;
    }
    
    // Full table
    tbody.innerHTML = alerts.map(alert => `
        <tr>
            <td>${formatTime(alert.timestamp)}</td>
            <td>${alert.alert_id || alert.id || 'N/A'}</td>
            <td class="severity-${alert.severity}">${(alert.severity || 'unknown').toUpperCase()}</td>
            <td>${alert.rule_name || 'Unknown Rule'}</td>
            <td>${alert.score ? alert.score.toFixed(2) : 'N/A'}</td>
            <td class="status-${alert.status || 'new'}">${alert.status || 'new'}</td>
            <td>
                <button class="btn-view" onclick="viewAlert('${alert.alert_id}')">View</button>
                <button class="btn-update" onclick="updateAlertStatus('${alert.alert_id}')">Update</button>
            </td>
        </tr>
    `).join('');
    
    // Recent alerts (for dashboard)
    if (recentTbody) {
        const recentAlerts = alerts.slice(0, 10);
        recentTbody.innerHTML = recentAlerts.map(alert => `
            <tr>
                <td>${formatTime(alert.timestamp)}</td>
                <td class="severity-${alert.severity}">${(alert.severity || 'unknown').toUpperCase()}</td>
                <td>${alert.rule_name || 'Unknown Rule'}</td>
                <td>${alert.source_ip || alert.src_ip || 'N/A'}</td>
                <td class="status-${alert.status || 'new'}">${alert.status || 'new'}</td>
                <td>
                    <button class="btn-view" onclick="viewAlert('${alert.alert_id}')">View</button>
                </td>
            </tr>
        `).join('');
    }
}

function viewAlert(alertId) {
    const alert = currentAlerts.find(a => a.alert_id === alertId);
    if (alert) {
        showAlertModal(alert);
    }
}

function showAlertModal(alert) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Alert Details</h3>
                <button class="modal-close" onclick="this.closest('.modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <div class="detail-row"><strong>Alert ID:</strong> ${alert.alert_id}</div>
                <div class="detail-row"><strong>Time:</strong> ${formatTime(alert.timestamp)}</div>
                <div class="detail-row"><strong>Severity:</strong> <span class="severity-${alert.severity}">${alert.severity}</span></div>
                <div class="detail-row"><strong>Rule:</strong> ${alert.rule_name}</div>
                <div class="detail-row"><strong>Description:</strong> ${alert.description || 'No description'}</div>
                <div class="detail-row"><strong>Score:</strong> ${alert.score || 'N/A'}</div>
                <div class="detail-row"><strong>Confidence:</strong> ${alert.confidence ? (alert.confidence * 100).toFixed(1) + '%' : 'N/A'}</div>
                <div class="detail-row"><strong>Status:</strong> ${alert.status || 'new'}</div>
                ${alert.source_ip ? `<div class="detail-row"><strong>Source IP:</strong> ${alert.source_ip}</div>` : ''}
                ${alert.dest_ip ? `<div class="detail-row"><strong>Destination IP:</strong> ${alert.dest_ip}</div>` : ''}
                ${alert.user ? `<div class="detail-row"><strong>User:</strong> ${alert.user}</div>` : ''}
                ${alert.indicators && alert.indicators.length ? `
                    <div class="detail-row"><strong>Indicators:</strong>
                        <ul>${alert.indicators.map(i => `<li>${i.type}: ${i.value}</li>`).join('')}</ul>
                    </div>
                ` : ''}
            </div>
            <div class="modal-footer">
                <button onclick="updateAlertStatus('${alert.alert_id}')">Update Status</button>
                <button onclick="this.closest('.modal').remove()">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function updateAlertStatus(alertId) {
    const newStatus = prompt('Enter new status (new, investigating, contained, resolved, false_positive):');
    if (!newStatus) return;
    
    fetch(`/api/v1/alerts/${alertId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
    })
        .then(res => res.json())
        .then(() => {
            loadAlerts();
            if (wsManager) {
                wsManager.send({
                    type: 'alert_status_update',
                    alert_id: alertId,
                    status: newStatus
                });
            }
        })
        .catch(err => console.error('Failed to update alert status:', err));
}

function formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function loadAlertsPage() {
    document.querySelector('[data-page="alerts"]').click();
    setTimeout(loadAlerts, 100);
}

// WebSocket handlers
function setupAlertWebSocketHandlers() {
    if (!wsManager) return;
    
    wsManager.subscribe('new_alert', (data) => {
        if (data.alert) {
            currentAlerts.unshift(data.alert);
            renderAlertsTable(currentAlerts.slice(0, 100));
            updateAlertTimeline(data.alert);
            
            // Show notification
            if (data.alert.severity === 'critical') {
                showNotification('Critical Alert!', data.alert.rule_name);
            }
        }
    });
    
    wsManager.subscribe('alert_status_update', (data) => {
        const alert = currentAlerts.find(a => a.alert_id === data.alert_id);
        if (alert) {
            alert.status = data.status;
            renderAlertsTable(currentAlerts.slice(0, 100));
        }
    });
}

function showNotification(title, message) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, { body: message, icon: '/assets/logo.svg' });
    } else if ('Notification' in window && Notification.permission !== 'denied') {
        Notification.requestPermission();
    }
}