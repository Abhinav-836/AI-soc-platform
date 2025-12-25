// Main Application
document.addEventListener('DOMContentLoaded', () => {
    // Initialize WebSocket
    initWebSocket();
    
    // Initialize charts
    initDashboardCharts();
    
    // Initialize components
    initEventsStream();
    
    // Setup event handlers
    setupEventHandlers();
    
    // Setup WebSocket handlers
    setupAlertWebSocketHandlers();
    setupEventWebSocketHandlers();
    setupStatsWebSocketHandlers();
    
    // Load initial data
    loadAlerts();
    loadIOCs();
    
    // Refresh stats periodically
    setInterval(() => {
        if (wsManager && wsManager.isConnected) {
            wsManager.getStats();
        } else {
            fetchStats();
        }
    }, 5000);
});

function setupEventHandlers() {
    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const page = btn.dataset.page;
            switchPage(page);
        });
    });
    
    // Alert filters
    const severityFilter = document.getElementById('alertSeverityFilter');
    const statusFilter = document.getElementById('alertStatusFilter');
    const refreshBtn = document.getElementById('refreshAlertsBtn');
    
    if (severityFilter) severityFilter.addEventListener('change', loadAlerts);
    if (statusFilter) statusFilter.addEventListener('change', loadAlerts);
    if (refreshBtn) refreshBtn.addEventListener('click', loadAlerts);
    
    // Events controls
    const toggleEventsBtn = document.getElementById('toggleEventsBtn');
    const clearEventsBtn = document.getElementById('clearEventsBtn');
    
    if (toggleEventsBtn) toggleEventsBtn.addEventListener('click', toggleEventsStream);
    if (clearEventsBtn) clearEventsBtn.addEventListener('click', clearEventsStream);
    
    // Intel search
    const searchBtn = document.getElementById('searchIocsBtn');
    const searchInput = document.getElementById('iocSearchInput');
    
    if (searchBtn) searchBtn.addEventListener('click', () => searchIOCs(searchInput?.value));
    if (searchInput) searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') searchIOCs(searchInput.value);
    });
    
    // Settings
    const reconnectBtn = document.getElementById('reconnectBtn');
    const themeSelect = document.getElementById('themeSelect');
    const refreshInterval = document.getElementById('refreshInterval');
    
    if (reconnectBtn) reconnectBtn.addEventListener('click', reconnectWebSocket);
    if (themeSelect) themeSelect.addEventListener('change', (e) => setTheme(e.target.value));
    if (refreshInterval) refreshInterval.addEventListener('change', (e) => setRefreshInterval(e.target.value));
    
    // Load saved settings
    loadSettings();
}

function switchPage(pageName) {
    // Update navigation buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.page === pageName) {
            btn.classList.add('active');
        }
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    const targetPage = document.getElementById(`${pageName}Page`);
    if (targetPage) {
        targetPage.classList.add('active');
    }
    
    // Load page-specific data
    if (pageName === 'alerts') {
        loadAlerts();
    } else if (pageName === 'intel') {
        loadIOCs();
    }
}

function fetchStats() {
    fetch('/api/v1/stats')
        .then(res => res.json())
        .then(stats => updateDashboardStats(stats))
        .catch(err => console.error('Failed to fetch stats:', err));
}

function setupStatsWebSocketHandlers() {
    if (!wsManager) return;
    
    wsManager.subscribe('stats_update', (data) => {
        if (data.data) {
            updateDashboardStats(data.data);
        }
    });
    
    wsManager.subscribe('stats', (data) => {
        if (data.data) {
            updateDashboardStats(data.data);
        }
    });
}

function reconnectWebSocket() {
    const apiEndpoint = document.getElementById('apiEndpoint')?.value || 'http://localhost:8080';
    const wsEndpoint = document.getElementById('wsEndpoint')?.value || 'ws://localhost:8080/ws';
    
    localStorage.setItem('apiEndpoint', apiEndpoint);
    localStorage.setItem('wsEndpoint', wsEndpoint);
    
    if (wsManager) {
        wsManager.disconnect();
    }
    
    initWebSocket();
    
    showToast('Reconnecting to server...', 'info');
}

function setTheme(theme) {
    localStorage.setItem('theme', theme);
    if (theme === 'light') {
        document.body.style.backgroundColor = '#f0f0f0';
        document.body.style.color = '#000';
    } else {
        document.body.style.backgroundColor = '';
        document.body.style.color = '';
    }
}

function setRefreshInterval(interval) {
    localStorage.setItem('refreshInterval', interval);
}

function loadSettings() {
    const apiEndpoint = localStorage.getItem('apiEndpoint');
    const wsEndpoint = localStorage.getItem('wsEndpoint');
    const theme = localStorage.getItem('theme');
    const refreshInterval = localStorage.getItem('refreshInterval');
    
    if (apiEndpoint) document.getElementById('apiEndpoint').value = apiEndpoint;
    if (wsEndpoint) document.getElementById('wsEndpoint').value = wsEndpoint;
    if (theme) setTheme(theme);
    if (refreshInterval) document.getElementById('refreshInterval').value = refreshInterval;
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 10px 20px;
        background: var(--card-bg);
        border: 1px solid var(--primary);
        border-radius: 5px;
        color: var(--primary);
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}