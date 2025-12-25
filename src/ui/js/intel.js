// Threat Intelligence functionality
let currentIOCs = [];

function loadIOCs() {
    fetch('/api/v1/intel/iocs?limit=100')
        .then(res => res.json())
        .then(data => {
            currentIOCs = data.iocs || [];
            renderIOCsTable(currentIOCs);
            updateIOCStats(currentIOCs);
        })
        .catch(err => console.error('Failed to load IOCs:', err));
}

function renderIOCsTable(iocs) {
    const tbody = document.getElementById('iocsTableBody');
    if (!tbody) return;
    
    if (!iocs || iocs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading">No IOCs found</td></tr>';
        return;
    }
    
    tbody.innerHTML = iocs.map(ioc => `
        <tr>
            <td>${(ioc.type || 'unknown').toUpperCase()}</td>
            <td><code>${escapeHtml(ioc.value || 'N/A')}</code></td>
            <td>${ioc.feed || ioc.source || 'unknown'}</td>
            <td>${ioc.confidence ? (ioc.confidence * 100).toFixed(0) + '%' : 'N/A'}</td>
            <td>${formatTime(ioc.first_seen || ioc.loaded_at)}</td>
        </tr>
    `).join('');
}

function updateIOCStats(iocs) {
    document.getElementById('totalIOCs').textContent = iocs.length;
    document.getElementById('ipIOCs').textContent = iocs.filter(i => i.type === 'ip').length;
    document.getElementById('domainIOCs').textContent = iocs.filter(i => i.type === 'domain').length;
    document.getElementById('hashIOCs').textContent = iocs.filter(i => i.type === 'hash').length;
}

function searchIOCs(query) {
    if (!query || query.trim() === '') {
        loadIOCs();
        return;
    }
    
    const filtered = currentIOCs.filter(ioc => 
        ioc.value?.toLowerCase().includes(query.toLowerCase()) ||
        ioc.type?.toLowerCase().includes(query.toLowerCase())
    );
    
    renderIOCsTable(filtered);
}