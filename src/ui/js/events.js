// Events stream functionality
let eventsPaused = false;
let eventHistory = [];
let sourceCounts = new Map();
let typeCounts = new Map();

function initEventsStream() {
    const container = document.getElementById('eventsStream');
    if (!container) return;
    
    container.innerHTML = '<div class="stream-placeholder">Waiting for events...</div>';
    
    // Load recent events
    loadRecentEvents();
}

function loadRecentEvents() {
    fetch('/api/v1/events?limit=50')
        .then(res => res.json())
        .then(data => {
            if (data.events && data.events.length > 0) {
                data.events.forEach(event => addEventToStream(event, false));
            }
        })
        .catch(err => console.error('Failed to load recent events:', err));
}

function addEventToStream(event, scroll = true) {
    if (eventsPaused) return;
    
    const container = document.getElementById('eventsStream');
    if (!container) return;
    
    // Remove placeholder if present
    if (container.querySelector('.stream-placeholder')) {
        container.innerHTML = '';
    }
    
    const eventDiv = document.createElement('div');
    eventDiv.className = 'event-entry';
    
    const time = formatTimeShort(event['@timestamp'] || event.timestamp);
    const eventType = event.event_type || event.type || 'unknown';
    const source = event.src_ip || event.source_ip || event.source || 'unknown';
    const message = event.message || event.raw_message || JSON.stringify(event).substring(0, 100);
    
    eventDiv.innerHTML = `
        <span class="event-time">${time}</span>
        <span class="event-type event-type-${eventType.replace(/_/g, '-')}">${eventType}</span>
        <span class="event-source">${source}</span>
        <span class="event-message">${escapeHtml(message)}</span>
    `;
    
    container.insertBefore(eventDiv, container.firstChild);
    
    // Update source counts
    sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    typeCounts.set(eventType, (typeCounts.get(eventType) || 0) + 1);
    
    // Update top sources chart
    updateTopSourcesChart();
    updateEventTypesChart();
    
    // Limit to 500 events
    while (container.children.length > 500) {
        container.removeChild(container.lastChild);
    }
    
    if (scroll) {
        container.scrollTop = 0;
    }
    
    // Update events per second stat
    updateEventsPerSecond();
}

function updateTopSourcesChart() {
    if (!topSourcesChart) return;
    
    const sorted = Array.from(sourceCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    topSourcesChart.data.labels = sorted.map(s => s[0]);
    topSourcesChart.data.datasets[0].data = sorted.map(s => s[1]);
    topSourcesChart.update();
}

function updateEventTypesChart() {
    if (!eventTypesChart) return;
    
    const sorted = Array.from(typeCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    eventTypesChart.data.labels = sorted.map(t => t[0]);
    eventTypesChart.data.datasets[0].data = sorted.map(t => t[1]);
    eventTypesChart.update();
}

let eventCounter = 0;
let lastEventTime = Date.now();

function updateEventsPerSecond() {
    const now = Date.now();
    const elapsed = (now - lastEventTime) / 1000;
    
    if (elapsed >= 1) {
        const eps = eventCounter / elapsed;
        document.getElementById('statEventsPerSec').textContent = eps.toFixed(1);
        eventCounter = 0;
        lastEventTime = now;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimeShort(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
}

function toggleEventsStream() {
    eventsPaused = !eventsPaused;
    const btn = document.getElementById('toggleEventsBtn');
    if (btn) {
        btn.textContent = eventsPaused ? '▶️ Resume Stream' : '⏸️ Pause Stream';
    }
}

function clearEventsStream() {
    const container = document.getElementById('eventsStream');
    if (container) {
        container.innerHTML = '<div class="stream-placeholder">Events cleared. Waiting for new events...</div>';
    }
    sourceCounts.clear();
    typeCounts.clear();
    updateTopSourcesChart();
    updateEventTypesChart();
}

// WebSocket handlers
function setupEventWebSocketHandlers() {
    if (!wsManager) return;
    
    wsManager.subscribe('new_event', (data) => {
        if (data.event) {
            addEventToStream(data.event);
            eventCounter++;
        }
    });
}