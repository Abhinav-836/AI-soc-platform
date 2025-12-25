// WebSocket Manager
class WebSocketManager {
    constructor(url) {
        this.url = url;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 3000;
        this.isConnected = false;
        this.subscribers = new Map();
        this.messageQueue = [];
    }
    
    connect() {
        try {
            this.ws = new WebSocket(this.url);
            
            this.ws.onopen = () => {
                console.log('[WebSocket] Connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.updateConnectionStatus(true);
                
                // Send queued messages
                while (this.messageQueue.length > 0) {
                    this.send(this.messageQueue.shift());
                }
                
                // Send initial subscription
                this.send({ type: 'subscribe', channel: 'alerts' });
                this.send({ type: 'subscribe', channel: 'events' });
                this.send({ type: 'subscribe', channel: 'stats' });
                this.send({ type: 'get_stats' });
            };
            
            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (e) {
                    console.error('[WebSocket] Parse error:', e);
                }
            };
            
            this.ws.onclose = () => {
                console.log('[WebSocket] Disconnected');
                this.isConnected = false;
                this.updateConnectionStatus(false);
                this.reconnect();
            };
            
            this.ws.onerror = (error) => {
                console.error('[WebSocket] Error:', error);
            };
            
        } catch (e) {
            console.error('[WebSocket] Connection error:', e);
            this.reconnect();
        }
    }
    
    reconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[WebSocket] Max reconnection attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        console.log(`[WebSocket] Reconnecting in ${this.reconnectDelay}ms (attempt ${this.reconnectAttempts})`);
        
        setTimeout(() => {
            this.connect();
        }, this.reconnectDelay);
    }
    
    send(data) {
        if (this.isConnected && this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        } else {
            this.messageQueue.push(data);
        }
    }
    
    subscribe(eventType, callback) {
        if (!this.subscribers.has(eventType)) {
            this.subscribers.set(eventType, []);
        }
        this.subscribers.get(eventType).push(callback);
    }
    
    unsubscribe(eventType, callback) {
        if (this.subscribers.has(eventType)) {
            const callbacks = this.subscribers.get(eventType);
            const index = callbacks.indexOf(callback);
            if (index !== -1) {
                callbacks.splice(index, 1);
            }
        }
    }
    
    handleMessage(data) {
        const eventType = data.type || data.event_type;
        
        if (this.subscribers.has(eventType)) {
            this.subscribers.get(eventType).forEach(callback => {
                try {
                    callback(data);
                } catch (e) {
                    console.error(`[WebSocket] Callback error for ${eventType}:`, e);
                }
            });
        }
        
        // Also handle by data.event_type if present
        if (data.event_type && data.event_type !== eventType && this.subscribers.has(data.event_type)) {
            this.subscribers.get(data.event_type).forEach(callback => {
                try {
                    callback(data);
                } catch (e) {
                    console.error(`[WebSocket] Callback error for ${data.event_type}:`, e);
                }
            });
        }
    }
    
    updateConnectionStatus(connected) {
        const statusEl = document.getElementById('wsStatus');
        if (statusEl) {
            statusEl.textContent = connected ? 'CONNECTED' : 'DISCONNECTED';
            statusEl.className = `status-value ${connected ? 'online' : 'offline'}`;
        }
    }
    
    getStats() {
        this.send({ type: 'get_stats' });
    }
    
    ping() {
        this.send({ type: 'ping' });
    }
    
    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Initialize WebSocket
let wsManager = null;

function initWebSocket() {
    const wsEndpoint = localStorage.getItem('wsEndpoint') || 'ws://localhost:8080/ws';
    wsManager = new WebSocketManager(wsEndpoint);
    wsManager.connect();
    
    // Ping every 30 seconds to keep connection alive
    setInterval(() => {
        if (wsManager && wsManager.isConnected) {
            wsManager.ping();
        }
    }, 30000);
}