// Response functionality
let responseHistory = [];

function executePlaybook(playbookName) {
    const context = {};
    
    if (playbookName === 'block_ip') {
        const ip = prompt('Enter IP address to block:');
        if (!ip) return;
        context.ip = ip;
        context.reason = prompt('Reason for blocking:', 'malicious activity');
    } else if (playbookName === 'brute_force_response') {
        context.src_ip = prompt('Enter source IP address:');
        context.username = prompt('Enter username (optional):');
    } else if (playbookName === 'malware_containment') {
        context.hostname = prompt('Enter hostname to isolate:');
    }
    
    const requireApproval = confirm('Require approval before execution?');
    
    addToResponseLog('info', `Executing playbook: ${playbookName}...`);
    
    fetch(`/api/v1/playbooks/${playbookName}/execute?require_approval=${requireApproval}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(context)
    })
        .then(res => res.json())
        .then(result => {
            if (result.success) {
                addToResponseLog('success', `✅ Playbook ${playbookName} executed successfully`);
            } else {
                addToResponseLog('error', `❌ Playbook execution failed: ${result.error || 'Unknown error'}`);
            }
        })
        .catch(err => {
            addToResponseLog('error', `❌ Error: ${err.message}`);
        });
}

function addToResponseLog(type, message) {
    const logContainer = document.getElementById('responseLog');
    if (!logContainer) return;
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerHTML = `[${new Date().toLocaleTimeString()}] ${message}`;
    
    logContainer.insertBefore(entry, logContainer.firstChild);
    
    // Keep only last 100 entries
    while (logContainer.children.length > 100) {
        logContainer.removeChild(logContainer.lastChild);
    }
}

// WebSocket handler for response events
function setupResponseWebSocketHandlers() {
    if (!wsManager) return;
    
    wsManager.subscribe('playbook_execution', (data) => {
        if (data.success) {
            addToResponseLog('success', `Playbook ${data.playbook} completed`);
        } else {
            addToResponseLog('error', `Playbook ${data.playbook} failed`);
        }
    });
}