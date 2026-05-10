/* ========================================
   NIKHIL AI - Frontend Script
   ======================================== */

let currentModule = 'all';
let scanResults = null;
let scanInProgress = false;
let scanStartTime = null;
let loadingInterval = null;

// ========================================
// LOADING SCREEN MANAGEMENT
// ========================================

function initializeLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    const timerText = document.getElementById('timer-text');
    const progressBar = document.getElementById('loading-progress');
    let remainingTime = 10;
    
    // Update timer every second
    loadingInterval = setInterval(() => {
        remainingTime--;
        timerText.textContent = remainingTime;
        
        if (remainingTime <= 0) {
            clearInterval(loadingInterval);
            hideLoadingScreen();
        }
    }, 1000);
}

function hideLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    loadingScreen.classList.add('hidden');
    setTimeout(() => {
        loadingScreen.style.display = 'none';
    }, 500);
}

// ========================================
// UTILITY FUNCTIONS
// ========================================

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function showError(message) {
    const errorSection = document.getElementById('error-section');
    const errorMessage = document.getElementById('error-message');
    errorMessage.textContent = message;
    errorSection.style.display = 'block';
    document.getElementById('results-section').style.display = 'none';
}

function hideError() {
    document.getElementById('error-section').style.display = 'none';
}

// ========================================
// MODULE SELECTION
// ========================================

function selectModule(module) {
    currentModule = module;
    document.querySelectorAll('.module-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-module="${module}"]`).classList.add('active');
    
    // Update info panel
    const infoText = {
        all: 'Run comprehensive security assessment on the target.',
        headers: 'Analyze HTTP security headers configuration.',
        ssl: 'Audit SSL/TLS certificate and protocol configuration.',
        dns: 'Check for DNS misconfiguration and origin exposure.',
        cors: 'Validate CORS policy implementation.',
        ports: 'Scan common ports and enumerate services.'
    };
    
    document.getElementById('info-text').textContent = infoText[module] || '';
}

// ========================================
// INPUT VALIDATION
// ========================================

async function validateTarget() {
    const urlInput = document.getElementById('target-url');
    const feedback = document.getElementById('input-feedback');
    const url = urlInput.value.trim();

    if (!url) {
        feedback.textContent = 'Please enter a URL';
        feedback.className = 'error';
        return false;
    }

    try {
        const response = await fetch('/api/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (response.ok) {
            feedback.textContent = '✓ Target validated successfully';
            feedback.className = 'success';
            urlInput.value = data.url;
            return true;
        } else {
            feedback.textContent = '✗ ' + data.error;
            feedback.className = 'error';
            return false;
        }
    } catch (error) {
        feedback.textContent = '✗ Validation error: ' + error.message;
        feedback.className = 'error';
        return false;
    }
}

// ========================================
// SCANNING
// ========================================

async function startScan() {
    const url = document.getElementById('target-url').value.trim();
    
    if (!url) {
        showError('Please enter a target URL');
        return;
    }

    if (scanInProgress) {
        showToast('Scan already in progress', 'warning');
        return;
    }

    // Validate first
    const isValid = await validateTarget();
    if (!isValid) return;

    scanInProgress = true;
    scanStartTime = Date.now();
    
    document.getElementById('scan-button').disabled = true;
    document.getElementById('progress-section').style.display = 'block';
    document.getElementById('results-section').style.display = 'none';
    hideError();

    // Start timer
    const timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        document.getElementById('scan-timer').textContent = elapsed + 's';
    }, 100);

    try {
        // Simulate progress
        simulateProgress();

        // Call API
        const response = await fetch(`/api/scan/${currentModule}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (response.ok) {
            scanResults = data.data;
            completeProgress();
            showResults();
            showToast('Scan completed successfully', 'success');
        } else {
            showError(data.error || 'Scan failed');
        }
    } catch (error) {
        showError('Error: ' + error.message);
    } finally {
        clearInterval(timerInterval);
        scanInProgress = false;
        document.getElementById('scan-button').disabled = false;
    }
}

function simulateProgress() {
    const fills = ['headers', 'ssl', 'dns', 'cors', 'ports'];
    fills.forEach((fill, index) => {
        const element = document.getElementById(`progress-${fill}`);
        const increment = 100 / (fills.length + 1);
        let progress = 0;
        
        const interval = setInterval(() => {
            progress += Math.random() * 30;
            if (progress > 95) progress = 95;
            element.style.width = progress + '%';
            
            if (!scanInProgress) {
                clearInterval(interval);
            }
        }, 200 + index * 100);
    });
}

function completeProgress() {
    const fills = ['headers', 'ssl', 'dns', 'cors', 'ports'];
    fills.forEach(fill => {
        document.getElementById(`progress-${fill}`).style.width = '100%';
    });
}

// ========================================
// RESULTS DISPLAY
// ========================================

function showResults() {
    document.getElementById('progress-section').style.display = 'none';
    document.getElementById('results-section').style.display = 'block';
    switchTab('summary');
}

function switchTab(tab) {
    // Hide all panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected pane
    const pane = document.getElementById(`tab-${tab}`);
    if (pane) {
        pane.classList.add('active');
    }

    // Add active class to clicked button
    const activeBtn = document.querySelector(`[onclick="switchTab('${tab}')"]`);
    if (activeBtn) {
        activeBtn.classList.add('active');
    }

    // Display content
    displayTabContent(tab);
}

function displayTabContent(tab) {
    const content = document.getElementById(`${tab}-content`);
    
    if (!content) {
        console.error(`Content element not found for tab: ${tab}`);
        return;
    }
    
    if (tab === 'summary') {
        displaySummary(content);
    } else if (tab === 'headers' && scanResults && scanResults.headers) {
        displayHeaders(content, scanResults.headers);
    } else if (tab === 'ssl' && scanResults && scanResults.ssl) {
        displaySSL(content, scanResults.ssl);
    } else if (tab === 'dns' && scanResults && scanResults.dns) {
        displayDNS(content, scanResults.dns);
    } else if (tab === 'cors' && scanResults && scanResults.cors) {
        displayCORS(content, scanResults.cors);
    } else if (tab === 'ports' && scanResults && scanResults.ports) {
        displayPorts(content, scanResults.ports);
    } else if (scanResults) {
        // Fallback for missing tab data
        content.innerHTML = '<p>No data available for this tab</p>';
    }
}

function displaySummary(content) {
    if (!scanResults || typeof scanResults !== 'object') {
        content.innerHTML = '<div class="result-card"><p>No scan results available</p></div>';
        return;
    }

    content.innerHTML = `
        <div class="result-card success">
            <h4><i class="fas fa-check-circle"></i> Total Modules Scanned</h4>
            <p>${Object.keys(scanResults).length} modules analyzed</p>
        </div>
        <div class="result-card">
            <h4><i class="fas fa-shield-alt"></i> Security Headers</h4>
            <p>${scanResults.headers ? (scanResults.headers.error ? 'Error: ' + scanResults.headers.error : 'Analyzed') : 'Not scanned'}</p>
        </div>
        <div class="result-card">
            <h4><i class="fas fa-lock"></i> SSL/TLS Status</h4>
            <p>${scanResults.ssl ? (scanResults.ssl.error ? 'Error: ' + scanResults.ssl.error : 'Analyzed') : 'Not scanned'}</p>
        </div>
        <div class="result-card">
            <h4><i class="fas fa-network-wired"></i> DNS Check</h4>
            <p>${scanResults.dns ? (scanResults.dns.error ? 'Error: ' + scanResults.dns.error : 'Analyzed') : 'Not scanned'}</p>
        </div>
        <div class="result-card">
            <h4><i class="fas fa-share-alt"></i> CORS Policy</h4>
            <p>${scanResults.cors ? (scanResults.cors.error ? 'Error: ' + scanResults.cors.error : 'Analyzed') : 'Not scanned'}</p>
        </div>
        <div class="result-card">
            <h4><i class="fas fa-door-open"></i> Open Ports</h4>
            <p>${scanResults.ports ? (scanResults.ports.error ? 'Error: ' + scanResults.ports.error : 'Scanned') : 'Not scanned'}</p>
        </div>
    `;
}

function displayHeaders(content, headers) {
    const formatValue = (value) => {
        if (typeof value === 'object') {
            return JSON.stringify(value, null, 2);
        }
        return String(value);
    };

    let html = '<div class="result-content">';
    
    if (headers.missing && headers.missing.length > 0) {
        html += '<div class="result-card warning"><h4>⚠️ Missing Headers</h4>';
        headers.missing.forEach(header => {
            html += `<p>• ${header}</p>`;
        });
        html += '</div>';
    }

    if (headers.present && Object.keys(headers.present).length > 0) {
        html += '<div class="result-card success"><h4>✓ Present Headers</h4>';
        Object.entries(headers.present).forEach(([header, value]) => {
            html += `<p><strong>${header}:</strong> ${formatValue(value).substring(0, 50)}...</p>`;
        });
        html += '</div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displaySSL(content, ssl) {
    let html = '<div class="result-content">';
    
    if (ssl.certificate) {
        html += '<div class="result-card success"><h4>🔒 Certificate Info</h4>';
        Object.entries(ssl.certificate).forEach(([key, value]) => {
            if (value) {
                html += `<p><strong>${key}:</strong> ${String(value).substring(0, 50)}</p>`;
            }
        });
        html += '</div>';
    }

    if (ssl.protocols) {
        html += '<div class="result-card"><h4>📋 Protocols</h4>';
        Object.entries(ssl.protocols).forEach(([proto, supported]) => {
            const status = supported ? '✓' : '✗';
            const color = supported ? 'var(--primary)' : 'var(--text-dim)';
            html += `<p><span style="color: ${color}">${status}</span> ${proto}</p>`;
        });
        html += '</div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displayDNS(content, dns) {
    let html = '<div class="result-content">';
    
    if (dns.resolved) {
        html += '<div class="result-card success"><h4>✓ DNS Resolution</h4>';
        html += `<p><strong>IP Address:</strong> ${dns.resolved}</p>`;
        html += '</div>';
    }

    if (dns.public !== undefined) {
        const status = dns.public ? 'danger' : 'success';
        const statusText = dns.public ? '⚠️ Public IP' : '✓ Private/Internal';
        html += `<div class="result-card ${status}"><h4>${statusText}</h4>`;
        html += `<p>Public: ${dns.public ? 'Yes' : 'No'}</p>`;
        html += '</div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displayCORS(content, cors) {
    let html = '<div class="result-content">';
    
    if (cors.status) {
        html += '<div class="result-card"><h4>HTTP Status</h4>';
        html += `<p>${cors.status}</p>`;
        html += '</div>';
    }

    if (cors.headers && Object.keys(cors.headers).length > 0) {
        html += '<div class="result-card"><h4>CORS Headers</h4>';
        Object.entries(cors.headers).forEach(([header, value]) => {
            html += `<p><strong>${header}:</strong><br/>${String(value).substring(0, 100)}</p>`;
        });
        html += '</div>';
    }

    if (cors.vulnerable) {
        html += '<div class="result-card danger"><h4>⚠️ Vulnerability</h4>';
        html += `<p>${cors.vulnerable}</p>`;
        html += '</div>';
    } else {
        html += '<div class="result-card success"><h4>✓ No Vulnerabilities</h4>';
        html += '<p>CORS is properly configured</p>';
        html += '</div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displayPorts(content, ports) {
    let html = '<div class="result-content">';
    
    if (ports.open && ports.open.length > 0) {
        html += '<div class="result-card warning"><h4>📊 Open Ports</h4>';
        html += '<table style="width: 100%; font-size: 11px; border-collapse: collapse;">';
        html += '<tr style="border-bottom: 1px solid var(--primary);"><th style="text-align: left;">PORT</th><th style="text-align: left;">SERVICE</th></tr>';
        ports.open.forEach(port => {
            html += `<tr style="border-bottom: 1px solid var(--border);"><td>${port.port}</td><td>${port.service || 'Unknown'}</td></tr>`;
        });
        html += '</table>';
        html += '</div>';
    }

    if (ports.filtered && ports.filtered.length > 0) {
        html += '<div class="result-card"><h4>🔒 Filtered Ports</h4>';
        html += `<p>${ports.filtered.length} ports filtered</p>`;
        html += '</div>';
    }

    if (!ports.open || ports.open.length === 0) {
        html += '<div class="result-card success"><h4>✓ No Open Ports</h4>';
        html += '<p>Scan completed successfully</p>';
        html += '</div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

// ========================================
// EXPORT FUNCTIONALITY
// ========================================

function exportResults() {
    if (!scanResults) {
        showToast('No results to export', 'warning');
        return;
    }

    const jsonStr = JSON.stringify(scanResults, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(jsonStr);
    
    const exportLink = document.createElement('a');
    exportLink.setAttribute('href', dataUri);
    exportLink.setAttribute('download', `nikhil-scan-${Date.now()}.json`);
    document.body.appendChild(exportLink);
    exportLink.click();
    document.body.removeChild(exportLink);
    
    showToast('Results exported successfully', 'success');
}

// ========================================
// RESET FUNCTIONALITY
// ========================================

function resetScanner() {
    if (scanInProgress) {
        showToast('Cannot reset while scan is in progress', 'warning');
        return;
    }

    document.getElementById('target-url').value = '';
    document.getElementById('input-feedback').textContent = '';
    document.getElementById('progress-section').style.display = 'none';
    document.getElementById('results-section').style.display = 'none';
    hideError();
    scanResults = null;
    
    showToast('Scanner reset', 'success');
}

// ========================================
// KEYBOARD SHORTCUTS
// ========================================

document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to start scan
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        startScan();
    }
    
    // Escape to reset
    if (e.key === 'Escape') {
        resetScanner();
    }
});

// ========================================
// INITIALIZATION
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('NIKHIL AI Frontend Initialized');
    
    // Initialize loading screen with 10-second countdown
    initializeLoadingScreen();
    
    // Set default module
    selectModule('all');
    
    // Add keyboard hint
    showToast('Ctrl+Enter to scan, Esc to reset', 'info');
});
