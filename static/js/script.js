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
            console.log('Scan results received:', scanResults);
            completeProgress();
            showResults();
            showToast('Scan completed successfully', 'success');
        } else {
            showError(data.error || 'Scan failed');
        }
    } catch (error) {
        console.error('Scan error:', error);
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
    
    console.log(`Displaying tab: ${tab}, scanResults:`, scanResults);
    
    if (tab === 'summary') {
        displaySummary(content);
    } else if (tab === 'headers') {
        if (scanResults && scanResults.headers) {
            displayHeaders(content, scanResults.headers);
        } else {
            content.innerHTML = '<div class="result-card"><p>No headers data available</p></div>';
        }
    } else if (tab === 'ssl') {
        if (scanResults && scanResults.ssl) {
            displaySSL(content, scanResults.ssl);
        } else {
            content.innerHTML = '<div class="result-card"><p>No SSL data available</p></div>';
        }
    } else if (tab === 'dns') {
        if (scanResults && scanResults.dns) {
            displayDNS(content, scanResults.dns);
        } else {
            content.innerHTML = '<div class="result-card"><p>No DNS data available</p></div>';
        }
    } else if (tab === 'cors') {
        if (scanResults && scanResults.cors) {
            displayCORS(content, scanResults.cors);
        } else {
            content.innerHTML = '<div class="result-card"><p>No CORS data available</p></div>';
        }
    } else if (tab === 'ports') {
        if (scanResults && scanResults.ports) {
            displayPorts(content, scanResults.ports);
        } else {
            content.innerHTML = '<div class="result-card"><p>No ports data available</p></div>';
        }
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
    
    // Handle error case
    if (headers.error) {
        html += `<div class="result-card danger"><h4>⚠️ Error</h4><p>${headers.error}</p></div>`;
        content.innerHTML = html + '</div>';
        return;
    }
    
    if (headers.missing && Array.isArray(headers.missing) && headers.missing.length > 0) {
        html += '<div class="result-card warning"><h4><i class="fas fa-exclamation-circle"></i> Missing Headers</h4>';
        headers.missing.forEach(header => {
            html += `<p>• ${header}</p>`;
        });
        html += '</div>';
    }

    if (headers.present && typeof headers.present === 'object' && Object.keys(headers.present).length > 0) {
        html += '<div class="result-card success"><h4><i class="fas fa-check-circle"></i> Present Headers</h4>';
        Object.entries(headers.present).forEach(([header, value]) => {
            const displayValue = formatValue(value).substring(0, 100);
            html += `<p><strong>${header}:</strong> <span style="color: var(--secondary);">${displayValue}</span></p>`;
        });
        html += '</div>';
    }

    if (!headers.missing && !headers.present) {
        html += '<div class="result-card"><p>No header information available</p></div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displaySSL(content, ssl) {
    let html = '<div class="result-content">';
    
    // Handle error case
    if (ssl.error) {
        html += `<div class="result-card danger"><h4><i class="fas fa-exclamation-circle"></i> Error</h4><p>${ssl.error}</p></div>`;
        content.innerHTML = html + '</div>';
        return;
    }
    
    if (ssl.certificate && typeof ssl.certificate === 'object') {
        const cert = ssl.certificate;
        html += '<div class="result-card success"><h4><i class="fas fa-lock"></i> Certificate Info</h4>';
        
        if (cert.issuer) html += `<p><strong>Issuer:</strong> ${cert.issuer}</p>`;
        if (cert.subject) html += `<p><strong>Subject:</strong> ${cert.subject}</p>`;
        if (cert.version) html += `<p><strong>Version:</strong> ${cert.version}</p>`;
        if (cert.serial) html += `<p><strong>Serial:</strong> ${cert.serial}</p>`;
        if (cert.not_before) html += `<p><strong>Valid From:</strong> ${cert.not_before}</p>`;
        if (cert.not_after) html += `<p><strong>Valid Until:</strong> ${cert.not_after}</p>`;
        
        html += '</div>';
    }

    if (ssl.protocols && typeof ssl.protocols === 'object') {
        html += '<div class="result-card"><h4><i class="fas fa-layer-group"></i> SSL/TLS Protocols</h4>';
        const protocols = Object.entries(ssl.protocols);
        if (protocols.length > 0) {
            protocols.forEach(([proto, supported]) => {
                const status = supported ? '✓ Enabled' : '✗ Disabled';
                const color = supported ? 'var(--primary)' : 'var(--text-dim)';
                html += `<p><span style="color: ${color}; font-weight: bold;">${status}:</span> ${proto}</p>`;
            });
        } else {
            html += '<p>No protocol information available</p>';
        }
        html += '</div>';
    }

    if (ssl.cipher_suites && typeof ssl.cipher_suites === 'object' && Object.keys(ssl.cipher_suites).length > 0) {
        html += '<div class="result-card"><h4><i class="fas fa-key"></i> Cipher Suites</h4>';
        Object.entries(ssl.cipher_suites).forEach(([type, ciphers]) => {
            if (Array.isArray(ciphers) && ciphers.length > 0) {
                html += `<p><strong>${type}:</strong> ${ciphers.join(', ').substring(0, 100)}...</p>`;
            }
        });
        html += '</div>';
    }

    if (!ssl.certificate && !ssl.protocols) {
        html += '<div class="result-card"><p>No SSL information available</p></div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displayDNS(content, dns) {
    let html = '<div class="result-content">';
    
    // Handle error case
    if (dns.error) {
        html += `<div class="result-card danger"><h4><i class="fas fa-exclamation-circle"></i> Error</h4><p>${dns.error}</p></div>`;
        content.innerHTML = html + '</div>';
        return;
    }
    
    if (dns.resolved) {
        html += '<div class="result-card success"><h4><i class="fas fa-check-circle"></i> DNS Resolution</h4>';
        html += `<p><strong>IP Address:</strong> <span style="color: var(--secondary);">${dns.resolved}</span></p>`;
        html += '</div>';
    }

    if (dns.public !== undefined) {
        const isPublic = dns.public;
        const statusClass = isPublic ? 'warning' : 'success';
        const statusIcon = isPublic ? '<i class="fas fa-globe"></i>' : '<i class="fas fa-lock"></i>';
        const statusText = isPublic ? '⚠️ Public IP Address' : '✓ Private/Internal IP';
        
        html += `<div class="result-card ${statusClass}"><h4>${statusIcon} ${statusText}</h4>`;
        html += `<p><strong>Public IP:</strong> ${isPublic ? 'Yes - Exposed' : 'No - Protected'}</p>`;
        html += '</div>';
    }

    if (dns.records && typeof dns.records === 'object' && Object.keys(dns.records).length > 0) {
        html += '<div class="result-card"><h4><i class="fas fa-list"></i> DNS Records</h4>';
        Object.entries(dns.records).forEach(([type, records]) => {
            if (Array.isArray(records) && records.length > 0) {
                html += `<p><strong>${type}:</strong></p><ul style="margin: 5px 0 10px 20px;">`;
                records.forEach(record => {
                    html += `<li>${record}</li>`;
                });
                html += '</ul>';
            }
        });
        html += '</div>';
    }

    if (!dns.resolved && !dns.public && !dns.records) {
        html += '<div class="result-card"><p>No DNS information available</p></div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displayCORS(content, cors) {
    let html = '<div class="result-content">';
    
    // Handle error case
    if (cors.error) {
        html += `<div class="result-card danger"><h4><i class="fas fa-exclamation-circle"></i> Error</h4><p>${cors.error}</p></div>`;
        content.innerHTML = html + '</div>';
        return;
    }
    
    if (cors.status) {
        html += '<div class="result-card"><h4><i class="fas fa-info-circle"></i> HTTP Status</h4>';
        html += `<p><strong>Status Code:</strong> <span style="color: var(--secondary);">${cors.status}</span></p>`;
        html += '</div>';
    }

    if (cors.headers && typeof cors.headers === 'object' && Object.keys(cors.headers).length > 0) {
        html += '<div class="result-card"><h4><i class="fas fa-heading"></i> CORS Headers</h4>';
        Object.entries(cors.headers).forEach(([header, value]) => {
            const displayValue = String(value).substring(0, 80);
            html += `<p><strong>${header}:</strong><br/><span style="color: var(--text-dim);">${displayValue}</span></p>`;
        });
        html += '</div>';
    }

    if (cors.vulnerable) {
        html += '<div class="result-card danger"><h4><i class="fas fa-exclamation-triangle"></i> ⚠️ CORS Vulnerability</h4>';
        html += `<p>${cors.vulnerable}</p>`;
        html += '</div>';
    } else if (cors.status) {
        html += '<div class="result-card success"><h4><i class="fas fa-check-circle"></i> ✓ No Vulnerabilities</h4>';
        html += '<p>CORS is properly configured</p>';
        html += '</div>';
    }

    if (!cors.status && !cors.headers && !cors.vulnerable) {
        html += '<div class="result-card"><p>No CORS information available</p></div>';
    }

    html += '</div>';
    content.innerHTML = html;
}

function displayPorts(content, ports) {
    let html = '<div class="result-content">';
    
    // Handle error case
    if (ports.error) {
        html += `<div class="result-card danger"><h4><i class="fas fa-exclamation-circle"></i> Error</h4><p>${ports.error}</p></div>`;
        content.innerHTML = html + '</div>';
        return;
    }
    
    if (ports.open && Array.isArray(ports.open) && ports.open.length > 0) {
        html += '<div class="result-card warning"><h4><i class="fas fa-door-open"></i> Open Ports Found</h4>';
        html += '<table style="width: 100%; font-size: 12px; border-collapse: collapse; margin: 10px 0;">';
        html += '<tr style="border-bottom: 2px solid var(--primary); padding: 8px 0;"><th style="text-align: left; padding: 8px; color: var(--primary);">PORT</th><th style="text-align: left; padding: 8px; color: var(--primary);">SERVICE</th><th style="text-align: left; padding: 8px; color: var(--primary);">STATE</th></tr>';
        
        ports.open.forEach(port => {
            const portNum = typeof port === 'object' ? port.port : port;
            const service = (typeof port === 'object' ? port.service : 'Unknown') || 'Unknown';
            const state = (typeof port === 'object' ? port.state : 'open') || 'open';
            html += `<tr style="border-bottom: 1px solid var(--border); padding: 8px 0;"><td style="padding: 8px; color: var(--secondary);">${portNum}</td><td style="padding: 8px;">${service}</td><td style="padding: 8px; color: var(--warning);">▲ ${state}</td></tr>`;
        });
        html += '</table>';
        html += `<p style="color: var(--warning); margin-top: 10px;"><i class="fas fa-exclamation-triangle"></i> Found <strong>${ports.open.length}</strong> open port(s)</p>`;
        html += '</div>';
    }

    if (ports.filtered && Array.isArray(ports.filtered) && ports.filtered.length > 0) {
        html += '<div class="result-card"><h4><i class="fas fa-filter"></i> Filtered Ports</h4>';
        html += `<p><strong>${ports.filtered.length} port(s)</strong> are filtered (blocked by firewall)</p>`;
        html += '</div>';
    }

    if (ports.closed && Array.isArray(ports.closed) && ports.closed.length > 0) {
        html += '<div class="result-card success"><h4><i class="fas fa-check-circle"></i> Closed Ports</h4>';
        html += `<p><strong>${ports.closed.length} port(s)</strong> are closed</p>`;
        html += '</div>';
    }

    if (!ports.open || ports.open.length === 0) {
        if (!ports.filtered && !ports.closed) {
            html += '<div class="result-card"><p>No port scan information available</p></div>';
        } else {
            html += '<div class="result-card success"><h4><i class="fas fa-check-circle"></i> ✓ No Open Ports</h4>';
            html += '<p>Scan completed - no critical ports exposed</p></div>';
        }
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
