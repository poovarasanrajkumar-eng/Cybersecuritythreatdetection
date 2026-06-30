// ===== DASHBOARD MODULE =====

class Dashboard {
    constructor() {
        this.scanningActive = false;
        this.scanInterval = null;
        this.updateStatsInterval = null;
    }

    // Utility function to show messages
    showMessage(text, type = 'info', duration = 5000) {
        const messageContainer = document.getElementById('message-container');
        if (!messageContainer) {
            console.error('Message container not found');
            return;
        }

        // Remove existing messages
        const existingMessage = messageContainer.querySelector('.alert');
        if (existingMessage) {
            existingMessage.remove();
        }

        // Create new message
        const messageDiv = document.createElement('div');
        messageDiv.className = `alert alert-${type}`;
        messageDiv.innerHTML = `
            <span class="alert-icon">${this.getAlertIcon(type)}</span>
            <div class="alert-content">
                <div class="alert-description">${text}</div>
            </div>
        `;

        messageContainer.appendChild(messageDiv);

        // Auto-hide success messages
        if (type === 'success' && duration > 0) {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.remove();
                }
            }, duration);
        }

        // Scroll message into view
        messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    getAlertIcon(type) {
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        return icons[type] || 'ℹ️';
    }

    // Format threat result for display
    formatThreatResult(data) {
        const levelClass = data.threat_level ? data.threat_level.toLowerCase() : 'safe';
        const riskScore = data.risk_score || 0;
        const confidence = data.confidence || 0;

        return `
            <article class="threat-result ${levelClass}" role="article">
                <header class="threat-header">
                    <div class="threat-title">
                        <span class="threat-icon" aria-hidden="true">${data.icon || '🔍'}</span>
                        <span>${data.threat_type || 'Analysis Result'}</span>
                    </div>
                    <div class="badge badge-${levelClass}">
                        ${data.threat_level || 'Unknown'}
                    </div>
                </header>
                <div class="threat-details">
                    <div class="threat-metrics">
                        <span><strong>Risk Score:</strong> ${riskScore}/100</span>
                        <span><strong>Confidence:</strong> ${(confidence * 100).toFixed(1)}%</span>
                    </div>
                    <p><strong>Description:</strong> ${data.threat_description || 'No description available'}</p>
                    ${data.ip_address ? `<p><strong>IP Address:</strong> <code>${data.ip_address}</code></p>` : ''}
                    ${data.source_ip ? `<p><strong>Source:</strong> <code>${data.source_ip}</code> | <strong>Destination:</strong> <code>${data.destination_ip}</code></p>` : ''}
                    ${data.protocol ? `<p><strong>Protocol:</strong> ${data.protocol.toUpperCase()} | <strong>Port:</strong> ${data.dest_port}</p>` : ''}
                    ${data.recommendations && data.recommendations.length > 0 ? 
                        `<div class="recommendations">
                            <strong>Recommendations:</strong>
                            <ul>${data.recommendations.map(rec => `<li>${rec}</li>`).join('')}</ul>
                        </div>` : ''}
                    <p class="timestamp"><strong>Timestamp:</strong> ${data.timestamp ? new Date(data.timestamp).toLocaleString() : 'N/A'}</p>
                </div>
            </article>
        `;
    }

    // Set button loading state
    setButtonLoading(button, isLoading, originalText) {
        if (isLoading) {
            button.disabled = true;
            button.innerHTML = `<span class="loading-spinner"></span>${originalText.includes('Analyze') ? 'Analyzing...' : 'Processing...'}`;
        } else {
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }

    // URL Analysis
    async analyzeUrl() {
        const urlInput = document.getElementById('url-input');
        const analyzeButton = document.getElementById('analyze-url-btn');
        const resultsContainer = document.getElementById('url-results');

        const url = urlInput.value.trim();

        if (!url) {
            this.showMessage('⚠️ Please enter a URL to analyze', 'error');
            urlInput.focus();
            return;
        }

        // Basic URL validation
        try {
            new URL(url);
        } catch {
            this.showMessage('⚠️ Please enter a valid URL (include http:// or https://)', 'error');
            urlInput.focus();
            return;
        }

        this.setButtonLoading(analyzeButton, true, '🔍 Analyze URL');

        try {
            const response = await fetch('/analyze_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (data.error) {
                this.showMessage(`❌ ${data.error}`, 'error');
            } else {
                resultsContainer.innerHTML = this.formatThreatResult(data);
                resultsContainer.classList.remove('hidden');

                const threatLevel = data.threat_level || 'Safe';
                this.showMessage(`✅ URL analysis complete. Threat Level: ${threatLevel}`, 
                          data.threat_detected ? 'warning' : 'success');
            }
        } catch (error) {
            this.showMessage('❌ Network error during analysis', 'error');
            console.error('URL Analysis Error:', error);
        } finally {
            this.setButtonLoading(analyzeButton, false, '🔍 Analyze URL');
        }
    }

    // Manual Network Analysis
    async analyzeManual() {
        const sourceIpInput = document.getElementById('source-ip');
        const destIpInput = document.getElementById('dest-ip');
        const protocolSelect = document.getElementById('protocol');
        const portInput = document.getElementById('port');
        const analyzeButton = document.getElementById('analyze-manual-btn');
        const resultsContainer = document.getElementById('manual-results');

        const sourceIp = sourceIpInput.value.trim();
        const destIp = destIpInput.value.trim();
        const protocol = protocolSelect.value;
        const port = portInput.value.trim();

        // Validation
        if (!sourceIp || !destIp) {
            this.showMessage('⚠️ Please enter both source and destination IP addresses', 'error');
            if (!sourceIp) sourceIpInput.focus();
            else destIpInput.focus();
            return;
        }

        // Basic IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(sourceIp)) {
            this.showMessage('⚠️ Invalid source IP address format', 'error');
            sourceIpInput.focus();
            return;
        }
        if (!ipRegex.test(destIp)) {
            this.showMessage('⚠️ Invalid destination IP address format', 'error');
            destIpInput.focus();
            return;
        }

        this.setButtonLoading(analyzeButton, true, '🔍 Analyze Network');

        try {
            const response = await fetch('/manual_analysis', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    source_ip: sourceIp,
                    destination_ip: destIp,
                    protocol: protocol,
                    dest_port: parseInt(port) || 80,
                    duration: 1.0,
                    source_bytes: 1024,
                    dest_bytes: 512
                })
            });

            const data = await response.json();

            if (data.error) {
                this.showMessage(`❌ ${data.error}`, 'error');
            } else {
                resultsContainer.innerHTML = this.formatThreatResult(data);
                resultsContainer.classList.remove('hidden');

                const threatLevel = data.threat_level || 'Safe';
                this.showMessage(`✅ Network analysis complete. Threat Level: ${threatLevel}`, 
                          data.threat_detected ? 'warning' : 'success');
            }
        } catch (error) {
            this.showMessage('❌ Network error during analysis', 'error');
            console.error('Manual Analysis Error:', error);
        } finally {
            this.setButtonLoading(analyzeButton, false, '🔍 Analyze Network');
        }
    }

    // Start Live Scan
    async startLiveScan() {
        const startButton = document.getElementById('start-scan-btn');
        const stopButton = document.getElementById('stop-scan-btn');
        const scanningIndicator = document.getElementById('scanning-indicator');
        const resultsContainer = document.getElementById('live-results');

        try {
            const response = await fetch('/start_live_scan', {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                this.scanningActive = true;
                startButton.disabled = true;
                stopButton.disabled = false;
                scanningIndicator.classList.add('active');
                resultsContainer.classList.remove('hidden');

                this.showMessage('✅ Live scanning started successfully', 'success');

                // Start polling for results
                this.scanInterval = setInterval(() => this.updateScanResults(), 2000);
            }
        } catch (error) {
            this.showMessage('❌ Failed to start live scanning', 'error');
            console.error('Start Scan Error:', error);
        }
    }

    // Stop Live Scan
    async stopLiveScan() {
        const startButton = document.getElementById('start-scan-btn');
        const stopButton = document.getElementById('stop-scan-btn');
        const scanningIndicator = document.getElementById('scanning-indicator');

        try {
            const response = await fetch('/stop_live_scan', {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                this.scanningActive = false;
                startButton.disabled = false;
                stopButton.disabled = true;
                scanningIndicator.classList.remove('active');

                if (this.scanInterval) {
                    clearInterval(this.scanInterval);
                }

                this.showMessage('✅ Live scanning stopped', 'info');
            }
        } catch (error) {
            this.showMessage('❌ Failed to stop live scanning', 'error');
            console.error('Stop Scan Error:', error);
        }
    }

    // Update scan results
    async updateScanResults() {
        try {
            const response = await fetch('/get_scan_results');
            const data = await response.json();

            if (data.results && data.results.length > 0) {
                const resultsContainer = document.getElementById('live-results');
                const latestResults = data.results.slice(-5); // Show last 5 results

                resultsContainer.innerHTML = latestResults.map(result => this.formatThreatResult(result)).join('');
            }

            // Update scanning status in stats
            const scanningStatusElement = document.getElementById('scanning-status');
            if (scanningStatusElement) {
                scanningStatusElement.textContent = data.scanning_active ? 'Active' : 'Stopped';
                scanningStatusElement.className = data.scanning_active ? 'stat-number threat-safe' : 'stat-number threat-info';
            }

        } catch (error) {
            console.error('Error updating scan results:', error);
        }
    }

    // Download report
    async downloadReport() {
        const downloadButton = document.getElementById('download-btn');

        this.setButtonLoading(downloadButton, true, '📄 Download Report');

        try {
            const response = await fetch('/download_report');
            const data = await response.json();

            if (data.content) {
                const blob = new Blob([data.content], { type: 'text/csv' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = data.filename || 'threat_report.csv';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                this.showMessage('📄 Report downloaded successfully', 'success');
            } else {
                this.showMessage('⚠️ No data available for report', 'info');
            }
        } catch (error) {
            this.showMessage('❌ Failed to download report', 'error');
            console.error('Download Error:', error);
        } finally {
            this.setButtonLoading(downloadButton, false, '📄 Download Report');
        }
    }

    // Update dashboard stats
    async updateDashboardStats() {
        try {
            const response = await fetch('/get_dashboard_stats');
            const data = await response.json();

            // Update stat numbers
            const totalScansElement = document.getElementById('total-scans');
            const totalThreatsElement = document.getElementById('total-threats');
            const highRiskThreatsElement = document.getElementById('high-risk-threats');

            if (totalScansElement) totalScansElement.textContent = data.total_scans || 0;
            if (totalThreatsElement) totalThreatsElement.textContent = data.total_threats || 0;
            if (highRiskThreatsElement) highRiskThreatsElement.textContent = data.high_risk_threats || 0;

            // Update model status
            const modelIndicator = document.getElementById('model-indicator');
            if (modelIndicator) {
                if (data.model_loaded) {
                    modelIndicator.innerHTML = '✅ <span class="model-loaded">XGBoost Model Active</span>';
                } else {
                    modelIndicator.innerHTML = '⚠️ <span class="model-simulation">Simulation Mode</span>';
                }
            }

        } catch (error) {
            console.error('Error updating dashboard stats:', error);
        }
    }

    // Initialize dashboard
    init() {
        // URL Analysis
        const analyzeUrlButton = document.getElementById('analyze-url-btn');
        if (analyzeUrlButton) {
            analyzeUrlButton.addEventListener('click', () => this.analyzeUrl());
        }

        const urlInput = document.getElementById('url-input');
        if (urlInput) {
            urlInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.analyzeUrl();
                }
            });
        }

        // Manual Analysis
        const analyzeManualButton = document.getElementById('analyze-manual-btn');
        if (analyzeManualButton) {
            analyzeManualButton.addEventListener('click', () => this.analyzeManual());
        }

        const portInput = document.getElementById('port');
        if (portInput) {
            portInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.analyzeManual();
                }
            });
        }

        // Live Scanning
        const startScanButton = document.getElementById('start-scan-btn');
        if (startScanButton) {
            startScanButton.addEventListener('click', () => this.startLiveScan());
        }

        const stopScanButton = document.getElementById('stop-scan-btn');
        if (stopScanButton) {
            stopScanButton.addEventListener('click', () => this.stopLiveScan());
        }

        // Download Report
        const downloadButton = document.getElementById('download-btn');
        if (downloadButton) {
            downloadButton.addEventListener('click', () => this.downloadReport());
        }

        // Update stats immediately and then every 10 seconds
        this.updateDashboardStats();
        this.updateStatsInterval = setInterval(() => this.updateDashboardStats(), 10000);

        // Show welcome message
        setTimeout(() => {
            this.showMessage('🛡️ Welcome to NP² Cybersecurity Dashboard! Start by analyzing a URL or network connection.', 'info');
        }, 1000);
    }

    // Cleanup when page unloads
    destroy() {
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
        }
        if (this.updateStatsInterval) {
            clearInterval(this.updateStatsInterval);
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const dashboard = new Dashboard();
    dashboard.init();

    // Cleanup on page unload
    window.addEventListener('beforeunload', function() {
        dashboard.destroy();
    });

    // Make dashboard globally available
    window.dashboard = dashboard;
});
