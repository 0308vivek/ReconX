document.addEventListener('DOMContentLoaded', () => {
    
    // --- HOME PAGE LOGIC ---
    const scanForm = document.getElementById('scanForm');
    
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const domainInput = document.getElementById('domainInput').value.trim();
            const scanBtn = document.getElementById('scanBtn');
            const loader = document.getElementById('loader');
            const errorBox = document.getElementById('errorBox');
            const loadingText = document.getElementById('loadingText');
            
            if (!domainInput) return;
            
            // UI State change to loading
            scanForm.querySelector('.input-group').style.display = 'none';
            scanBtn.style.display = 'none';
            loader.classList.remove('hidden');
            errorBox.classList.add('hidden');
            
            // Updating text simulation
            const messages = [
                'Resolving IP address and DNS...',
                'Hunting for subdomains...',
                'Executing port scan...',
                'Analyzing SSL certificates...',
                'Inspecting security headers...',
                'Discovering hidden paths...',
                'Generating final risk report...'
            ];
            
            let msgIndex = 0;
            const msgInterval = setInterval(() => {
                msgIndex = (msgIndex + 1) % messages.length;
                loadingText.innerText = messages[msgIndex];
            }, 3000);
            
            try {
                // Execute API Call
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ domain: domainInput })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.error || 'Server error occurred during scan.');
                }
                
                // Store in local storage and redirect to dashboard
                localStorage.setItem('reconReport', JSON.stringify(data));
                window.location.href = '/dashboard';
                
            } catch (err) {
                // Handle Error state
                clearInterval(msgInterval);
                loader.classList.add('hidden');
                scanForm.querySelector('.input-group').style.display = 'flex';
                scanBtn.style.display = 'block';
                
                errorBox.innerText = `[Scan Failed]: ${err.message}`;
                errorBox.classList.remove('hidden');
            }
        });
    }
});

// --- DASHBOARD RENDERING LOGIC ---
// Called from dashboard.ejs inline script
window.renderDashboard = function(report) {
    
    // Header Data
    document.getElementById('targetDomain').innerText = report.domain;
    document.getElementById('targetIp').innerText = report.target_ip || 'Unknown';
    
    // Risk Score
    const riskBadge = document.getElementById('riskBadge');
    document.getElementById('riskScore').innerText = report.risk.score;
    document.getElementById('riskLevel').innerText = `(${report.risk.level})`;
    
    if (report.risk.level === 'Low') riskBadge.classList.add('risk-low');
    else if (report.risk.level === 'Medium') riskBadge.classList.add('risk-medium');
    else riskBadge.classList.add('risk-high');

    // Ports
    const portsList = document.getElementById('portsList');
    if (report.open_ports && report.open_ports.length > 0) {
        const riskyPorts = [21, 22, 3306];
        report.open_ports.forEach(port => {
            const li = document.createElement('li');
            li.innerHTML = `Port ${port}`;
            if (riskyPorts.includes(port)) {
                li.classList.add('port-risky');
                li.innerHTML += ' ⚠';
            }
            portsList.appendChild(li);
        });
    } else {
        portsList.innerHTML = '<li>No open ports detected</li>';
    }

    // Directories
    const dirsList = document.getElementById('dirsList');
    if (report.discovered_directories && report.discovered_directories.length > 0) {
        report.discovered_directories.forEach(dir => {
            const li = document.createElement('li');
            li.innerText = dir;
            dirsList.appendChild(li);
        });
    } else {
        dirsList.innerHTML = '<li style="color:#aaa; border-bottom:none">&lt;No sensitive directories found&gt;</li>';
    }

    // Headers
    const presentHeadersObj = report.security_headers || {};
    const presentHeadersStr = Object.entries(presentHeadersObj)
        .filter(([_, value]) => value !== null)
        .map(([key, value]) => `${key}: ${value}`)
        .join('\n');
    document.getElementById('presentHeaders').innerText = presentHeadersStr || 'None implemented';

    const missingList = document.getElementById('missingHeaders');
    if (report.missing_headers && report.missing_headers.length > 0) {
        report.missing_headers.forEach(header => {
            const li = document.createElement('li');
            li.innerText = header;
            missingList.appendChild(li);
        });
    } else {
        missingList.innerHTML = '<li style="color:#00ffaa; border:none">None! Excellent.</li>';
    }

    // Technologies
    const techList = document.getElementById('techList');
    if (report.technologies) {
        Object.entries(report.technologies).forEach(([key, value]) => {
            if (value && value !== 'Unknown') {
                const li = document.createElement('li');
                li.innerText = `${key}: ${value}`;
                techList.appendChild(li);
            }
        });
    }
    if (techList.children.length === 0) {
        techList.innerHTML = '<li>No clear tech signatures</li>';
    }

    // SSL Info
    const sslGrid = document.getElementById('sslInfo');
    const ssl = report.ssl_info || {};
    
    if (ssl.error) {
        sslGrid.innerHTML = `<div class="info-label">Status</div><div class="info-value value-bad">Error: ${ssl.error}</div>`;
    } else if (!ssl.issuer) {
        sslGrid.innerHTML = `<div class="info-label">Status</div><div class="info-value">No certificate / Port 443 closed</div>`;
    } else {
        const isExp = ssl.expired ? 'value-bad' : 'value-good';
        const expStatus = ssl.expired ? 'EXPIRED' : 'Valid';
        
        sslGrid.innerHTML = `
            <div class="info-label">Issuer</div>
            <div class="info-value">${ssl.issuer}</div>
            
            <div class="info-label">Valid From</div>
            <div class="info-value">${ssl.valid_from}</div>
            
            <div class="info-label">Valid To</div>
            <div class="info-value ${isExp}">${ssl.valid_to} (${expStatus})</div>
            
            <div class="info-label">TLS Version</div>
            <div class="info-value">${ssl.tls_version || 'Unknown'}</div>
        `;
    }

    // Subdomains
    const subList = document.getElementById('subdomainsList');
    const subCount = report.subdomains ? report.subdomains.length : 0;
    document.getElementById('subCount').innerText = subCount;
    
    if (subCount > 0) {
        report.subdomains.forEach(sub => {
            const li = document.createElement('li');
            li.innerText = sub;
            subList.appendChild(li);
        });
    } else {
        subList.innerHTML = '<li>No subdomains found in crt.sh</li>';
    }
};
