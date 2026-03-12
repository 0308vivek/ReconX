const express = require('express');
const router = express.Router();
const axios = require('axios');
const { runPythonScript } = require('../services/pythonRunner');

/**
 * Helper to analyze security headers and technologies
 */
const analyzeHeaders = async (domain) => {
    try {
        const url = domain.startsWith('http') ? domain : `https://${domain}`;
        const response = await axios.get(url, { timeout: 10000 });
        const headers = response.headers;

        const securityHeaders = {
            'Content-Security-Policy': headers['content-security-policy'] || null,
            'X-Frame-Options': headers['x-frame-options'] || null,
            'Strict-Transport-Security': headers['strict-transport-security'] || null,
            'X-XSS-Protection': headers['x-xss-protection'] || null,
            'X-Content-Type-Options': headers['x-content-type-options'] || null
        };

        const missingHeaders = Object.keys(securityHeaders).filter(key => !securityHeaders[key]);

        const technologies = {
            'Server': headers['server'] || 'Unknown',
            'X-Powered-By': headers['x-powered-by'] || 'Unknown',
        };

        return { securityHeaders, missingHeaders, technologies };
    } catch (error) {
        console.error(`[Error] Header analysis failed for ${domain}:`, error.message);
        return { securityHeaders: {}, missingHeaders: ['All (Analysis Failed)'], technologies: {} };
    }
};

/**
 * Generate risk score
 */
const calculateRiskScore = (headerAnalysis, portData, sslData, dirData) => {
    let score = 1; // Base score

    // Missing headers (up to +3)
    if (headerAnalysis.missingHeaders) {
        score += Math.min(3, headerAnalysis.missingHeaders.length * 0.6);
    }

    // Open risky ports (up to +3)
    const riskyPorts = [21, 22, 3306];
    if (portData && portData.open_ports) {
        const openRisky = portData.open_ports.filter(port => riskyPorts.includes(port));
        score += Math.min(3, openRisky.length * 1.5);
    }

    // SSL expired / issues (up to +2)
    if (sslData && (sslData.expired || sslData.error)) {
        score += 2;
    }

    // Exposed directories (up to +2)
    if (dirData && dirData.directories && dirData.directories.length > 0) {
        score += Math.min(2, dirData.directories.length * 0.5);
    }

    // Cap at 10
    score = Math.min(10, Math.round(score));

    let level = 'Low';
    if (score >= 4 && score <= 7) level = 'Medium';
    else if (score > 7) level = 'High';

    return { score, level };
};

router.post('/', async (req, res) => {
    let { domain } = req.body;
    
    if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
    }

    // Basic sanitize
    domain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');

    try {
        console.log(`Starting scan for: ${domain}`);

        // Run Python scripts concurrently
        const [
            dnsData,
            subdomainData,
            portData,
            sslData,
            dirData,
            headerData
        ] = await Promise.all([
            runPythonScript('dns_scan.py', domain),
            runPythonScript('subdomain_scan.py', domain),
            runPythonScript('port_scan.py', domain),
            runPythonScript('ssl_scan.py', domain),
            runPythonScript('dir_scan.py', domain),
            analyzeHeaders(domain)
        ]);

        const risk = calculateRiskScore(headerData, portData, sslData, dirData);

        const report = {
            domain,
            target_ip: dnsData.ip || 'Unknown',
            dns_records: dnsData.records || {},
            subdomains: subdomainData.subdomains || [],
            open_ports: portData.open_ports || [],
            technologies: headerData.technologies || {},
            ssl_info: sslData || {},
            security_headers: headerData.securityHeaders || {},
            missing_headers: headerData.missingHeaders || [],
            discovered_directories: dirData.directories || [],
            risk
        };

        res.json(report);
    } catch (error) {
        console.error(`[Scan Error] ${error.message}`);
        res.status(500).json({ error: 'Failed to complete recon scan' });
    }
});

module.exports = router;
