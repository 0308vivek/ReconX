# ReconX

ReconX is a web-based cybersecurity reconnaissance tool that automates the process of gathering security-related information about a target domain. The tool performs multiple reconnaissance scans and generates a structured security report to help identify potential vulnerabilities and misconfigurations.

## Features

ReconX performs several automated reconnaissance tasks:

* DNS record analysis
* Subdomain enumeration
* Port scanning
* Directory discovery
* SSL/TLS certificate inspection
* Security header analysis
* Technology fingerprinting
* Automated risk scoring

The tool aggregates all results into a single security report for easier analysis.

---

## Architecture

ReconX uses a hybrid architecture combining Node.js and Python.

Frontend:

* HTML
* CSS
* JavaScript
* EJS Templates

Backend:

* Node.js
* Express.js

Security scanning modules:

* Python

The Node.js backend orchestrates the scanning process while Python modules perform the reconnaissance tasks.

```
User Input (Domain)
        ↓
Node.js API
        ↓
Python Recon Modules
        ↓
Security Analysis Engine
        ↓
Risk Score + Security Report
```

---

## Reconnaissance Modules

### DNS Scanner

Retrieves DNS records including:

* A
* AAAA
* MX
* NS
* TXT
* CNAME

This helps identify infrastructure and mail servers associated with the domain.

---

### Subdomain Enumeration

Uses Certificate Transparency logs (crt.sh) to discover subdomains associated with the target domain.

Examples:

```
api.example.com
mail.example.com
dev.example.com
```

---

### Port Scanner

Performs TCP connect scanning to detect open ports such as:

* 21 (FTP)
* 22 (SSH)
* 80 (HTTP)
* 443 (HTTPS)
* 3306 (MySQL)

Open ports may expose services that could be targeted during attacks.

---

### Directory Discovery

Scans for sensitive directories such as:

```
/admin
/login
/dashboard
/api
/wp-admin
/backup
```

These endpoints may reveal administrative interfaces or APIs.

---

### SSL/TLS Scanner

Analyzes the HTTPS configuration including:

* Certificate issuer
* Certificate validity period
* Expiration date
* TLS protocol version

Misconfigured or expired certificates may expose users to security risks.

---

### Security Header Analysis

Checks for important HTTP security headers including:

* Content-Security-Policy
* X-Frame-Options
* Strict-Transport-Security
* X-XSS-Protection
* X-Content-Type-Options

Missing headers increase the attack surface for vulnerabilities such as XSS and clickjacking.

---

### Risk Scoring Engine

ReconX generates an overall risk score based on:

* Missing security headers
* Open risky ports
* SSL certificate issues
* Exposed directories

Risk levels:

| Score | Risk Level |
| ----- | ---------- |
| 1-3   | Low        |
| 4-7   | Medium     |
| 8-10  | High       |

---

## Tech Stack

Frontend:

* HTML
* CSS
* JavaScript
* EJS

Backend:

* Node.js
* Express.js

Security Modules:

* Python
* Requests
* Socket
* DNS Resolver

---

## Installation

Clone the repository:

```
git clone https://github.com/yourusername/ReconX.git
```

Navigate into the project folder:

```
cd ReconX
```

Install Node dependencies:

```
npm install
```

Install Python dependencies:

```
pip3 install -r requirements.txt
```

---

## Running the Application

Start the server:

```
node app.js
```

Open in browser:

```
http://localhost:3000
```

Enter a domain and run the reconnaissance scan.

---

## Example Output

ReconX generates a report containing:

* Target IP address
* DNS records
* Discovered subdomains
* Open ports
* Detected technologies
* SSL certificate details
* Security headers
* Exposed directories
* Overall risk score

---

## Security Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Do not scan systems without proper permission.

---

## Author

Vivek Prasad

B.Tech Computer Science & Engineering
Cybersecurity and Full Stack Development
