# VulnScanner — Production-Ready Vulnerability Assessment Platform

**A professional web-based penetration testing tool with admin panel, real exploitation, audit logging, and user management.**

---

## ⚠️ Legal Warning

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY.**

- Only test targets you own or have explicit written permission to scan
- Unauthorized access to computer systems is illegal
- Keep audit logs for compliance and legal protection
- Violators will be prosecuted to the fullest extent of the law

---

## 🎯 Features

### Core Scanning
- ✅ **Real Nmap Integration** — Port scanning with SYN, service detection, OS fingerprinting
- ✅ **Service Enumeration** — HTTP headers, SSL/TLS, FTP, SSH, SMB, RDP analysis
- ✅ **CVE Lookup** — NVD API integration for real vulnerability databases
- ✅ **Web Application Scanning** — XSS, SQLi, CORS, missing headers, robots.txt
- ✅ **OSINT Gathering** — WHOIS, DNS, zone transfer attempts, Shodan integration
- ✅ **Active Exploitation** — FTP anonymous login, SSH weak credentials, HTTP defaults
- ✅ **Risk Scoring** — CVSS-weighted automated risk assessment

### Admin Features
- 📊 **Dashboard** — Real-time statistics and system health
- 👥 **User Management** — Approve, block, ban users with fine-grained permissions
- 🔍 **Scan Monitoring** — View all scans across all users
- 📋 **Audit Logging** — 90-day compliance log with full action trail
- ⚙️ **Configuration** — IP whitelisting/blacklisting, scan limits, approval workflows
- 📈 **Analytics** — Risk trends, scan volume, user activity patterns

### Security
- 🔐 **JWT Authentication** — Stateless token-based auth with 8-hour expiry
- 🛡️ **Authorization Checks** — Target whitelist/blacklist enforcement
- 📝 **Complete Audit Trail** — Every action logged with timestamp and user
- 🚫 **User Account Control** — Active/inactive status, ban functionality
- 🔒 **Rate Limiting** — Max concurrent scans, request throttling

---

## 📋 Project Structure

```
vuln-scanner/
├── backend/
│   ├── app.py                     # Flask API server + admin endpoints
│   ├── requirements.txt
│   ├── auth/
│   │   └── auth.py                # JWT + password hashing
│   ├── models/
│   │   └── database.py            # SQLAlchemy models + audit log
│   ├── scanner/
│   │   ├── port_scanner.py        # Nmap (real)
│   │   ├── service_enum.py        # HTTP/SSH/FTP/SMB (real)
│   │   ├── cve_lookup.py          # NVD API (real)
│   │   ├── web_scanner.py         # OWASP checks (real)
│   │   ├── osint_module.py        # WHOIS/DNS/Shodan (real)
│   │   ├── active_exploits.py     # FTP/SSH/SMB brute (real)
│   │   └── risk_scorer.py         # CVSS calculation
│   └── reports/
│       └── report_gen.py          # PDF reports
├── frontend/
│   ├── VulnScanner.jsx            # User scanning UI
│   ├── AdminPanel.jsx             # Admin dashboard
│   └── package.json
└── docker-compose.yml             # Container orchestration
```

---

## 🚀 Installation & Setup

### Prerequisites
- Linux (Ubuntu 20.04+ or Kali Linux recommended)
- Python 3.8+
- Node.js 14+ (for frontend)
- Nmap 7.70+ (`sudo apt install nmap`)
- CrackMapExec (optional, for SMB exploitation)

### Backend Setup

#### 1. Install system dependencies
```bash
sudo apt update
sudo apt install nmap python3-pip python3-venv git -y

# Install CrackMapExec (optional but recommended)
sudo apt install crackmapexec -y

# Shodan CLI (optional)
pip install shodan --break-system-packages
```

#### 2. Create Python environment and install packages
```bash
cd backend/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --break-system-packages
```

#### 3. Run Flask server
```bash
# Development mode
python app.py

# Production (with Gunicorn)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

The API runs on `http://localhost:5000`

### Frontend Setup

#### Option A — React with Vite
```bash
cd frontend/
npm create vite@latest . -- --template react
npm install
npm run dev
```

The UI runs on `http://localhost:5173`

#### Option B — Direct HTML
```html
<!DOCTYPE html>
<html>
<head>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
</head>
<body>
    <div id="root"></div>
    <!-- Paste VulnScanner.jsx here -->
</body>
</html>
```

---

## 🔐 Configuration & Security

### JWT Secret (Production)
```bash
export JWT_SECRET="your-very-long-random-secret-key-min-32-chars"
python app.py
```

### IP Whitelisting (Admin Panel)
```
Admin → Configuration → Whitelisted IPs
```

Add CIDR ranges:
```
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
```

### Enable Approval Workflow
```
Admin → Configuration → Require Admin Approval
```

Users must wait for admin approval before running scans.

### Audit Log Retention
```
Admin → Configuration → Log Retention Days: 90
```

---

## 📊 API Endpoints

### Scan Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start new scan |
| GET | `/api/scan/{id}/status` | Poll scan progress |
| GET | `/api/scan/{id}/results` | Get findings |
| GET | `/api/scans` | List user's scans |
| GET | `/api/scan/{id}/report` | Download PDF |
| POST | `/api/scan/{id}/cancel` | Stop scan |

### Admin Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/dashboard` | Stats/metrics |
| GET | `/api/admin/users` | List all users |
| PATCH | `/api/admin/user/{id}` | Edit user permissions |
| POST | `/api/admin/users/{id}/ban` | Ban user |
| GET | `/api/admin/scans` | View all scans (paginated) |
| DELETE | `/api/admin/scan/{id}` | Delete scan |
| GET | `/api/admin/audit-log` | Compliance logs |
| GET | `/api/admin/config` | System config |
| POST | `/api/admin/config` | Update config |

---

## 🧪 Testing Workflow

### 1. Register & Login
```bash
# User registration
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"sudev","email":"sudev@test.com","password":"SecurePass123"}'

# Login → get JWT token
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"sudev","password":"SecurePass123"}'
```

### 2. Start a Scan
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target":"192.168.100.10",
    "profile":"full",
    "modules":["ports","services","cve","web","osint"],
    "run_exploits":true,
    "consent_given":true
  }'
```

### 3. Monitor Progress
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:5000/api/scan/SCAN_ID/status
```

### 4. Get Results
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:5000/api/scan/SCAN_ID/results
```

### 5. Download Report
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:5000/api/scan/SCAN_ID/report > report.pdf
```

---

## 🛠️ Real Attack Capabilities

### What It Really Does

#### Port Scanning
```bash
# Quick (top 1000 ports)
nmap -sV -T4 --top-ports 1000 --open TARGET

# Full (all 65535 ports)
nmap -sV -T4 -p- --open TARGET

# Stealth (SYN scan)
sudo nmap -sS -sV -T3 --top-ports 1000 --open TARGET
```

#### Service Enumeration
- **HTTP/HTTPS** → Headers, SSL cert validation, default pages, directories
- **FTP** → Anonymous login, file listing
- **SSH** → Banner version, weak password brute (common creds)
- **SMB** → Null session, shares, signing enforcement
- **RDP** → Exposure check

#### CVE Lookup
Real-time queries to **NIST NVD API** matching service versions to known CVEs:
```
Apache 2.4.49 → CVE-2021-41773 (RCE) → CVSS 8.1 (High)
```

#### Web Application Scanning
- XSS injection probes
- SQLi error-based detection
- Missing security headers (HSTS, CSP, X-Frame-Options)
- CORS misconfiguration
- Default credentials on common apps

#### Active Exploitation
- **FTP Anonymous** → Login + file enumeration
- **SSH Weak Passwords** → Brute force common credentials (root/password, admin/admin)
- **HTTP Defaults** → Admin panel discovery, API enumeration
- **SMB Null Session** → User enumeration with `crackmapexec`

#### OSINT
- WHOIS lookups
- DNS records (A, MX, TXT, NS, CNAME)
- Zone transfer attempts
- Shodan API queries (if configured)

---

## 👥 User Roles & Permissions

### Analyst (Default User)
- Run scans on whitelisted targets
- View own scan results
- Download reports
- Cannot access admin panel

### Admin
- Manage users (approve/ban)
- View all scans + audit logs
- Configure system (whitelist/blacklist/limits)
- Delete scans
- Access full dashboard

---

## 📝 Audit Logging Examples

```json
{
  "action": "scan_started",
  "user_id": "user-123",
  "details": "Target: 192.168.100.10, Profile: full, Exploits: true",
  "timestamp": "2024-05-26T10:15:30Z",
  "success": true
}

{
  "action": "user_banned",
  "user_id": "admin-456",
  "details": "Banned user-789. Reason: Unauthorized target scanning",
  "timestamp": "2024-05-26T11:22:45Z",
  "success": true
}

{
  "action": "scan_blocked",
  "user_id": "user-101",
  "details": "Blocked: Target 8.8.8.8 not on whitelist",
  "timestamp": "2024-05-26T12:05:12Z",
  "success": false
}
```

---

## 🐳 Docker Deployment (Optional)

```dockerfile
# Dockerfile
FROM python:3.10-slim

RUN apt update && apt install -y nmap

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/ .

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

```bash
docker build -t vulnscanner:latest .
docker run -p 5000:5000 vulnscanner:latest
```

---

## 🚨 Troubleshooting

### Nmap not found
```bash
sudo apt install nmap -y
which nmap
```

### Permission denied on port scan
```bash
# Nmap SYN scan requires root
sudo python app.py
# OR use UDP scans (unprivileged)
```

### JWT token expired
Tokens expire after 8 hours. Login again to refresh.

### Database locked
```bash
rm vulnscanner.db
# App will recreate it
```

---

## 📚 Resources

- [Nmap Documentation](https://nmap.org/book/)
- [NVD API](https://nvd.nist.gov/developers/request-an-api-key)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CrackMapExec Docs](https://www.hackingarticles.in/a-detailed-guide-on-crackmapexec/)

---

## 👤 Author

**Sudev CS**
- BCA Student, Krupanidhi Degree College, Bangalore
- IBM Cybersecurity Analyst (CECSA1IN)
- GitHub: @sudev404
- Email: csudev5@gmail.com

---

## ⚖️ License

**Educational Use Only** — For authorized penetration testing and security research

---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally. 🎯
