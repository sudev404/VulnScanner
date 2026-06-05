# VulnScanner — Quick Start Guide

## 🚀 5-Minute Setup

### 1. Clone & Install (Kali Linux)
```bash
sudo apt update
sudo apt install nmap python3-pip git -y

git clone https://github.com/yourusername/vulnscanner.git
cd vulnscanner/backend

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --break-system-packages
```

### 2. Start Backend
```bash
python app.py
# API on http://localhost:5000
```

### 3. Start Frontend (New Terminal)
```bash
cd frontend
npm install
npm run dev
# UI on http://localhost:5173
```

---

## 👨‍💻 First Admin Setup

### Create Your Admin Account
```bash
curl -X POST http://localhost:5000/api/auth/create-admin \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@yourdomain.com",
    "password": "VerySecurePassword123!"
  }'
```

Login with these credentials on the UI.

---

## 🔍 Your First Real Scan

### 1. Open VulnScanner UI
- Go to `http://localhost:5173`
- Login with your admin credentials

### 2. Request Scan Approval (if enabled)
- Submit scan request
- Check "Admin Panel" → "Dashboard"
- Approve users who need approval

### 3. Run a Scan
```
Target: 192.168.100.10 (your AD lab DC or lab machine)
Profile: QUICK (1000 ports)
Modules: 
  ✓ Port Scan
  ✓ Services
  ✓ CVE Lookup
  ✓ Web Scan
Run Exploits: ✓ (enabled for real attacks)
```

### 4. Watch Live Progress
- Progress bar shows current stage
- Real Nmap scan running
- Service enumeration happening
- CVE database queries
- Web scanning + XSS/SQLi probes
- Active exploits attempting real login

### 5. View Results
- Critical findings highlighted
- CVSS scores from NVD API
- Severity ratings
- Evidence of exploits (if successful)

---

## 🛡️ Real Attack Examples

### What You'll See in Real Scans

#### Port Scan
```
Open Ports Found:
  22/tcp   — SSH
  80/tcp   — HTTP
  445/tcp  — SMB
  3389/tcp — RDP
```

#### Service Enumeration
```
[High] RDP Exposed on port 3389
[Critical] FTP Anonymous Login Allowed
[High] SSH Banner: OpenSSH 7.4 (outdated)
[Medium] SMB Signing Disabled
```

#### Active Exploitation
```
[Critical] FTP Anonymous Access — Files Exposed (5 files found)
[Critical] SSH Weak Credentials: root:password — RCE
[Critical] HTTP Default Credentials: admin:admin — Authenticated
[High] SMB Null Session Enumeration — User list retrieved
```

#### CVE Lookup
```
[Critical] CVE-2021-44228 — Apache Log4j RCE (CVSS 10.0)
[High] CVE-2017-0144 — EternalBlue SMB (CVSS 8.1)
[Medium] CVE-2019-1234 — HTTP Header Injection (CVSS 5.3)
```

---

## 👥 Admin Control Panel

### Dashboard
- Total users, scans, running jobs
- Risk statistics
- System health

### User Management
- Approve/block scan access
- Promote to admin
- Ban users
- View login history

### Scan Monitoring
- View all scans across all users
- Delete findings if needed
- Track source IPs
- Audit who ran what

### Audit Log
- 90-day compliance trail
- Every action logged
- User + timestamp for each event
- Success/failure indicators

### Configuration
- IP whitelist (only scan approved targets)
- IP blacklist (prevent scanning others)
- Concurrent scan limits (prevent DoS)
- Approval workflow toggle
- Log retention

---

## 🎯 Real Lab Scenarios

### Scenario 1: AD Exploitation Lab
```
Target: 192.168.100.10 (DC with known weak config)
Profile: FULL (all ports)
Exploits: ENABLED
Expected: SMB exploitation, Kerberoasting, credential access
```

### Scenario 2: Web Application Assessment
```
Target: 192.168.100.50 (Vulnerable web app)
Profile: WEB (HTTP/HTTPS ports only)
Exploits: ENABLED
Expected: XSS, SQLi, default credentials discovered
```

### Scenario 3: Compliance Audit
```
Target: Internal network 192.168.0.0/16
Profile: QUICK
Exploits: DISABLED
Expected: Inventory of services, CVE baseline
Use: Generate compliance reports for auditors
```

---

## 🔐 Important Security Notes

### Before Each Scan
- [ ] You own the target OR have written permission
- [ ] Target IP is on whitelist (if whitelist enabled)
- [ ] Nobody else uses this IP
- [ ] Understand what "Run Exploits" means
- [ ] Document the scan authorization

### Audit Trail for Legal Protection
All scans logged with:
- Timestamp (when)
- User (who)
- Target (what)
- Source IP (where from)
- Modules run (how)

This proves authorization in court.

### Export Reports for Records
```bash
# Download each scan's PDF report
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:5000/api/scan/SCAN_ID/report > report.pdf
```

Store reports for 7+ years for compliance.

---

## 📈 Production Deployment

### Option A: Docker
```bash
docker-compose up -d

# Logs
docker logs -f vulnscanner-backend
```

### Option B: Linux Service
```bash
# Create systemd service
sudo nano /etc/systemd/system/vulnscanner.service

[Unit]
Description=VulnScanner Backend
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/vulnscanner/backend
ExecStart=/home/ubuntu/vulnscanner/backend/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target

# Enable & start
sudo systemctl enable vulnscanner
sudo systemctl start vulnscanner
```

### Option C: AWS/Azure
- Run backend on EC2/VM
- Run database on RDS/Azure SQL
- Put frontend on S3/Azure Blob + CloudFront/CDN
- Use security groups to restrict source IPs

---

## 🐛 Troubleshooting

### Nmap not finding ports
```bash
# Check if Nmap is installed
which nmap

# Install if missing
sudo apt install nmap -y

# Check if you have permission (SYN scan needs root)
sudo python app.py
```

### "Target not whitelisted" error
```bash
# Add target to whitelist in Admin Panel → Config
# Or disable whitelist if not needed
```

### Scan stuck in "Initializing"
```bash
# Check backend logs
cat vulnscanner.log | tail -50

# Restart if needed
pkill -f "python app.py"
python app.py
```

### "Max concurrent scans reached"
```bash
# Increase limit in Admin Panel → Config → Max Concurrent Scans
# Or wait for running scans to complete
```

---

## 📚 Real Tools Behind the Scenes

| Module | Real Tool | Why |
|--------|-----------|-----|
| Port Scan | **Nmap** | Industry standard |
| Service Enum | **requests, paramiko, ftplib** | Direct protocol probing |
| CVE Lookup | **NIST NVD API** | Official CVE database |
| Web Scan | **requests** + OWASP checks | Real vulnerability patterns |
| SSH Brute | **paramiko** | Actual SSH login attempts |
| FTP Enum | **ftplib** | Real file listing |
| SMB Enum | **crackmapexec** (optional) | Domain enumeration |

---

## 🎓 Learning Outcomes

By using this tool, you'll understand:
- How penetration testers work in practice
- Real vulnerability assessment workflow
- CVSS scoring and risk calculation
- Proper security testing authorization
- Audit logging for compliance
- Admin controls for multi-user systems
- Real exploitation (not simulated)

---

## 🔗 Next Steps

1. **Scan your lab environment** (AD, web apps, etc.)
2. **Review results** to understand vulnerabilities
3. **Remediate findings** (patch, configure, harden)
4. **Re-scan to verify fixes** (before/after comparison)
5. **Generate compliance reports** for documentation
6. **Expand to other targets** (with proper authorization)

---

## 📞 Support

**Issues?**
- Check `vulnscanner.log` in backend directory
- Review `PRODUCTION_GUIDE.md` for detailed setup
- Test endpoints with curl before using UI

**Want to contribute?**
- Fix bugs
- Add new scanner modules
- Improve UI/UX
- Write documentation

---

## ⚠️ Final Reminder

**THIS TOOL IS POWERFUL. USE IT ETHICALLY.**

- Never scan without permission
- Keep audit logs as proof
- Respect targets and data
- Report responsibly
- Follow local laws

Happy hunting! 🎯
