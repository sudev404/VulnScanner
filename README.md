# VulnScanner — Web-Based Vulnerability Assessment Tool

## Project Structure
```
vuln-scanner/
├── backend/
│   ├── app.py                  # Flask API server
│   ├── requirements.txt
│   ├── auth/auth.py            # JWT authentication
│   ├── models/database.py      # SQLite models (User, Scan, Finding)
│   ├── scanner/
│   │   ├── port_scanner.py     # Nmap port scanning
│   │   ├── service_enum.py     # HTTP/FTP/SSH/SMB enumeration
│   │   ├── cve_lookup.py       # NVD API CVE lookup
│   │   ├── web_scanner.py      # XSS/SQLi/CORS/Headers checks
│   │   ├── osint_module.py     # WHOIS/DNS/Shodan
│   │   └── risk_scorer.py      # CVSS-based scoring
│   └── reports/report_gen.py   # PDF report generation
└── frontend/
    └── VulnScanner.jsx         # React frontend

---

## Backend Setup (Kali Linux)

### 1. Install system dependencies
```bash
sudo apt update
sudo apt install nmap python3-pip -y
```

### 2. Install Python packages
```bash
cd backend/
pip install -r requirements.txt --break-system-packages
```

### 3. Run the Flask server
```bash
python app.py
# Runs on http://localhost:5000
```

---

## Frontend Setup

### Option A — Use with React (Vite)
```bash
npm create vite@latest frontend -- --template react
cd frontend
# Replace src/App.jsx with VulnScanner.jsx
npm install
npm run dev
# Runs on http://localhost:3000
```

### Option B — Run as Claude Artifact
Paste VulnScanner.jsx directly into Claude as an artifact — 
it runs in demo mode with mock data (no backend needed).

---

## API Endpoints

| Method | Endpoint                        | Description            |
|--------|---------------------------------|------------------------|
| POST   | /api/auth/register              | Register user          |
| POST   | /api/auth/login                 | Login → JWT token      |
| POST   | /api/scan                       | Start new scan         |
| GET    | /api/scan/{id}/status           | Poll scan progress     |
| GET    | /api/scan/{id}/results          | Get findings           |
| GET    | /api/scans                      | List scan history      |
| GET    | /api/scan/{id}/report           | Download PDF report    |

---

## Environment Variables (Optional)
```bash
export JWT_SECRET="your-secret-key"
export SHODAN_API_KEY="your-shodan-key"   # For Shodan OSINT
```

---

## Important Notes
- Only scan targets you own or have explicit permission to test
- Run as root/sudo for Nmap SYN scan (stealth profile)
- NVD API is rate-limited to 5 req/30s without API key
  Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

---

Built by Sudev CS | BCA — Krupanidhi Degree College
