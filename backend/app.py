"""
VulnScanner Backend - Flask Application
Enhanced with RBAC, Scheduling, and Reporting
"""

from flask import Flask, jsonify, request, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import uuid
import json
import subprocess
import tempfile
import os
import threading
import urllib3
from collections import Counter
import nmap
import requests
import csv
from io import StringIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import report generator
from reports.report_gen import generate_pdf_report as generate_pdf

# Real-time scan progress tracker { scan_id: {"progress": int, "stage": str} }
scan_progress = {}

def is_web_target(target):
    """Returns True if target is a hostname/domain (not bare IP) or starts with http"""
    import re
    if target.startswith("http"):
        return True
    # Check if it's a domain name (has letters, not just numbers/dots)
    return bool(re.search(r'[a-zA-Z]', target))

# Import models
from models.database import (
    db, User, Scan, Finding, UserRole, ScheduledScan, AuditLog, AdminConfig
)

# ════════════════════════════════════════════════════════════════════════════
# FLASK APP SETUP
# ════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///vulnscanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'SrCDK4ih7qlLOlrup6gJeITbpfaWPehv73YYCZ7-mQw')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

# Initialize extensions
db.init_app(app)
CORS(app)
jwt = JWTManager(app)

# Scheduler flag to ensure it starts only once
_scheduler_started = False

# ════════════════════════════════════════════════════════════════════════════
# RBAC DECORATORS - FIXED VERSION
# ════════════════════════════════════════════════════════════════════════════

def role_required(*allowed_roles):
    """Decorator to check if user has required role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "No token provided"}), 401
            
            token = auth_header.replace("Bearer ", "")
            
            try:
                # Decode JWT
                payload = decode_token(token)
                user_id = payload.get("sub")
                
                if not user_id:
                    return jsonify({"error": "Invalid token"}), 401
                
                # Get user from database
                user = User.query.get(user_id)
                if not user:
                    return jsonify({"error": "User not found"}), 401
                
                # Check if user has required role
                if user.role not in allowed_roles:
                    return jsonify({"error": "Insufficient permissions"}), 403
                
                # Store user in request
                request.user = user
                
            except Exception as e:
                print(f"Auth error: {str(e)}")
                return jsonify({"error": "Invalid token"}), 401
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_required(permission_name):
    """Decorator to check specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "No token provided"}), 401
            
            token = auth_header.replace("Bearer ", "")
            
            try:
                # Decode JWT
                payload = decode_token(token)
                user_id = payload.get("sub")
                
                if not user_id:
                    return jsonify({"error": "Invalid token"}), 401
                
                # Get user
                user = User.query.get(user_id)
                if not user:
                    return jsonify({"error": "User not found"}), 401
                
                # Check permission
                has_permission = getattr(user, f"can_{permission_name}", False)
                
                # Admin always has all permissions
                if user.role != "admin" and not has_permission:
                    return jsonify({"error": "Permission denied"}), 403
                
                # Store user
                request.user = user
                
            except Exception as e:
                print(f"Permission error: {str(e)}")
                return jsonify({"error": "Invalid token"}), 401
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def calculate_next_run(frequency):
    """Calculate next run time based on frequency"""
    now = datetime.utcnow()
    
    if frequency == "daily":
        return now + timedelta(days=1)
    elif frequency == "weekly":
        return now + timedelta(weeks=1)
    elif frequency == "monthly":
        return now + timedelta(days=30)
    else:
        return None


def log_audit(action, resource_type, resource_id, details=None):
    """Log audit action for compliance"""
    try:
        log = AuditLog(
            id=str(uuid.uuid4()),
            user_id=request.user.id if hasattr(request, "user") and request.user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Audit log error: {str(e)}")


def get_most_common(items):
    """Get most common item in list"""
    if not items or len(items) == 0:
        return None
    return Counter(items).most_common(1)[0][0]

# ════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for Render"""
    try:
        # Test database connection
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "healthy", "service": "vulnscanner-backend", "database": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route("/ready", methods=["GET"])
def readiness_check():
    """Readiness check endpoint for Render"""
    return jsonify({"status": "ready", "service": "vulnscanner-backend"}), 200

# ════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register new user"""
    data = request.get_json()
    
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check if user exists
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username taken"}), 400
    
    # Create new user
    user = User(
        id=str(uuid.uuid4()),
        username=data["username"],
        email=data.get("email", ""),
        password=generate_password_hash(data["password"]),
        role=UserRole.USER.value,
        can_create_scans=True,
        can_export_reports=True
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Create token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "token": access_token,
        "role": user.role
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Login user"""
    data = request.get_json()
    
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing credentials"}), 400
    
    # Find user
    user = User.query.filter_by(username=data["username"]).first()
    
    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    
    if not user.is_active:
        return jsonify({"error": "Account is inactive"}), 403
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "token": access_token,
        "role": user.role,
        "is_admin": user.role == "admin",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_admin": user.role == "admin"
        }
    }), 200

# ════════════════════════════════════════════════════════════════════════════
# EXISTING SCAN ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
@permission_required("create_scans")
def start_scan():
    """Start a vulnerability scan"""
    data = request.get_json()
    
    # Validate input
    if not data.get("target"):
        return jsonify({"error": "Target required"}), 400
    
    if not data.get("consent_given"):
        return jsonify({"error": "Consent required"}), 400
    
    # Get user ID from decorator
    user_id = request.user.id
    
    # Create scan record
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id=user_id,
        target=data.get("target"),
        profile=data.get("profile", "quick"),
        status="started",
        run_exploits=data.get("run_exploits", False),
        consent_given=True,
        source_ip=request.remote_addr
    )
    
    db.session.add(scan)
    db.session.commit()

    log_audit("START_SCAN", "scan", scan.id, {"target": data.get("target")})

    # Start scan in background thread
    import threading
    thread = threading.Thread(target=run_scan_background, args=(app, scan.id, data.get("target"), data.get("profile", "quick")))
    thread.daemon = True
    thread.start()

    return jsonify({
        "scan_id": scan.id,
        "status": scan.status,
        "target": scan.target
    }), 201


# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL SCANNER MODULES
# ════════════════════════════════════════════════════════════════════════════

def run_nikto_scan(target):
    """Pure-Python web vulnerability scanner — no Nikto required."""
    if not target.startswith("http"):
        base_url = f"http://{target}"
    else:
        base_url = target.rstrip("/")

    findings = []
    hdrs = {"User-Agent": "VulnScanner/1.0"}

    # ── Sensitive files ───────────────────────────────────────────────────────
    sensitive_paths = [
        ("/.env",            "Critical", "Environment file exposed — may contain DB passwords and API keys"),
        ("/phpinfo.php",     "High",     "PHP info page exposed — reveals full server configuration"),
        ("/admin",           "Medium",   "Admin panel found — verify authentication is required"),
        ("/admin.php",       "Medium",   "Admin PHP page found"),
        ("/wp-admin",        "Medium",   "WordPress admin panel found"),
        ("/wp-config.php",   "Critical", "WordPress config exposed — may contain DB credentials"),
        ("/config.php",      "Critical", "Config file exposed — may contain credentials"),
        ("/.git/config",     "High",     "Git repository exposed — source code may be downloadable"),
        ("/backup",          "High",     "Backup directory found — may contain sensitive data"),
        ("/db.sql",          "Critical", "SQL dump file found — full database may be exposed"),
        ("/server-status",   "Medium",   "Apache server-status page exposed"),
        ("/.htaccess",       "Medium",   ".htaccess file accessible — may reveal rewrite rules"),
        ("/web.config",      "High",     "web.config exposed — may reveal app configuration"),
        ("/debug",           "High",     "Debug endpoint found — may expose stack traces"),
        ("/console",         "High",     "Console endpoint found — may allow remote code execution"),
        ("/swagger.json",    "Low",      "Swagger/OpenAPI spec exposed — full API structure visible"),
        ("/api/docs",        "Low",      "API documentation exposed — reveals endpoints"),
        ("/robots.txt",      "Low",      "robots.txt found — may list hidden paths"),
        ("/actuator",        "High",     "Spring Boot Actuator exposed — may allow server control"),
    ]
    for path, severity, description in sensitive_paths:
        try:
            r = requests.get(f"{base_url}{path}", timeout=8, verify=False,
                             headers=hdrs, allow_redirects=False)
            if r.status_code in [200, 403, 301, 302]:
                label = "accessible" if r.status_code == 200 else f"HTTP {r.status_code}"
                findings.append({
                    "title": f"[WebScan] Sensitive path {label}: {path}",
                    "description": description,
                    "severity": severity, "port": "80", "service": "http",
                    "cvss_score": 9.0 if severity=="Critical" else 7.0 if severity=="High" else 5.0 if severity=="Medium" else 3.0
                })
        except requests.exceptions.RequestException:
            pass

    # ── Security headers ──────────────────────────────────────────────────────
    try:
        r = requests.get(base_url, timeout=8, verify=False, headers=hdrs)
        rh = {k.lower(): v for k, v in r.headers.items()}

        for hdr, (sev, desc) in {
            "x-frame-options":           ("Medium", "Missing X-Frame-Options — clickjacking attacks possible"),
            "content-security-policy":   ("Medium", "Missing Content-Security-Policy — XSS risk increased"),
            "strict-transport-security": ("Medium", "Missing HSTS header — HTTP downgrade attacks possible"),
            "x-content-type-options":    ("Low",    "Missing X-Content-Type-Options — MIME sniffing possible"),
            "x-xss-protection":          ("Low",    "Missing X-XSS-Protection header"),
            "referrer-policy":           ("Low",    "Missing Referrer-Policy — referrer data may leak"),
        }.items():
            if hdr not in rh:
                findings.append({
                    "title": f"[WebScan] Missing security header: {hdr}",
                    "description": desc, "severity": sev,
                    "port": "80", "service": "http",
                    "cvss_score": 5.0 if sev=="Medium" else 3.0
                })

        # Server banner
        for h in ["server", "x-powered-by"]:
            val = rh.get(h, "")
            if val:
                findings.append({
                    "title": f"[WebScan] {h} header disclosed: {val}",
                    "description": f"Header '{h}' reveals backend software '{val}'. Attackers can look up CVEs for this version.",
                    "severity": "Low", "port": "80", "service": "http", "cvss_score": 3.0
                })

        # Insecure cookies
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if issues:
                findings.append({
                    "title": f"[WebScan] Insecure cookie: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' has: {', '.join(issues)}.",
                    "severity": "Medium", "port": "80", "service": "http", "cvss_score": 5.0
                })
    except requests.exceptions.RequestException as e:
        print(f"WebScan header check error: {e}")

    # ── Dangerous HTTP methods ─────────────────────────────────────────────────
    try:
        r = requests.options(base_url, timeout=8, verify=False, headers=hdrs)
        allow = r.headers.get("Allow", "") + r.headers.get("allow", "")
        dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
        if dangerous:
            findings.append({
                "title": f"[WebScan] Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                "description": f"Server allows {', '.join(dangerous)}. PUT/DELETE can allow file upload/deletion. TRACE enables XST attacks.",
                "severity": "High", "port": "80", "service": "http", "cvss_score": 7.5
            })
    except requests.exceptions.RequestException:
        pass

    print(f"[WebScan] Found {len(findings)} web findings on {target}")
    return findings


def run_sqli_xss_checks(target):
    """Run basic SQL injection and XSS detection checks"""
    if not target.startswith("http"):
        base_url = f"http://{target}"
    else:
        base_url = target

    findings = []

    sqli_payloads = ["'", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "1' AND SLEEP(3)--"]
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>"
    ]
    sql_error_signatures = [
        "sql syntax", "mysql_fetch", "ora-", "syntax error",
        "unclosed quotation", "quoted string not properly terminated",
        "sqlstate", "pg_query", "sqlite3", "warning: mysql"
    ]
    test_params = ["id", "search", "q", "page", "user", "name", "item", "category"]

    try:
        for param in test_params:
            # SQLi check
            for payload in sqli_payloads:
                try:
                    resp = requests.get(
                        f"{base_url}?{param}={payload}",
                        timeout=5, verify=False,
                        headers={"User-Agent": "VulnScanner/1.0"}
                    )
                    if any(sig in resp.text.lower() for sig in sql_error_signatures):
                        findings.append({
                            "title": f"[SQLi] Potential SQL Injection — parameter '{param}'",
                            "description": f"SQL error response detected when injecting into parameter '{param}' with payload: {payload}. This may allow database manipulation.",
                            "severity": "Critical",
                            "port": "80",
                            "service": "http",
                            "cvss_score": 9.8
                        })
                        break  # one finding per param is enough
                except requests.exceptions.RequestException:
                    pass

            # XSS check
            for payload in xss_payloads:
                try:
                    resp = requests.get(
                        f"{base_url}?{param}={payload}",
                        timeout=5, verify=False,
                        headers={"User-Agent": "VulnScanner/1.0"}
                    )
                    if payload in resp.text:
                        findings.append({
                            "title": f"[XSS] Reflected XSS — parameter '{param}'",
                            "description": f"XSS payload was reflected unescaped in the response for parameter '{param}'. Attackers can steal session cookies or redirect users.",
                            "severity": "High",
                            "port": "80",
                            "service": "http",
                            "cvss_score": 7.5
                        })
                        break
                except requests.exceptions.RequestException:
                    pass

    except Exception as e:
        print(f"SQLi/XSS check error: {e}")

    return findings


def run_cve_nmap_scan(target):
    """Run nmap with vuln scripts to detect CVEs"""
    findings = []
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV --script vuln -T4 --open")

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info = nm[host][proto][port]
                    if info["state"] != "open":
                        continue
                    # Extract script output (vuln scripts store results here)
                    scripts = info.get("script", {})
                    for script_name, output in scripts.items():
                        if not output or "ERROR" in output.upper():
                            continue
                        # Determine severity from CVE/CVSS hints in output
                        out_lower = output.lower()
                        if "cvss: 9" in out_lower or "cvss: 10" in out_lower or "critical" in out_lower:
                            sev, cvss = "Critical", 9.0
                        elif "cvss: 7" in out_lower or "cvss: 8" in out_lower or "high" in out_lower:
                            sev, cvss = "High", 7.5
                        elif "cvss: 5" in out_lower or "cvss: 6" in out_lower or "medium" in out_lower:
                            sev, cvss = "Medium", 5.0
                        else:
                            sev, cvss = "Medium", 5.0

                        # Extract CVE ID if present
                        cve_id = ""
                        for word in output.split():
                            if word.upper().startswith("CVE-"):
                                cve_id = word.strip(".,;()")
                                break

                        title = f"[CVE] {script_name} on port {port}"
                        if cve_id:
                            title = f"[CVE] {cve_id} — {script_name} on port {port}"

                        findings.append({
                            "title": title,
                            "description": output[:500],
                            "severity": sev,
                            "port": str(port),
                            "service": info.get("name", "unknown"),
                            "cvss_score": cvss
                        })
    except Exception as e:
        print(f"CVE scan error: {e}")

    return findings


def run_scan_background(flask_app, scan_id, target, profile):
    """Run full vulnerability scan in background and update DB"""

    def upd(pct, msg):
        scan_progress[scan_id] = {"progress": pct, "stage": msg}
        print(f"[{pct:3d}%] {msg}")

    with flask_app.app_context():
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return
            scan.status = "running"
            db.session.commit()
            upd(5, "Initializing scan...")

            # ── Phase 1: nmap port scan ───────────────────────────────────────
            nm = nmap.PortScanner()
            args_map = {
                "quick":  "-sT -T4 -Pn --open -p 21,22,23,80,443,445,3306,3389,5900 --script banner -sV",
                "full":   "-sT -T4 -Pn -A --open -p 1-65535 --script banner,ssl-enum-ciphers -sV",
                "stealth":"-sT -T2 -Pn --open -p 80,443 --script banner -sV",
                "web":    "-sT -T4 -Pn --open -p 80,443,8080,8443 -sV --script http-title,http-headers",
                "vuln":   "-sT -T4 -Pn --open -p 21,22,23,80,443,445,3306,3389,5900"
            }
            upd(10, f"Phase 1: Running port scan on {target}...")
            nm.scan(target, arguments=args_map.get(profile, "-sT -T4 -Pn -F"))
            upd(30, "Phase 1: Processing port scan results...")

            findings = []
            detected_services = set()
            open_web_ports = set()
            risk_score = 0

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        info = nm[host][proto][port]
                        if info["state"] == "open":
                            service = info.get("name", "unknown")
                            detected_services.add(service.lower())
                            if port in [80, 443, 8080, 8443]:
                                open_web_ports.add(port)
                            product = info.get("product", "")
                            version = info.get("version", "")
                            if port in [21, 23, 445, 3389, 5900]:
                                severity, score = "Critical", 25
                            elif port in [22, 80, 8080, 1433, 3306]:
                                severity, score = "High", 15
                            elif port in [443, 8443, 25, 110, 143]:
                                severity, score = "Medium", 8
                            else:
                                severity, score = "Low", 3
                            risk_score += score
                            findings.append(Finding(
                                id=str(uuid.uuid4()), scan_id=scan_id,
                                title=f"Open Port {port}/{proto} - {service}",
                                description=f"Port {port} is open running {service} {product} {version}".strip(),
                                severity=severity, port=str(port), service=service,
                                cvss_score=9.0 if severity=="Critical" else 7.0 if severity=="High" else 5.0 if severity=="Medium" else 3.0
                            ))
            upd(35, f"Phase 1 done — {len(findings)} open ports found")

            # ── Phase 2: CVE detection ────────────────────────────────────────
            if profile in ("vuln", "full"):
                upd(40, "Phase 2: Running CVE detection (nmap vuln scripts)...")
                cve_results = run_cve_nmap_scan(target)
                for f in cve_results:
                    risk_score += 10
                    findings.append(Finding(
                        id=str(uuid.uuid4()), scan_id=scan_id,
                        title=f["title"], description=f["description"],
                        severity=f["severity"], port=f["port"],
                        service=f["service"], cvss_score=f["cvss_score"]
                    ))
                upd(55, f"Phase 2 done — {len(cve_results)} CVEs found")
            else:
                upd(55, "Phase 2 skipped (use vuln/full profile for CVE scan)")

            # ── Phase 3: Web scan (always run for domains/URLs) ───────────────
            run_web = bool(open_web_ports) or profile in ("web", "full", "vuln") or is_web_target(target)
            if run_web:
                upd(60, f"Phase 3: Web vulnerability scan on {target}...")
                web_results = run_nikto_scan(target)
                for f in web_results:
                    risk_score += 5
                    findings.append(Finding(
                        id=str(uuid.uuid4()), scan_id=scan_id,
                        title=f["title"], description=f["description"],
                        severity=f["severity"], port=f["port"],
                        service=f["service"], cvss_score=f["cvss_score"]
                    ))
                upd(75, f"Phase 3 done — {len(web_results)} web issues found")
            else:
                upd(75, "Phase 3 skipped (no web ports open)")

            # ── Phase 4: SQLi / XSS ───────────────────────────────────────────
            run_sqli = bool(open_web_ports) or target.startswith("http") or is_web_target(target)
            if run_sqli:
                upd(80, "Phase 4: Running SQLi and XSS injection tests...")
                sqli_results = run_sqli_xss_checks(target)
                for f in sqli_results:
                    risk_score += 15
                    findings.append(Finding(
                        id=str(uuid.uuid4()), scan_id=scan_id,
                        title=f["title"], description=f["description"],
                        severity=f["severity"], port=f["port"],
                        service=f["service"], cvss_score=f["cvss_score"]
                    ))
                upd(90, f"Phase 4 done — {len(sqli_results)} injection issues found")
            else:
                upd(90, "Phase 4 skipped (no web ports open)")

            upd(95, "Saving results to database...")
            for f in findings:
                db.session.add(f)

            scan.status = "completed"
            scan.risk_score = min(risk_score, 100)
            high_risk_services = {"mysql", "postgres", "mssql", "ssh", "ftp", "telnet", "smb"}
            if any(svc in detected_services for svc in high_risk_services):
                risk_level = "Critical"
            elif risk_score >= 75:
                risk_level = "Critical"
            elif risk_score >= 50:
                risk_level = "High"
            elif risk_score >= 25:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            scan.risk_level = risk_level
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            upd(100, f"Scan complete — {len(findings)} findings, risk: {risk_level}")
            import threading as _t
            _t.Timer(60, lambda: scan_progress.pop(scan_id, None)).start()

        except Exception as e:
            print(f"Scan error: {e}")
            scan_progress[scan_id] = {"progress": 0, "stage": f"Scan failed: {e}"}
            try:
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = "failed"
                    db.session.commit()
            except Exception:
                pass


@app.route("/api/scans", methods=["GET"])
@jwt_required()
def list_scans():
    """List scans for current user (admins see all)"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 401

    if user.role in ["admin", "auditor"]:
        scans = Scan.query.order_by(Scan.started_at.desc()).all()
    else:
        scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.started_at.desc()).all()

    return jsonify({
        "scans": [{
            "id": s.id,
            "target": s.target,
            "profile": s.profile,
            "status": s.status,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "finding_count": Finding.query.filter_by(scan_id=s.id).count()
        } for s in scans]
    }), 200


@app.route("/api/scan/<scan_id>/status", methods=["GET"])
@jwt_required()
def get_scan_status(scan_id):
    """Get scan status"""
    scan = Scan.query.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Check permission
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if scan.user_id != user_id and user.role not in ["admin", "auditor"]:
        return jsonify({"error": "Access denied"}), 403
    
    status_map = {
        "started":   (5,   "Initializing scan...", True),
        "completed": (100, "Scan complete",         False),
        "failed":    (0,   "Scan failed",           False),
    }
    if scan.status == "running":
        live = scan_progress.get(scan_id, {})
        progress = live.get("progress", 10)
        stage    = live.get("stage",    "Scanning in progress...")
        is_active = True
    else:
        progress, stage, is_active = status_map.get(scan.status, (0, "Unknown", False))
    return jsonify({
        "scan_id": scan.id,
        "status": scan.status,
        "progress": progress,
        "stage": stage,
        "is_active": is_active
    }), 200


@app.route("/api/scan/<scan_id>/results", methods=["GET"])
@jwt_required()
def get_scan_results(scan_id):
    """Get scan results"""
    scan = Scan.query.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    return jsonify({
        "scan": {
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "profile": scan.profile,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        },
        "findings": [f.to_dict() for f in findings]
    }), 200

# ════════════════════════════════════════════════════════════════════════════
# NEW ENDPOINTS: RBAC
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/users/<user_id>/role", methods=["PATCH"])
@role_required("admin")
def update_user_role(user_id):
    """Admin: Update user role and permissions"""
    data = request.get_json()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Update role
    if "role" in data:
        user.role = data["role"]
        
        # Set default permissions based on role
        if data["role"] == "admin":
            user.can_create_scans = True
            user.can_schedule_scans = True
            user.can_view_all_scans = True
            user.can_manage_users = True
            user.can_export_reports = True
        
        elif data["role"] == "analyst":
            user.can_create_scans = True
            user.can_schedule_scans = True
            user.can_view_all_scans = False
            user.can_manage_users = False
            user.can_export_reports = True
        
        elif data["role"] == "auditor":
            user.can_create_scans = False
            user.can_schedule_scans = False
            user.can_view_all_scans = True
            user.can_manage_users = False
            user.can_export_reports = True
        
        elif data["role"] == "user":
            user.can_create_scans = True
            user.can_schedule_scans = False
            user.can_view_all_scans = False
            user.can_manage_users = False
            user.can_export_reports = True
    
    # Update custom permissions
    if "permissions" in data:
        for perm, value in data["permissions"].items():
            if hasattr(user, f"can_{perm}"):
                setattr(user, f"can_{perm}", value)
    
    db.session.commit()
    log_audit("UPDATE_USER_ROLE", "user", user_id, {"role": user.role})
    
    return jsonify({
        "user_id": user.id,
        "role": user.role,
        "permissions": {
            "create_scans": user.can_create_scans,
            "schedule_scans": user.can_schedule_scans,
            "view_all_scans": user.can_view_all_scans,
            "manage_users": user.can_manage_users,
            "export_reports": user.can_export_reports
        }
    }), 200


@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def list_users_with_roles():
    """Admin: List all users with their roles"""
    users = User.query.all()
    
    return jsonify({
        "users": [{
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "is_approved": u.is_approved,
            "permissions": {
                "create_scans": u.can_create_scans,
                "schedule_scans": u.can_schedule_scans,
                "view_all_scans": u.can_view_all_scans,
                "manage_users": u.can_manage_users,
                "export_reports": u.can_export_reports
            },
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login": u.last_login.isoformat() if u.last_login else None
        } for u in users]
    }), 200

# ════════════════════════════════════════════════════════════════════════════
# NEW ENDPOINTS: SCHEDULING
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/scheduled-scans", methods=["POST"])
@permission_required("schedule_scans")
def create_scheduled_scan():
    """Create a scheduled scan"""
    data = request.get_json()
    
    scan = ScheduledScan(
        id=str(uuid.uuid4()),
        user_id=request.user.id,
        name=data.get("name"),
        description=data.get("description", ""),
        target=data.get("target"),
        profile=data.get("profile", "quick"),
        frequency=data.get("frequency", "weekly"),
        notify_email=data.get("notify_email", request.user.email),
        notify_on_critical=data.get("notify_on_critical", True),
        modules=data.get("modules", ["ports", "services", "cve"])
    )
    
    scan.next_run = calculate_next_run(scan.frequency)
    
    db.session.add(scan)
    db.session.commit()
    
    log_audit("CREATE_SCHEDULED_SCAN", "schedule", scan.id, {"target": data.get("target")})
    
    return jsonify({
        "scan_id": scan.id,
        "name": scan.name,
        "frequency": scan.frequency,
        "next_run": scan.next_run.isoformat() if scan.next_run else None,
        "status": "created"
    }), 201


@app.route("/api/scheduled-scans", methods=["GET"])
@permission_required("schedule_scans")
def list_scheduled_scans():
    """List user's scheduled scans"""
    scans = ScheduledScan.query.filter_by(user_id=request.user.id).all()
    
    return jsonify({
        "scheduled_scans": [{
            "id": s.id,
            "name": s.name,
            "target": s.target,
            "frequency": s.frequency,
            "is_active": s.is_active,
            "next_run": s.next_run.isoformat() if s.next_run else None,
            "last_run": s.last_run.isoformat() if s.last_run else None,
            "created_at": s.created_at.isoformat() if s.created_at else None
        } for s in scans]
    }), 200


@app.route("/api/scheduled-scans/<scan_id>", methods=["PATCH"])
@permission_required("schedule_scans")
def update_scheduled_scan(scan_id):
    """Update a scheduled scan"""
    scan = ScheduledScan.query.get(scan_id)
    
    if not scan or scan.user_id != request.user.id:
        return jsonify({"error": "Scan not found"}), 404
    
    data = request.get_json()
    
    if "frequency" in data:
        scan.frequency = data["frequency"]
        scan.next_run = calculate_next_run(data["frequency"])
    
    if "name" in data:
        scan.name = data["name"]
    
    if "is_active" in data:
        scan.is_active = data["is_active"]
    
    scan.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({"status": "updated"}), 200


@app.route("/api/scheduled-scans/<scan_id>", methods=["DELETE"])
@permission_required("schedule_scans")
def delete_scheduled_scan(scan_id):
    """Delete a scheduled scan"""
    scan = ScheduledScan.query.get(scan_id)
    
    if not scan or scan.user_id != request.user.id:
        return jsonify({"error": "Scan not found"}), 404
    
    db.session.delete(scan)
    db.session.commit()
    
    log_audit("DELETE_SCHEDULED_SCAN", "schedule", scan_id)
    
    return jsonify({"status": "deleted"}), 200

# ════════════════════════════════════════════════════════════════════════════
# NEW ENDPOINTS: REPORTING (FIXED WITH ACTUAL PDF GENERATION)
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/reports/dashboard", methods=["GET"])
@permission_required("export_reports")
def get_report_dashboard():
    """Get vulnerability statistics"""
    # Determine whose scans to include
    if request.user.role in ["admin", "auditor"]:
        scans = Scan.query.all()
    else:
        scans = Scan.query.filter_by(user_id=request.user.id).all()
    
    # Get findings from those scans
    findings = Finding.query.filter(
        Finding.scan_id.in_([s.id for s in scans])
    ).all() if scans else []
    
    # Count by severity
    critical = len([f for f in findings if f.severity == "Critical"])
    high = len([f for f in findings if f.severity == "High"])
    medium = len([f for f in findings if f.severity == "Medium"])
    low = len([f for f in findings if f.severity == "Low"])
    
    # Calculate average risk score
    avg_risk = sum([s.risk_score for s in scans]) / len(scans) if scans else 0
    
    return jsonify({
        "total_scans": len(scans),
        "total_findings": len(findings),
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "avg_risk_score": avg_risk,
        "most_common_service": get_most_common([f.service for f in findings if f.service]),
        "most_critical_port": get_most_common([f.port for f in findings if f.port])
    }), 200


@app.route("/api/scan/<scan_id>/report/pdf", methods=["GET"])
@permission_required("export_reports")
def generate_pdf_report_endpoint(scan_id):
    """Generate PDF report for a scan"""
    scan = Scan.query.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Check permission
    if scan.user_id != request.user.id and request.user.role not in ["admin", "auditor"]:
        return jsonify({"error": "Access denied"}), 403
    
    # Get findings for this scan
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    # Prepare scan data for report generator
    scan_data = {
        "id": scan.id,
        "target": scan.target,
        "risk_score": scan.risk_score or 0,
        "risk_level": scan.risk_level or "Unknown"
    }
    
    # Prepare findings data
    findings_data = []
    for f in findings:
        findings_data.append({
            "severity": f.severity,
            "title": f.title,
            "category": f.service or "Unknown",
            "port": f.port,
            "service": f.service,
            "cve_id": getattr(f, 'cve_id', None),
            "cvss_score": f.cvss_score,
            "description": f.description,
            "remediation": f.remediation
        })
    
    try:
        # Generate PDF using your existing report_gen.py
        pdf_path = generate_pdf(scan_data, findings_data)
        return send_file(
            pdf_path, 
            as_attachment=True, 
            download_name=f"report_{scan.id[:8]}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


@app.route("/api/scan/<scan_id>/report/csv", methods=["GET"])
@permission_required("export_reports")
def generate_csv_report_endpoint(scan_id):
    """Generate CSV report for a scan"""
    scan = Scan.query.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Check permission
    if scan.user_id != request.user.id and request.user.role not in ["admin", "auditor"]:
        return jsonify({"error": "Access denied"}), 403
    
    # Get findings
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Severity', 'Title', 'Category', 'Port', 'Service', 'CVSS Score', 'Description', 'Remediation'])
    
    # Write rows
    for f in findings:
        writer.writerow([
            f.severity,
            f.title,
            f.service or 'Unknown',
            f.port or 'N/A',
            f.service or 'N/A',
            f.cvss_score or 'N/A',
            f.description[:500] if f.description else '',
            f.remediation or ''
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename=report_{scan.id[:8]}.csv"}
    )


@app.route("/api/scan/<scan_id>/report/html", methods=["GET"])
@permission_required("export_reports")
def generate_html_report(scan_id):
    """Generate HTML report for a scan"""
    scan = Scan.query.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Check permission
    if scan.user_id != request.user.id and request.user.role not in ["admin", "auditor"]:
        return jsonify({"error": "Access denied"}), 403
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Vulnerability Scan Report - {scan.target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; padding: 20px; }}
            .header {{ background: #333; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .critical {{ background: #ffebee; border-left: 4px solid #d32f2f; padding: 10px; margin: 10px 0; }}
            .high {{ background: #fff3e0; border-left: 4px solid #f57c00; padding: 10px; margin: 10px 0; }}
            .medium {{ background: #fffde7; border-left: 4px solid #fbc02d; padding: 10px; margin: 10px 0; }}
            .low {{ background: #f1f8e9; border-left: 4px solid #388e3c; padding: 10px; margin: 10px 0; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Vulnerability Scan Report</h1>
                <p><strong>Target:</strong> {scan.target}</p>
                <p><strong>Scan Date:</strong> {scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'}</p>
                <p><strong>Risk Score:</strong> {scan.risk_score}/100</p>
                <p><strong>Risk Level:</strong> {scan.risk_level}</p>
            </div>
            
            <h2>Executive Summary</h2>
            <p>Total Findings: <strong>{len(findings)}</strong></p>
            
            <h2>Findings by Severity</h2>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Count</th></tr>
                </thead>
                <tbody>
                    <tr><td>Critical</td><td>{len([f for f in findings if f.severity == 'Critical'])}</td></tr>
                    <tr><td>High</td><td>{len([f for f in findings if f.severity == 'High'])}</td></tr>
                    <tr><td>Medium</td><td>{len([f for f in findings if f.severity == 'Medium'])}</td></tr>
                    <tr><td>Low</td><td>{len([f for f in findings if f.severity == 'Low'])}</td></tr>
                </tbody>
            </table>
            
            <h2>Detailed Findings</h2>
            {"".join([f'<div class="{f.severity.lower()}"><strong>{f.title}</strong><p>{f.description}</p></div>' for f in findings])}
            
            <hr>
            <p style="text-align: center; color: #666; font-size: 12px;">Generated by VulnScanner - Security Assessment Tool</p>
        </div>
    </body>
    </html>
    """
    
    return html, 200, {"Content-Type": "text/html"}

# ════════════════════════════════════════════════════════════════════════════
# DATABASE INITIALIZATION
# ════════════════════════════════════════════════════════════════════════════

@app.before_request
def create_tables():
    """Create database tables if they don't exist"""
    db.create_all()


# ════════════════════════════════════════════════════════════════════════════
# SCHEDULER - runs due scheduled scans every minute (FIXED FOR GUNICORN)
# ════════════════════════════════════════════════════════════════════════════

def run_due_scheduled_scans():
    """Check for due scheduled scans and execute them"""
    with app.app_context():
        try:
            now = datetime.utcnow()
            due_scans = ScheduledScan.query.filter(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run <= now
            ).all()

            for sched in due_scans:
                print(f"[Scheduler] Running scheduled scan: {sched.name} → {sched.target}")
                # Create a new Scan record
                scan = Scan(
                    id=str(uuid.uuid4()),
                    user_id=sched.user_id,
                    target=sched.target,
                    profile=sched.profile,
                    status="started",
                    risk_score=0,
                    risk_level="Low"
                )
                db.session.add(scan)
                db.session.commit()

                # Run the scan in a background thread
                import threading as _t
                t = _t.Thread(
                    target=run_scan_background,
                    args=(app, scan.id, sched.target, sched.profile)
                )
                t.daemon = True
                t.start()

                # Update schedule timing
                sched.last_run = now
                sched.next_run = calculate_next_run(sched.frequency)
                db.session.commit()
                print(f"[Scheduler] Scan {scan.id} started. Next run: {sched.next_run}")

        except Exception as e:
            print(f"[Scheduler] Error: {e}")


# Start the background scheduler ONLY ONCE using before_first_request
# This prevents multiple scheduler instances in Gunicorn workers
@app.before_request
def start_scheduler_once():
    """Start scheduler only once on first request (prevents Gunicorn worker conflicts)"""
    global _scheduler_started
    if not _scheduler_started:
        try:
            scheduler = BackgroundScheduler()
            scheduler.add_job(run_due_scheduled_scans, "interval", minutes=1, id="scheduled_scans")
            scheduler.start()
            _scheduler_started = True
            print("[Scheduler] Started successfully — checking for due scans every minute")
        except Exception as e:
            print(f"[Scheduler] Warning: Could not start scheduler: {e}")


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
