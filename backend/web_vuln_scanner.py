"""
web_vuln_scanner.py
──────────────────────────────────────────────────────────────────────────────
Drop-in replacement scan logic for VulnScanner's run_scan_background().

Fixes:
  1. URL vs hostname — extract hostname before nmap so nmap doesn't silently fail.
  2. Web vuln detection — SQLi, XSS, open-redirect, security headers, info leakage.

Usage: copy this file next to app.py, then in app.py:
    from web_vuln_scanner import run_scan_background   # replaces the old one
──────────────────────────────────────────────────────────────────────────────
"""

import uuid
import requests
import re
import nmap
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from datetime import datetime

# ── Only import db / Scan / Finding inside app context (passed via flask_app) ──


# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

TIMEOUT = 10  # seconds per HTTP request

# SQL Injection payloads (error-based detection)
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' AND 1=CONVERT(int,@@version)--",
    "1 AND 1=2 UNION SELECT NULL--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"pg_query\(\).*failed",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array\(\)",
    r"ora-\d{5}",          # Oracle errors
    r"db2 sql error",
    r"sqlite3?.*error",
    r"syntax error.*near",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
]

# Open redirect payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

# Security headers that should be present
EXPECTED_HEADERS = {
    "X-Frame-Options":           ("Medium", 8,  "Clickjacking protection missing"),
    "X-Content-Type-Options":    ("Low",    3,  "MIME-sniffing protection missing"),
    "Content-Security-Policy":   ("High",   15, "No Content Security Policy set"),
    "Strict-Transport-Security": ("Medium", 8,  "HSTS header missing"),
    "X-XSS-Protection":          ("Low",    3,  "XSS filter header missing"),
    "Referrer-Policy":           ("Low",    3,  "Referrer-Policy header missing"),
}

# Information leakage patterns in response body
INFO_LEAK_PATTERNS = {
    r"(exception|stack trace|traceback).*line \d+": (
        "High", 15,
        "Stack Trace Disclosure",
        "Application error messages leak internal stack traces.",
    ),
    r"(password|passwd|pwd)\s*[:=]\s*\S+": (
        "Critical", 25,
        "Credential Disclosure",
        "Response may contain plaintext credentials.",
    ),
    r"(AWS_ACCESS_KEY|api_key|apikey|secret_key)\s*[:=]\s*['\"]?\w{10,}": (
        "Critical", 25,
        "API Key / Secret Disclosure",
        "A secret key or API token appears in the response.",
    ),
    r"phpinfo\(\)": (
        "Medium", 8,
        "PHP Info Disclosure",
        "phpinfo() output exposes server configuration.",
    ),
}

# Ports scored by nmap findings
PORT_SEVERITY = {
    frozenset([21, 23, 445, 3389, 5900]): ("Critical", 25),
    frozenset([22, 80, 8080, 1433, 3306]): ("High", 15),
    frozenset([443, 8443, 25, 110, 143]):  ("Medium", 8),
}


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _is_url(target: str) -> bool:
    return target.startswith(("http://", "https://"))


def _extract_hostname(target: str) -> str:
    """Return bare hostname/IP for nmap."""
    parsed = urlparse(target)
    return parsed.hostname or target


def _safe_get(url, params=None, timeout=TIMEOUT):
    """GET with a browser-like UA; returns Response or None."""
    headers = {"User-Agent": "Mozilla/5.0 VulnScanner/1.0"}
    try:
        return requests.get(url, params=params, headers=headers,
                            timeout=timeout, allow_redirects=True,
                            verify=False)
    except Exception:
        return None


def _extract_params(url: str) -> dict:
    """Return query-string parameters as {name: [values]} dict."""
    return parse_qs(urlparse(url).query)


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a new URL with `param` replaced by `payload`."""
    from urllib.parse import urlunparse, quote
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


# ════════════════════════════════════════════════════════════════════════════
# WEB VULNERABILITY CHECKS
# ════════════════════════════════════════════════════════════════════════════

def check_sqli(url: str) -> list:
    """
    Error-based SQL injection detection.
    Returns list of finding dicts.
    """
    findings = []
    params = _extract_params(url)
    if not params:
        return findings

    baseline = _safe_get(url)
    if not baseline:
        return findings

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            resp = _safe_get(test_url)
            if not resp:
                continue
            body_lower = resp.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body_lower):
                    findings.append({
                        "title": f"SQL Injection – parameter '{param}'",
                        "description": (
                            f"Parameter '{param}' appears vulnerable to SQL injection. "
                            f"Payload `{payload}` triggered a database error pattern matching "
                            f"`{pattern}`. Manual confirmation recommended."
                        ),
                        "severity": "Critical",
                        "cvss_score": 9.8,
                        "risk_score": 30,
                        "service": "http",
                        "port": str(urlparse(url).port or (443 if url.startswith("https") else 80)),
                    })
                    # One finding per param is enough
                    break
            else:
                continue
            break

    return findings


def check_xss(url: str) -> list:
    """Reflected XSS detection."""
    findings = []
    params = _extract_params(url)
    if not params:
        return findings

    for param in params:
        for payload in XSS_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            resp = _safe_get(test_url)
            if resp and payload in resp.text:
                findings.append({
                    "title": f"Reflected XSS – parameter '{param}'",
                    "description": (
                        f"Parameter '{param}' reflects user input without encoding. "
                        f"Payload `{payload}` appeared verbatim in the response body."
                    ),
                    "severity": "High",
                    "cvss_score": 7.5,
                    "risk_score": 20,
                    "service": "http",
                    "port": str(urlparse(url).port or (443 if url.startswith("https") else 80)),
                })
                break  # one finding per param

    return findings


def check_security_headers(url: str) -> list:
    """Check for missing security headers on the base URL."""
    findings = []
    resp = _safe_get(url)
    if not resp:
        return findings

    for header, (severity, score, description) in EXPECTED_HEADERS.items():
        if header.lower() not in {k.lower() for k in resp.headers}:
            findings.append({
                "title": f"Missing Security Header: {header}",
                "description": description,
                "severity": severity,
                "cvss_score": 7.0 if severity == "High" else 5.0 if severity == "Medium" else 3.0,
                "risk_score": score,
                "service": "http",
                "port": str(urlparse(url).port or (443 if url.startswith("https") else 80)),
            })

    # Check if server version is leaked
    server = resp.headers.get("Server", "")
    if re.search(r"[\d.]{3,}", server):  # version number present
        findings.append({
            "title": "Server Version Disclosure",
            "description": f"Server header discloses version information: '{server}'. "
                           "Attackers can use this to target known CVEs.",
            "severity": "Low",
            "cvss_score": 3.0,
            "risk_score": 3,
            "service": "http",
            "port": str(urlparse(url).port or (443 if url.startswith("https") else 80)),
        })

    return findings


def check_info_leakage(url: str) -> list:
    """Look for sensitive info in response body."""
    findings = []
    resp = _safe_get(url)
    if not resp:
        return findings

    for pattern, (severity, score, title, description) in INFO_LEAK_PATTERNS.items():
        if re.search(pattern, resp.text, re.IGNORECASE):
            findings.append({
                "title": title,
                "description": description,
                "severity": severity,
                "cvss_score": 9.0 if severity == "Critical" else 7.0 if severity == "High" else 5.0,
                "risk_score": score,
                "service": "http",
                "port": str(urlparse(url).port or (443 if url.startswith("https") else 80)),
            })

    return findings


def check_open_redirect(url: str) -> list:
    """Check query params for open redirect."""
    findings = []
    params = _extract_params(url)
    redirect_params = [p for p in params if p.lower() in
                       ("redirect", "url", "next", "return", "goto", "dest", "destination", "rurl")]
    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            resp = _safe_get(test_url)
            if resp and urlparse(resp.url).netloc in ("evil.com",):
                findings.append({
                    "title": f"Open Redirect – parameter '{param}'",
                    "description": (
                        f"Parameter '{param}' allows redirection to external domains. "
                        "This can be used in phishing attacks."
                    ),
                    "severity": "Medium",
                    "cvss_score": 6.1,
                    "risk_score": 10,
                    "service": "http",
                    "port": str(urlparse(url).port or 80),
                })
                break

    return findings


# ════════════════════════════════════════════════════════════════════════════
# NMAP PORT SCAN
# ════════════════════════════════════════════════════════════════════════════

def run_nmap_scan(hostname: str, profile: str) -> list:
    """
    Run nmap against bare hostname/IP.
    Returns list of finding dicts.
    """
    args_map = {
        "quick":   "-T4 -F",
        "full":    "-T4 -A",
        "stealth": "-T2 -sS",
        "web":     "-T4 -p 80,443,8080,8443",
    }
    findings = []
    try:
        nm = nmap.PortScanner(nmap_search_path=("/usr/bin/nmap",))
        nm.scan(hostname, arguments=args_map.get(profile, "-T4 -F"))

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info = nm[host][proto][port]
                    if info["state"] != "open":
                        continue

                    service = info.get("name", "unknown")
                    product = info.get("product", "")
                    version = info.get("version", "")

                    # Determine severity
                    if port in (21, 23, 445, 3389, 5900):
                        severity, score = "Critical", 25
                    elif port in (22, 80, 8080, 1433, 3306):
                        severity, score = "High", 15
                    elif port in (443, 8443, 25, 110, 143):
                        severity, score = "Medium", 8
                    else:
                        severity, score = "Low", 3

                    findings.append({
                        "title": f"Open Port {port}/{proto} – {service}",
                        "description": f"Port {port} is open running {service} {product} {version}".strip(),
                        "severity": severity,
                        "cvss_score": 9.0 if severity == "Critical" else 7.0
                                      if severity == "High" else 5.0 if severity == "Medium" else 3.0,
                        "risk_score": score,
                        "service": service,
                        "port": str(port),
                    })
    except Exception as e:
        print(f"[nmap] error: {e}")

    return findings


# ════════════════════════════════════════════════════════════════════════════
# MAIN BACKGROUND FUNCTION  (drop-in for app.py)
# ════════════════════════════════════════════════════════════════════════════

def run_scan_background(flask_app, scan_id, target, profile):
    """
    Run a comprehensive scan in background and update DB.

    Strategy:
      - Always run nmap against the bare hostname.
      - If target looks like a URL, also run all web checks.
    """
    with flask_app.app_context():
        # Late import to stay inside app context
        from models.database import db, Scan, Finding

        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return

            scan.status = "running"
            db.session.commit()

            all_findings_data = []

            # ── 1. nmap port scan ───────────────────────────────────────────
            hostname = _extract_hostname(target)
            nmap_findings = run_nmap_scan(hostname, profile)
            all_findings_data.extend(nmap_findings)

            # ── 2. Web vulnerability checks (only if target is a URL) ───────
            if _is_url(target):
                all_findings_data.extend(check_security_headers(target))
                all_findings_data.extend(check_sqli(target))
                all_findings_data.extend(check_xss(target))
                all_findings_data.extend(check_info_leakage(target))
                all_findings_data.extend(check_open_redirect(target))

            # ── 3. Persist findings ─────────────────────────────────────────
            total_risk = 0
            for fd in all_findings_data:
                total_risk += fd.pop("risk_score", 0)
                f = Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    title=fd["title"],
                    description=fd["description"],
                    severity=fd["severity"],
                    cvss_score=fd.get("cvss_score", 5.0),
                    port=fd.get("port"),
                    service=fd.get("service"),
                )
                db.session.add(f)

            # ── 4. Update scan record ───────────────────────────────────────
            scan.status = "completed"
            scan.risk_score = min(total_risk, 100)
            scan.risk_level = (
                "Critical" if total_risk >= 75 else
                "High"     if total_risk >= 50 else
                "Medium"   if total_risk >= 25 else
                "Low"
            )
            scan.completed_at = datetime.utcnow()
            db.session.commit()

        except Exception as e:
            print(f"[scan] fatal error: {e}")
            try:
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = "failed"
                    db.session.commit()
            except Exception:
                pass
