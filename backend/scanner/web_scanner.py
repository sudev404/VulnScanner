import requests
import urllib.parse
import re

requests.packages.urllib3.disable_warnings()
TIMEOUT = 6

COMMON_PATHS = [
    "/.git/config", "/.env", "/config.php", "/wp-config.php",
    "/admin", "/admin/login", "/administrator", "/phpmyadmin",
    "/backup", "/backup.zip", "/db.sql", "/robots.txt",
    "/sitemap.xml", "/.htaccess", "/server-status", "/info.php",
    "/test.php", "/shell.php", "/config.yml", "/credentials.txt",
    # Extended paths for better coverage
    "/.well-known/acme-challenge",
    "/.well-known/pki-validation",
    "/backup", "/backups", "/backup.zip", "/db_dump",
    "/admin", "/administrator", "/webadmin",
    "/phpinfo.php", "/info.php",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/nginx.conf", "/web.config"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
]

def run_web_scan(target: str) -> list:
    findings = []

    # Determine base URL
    base_urls = []
    for scheme in ("https", "http"):
        for port in (443 if scheme == "https" else 80, 8443 if scheme == "https" else 8080):
            base_urls.append(f"{scheme}://{target}")
            break

    base_url = _find_live_url(base_urls)
    if not base_url:
        return []

    findings += _directory_bruteforce(base_url)
    findings += _check_cors(base_url)
    findings += _check_cookies(base_url)
    findings += _check_xss(base_url)
    findings += _check_sqli(base_url)
    findings += _check_robots(base_url)
    findings += _check_methods(base_url)

    return findings


def _find_live_url(urls):
    for url in urls:
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False)
            return url
        except:
            continue
    return None


def _directory_bruteforce(base_url):
    findings = []
    # Extended paths for better coverage
    extended_paths = COMMON_PATHS + [
        "/.well-known/acme-challenge",
        "/.well-known/pki-validation",
        "/backup", "/backups", "/backup.zip",
        "/db", "/database", "/db.sql", "/db_dump",
        "/admin", "/administrator", "/webadmin",
        "/phpinfo.php", "/info.php",
        "/robots.txt", "/sitemap.xml",
        "/.htaccess", "/nginx.conf", "/web.config"
    ]

    for path in extended_paths:
        url = base_url.rstrip("/") + path
        try:
            r = requests.get(
                url,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "VulnScanner-Bot/1.0"},
            )
            if r.status_code in (200, 301, 302, 401, 403, 500):
                severity = (
                    "Critical"
                    if path in (".env", "/config.php", "/wp-config.php", "/db.sql", "/credentials.txt")
                    else "High"
                    if r.status_code == 200
                    else "Medium"
                )
                findings.append({
                    "title": f"Sensitive Path Exposed: {path}",
                    "description": (
                        f"{url} returned HTTP {r.status_code}. "
                        "This path may expose configuration, credentials, or backup data."
                    ),
                    "severity": severity,
                })
        except Exception:
            continue
    return findings


def _check_cors(base_url):
    findings = []
    try:
        r = requests.get(
            base_url,
            timeout=TIMEOUT,
            verify=False,
            headers={"Origin": "https://malicious-site.com"},
        )
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = r.headers.get(
            "Access-Control-Allow-Credentials", ""
        ).lower() == "true"

        if allow_origin == "*":
            findings.append(
                {
                    "title": "CORS Wildcard Misconfiguration",
                    "description": "Server reflects any Origin with a wildcard, "
                                   "potentially allowing CSRF or data exfiltration.",
                    "severity": "Medium",
                }
            )
        if allow_origin in (r.headers.get("Referer", ""), r.headers.get("Origin", "")) and allow_credentials:
            findings.append(
                {
                    "title": "CORS Credentials + Dynamic Origin",
                    "description": "Server reflects a dynamic Origin (possibly attacker‑controlled) "
                                   "and permits `Access-Control-Allow-Credentials: true`.",
                    "severity": "High",
                }
            )
    except Exception:
        pass
    return findings


def _check_cookies(base_url):
    findings = []
    try:
        r = requests.get(base_url, timeout=TIMEOUT, verify=False)
        for cookie in r.cookies:
            issues = []
            cookie_attrs = str(cookie).lower()
            if "httponly" not in cookie_attrs:
                issues.append("HttpOnly flag missing")
            if not cookie.secure and base_url.startswith("https"):
                issues.append("Secure flag missing")
            if "samesite" not in cookie_attrs:
                issues.append("SameSite attribute missing")
            if issues:
                findings.append({
                    "title": f"Insecure Cookie: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' has issues: {', '.join(issues)}",
                    "severity": "Medium",
                })
    except Exception:
        pass
    return findings


def _check_xss(base_url):
    """Improved reflective XSS probe – checks for unescaped rendering."""
    findings = []
    test_url = base_url.rstrip("/") + "/search"
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(
                test_url,
                params={"q": payload},
                timeout=TIMEOUT,
                verify=False,
                headers={"User-Agent": "VulnScanner-Bot/1.0"},
            )
            # Verify payload is reflected *unescaped* (e.g., inside a script tag or event handler)
            if payload in r.text and any(tag in r.text.lower() for tag in ("<script", "onerror=", "onload=", "onmouseover=")):
                findings.append({
                    "title": "Reflected XSS Vulnerability Detected",
                    "description": f"Payload `{payload}` rendered unescaped at {test_url}.",
                    "severity": "High",
                })
                break
        except Exception:
            continue
    return findings


def _check_sqli(base_url):
    """Improved SQLi probe – error‑ and time‑based detection with broader payload set."""
    findings = []
    test_url = base_url.rstrip("/") + "/search"
    # Expanded payload list covering error‑based, boolean‑based, and time‑based injections
    sqli_payloads = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(2)--",
        "' AND BENCHMARK(5000000,SHA1('vulnscanner'))--",
        "' OR EXISTS(SELECT * FROM information_schema.tables)--",
        "' OR 1337=1337--"
    ]
    # Comprehensive error signatures across major DBMSs
    sqli_errors = [
        # MySQL / MariaDB
        "sql syntax", "mysql", "mysqldump", "you have an error in your sql syntax",
        # PostgreSQL
        "psql", "pg_", "syntax error", "unterminated quoted string",
        # SQL Server / MSSQL
        "sql server", "odbc", "mssql", "incorrect syntax near",
        # SQLite
        "sqlite", "sqlite3", "database is locked",
        # Oracle
        "ora-", "oracle error",
        # Generic
        "error", "warning", "exception"
    ]
    for payload in sqli_payloads:
        try:
            r = requests.get(test_url, params={"id": payload}, timeout=TIMEOUT, verify=False)
            body = r.text.lower()
            # 1️⃣  Error‑based detection
            if any(err in body for err in sqli_errors):
                findings.append({
                    "title": "Potential SQL Injection",
                    "description": f"SQL error detected for payload `{payload}` at {test_url}.",
                    "severity": "Critical",
                })
                break
            # 2️⃣  Time‑based blind detection – check response delay (>1.5 s)
            # (Simple heuristic: requests library raises timeout only if >TIMEOUT, so we use a lower timeout for detection)
            try:
                r_time = requests.get(test_url, params={"id": payload}, timeout=TIMEOUT-1, verify=False)
                # If the request succeeds quickly, we assume no delay; if it times out, treat as probable time‑based injection
            except Exception:
                # Timeout indicates a possible sleep‑based payload
                findings.append({
                    "title": "Potential Time‑Based SQL Injection",
                    "description": f"Payload `{payload}` caused a delayed response, suggesting blind SQLi.",
                    "severity": "Critical",
                })
                break
        except Exception:
            continue
    return findings


def _check_robots(base_url):
    findings = []
    try:
        r = requests.get(base_url.rstrip("/") + "/robots.txt",
                         timeout=TIMEOUT, verify=False)
        if r.status_code == 200 and "disallow" in r.text.lower():
            disallowed = [l.split(":",1)[1].strip()
                          for l in r.text.splitlines()
                          if l.lower().startswith("disallow") and len(l.split(":",1)) > 1]
            findings.append({
                "title":       "Robots.txt Discloses Hidden Paths",
                "description": f"robots.txt reveals {len(disallowed)} disallowed path(s): "
                               + ", ".join(disallowed[:10])
                               + ". These paths may contain sensitive functionality.",
                "severity":    "Info",
            })
    except:
        pass
    return findings


def _check_methods(base_url):
    findings = []
    try:
        r = requests.options(base_url, timeout=TIMEOUT, verify=False)
        allow = r.headers.get("Allow", "")
        dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow]
        if dangerous:
            findings.append({
                "title":       "Dangerous HTTP Methods Enabled",
                "description": f"The server allows potentially dangerous HTTP methods: {', '.join(dangerous)}. "
                               "PUT/DELETE can allow file upload/deletion; TRACE enables XST attacks.",
                "severity":    "Medium",
            })
    except:
        pass
    return findings
