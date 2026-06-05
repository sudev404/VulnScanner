import socket
import requests
import ftplib
import ssl

TIMEOUT = 5

def enumerate_services(target: str, port_results: list) -> list:
    findings = []
    for p in port_results:
        port    = p["port"]
        service = p.get("service", "").lower()

        if service in ("http", "http-proxy") or port in (80, 8080, 8000, 3000):
            findings += _check_http(target, port, https=False)
        elif service in ("https", "ssl/http") or port in (443, 8443):
            findings += _check_http(target, port, https=True)
        elif service == "ftp" or port == 21:
            findings += _check_ftp(target, port)
        elif service == "ssh" or port == 22:
            findings += _check_ssh(target, port)
        elif service in ("microsoft-ds", "netbios-ssn") or port in (445, 139):
            findings += _check_smb(target, port)
        elif service == "rdp" or port == 3389:
            findings.append({
                "title":       "RDP Exposed",
                "description": f"Remote Desktop Protocol is exposed on port {port}. "
                               "This is a common attack surface for brute force and exploits.",
                "severity":    "High",
                "port":        port,
                "service":     "rdp",
            })
        elif service == "telnet" or port == 23:
            findings.append({
                "title":       "Telnet Service Detected",
                "description": "Telnet transmits data in cleartext including credentials. "
                               "Should be replaced with SSH immediately.",
                "severity":    "Critical",
                "port":        port,
                "service":     "telnet",
            })
    return findings


def _check_http(target, port, https=False):
    findings = []
    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}"
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        headers = r.headers

        # Missing security headers
        security_headers = {
            "X-Frame-Options":          ("Clickjacking Protection Missing",   "Medium"),
            "X-Content-Type-Options":   ("MIME Sniffing Protection Missing",  "Low"),
            "Strict-Transport-Security":("HSTS Header Missing",               "Medium"),
            "Content-Security-Policy":  ("CSP Header Missing",                "Medium"),
            "X-XSS-Protection":         ("XSS Protection Header Missing",     "Low"),
            "Referrer-Policy":          ("Referrer Policy Missing",            "Low"),
        }
        for header, (title, severity) in security_headers.items():
            if header not in headers:
                findings.append({
                    "title":       title,
                    "description": f"The HTTP response is missing the '{header}' security header on {url}.",
                    "severity":    severity,
                    "port":        port,
                    "service":     "http",
                })

        # Server version disclosure
        server = headers.get("Server", "")
        if server:
            findings.append({
                "title":       "Server Version Disclosure",
                "description": f"Server header reveals version info: '{server}'. "
                               "This aids attackers in fingerprinting the target.",
                "severity":    "Low",
                "port":        port,
                "service":     "http",
            })

        # Check for default pages
        body = r.text.lower()
        if any(x in body for x in ["it works!", "apache2 ubuntu default", "welcome to nginx"]):
            findings.append({
                "title":       "Default Web Page Detected",
                "description": "The web server is serving its default installation page, "
                               "indicating the application may not be properly configured.",
                "severity":    "Low",
                "port":        port,
                "service":     "http",
            })

        # SSL check
        if https:
            findings += _check_ssl(target, port)

    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        pass

    return findings


def _check_ssl(target, port):
    findings = []
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=target)
        conn.settimeout(TIMEOUT)
        conn.connect((target, port))
        cert = conn.getpeercert()
        conn.close()

        import datetime
        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days
        if days_left < 30:
            findings.append({
                "title":       "SSL Certificate Expiring Soon",
                "description": f"SSL certificate expires in {days_left} days ({cert['notAfter']}). "
                               "Expired certificates break HTTPS and erode user trust.",
                "severity":    "Medium" if days_left > 0 else "High",
                "port":        port,
                "service":     "https",
            })
    except ssl.SSLCertVerificationError:
        findings.append({
            "title":       "Invalid/Self-Signed SSL Certificate",
            "description": "The SSL certificate is self-signed or invalid. "
                           "This may expose users to MITM attacks.",
            "severity":    "Medium",
            "port":        port,
            "service":     "https",
        })
    except Exception:
        pass
    return findings


def _check_ftp(target, port):
    findings = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=TIMEOUT)
        banner = ftp.getwelcome()
        findings.append({
            "title":       "FTP Banner Disclosure",
            "description": f"FTP banner: {banner}",
            "severity":    "Info",
            "port":        port,
            "service":     "ftp",
        })
        try:
            ftp.login("anonymous", "anonymous@")
            findings.append({
                "title":       "FTP Anonymous Login Allowed",
                "description": "The FTP server allows anonymous login. "
                               "Attackers can list and potentially download files without credentials.",
                "severity":    "High",
                "port":        port,
                "service":     "ftp",
            })
        except ftplib.error_perm:
            pass
        ftp.quit()
    except Exception:
        pass
    return findings


def _check_ssh(target, port):
    findings = []
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((target, port))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        if banner:
            findings.append({
                "title":       "SSH Banner",
                "description": f"SSH version banner: {banner}",
                "severity":    "Info",
                "port":        port,
                "service":     "ssh",
            })
            if "OpenSSH_7." in banner or "OpenSSH_6." in banner:
                findings.append({
                    "title":       "Outdated OpenSSH Version",
                    "description": f"Detected older OpenSSH version: {banner}. "
                                   "Older versions may be vulnerable to known CVEs.",
                    "severity":    "Medium",
                    "port":        port,
                    "service":     "ssh",
                })
    except Exception:
        pass
    return findings


def _check_smb(target, port):
    findings = []
    # Basic SMB exposure check — full enumeration done via crackmapexec
    findings.append({
        "title":       "SMB Service Exposed",
        "description": f"SMB (port {port}) is accessible. "
                       "If misconfigured, SMB can allow unauthenticated access, "
                       "relay attacks, or exploitation via EternalBlue (MS17-010).",
        "severity":    "Medium",
        "port":        port,
        "service":     "smb",
    })
    return findings
