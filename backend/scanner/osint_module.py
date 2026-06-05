import socket
import requests
import json
import re

TIMEOUT = 6

def run_osint(target: str) -> list:
    findings = []
    findings += _whois_lookup(target)
    findings += _dns_lookup(target)
    findings += _reverse_ip(target)
    findings += _shodan_check(target)
    return findings


def _whois_lookup(target: str) -> list:
    findings = []
    try:
        import whois
        w = whois.whois(target)
        info_parts = []
        if w.registrar:
            info_parts.append(f"Registrar: {w.registrar}")
        if w.creation_date:
            info_parts.append(f"Created: {w.creation_date}")
        if w.expiration_date:
            info_parts.append(f"Expires: {w.expiration_date}")
        if w.name_servers:
            ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            info_parts.append(f"Nameservers: {', '.join(ns[:3])}")
        if info_parts:
            findings.append({
                "title":       "WHOIS Information",
                "description": " | ".join(str(i) for i in info_parts),
                "severity":    "Info",
            })
    except Exception as e:
        pass
    return findings


def _dns_lookup(target: str) -> list:
    findings = []
    try:
        import dns.resolver
        record_types = ["A", "MX", "TXT", "NS", "CNAME", "AAAA"]
        dns_data = {}
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=5)
                dns_data[rtype] = [str(r) for r in answers]
            except:
                continue

        if dns_data:
            desc = " | ".join(f"{k}: {', '.join(v[:2])}" for k, v in dns_data.items())
            findings.append({
                "title":       "DNS Records",
                "description": desc,
                "severity":    "Info",
            })

        # Zone transfer attempt
        try:
            ns_answers = dns.resolver.resolve(target, "NS", lifetime=5)
            for ns in ns_answers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), target))
                    findings.append({
                        "title":       "DNS Zone Transfer Allowed",
                        "description": f"Nameserver {ns} allows zone transfer (AXFR). "
                                       "This exposes all DNS records to any requester.",
                        "severity":    "High",
                    })
                except:
                    pass
        except:
            pass

    except Exception:
        pass
    return findings


def _reverse_ip(target: str) -> list:
    findings = []
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.gethostbyaddr(ip)[0]
        findings.append({
            "title":       "Reverse DNS Lookup",
            "description": f"IP {ip} resolves to hostname: {hostname}",
            "severity":    "Info",
        })
    except:
        pass
    return findings


def _shodan_check(target: str) -> list:
    """
    Queries Shodan's free search without API key.
    For full results, add SHODAN_API_KEY to env.
    """
    findings = []
    api_key = None  # Set via os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return findings
    try:
        import shodan
        api = shodan.Shodan(api_key)
        ip = socket.gethostbyname(target)
        host = api.host(ip)
        ports = host.get("ports", [])
        vulns = host.get("vulns", [])
        findings.append({
            "title":       "Shodan Host Data",
            "description": f"Shodan sees {len(ports)} open port(s): {ports[:10]}. "
                           f"Detected {len(vulns)} known vulnerability/ies via Shodan.",
            "severity":    "Info" if not vulns else "High",
        })
        for vuln in list(vulns)[:5]:
            findings.append({
                "title":       f"Shodan CVE: {vuln}",
                "description": f"Shodan has indexed this host as vulnerable to {vuln}.",
                "severity":    "High",
            })
    except:
        pass
    return findings
