import requests
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVSS_SEVERITY = {
    (9.0, 10.0): "Critical",
    (7.0,  8.9): "High",
    (4.0,  6.9): "Medium",
    (0.1,  3.9): "Low",
}

def _cvss_to_severity(score: float) -> str:
    for (lo, hi), label in CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return label
    return "Info"


def lookup_cves(port_results: list) -> list:
    """
    For each detected service+version, query the NVD API for CVEs.
    Returns a list of CVE findings.
    """
    findings = []
    queried   = set()

    for p in port_results:
        product = p.get("product", "").strip()
        version = p.get("version", "").strip()
        service = p.get("service", "").strip()
        port    = p.get("port")

        if not product:
            continue

        query_key = f"{product} {version}".strip().lower()
        if query_key in queried:
            continue
        queried.add(query_key)

        keyword = f"{product} {version}".strip() if version else product

        try:
            resp = requests.get(
                NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                timeout=10,
                headers={"User-Agent": "VulnScanner/1.0"}
            )
            if resp.status_code != 200:
                time.sleep(1)
                continue

            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            for v in vulns:
                cve  = v.get("cve", {})
                cve_id = cve.get("id", "")
                descs  = cve.get("descriptions", [])
                desc   = next((d["value"] for d in descs if d["lang"] == "en"), "No description")

                # Extract CVSS score
                cvss_score = None
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        break

                severity = _cvss_to_severity(cvss_score) if cvss_score else "Medium"

                findings.append({
                    "cve_id":      cve_id,
                    "description": desc[:500],
                    "cvss":        cvss_score,
                    "severity":    severity,
                    "port":        port,
                    "service":     service,
                    "product":     product,
                    "version":     version,
                })

            time.sleep(0.6)   # NVD rate limit — 5 req/30s without API key

        except Exception as e:
            print(f"[!] CVE lookup error for {keyword}: {e}")
            continue

    return findings
