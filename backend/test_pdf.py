from reports.report_gen import generate_pdf_report

# Sample data
test_scan = {
    'id': 'test123',
    'target': '192.168.196.1',
    'risk_score': 25,
    'risk_level': 'Medium'
}

test_findings = [
    {
        'severity': 'Critical',
        'title': 'Open Port 445/tcp',
        'category': 'Network Service',
        'port': 445,
        'service': 'microsoft-ds',
        'description': 'Port 445 is open running microsoft-ds',
        'remediation': 'Close port 445 if not required or restrict access'
    }
]

# Generate PDF
pdf_path = generate_pdf_report(test_scan, test_findings)
print(f"PDF generated at: {pdf_path}")