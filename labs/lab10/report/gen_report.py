#!/usr/bin/env python3
import json

with open('/tmp/dd_findings.json') as f:
    data = json.load(f)

findings = data['results']
total = data['count']

# Severity counts
sev_counts = {}
for finding in findings:
    s = finding['severity']
    sev_counts[s] = sev_counts.get(s, 0) + 1

# Test -> tool mapping
test_map = {2: 'Semgrep', 3: 'Trivy', 4: 'Nuclei', 5: 'Grype', 6: 'ZAP'}
tool_counts = {}
for finding in findings:
    tool = test_map.get(finding['test'], 'Test #' + str(finding['test']))
    tool_counts[tool] = tool_counts.get(tool, 0) + 1

# CWE counts
cwe_counts = {}
for finding in findings:
    c = finding.get('cwe', 0)
    if c and c > 0:
        cwe_counts[c] = cwe_counts.get(c, 0) + 1
top_cwes = sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]

severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
severity_colors = {
    'Critical': '#d32f2f', 'High': '#f57c00', 'Medium': '#fbc02d',
    'Low': '#388e3c', 'Info': '#1976d2'
}
cwe_names = {
    1333: 'ReDoS', 407: 'Algorithmic Complexity', 22: 'Path Traversal',
    20: 'Improper Input Validation', 79: 'XSS', 674: 'Uncontrolled Recursion',
    1321: 'Prototype Pollution', 400: 'Uncontrolled Resource Consumption',
    94: 'Code Injection', 89: 'SQL Injection', 693: 'Protection Mechanism Failure',
    319: 'Cleartext Transmission', 1004: 'Sensitive Cookie Without HttpOnly',
    614: 'Sensitive Cookie Without Secure', 565: 'Reliance on Cookies',
    601: 'Open Redirect', 200: 'Information Exposure', 942: 'Permissive CORS',
    1021: 'Clickjacking', 502: 'Deserialization', 95: 'Eval Injection',
    798: 'Hardcoded Credentials'
}

# Build report HTML
lines = []
lines.append('<!DOCTYPE html>')
lines.append('<html><head><meta charset="utf-8"><title>DefectDojo Executive Report</title>')
lines.append('<style>')
lines.append('body { font-family: Arial, sans-serif; margin: 40px; color: #333; }')
lines.append('h1 { color: #1a237e; border-bottom: 3px solid #1a237e; padding-bottom: 10px; }')
lines.append('h2 { color: #283593; margin-top: 30px; }')
lines.append('table { border-collapse: collapse; margin: 15px 0; width: 100%; }')
lines.append('th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }')
lines.append('th { background: #e8eaf6; font-weight: bold; }')
lines.append('.sev { padding: 3px 10px; border-radius: 4px; color: white; font-weight: bold; }')
lines.append('.box { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0; }')
lines.append('.stat { display: inline-block; margin: 10px 20px; text-align: center; }')
lines.append('.stat .num { font-size: 2em; font-weight: bold; }')
lines.append('.stat .lbl { font-size: 0.9em; color: #666; }')
lines.append('footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; }')
lines.append('</style></head><body>')
lines.append('<h1>DefectDojo Executive Security Report</h1>')
lines.append('<p><strong>Product:</strong> Juice Shop | <strong>Engagement:</strong> Labs Security Testing | <strong>Date:</strong> April 13, 2026</p>')

lines.append('<h2>Executive Summary</h2>')
lines.append('<div class="box">')
lines.append('<p>This report consolidates vulnerability findings from <strong>5 security scanning tools</strong> (ZAP, Semgrep, Trivy, Nuclei, Grype) imported into OWASP DefectDojo for the Juice Shop application.</p>')
lines.append('<div>')
for sev in severity_order:
    c = sev_counts.get(sev, 0)
    color = severity_colors.get(sev, '#999')
    lines.append(f'<div class="stat"><div class="num" style="color:{color}">{c}</div><div class="lbl">{sev}</div></div>')
lines.append('</div>')
lines.append(f'<p><strong>Total active findings: {total}</strong> | All Open (none closed/mitigated yet).</p>')
lines.append('</div>')

lines.append('<h2>Findings by Severity</h2>')
lines.append('<table><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>')
for sev in severity_order:
    c = sev_counts.get(sev, 0)
    pct = round(c / total * 100, 1) if total else 0
    color = severity_colors.get(sev, '#999')
    lines.append(f'<tr><td><span class="sev" style="background:{color}">{sev}</span></td><td>{c}</td><td>{pct}%</td></tr>')
lines.append(f'<tr style="font-weight:bold"><td>Total</td><td>{total}</td><td>100%</td></tr></table>')

lines.append('<h2>Findings by Tool</h2>')
lines.append('<table><tr><th>Tool</th><th>Findings</th><th>Share</th></tr>')
for tool in ['ZAP', 'Semgrep', 'Trivy', 'Nuclei', 'Grype']:
    c = tool_counts.get(tool, 0)
    pct = round(c / total * 100, 1) if total else 0
    lines.append(f'<tr><td>{tool}</td><td>{c}</td><td>{pct}%</td></tr>')
lines.append('</table>')

lines.append('<h2>Top CWE Categories</h2>')
lines.append('<table><tr><th>CWE ID</th><th>Count</th></tr>')
for cwe, count in top_cwes:
    name = cwe_names.get(cwe, '')
    label = f'CWE-{cwe}: {name}' if name else f'CWE-{cwe}'
    lines.append(f'<tr><td>{label}</td><td>{count}</td></tr>')
lines.append('</table>')

lines.append('<h2>SLA and Risk Outlook</h2>')
lines.append('<div class="box"><ul>')
lines.append('<li><strong>Critical findings (21):</strong> Require immediate attention within 7 days per standard SLA.</li>')
lines.append('<li><strong>High findings (153):</strong> Should be triaged and remediated within 30 days.</li>')
lines.append('<li><strong>No findings are currently closed or mitigated</strong> - initial import baseline.</li>')
lines.append('<li><strong>Next review date:</strong> April 27, 2026 (14 days from capture).</li>')
lines.append('</ul></div>')

lines.append('<h2>Recommendations</h2><ol>')
lines.append('<li><strong>Patch dependencies:</strong> Update vulnerable npm and OS packages (Trivy/Grype).</li>')
lines.append('<li><strong>Fix injection flaws:</strong> Address SQL injection and XSS (ZAP/Semgrep).</li>')
lines.append('<li><strong>Harden security headers:</strong> Implement CSP, HSTS, X-Frame-Options.</li>')
lines.append('<li><strong>Remove hardcoded secrets:</strong> Rotate and externalize JWT secrets.</li>')
lines.append('<li><strong>Establish deduplication:</strong> Review Trivy/Grype overlaps to reduce noise.</li>')
lines.append('</ol>')

lines.append('<footer><p>Generated from OWASP DefectDojo | Product: Juice Shop | Report date: April 13, 2026</p></footer>')
lines.append('</body></html>')

with open('labs/lab10/report/dojo-report.html', 'w') as out:
    out.write('\n'.join(lines))
print('Report generated successfully')

