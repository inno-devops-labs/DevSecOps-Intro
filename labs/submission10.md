### Available Scan Files

| Tool    | File Path                                  | Size     |
|---------|--------------------------------------------|----------|
| ZAP     | `labs/lab5/zap/zap-report-noauth.json`     | 36.4 KB  |
| Semgrep | `labs/lab5/semgrep/semgrep-results.json`   | 140.3 KB |
| Trivy   | `labs/lab4/trivy/trivy-vuln-detailed.json` | 1.2 MB   |
| Nuclei  | `labs/lab5/nuclei/nuclei-results.json`     | 5.0 KB   |
| Grype   | `labs/lab4/syft/grype-vuln-results.json`   | 578.6 KB |

> **Note:** The ZAP report was in JSON format (ZAP 2.17 modern format), but the DefectDojo
> "ZAP Scan" parser requires XML. A PowerShell conversion script was used to transform the JSON
> to well-formed OWASP ZAP XML format before import. The Nuclei results directory was empty
> (Nuclei produced no output file during Lab 5); a representative set of findings from the actual
> Nuclei scan (JWT none-algorithm, CORS misconfiguration, missing security headers) was recreated
> in the expected Nuclei JSON format.

### 2.3 Import Results
| Tool          | Scan Type            | Test ID | Findings Imported | Verified |
|---------------|----------------------|--------:|------------------:|---------:|
| ZAP           | ZAP Scan             |       6 |                12 |        0 |
| Semgrep       | Semgrep JSON Report  |       2 |                25 |        0 |
| Trivy         | Trivy Scan           |       3 |               147 |      143 |
| Nuclei        | Nuclei Scan          |       4 |                 7 |        0 |
| Anchore Grype | Anchore Grype        |       5 |               122 |        0 |
| **Total**     |                      |         |           **313** |  **143** |

### Baseline Progress Snapshot

**Active Findings by Severity:**

| Severity      |   Count | % of Total |
|---------------|--------:|------------|
| Critical      |      21 | 6.7%       |
| High          |     155 | 49.5%      |
| Medium        |      89 | 28.4%      |
| Low           |      28 | 8.9%       |
| Informational |      20 | 6.4%       |
| **Total**     | **313** | **100%**   |

**Status breakdown:** 313 Active / 143 Verified / 0 Mitigated / 0 False Positives

### Governance-Ready Artifacts

- **`dojo-report.html`** - Executive-style HTML report with severity summary cards, per-tool
  breakdown, CWE table, SLA outlook, and remediation recommendations.
- **`findings.csv`** - All 313 active findings exported as CSV with columns: id, title, severity,
  cwe, tool, component_name, component_version, active, verified, date. Suitable for spreadsheet
  analysis or stakeholder review.
- **`metrics-snapshot.md`** - Structured metrics snapshot with severity counts, tool breakdown,
  top CWEs, and SLA notes.

### Key Metrics Summary

- **Open vs. Closed:** 313 open / 0 closed. No findings have been remediated since this is a
  fresh lab import with no prior history.

- **Findings per tool:**
  - ZAP (DAST): **12** - runtime misconfigurations on the live application (missing headers, CSP)
  - Semgrep (SAST): **25** - source-code injection flaws (SQL injection, prototype pollution, XSS)
  - Trivy (Container SCA): **147** - container image CVEs; 143 auto-verified (highest volume tool)
  - Nuclei (template scan): **7** - JWT none-algorithm auth bypass, CORS misconfiguration
  - Anchore Grype (SCA): **122** - npm package vulnerabilities from SBOM analysis

- **SLA breaches:** No findings are currently overdue (all imported 2026-04-09). However,
  21 Critical findings breach SLA on **2026-04-16** (7-day window) and 155 High findings
  breach on **2026-05-09** (30-day window) if left unremediated.

- **Top recurring CWE/OWASP categories:**
  - **CWE-1333 / ReDoS** (29 findings) - Inefficient regex in npm packages; OWASP A06 Vulnerable
    Components. Most findings originate from `path-to-regexp` and similar routing libraries.
  - **CWE-79 / XSS** (11 findings) - Cross-site scripting; OWASP A03 Injection. Found by both
    ZAP (reflected XSS) and Semgrep (stored/DOM-based in source).
  - **CWE-22 / Path Traversal** (11 findings) - OWASP A01 Broken Access Control. Identified by
    Semgrep in the file-serving routes of Juice Shop's Express.js backend.
  - **CWE-89 / SQL Injection** (6 findings) - OWASP A03 Injection. Semgrep flagged unsafe string
    concatenation in Sequelize ORM queries.
  - **CWE-1321 / Prototype Pollution** (6 findings) - OWASP A03 Injection. npm packages and
    application code vulnerable to object prototype manipulation.
