# Lab 10 Submission — DefectDojo Vulnerability Management

## Task 1 — DefectDojo Setup and Structure

### 1.2 DefectDojo setup


The application started successfully on `http://localhost:8080`.

---

## Task 2 — Import Prior Findings

### 2.1 Reports used as import sources

The following prior-lab reports were available at the expected paths:

- ZAP: `labs/lab5/zap/zap-report-noauth.json`
- Semgrep: `labs/lab5/semgrep/semgrep-results.json`
- Trivy: `labs/lab4/trivy/trivy-vuln-detailed.json`
- Nuclei: `labs/lab5/nuclei/nuclei-results.json`
- Grype: `labs/lab4/syft/grype-vuln-results.json`



### 2.3 Imported tests and findings summary

The following test imports are present under the `Labs Security Testing` engagement:

| Tool / Test Type | Total Findings | Active (Verified / Fixable) | Mitigated | Notes |
|---|---:|---:|---:|---|
| Anchore Grype | 120 | 120 (0 / 100) | 0 | Dependency/package findings |
| Nuclei Scan | 2 | 2 (0 / 0) | 0 | Small set of web exposure findings |
| Semgrep JSON Report | 25 | 25 (0 / 0) | 0 | Static analysis findings |
| Trivy Scan | 147 | 147 (143 / 127) | 0 | Largest and most verified data source |
| ZAP Scan | 0 | 0 (0 / 0) | 0 | Import completed, but this dataset contained no findings |

Total imported findings in DefectDojo: **294**

### 2.4 Import observations

- The imports completed successfully for all available tools.
- Trivy contributed the largest number of findings and the only large verified subset.
- Grype contributed a large number of fixable dependency findings.
- ZAP imported successfully but did not produce any findings in this dataset, which is acceptable if the source report contained no recognized alerts.

---

## Task 3 — Reporting and Program Metrics

### 3.1 Generated reporting artifacts

The following required artifacts were generated and saved under `labs/lab10/report/`:

- Metrics snapshot: `labs/lab10/report/metrics-snapshot.md`
- Human-readable report: `labs/lab10/report/dojo-report.html`
- Findings export: `labs/lab10/report/findings.csv`

### 3.2 Baseline snapshot

From the engagement dashboard and exported findings data captured on **April 10, 2026**:

| Severity | Open / Active | Closed / Mitigated |
|---|---:|---:|
| Critical | 21 | 0 |
| High | 152 | 0 |
| Medium | 86 | 0 |
| Low | 21 | 0 |
| Informational | 14 | 0 |
| **Total** | **294** | **0** |

Verified vs. mitigated summary:
- The engagement is currently an imported baseline rather than a remediation-tracking state.
- **143** findings are marked as verified.
- **0** findings are mitigated.
- Most verified findings come from the Trivy import.

### 3.3 Findings per tool

| Tool | Findings |
|---|---:|
| Trivy Scan | 147 |
| Anchore Grype | 120 |
| Semgrep JSON Report | 25 |
| Nuclei Scan | 2 |
| ZAP Scan | 0 |

### 3.4 SLA summary

From the exported findings data:

- Findings currently violating SLA: **0**
- Findings due within the next 14 days: **21**
- All 21 near-term SLA items are **Critical** findings.
- The near-term SLA items come from:
  - Anchore Grype: **11**
  - Trivy Scan: **10**

### 3.5 Top recurring CWE categories

The exported findings data did not include clear OWASP labels for every finding, so recurring **CWE** categories were used as the primary taxonomy summary:

| CWE | Count |
|---|---:|
| CWE-1333 | 29 |
| CWE-407 | 13 |
| CWE-22 | 11 |
| CWE-79 | 11 |
| CWE-1321 | 6 |
| CWE-20 | 6 |
| CWE-89 | 6 |
| CWE-674 | 6 |

These recurring categories indicate that the imported dataset is dominated by dependency/package risk, input handling weaknesses, path traversal issues, cross-site scripting, and injection-related weaknesses.

### 3.6 Metric summary bullets for governance review

- DefectDojo was deployed successfully on April 10, 2026, and used to centralize findings for the `Juice Shop` product under the `Labs Security Testing` engagement.
- The engagement contains **294 active findings** and **0 mitigated findings**, which shows that this snapshot represents initial aggregation and triage rather than completed remediation.
- Trivy and Anchore Grype account for the majority of findings, contributing **147** and **120** findings respectively, while Semgrep added **25**, Nuclei added **2**, and ZAP added **0** in this dataset.
- Severity distribution is weighted toward higher-risk items, with **21 Critical** and **152 High** findings currently open.
- No findings are currently in SLA breach, but **21 Critical findings** are due within the next 14 days and should be prioritized first.
- The most frequent recurring weakness categories are **CWE-1333**, **CWE-407**, **CWE-22**, and **CWE-79**, indicating repeated patterns in package security, inefficient resource handling, file/path handling, and client-side web risk.

---
