# Lab 10 — Submission: Vulnerability Management with DefectDojo

## Task 1: DefectDojo Setup + Scan Imports

### Environment
- DefectDojo v2.58.x running via `docker compose up -d` at http://localhost:8080
- Admin password retrieved from initializer logs: `docker compose logs initializer | grep -i password`
- Admin password: `[REDACTED]`
- API token obtained via Profile → API v2 Key

### Product + Engagement
- **Product ID:** 1 — "OWASP Juice Shop"
- **Engagement ID:** 1 — "Labs 4-9 Capstone" (2026-06-01 → 2026-07-04, CI/CD type)
- Deduplication enabled: `deduplication_on_engagement: true`

### Imports table

| Lab | Scan type (DefectDojo) | File | Findings |
|-----|----------------------|------|-------:|
| 4 | Trivy Scan | trivy.json | 112 |
| 4 | Anchore Grype | grype-from-sbom.json | 103 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.xml | 10 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | results.json | 10 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Scan (k8s config) | trivy-k8s.json | 3 |
| **Total raw imports** | | | **390** |
| **After dedup** | | | **390** |

Note: DefectDojo deduplication requires identical title+component strings across tools. Trivy and Grype use different title formats (e.g. `CVE-2023-46233 Crypto-Js 3.3.0` vs `GHSA-xwcq-pm8m-c4vf in crypto-js:3.3.0`) so automatic dedup did not merge them. Manual cross-tool correlation is documented below.

### Dedup example (cross-tool correlation)

The same underlying vulnerability was reported by both Trivy (test=1) and Anchore Grype (test=10):

- **CVE/ID:** `GHSA-5mrr-rgp6-x4gr` (marsdb 0.6.11 — NoSQL injection)
- **Source tools:** 2 — Trivy Scan (finding id=60) + Anchore Grype (finding id=372)
- **Severity:** Critical in both tools
- **Why not auto-deduped:** Trivy title = `GHSA-5mrr-rgp6-x4gr Marsdb 0.6.11`; Grype title = `GHSA-5mrr-rgp6-x4gr in marsdb:0.6.11` — different string format prevents hash match
- **Manual dedup action:** Marked Grype finding id=372 as duplicate of Trivy finding id=60 in DefectDojo UI

Second example — same CVE, three representations:
- **CVE/ID:** `CVE-2023-46233` / `GHSA-xwcq-pm8m-c4vf` (crypto-js 3.3.0)
- **Source tools:** Trivy (id=35) + Grype (id=299)
- **Severity:** Critical in both

---

## Task 2: Governance Report

### SLA Matrix Applied
Configuration "DevSecOps Course SLA" (ID: 3) applied via API:

| Severity | SLA (days) |
|----------|----------:|
| Critical | 1 |
| High | 7 |
| Medium | 30 |
| Low | 90 |

### Executive Summary
390 raw findings were imported from 8 scan types across Labs 4-9, covering SCA (Trivy, Grype), SAST (Semgrep), DAST (ZAP), IaC (Checkov, KICS), and container image hardening. The backlog is dominated by High and Medium severity dependency vulnerabilities in OWASP Juice Shop's npm dependency tree — expected for a deliberately vulnerable application. Critical findings (17 total) are the immediate remediation priority under the 24-hour SLA.

### Findings by severity

| Severity | Count | % of total | SLA |
|----------|------:|-----------:|-----|
| Critical | 17 | 4.4% | 24 hours |
| High | 160 | 41.0% | 7 days |
| Medium | 169 | 43.3% | 30 days |
| Low | 34 | 8.7% | 90 days |
| Info | 10 | 2.6% | N/A |
| **Total** | **390** | 100% | |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Trivy Scan (Lab 4) | 112 | 0 | 0 | 0 |
| Anchore Grype (Lab 4) | 103 | 0 | 0 | 0 |
| Checkov Scan (Lab 6) | 80 | 0 | 0 | 0 |
| Trivy Scan image (Lab 7) | 50 | 0 | 0 | 0 |
| Semgrep (Lab 5) | 22 | 0 | 0 | 0 |
| KICS Scan (Lab 6) | 10 | 0 | 0 | 0 |
| ZAP Scan (Lab 5) | 10 | 0 | 0 | 0 |
| Trivy Scan k8s (Lab 7) | 3 | 0 | 0 | 0 |

### Program metrics

Since this is a lab environment with a single-day import session (all findings imported 2026-07-04), MTTD/MTTR are based on the Lab 4 scan date (2026-06-17) as the detection baseline:

- **MTTD** (Mean Time to Detect): ~17 days (from Juice Shop v20.0.0 release to first scan in Lab 4)
- **MTTR** (Mean Time to Remediate): N/A — no findings have been mitigated in this engagement (Juice Shop is intentionally vulnerable; remediation is out of scope for the lab)
- **Vuln-age median** (open findings): 17 days (all findings detected 2026-06-17)
- **Backlog trend**: +390 findings (baseline = 0, first engagement)
- **SLA compliance**: 0% for Critical/High (no findings closed within SLA window) — expected given Juice Shop is a deliberately vulnerable demo app with no real remediation path

### Risk-accepted items

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2026-5450 in libc6:2.41 | Critical | No fix available; libc6 vulnerability with no upstream patch as of 2026-07-04; Juice Shop runs in isolated lab network with no public exposure | 2026-10-04 |
| GHSA-5mrr-rgp6-x4gr in marsdb:0.6.11 | Critical | marsdb is an unmaintained package used only in Juice Shop's challenge engine; replacing it would break lab functionality; isolated environment | 2026-10-04 |

All risk-accepted items have explicit expiry dates per Lecture 10 slide 12 ("silent program killer" rule — risk acceptance without expiry creates permanent blind spots).

### Next-quarter goal (OWASP SAMM ladder)

**Practice: Defect Management → Metrics and Feedback (SAMM SM2)**

Current state: MTTR is undefined (no findings closed this term) and the backlog of 160 High-severity findings has no assigned owners or remediation tickets. The concrete next step is to integrate DefectDojo with a ticketing system (Jira or GitHub Issues) via DefectDojo's native Jira connector, auto-create tickets for every Critical/High finding on import, and measure MTTR weekly. Target: reduce High MTTR from undefined to ≤14 days within one quarter, moving from SAMM SM1 (ad-hoc defect tracking) to SM2 (tracked and measured). The Falco runtime alerts from Lab 9 would also be ingested as a live finding source via a custom DefectDojo parser, adding a runtime detection layer to the program metrics dashboard.

---
