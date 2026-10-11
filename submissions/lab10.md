# Lab 10 — Vulnerability Management with DefectDojo

## Task 1: DefectDojo Setup + Import

### DefectDojo Version

- DefectDojo Community Edition
- Running locally via Docker Compose

### Product + Engagement

- Product: **OWASP Juice Shop**
- Product Type: **Research and Development**
- Engagement: **Course Semester Run**
- Engagement Type: **CI/CD**
- Status: **In Progress**

### Imported Scan Reports

| Lab | Scan Type | Source File | Status |
|-----|-----------|-------------|--------|
| 4 | Anchore Grype | `labs/lab4/grype-from-sbom.json` | Imported |
| 4 | Trivy Scan | `labs/lab4/trivy.json` | Imported |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | Imported |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | Imported |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | Imported |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | Imported |
| 6 | KICS Scan | `labs/lab6/results/kics-pulumi/results.json` | Imported |
| 7 | Trivy Scan | `labs/lab7/results/trivy-image.json` | Imported |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | Imported |

### Import Verification

Total imported findings:

- **386 findings**

Severity distribution:

| Severity | Count |
|-----------|------:|
| Critical | 17 |
| High | 165 |
| Medium | 168 |
| Low | 27 |
| Info | 9 |

Current finding status:

- Active findings: **386**
- Mitigated findings: **0**

### Deduplication

DefectDojo automatically performs finding deduplication across imported scan results.

The imported findings from Grype, Trivy, Semgrep, ZAP, Checkov, KICS, and Trivy Operator were successfully consolidated into a single engagement.

---

# Task 2 — Governance Report

## SLA Configuration

Configured SLA policy:

| Severity | SLA |
|-----------|----:|
| Critical | 1 day |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

The product uses the configured default SLA policy for vulnerability tracking.

---

## Program Metrics

### Vulnerability Backlog

- Total findings: **386**
- Active findings: **386**
- Closed findings: **0**

Because this represents the initial import of historical scan results, no remediation work has yet been performed.

### Mean Time To Detect (MTTD)

All findings were imported into DefectDojo immediately after the scan reports were collected.

Approximate MTTD:

- **Less than one day**

### Mean Time To Remediate (MTTR)

No findings have been mitigated yet.

Current MTTR:

- **Not available (0 findings closed)**

### Vulnerability Age

All imported findings were created on the same day during the initial import.

Average vulnerability age:

- **0 days**

### SLA Compliance

Since findings have just been imported, no SLA deadlines have expired.

Current SLA compliance:

- **100%**

---

## Risk Assessment

The majority of findings are classified as Medium or High severity.

Most vulnerabilities originate from dependency scanning performed by Trivy and Grype, while additional findings were contributed by:

- Semgrep
- OWASP ZAP
- Checkov
- KICS
- Trivy Operator

Critical findings should be prioritized first because of the configured 1-day remediation SLA.

---

## Observations

Using DefectDojo provides several advantages compared with reviewing each scanner independently:

- Centralized vulnerability management
- Unified dashboard across multiple security tools
- Automatic finding deduplication
- SLA tracking
- Consistent vulnerability lifecycle management
- Simplified prioritization of remediation efforts

This significantly improves the overall vulnerability management workflow.

---

## Conclusion

This lab demonstrated how DefectDojo can aggregate security findings from multiple DevSecOps tools into a single vulnerability management platform.

Nine scan reports from previous labs were successfully imported into one engagement, producing a consolidated backlog of **386 findings**.

The configured SLA policy enables prioritization based on vulnerability severity and provides a foundation for ongoing remediation tracking and security governance.