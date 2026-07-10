# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

```text
defectdojo-uwsgi   defectdojo/defectdojo-django   2.39.3   linux/amd64   7d2c34a1b8f0   1.23GB
```

### Product + Engagement

- **Product ID:** 3
- **Product name:** OWASP Juice Shop
- **Engagement ID:** 5
- **Engagement status:** In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `grype-from-sbom.json` | 37 |
| 4 | Trivy Scan | `trivy.json` | 41 |
| 5 | Semgrep JSON Report | `semgrep.json` | 12 |
| 5 | ZAP Scan | `auth-report.json` | 18 |
| 6 | Checkov Scan | `results_json.json` | 23 |
| 6 | KICS Scan | `kics-ansible/results.json` | 17 |
| 6 | KICS Scan | `kics-pulumi/results.json` | 14 |
| 7 | Trivy Scan (image) | `trivy-image.json` | 46 |
| 7 | Trivy Operator Scan | `trivy-k8s.json` | 29 |
| **Total raw imports** |  |  | **237** |
| **After dedup** |  |  | **162 unique findings** |

### Dedup example (Lecture 10 slide 11)

DefectDojo identified the same container-related vulnerability in three separate scanner results and merged the source instances into one logical finding.

- **CVE/ID:** CVE-2024-21626
- **Number of source tools:** 3 — Anchore Grype, Trivy image, and Trivy Kubernetes
- **DefectDojo's single finding ID:** 184

---

## Task 2: Governance Report

### Executive Summary

Juice Shop, scanned across 9 imported scan sources, currently has 118 open findings, including 6 Critical and 24 High findings.  
Mean Time to Remediate (MTTR) for findings closed during this reporting period is 11.6 days.  
A total of 78% of findings were closed within their assigned SLA.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 6 |
| High | 24 |
| Medium | 61 |
| Low | 27 |
| **Total** | **118** |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 24 | 8 | 3 | 2 |
| Trivy Scan | 28 | 7 | 4 | 2 |
| Semgrep JSON Report | 7 | 3 | 1 | 1 |
| ZAP Scan | 10 | 5 | 2 | 1 |
| Checkov Scan | 15 | 5 | 2 | 1 |
| KICS Scan — Ansible | 11 | 4 | 1 | 1 |
| KICS Scan — Pulumi | 9 | 3 | 1 | 1 |
| Trivy Scan — Image | 31 | 9 | 4 | 2 |
| Trivy Operator Scan | 19 | 7 | 2 | 1 |
| **Total source instances** | **154** | **51** | **20** | **12** |

### Program metrics

- **MTTD** (Mean Time to Detect): 1.8 days
- **MTTR** (Mean Time to Remediate): 11.6 days
- **Vuln-age median** (open findings): 19 days
- **Backlog trend:** +14 findings vs. the baseline of 104 active findings
- **SLA compliance:** 78%

### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| ZAP-102 — Content Security Policy header not set | Medium | The application is deployed only in an isolated training environment; remediation is scheduled with the next reverse-proxy configuration update. | 2026-09-30 |
| ZAP-117 — `X-Powered-By` header disclosure | Low | The disclosed framework information does not expose credentials or sensitive application data; removal is grouped with the next hardening sprint. | 2026-08-31 |
| CKV_K8S_43 — Image pull policy is not set to `Always` | Medium | Images are pinned by digest in the laboratory cluster, reducing the likelihood of an unintended image substitution. | 2026-10-15 |
| CKV_K8S_20 — `allowPrivilegeEscalation` is not explicitly disabled | Medium | The affected workload runs in a restricted, non-production namespace with no host mounts; the manifest will be corrected during the next Kubernetes baseline update. | 2026-08-15 |
| KICS-ANS-14 — CPU limits are not defined | Low | The Ansible-managed deployment is short-lived and runs under a namespace-level quota; explicit container limits are planned for the next template revision. | 2026-09-15 |
| KICS-PUL-09 — Memory limits are not defined | Medium | The Pulumi stack is used only for ephemeral testing and is protected by cluster-level resource quotas. | 2026-09-15 |
| SEMGREP-7 — Weak pseudo-random number generator in non-security game logic | Low | The code path is used only for cosmetic challenge behavior and does not generate tokens, credentials, or security-sensitive values. | 2026-12-01 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

The next practice to mature is **Defect Management**. The current MTTR for High-severity findings is 16.4 days, and the next-quarter target is to reduce it to 10 days by introducing weekly overdue-finding reviews, automated SLA-aging notifications, and ownership rules for every Critical and High finding. Runtime coverage will also be improved by importing Falco alerts through a custom DefectDojo parser, helping the team prioritize vulnerabilities that are observable in the running environment.
