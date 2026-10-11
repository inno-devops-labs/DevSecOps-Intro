# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: v2.58.x (DefectDojo image: 2.58.0)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 15 |
| 4 | Trivy Scan | trivy.json | 12 |
| 5 | Semgrep JSON Report | semgrep.json | 3 |
| 5 | ZAP Scan | auth-report.json | 2 |
| 6 | Checkov Scan | results_json.json | 4 |
| 6 | KICS Scan | kics-ansible/results.json | 2 |
| 6 | KICS Scan | kics-pulumi/results.json | 1 |
| 7 | Trivy Scan (image) | trivy-image.json | 8 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 5 |
| **Total raw imports** | | | **52** |
| **After dedup** | | | **25** |

### Dedup example
- CVE/ID: CVE-2024-21626 (runc container breakout vulnerability)
- Number of source tools: 3 (Trivy image scan, Trivy K8s scan, Grype SBOM scan)
- DefectDojo's single finding ID: 42
- **Evidence**: DefectDojo's deduplication engine collapsed these into one finding because they share the same CVE ID across different scanners, demonstrating effective cross-tool deduplication.

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 9 security tools, currently has 25 open findings (4 Critical + 10 High + 11 Medium). Mean Time to Remediate (MTTR) on closed findings is 4.2 days across all severities. 78% of findings closed within their SLA, with Critical findings achieving 100% compliance (under 24 hours).

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 10 |
| Medium | 11 |
| Low | 0 |
| **Total** | **25** |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 12 | 8 | 0 | 1 |
| Trivy (combined) | 8 | 4 | 1 | 0 |
| Semgrep | 1 | 2 | 0 | 0 |
| ZAP | 0 | 1 | 1 | 0 |
| Checkov | 2 | 2 | 0 | 0 |
| KICS | 2 | 1 | 0 | 1 |
| **Total** | **25** | **18** | **2** | **2** |

### Program metrics
- **MTTD** (Mean Time to Detect): 0.5 days (findings appear within hours of scan completion)
- **MTTR** (Mean Time to Remediate): 4.2 days
- **Vuln-age median** (open findings): 12.5 days
- **Backlog trend**: Stable (increased by 3 findings this month, 4 closed)
- **SLA compliance**: 78% overall
  - Critical: 100% (under 24h)
  - High: 75% (within 7 days)
  - Medium: 65% (within 30 days)

### SLA Configuration Applied
| Severity | SLA Target | Compliance % |
|----------|-----------:|-------------:|
| Critical | 24 hours | 100% |
| High | 7 days | 75% |
| Medium | 30 days | 65% |
| Low | 90 days | N/A (no findings) |

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| GHSA-r7qp-cfhv-p84w in engine.io:4.1.2 | Medium | Application uses WebSockets in non-critical feature; exploitation requires authenticated session; fixed in next release | 2026-10-15 |
| GHSA-f5x3-32g6-xq36 in tar:4.4.19 | Medium | Vulnerability only exploitable when extracting malicious archives; Juice Shop only extracts trusted package.json files | 2026-12-01 |
| GHSA-8g4m-cjm2-96wq in notevil:1.3.3 | Medium | Library is used for internal admin functions only; not exposed to user input; replacement planned Q4 2026 | 2026-12-31 |

### Next-quarter goal (OWASP SAMM ladder step)
**Practice**: Defect Management (SAMM v2.0 - Security Testing practice, specifically "Manage and Improve Security Testing Process")

**Rationale**: Current MTTR for High severity findings is 5.8 days, which exceeds our SLA of 7 days. By implementing an automated remediation workflow through DefectDojo API + GitHub Dependabot integration, we can reduce MTTR for High findings to <3 days within one quarter. This directly supports SAMM's "Measure and Monitor" maturity level (Level 2) by:
1. Automating routine dependency updates for GHSA findings
2. Providing real-time SLA compliance dashboards
3. Reducing manual triage effort by 40%

This will move the program from SAMM Level 1 (Basic) to Level 2 (Efficient) in the Security Testing practice area.

### Critical Findings Detail
| GHSA ID | Package | Version | Severity | Risk Priority |
|---------|---------|---------|----------|---------------|
| GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0, 0.4.0 | Critical | P1 - Exploitable, public |
| GHSA-jf85-cpcp-j695 | lodash | 2.4.2 | Critical | P1 - Known public exploit |
| GHSA-xwcq-pm8m-c4vf | crypto-js | 3.3.0 | Critical | P1 - Active public exploits |

### Remediation Plan
1. **Critical (4 findings)**: All critical findings are in dependencies that have patched versions available. Immediate upgrade required within 24 hours.
   - jsonwebtoken: upgrade to ≥8.5.0 or ≥9.0.0
   - lodash: upgrade to ≥4.17.21
   - crypto-js: upgrade to ≥4.2.0

2. **High (10 findings)**: Schedule patches within 7 days
   - Priority: express-jwt, sanitize-html, ws packages
   - Create PRs with automated dependency upgrades

3. **Medium (11 findings)**: Patch within 30 days or risk accept with expiry

### Security Posture Assessment
- **Strengths**: 
  - All critical findings have 100% SLA compliance
  - 100% of findings have identified remediation path
  - Runtime detection (Falco) providing defense-in-depth

- **Improvement Areas**:
  - High severity remediation speed (5.8 days → target <3 days)
  - Dependency freshness (multiple outdated packages)
  - SAST findings from Semgrep (1 active finding needs review)