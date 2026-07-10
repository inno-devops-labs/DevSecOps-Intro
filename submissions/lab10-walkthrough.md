# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00-0:30) Context

I built a DevSecOps program based on OWASP Juice Shop as the target application, including the full pipeline from pre-commit secret scans through runtime detection. There are 9 security tools used in 5 layers: pre-commit (gitleaks), build (Syft SBOM + Grype SCA + Semgrep SAST), pre-deploy (Checkov IaC + Cosign signing + Conftest policy gates), and runtime (Falco eBPF detection), which all are aggregated in DefectDojo with SLA matrix.

## (0:30-2:00) Layers

There are 5 layers included in my DevSecOps program:

- pre-commit layer with gitleaks scans for secrets, all commits are signed via SSH for provenance;
- build layer with Syft SBOM creation, Grype SCA scan, Semgrep SAST on JS codebase;
- pre-deploy layer with Checkov validations for Terraform and Ansible IaC, Cosign signing of Docker images, Conftest policy gates;
- runtime layer with Falco monitoring for anomalies using eBPF;
- program level where all the findings are aggregated in DefectDojo, deduped between tools (e.g., lodash prototype pollution found via both Grype and Trivy reduces to one finding), SLA matrix is applied, and program metrics are calculated.

## (2:00-3:00) Findings + Closures

We've imported 390 findings via 9 tools: 19 Critical, 164 High, 169 Medium, 29 Low, 9 Info. On the day 1, no findings are closed yet — this is the baseline. Strongly correlated finding here is GHSA-35jh-r3h4-6jhm (lodash prototype pollution, also known as CVE-2021-23337), which is found by both Anchore Grype and Trivy. DefectDojo has deduplicated this finding to one (finding ID is 541), providing better confidence and reducing noise. We have already risk-accepted 3 Critical findings (jsonwebtoken 0.1.0, lodash 2.4.2, crypto-js 3.3.0) with explicit 90-day expiry dates because they exist in legacy/test dependencies that are not exposed to production traffic. These are now out of SLA compliance (Critical = 24h) but documented as accepted risk with re-evaluation scheduled. The remaining 16 Critical findings require active remediation within their SLA windows.

## (3:00-4:00) Metrics

- MTTR: N/A (baseline on the day 1 - no findings closed yet);
- Vuln-age median: 0 days (findings are imported today);
- SLA compliance: 100% (all findings are in SLA window; matrix is just applied);
- Backlog trend: +390 compared to baseline of 0 (just started program);
- comparison: DORA elite performers have MTTR <1 day (Lecture 9, slide 13); our goal is to get this MTTR within 2 quarters implementing automated triage and EPSS prioritization.

## (4:00-4:30) Next Steps

If I were having another quarter, I would integrate EPSS score into the DefectDojo Rules Engine to prioritize 19 critical findings based on exploitation likelihood instead of just CVSS severity. This will allow me to achieve SAMM Level 2 in Defect Management and reduce Critical+High backlog by 50% in 90 days.

## (4:30-5:00) Q&A Anticipation

Q1: "How would you handle a Log4Shell scenario?"

Based on our SBOM (Lab 4), we would be able to find all the instances of log4j in seconds, not weeks. Grype would identify CVE-2021-44228, DefectDojo would deduplicate findings from all scans, and SLA matrix would page the on-call engineer to fix the issue within 24 hours. We would patch, re-scan, check the fix, and close all. This would all be tracked in DefectDojo.

Q2: "Why did you not use IAST / paid tools?"

Open-source tools (Trivy, Semgrep, Grype, DefectDojo) give us 90% coverage of commercial tools' functionality at zero cost. In the learning environment, and for the purpose of portfolio project, this trade-off is acceptable. In production, I would consider using commercial DAST tools (Invicti) for authenticated scanning, and IAST, but only after proving open-source pipeline.
