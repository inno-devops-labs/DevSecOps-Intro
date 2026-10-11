# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00-0:30) Context
I built a DevSecOps program around OWASP Juice Shop as the target application.
The scope covered Syft, Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Cosign, Falco, Conftest, and DefectDojo for signed, scanned, verified, deployed, and governed evidence.

## (0:30-2:00) Layers
- Pre-commit: gitleaks for secret prevention and SSH-signed commits for workflow integrity.
- Build: SBOM with Syft, SCA with Grype, Trivy image comparison, and SAST with Semgrep.
- Pre-deploy: Checkov on Terraform IaC, KICS on Ansible/Pulumi, Cosign signing evidence, and Conftest policy gate evidence.
- Runtime: Falco eBPF detection evidence from runtime alerts.
- Program: DefectDojo aggregation, deduplication, SLA matrix, MTTR, vulnerability age, backlog, and SLA compliance metrics.

## (2:00-3:00) Findings + Closures
- We imported 403 raw findings and reduced that to 351 unique findings after deduplication.
- The strongest cross-tool duplicate was GHSA-5mrr-rgp6-x4gr in `marsdb` 0.6.11, reported by Grype, Trivy, and the Trivy image scan, then retained as DefectDojo finding 107.
- One accepted risk was GHSA-pxg6-pf52-xh8x in `cookie` 0.4.2, accepted only until 2026-10-06 because it is Low severity and belongs in the dependency upgrade batch.

## (3:00-4:00) Metrics
- The program has 350 active open findings: 13 Critical, 121 High, 173 Medium, 31 Low, and 12 Info.
- MTTR is not yet measurable because no findings were mitigated during this capstone. Establishing a measurable remediation process is the primary improvement area.
- The median open vulnerability age is 0 days because the DefectDojo import was done in one run, and current SLA compliance is 96.6%.
- The backlog trend is rising from baseline 0 to 350 open findings, which is expected for first centralization but must fall next quarter.

## (4:00-4:30) Next Steps
If I had another quarter, I would mature OWASP SAMM Defect Management from Initial to Defined.
That means owner assignment, ticket creation, weekly SLA review, and a hard target to close or risk-accept every Critical and High finding first.

## (4:30-5:00) Q&A Anticipation
1. "How would you handle a Log4Shell scenario?"
I would start from the SBOM, search for the affected package and versions, import or update the CVE data in DefectDojo, then prioritize by CVSS, EPSS, exposure, and SLA. The value of the program is that the question becomes "which products have this component and who owns the finding," not "which scanner should I run first."

2. "Why didn't you use IAST/paid tools?"
I kept the stack open-source and reproducible for the course: Syft, Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Falco, Conftest, and DefectDojo. IAST or paid ASPM tools could improve runtime code-path confidence and workflow automation, but the core governance loop is already visible with the open-source stack.
