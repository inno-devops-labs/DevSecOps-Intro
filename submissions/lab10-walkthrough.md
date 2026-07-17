# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a comprehensive DevSecOps program around the OWASP Juice Shop application to demonstrate a full-lifecycle security pipeline. The scope includes secrets detection, SBOM generation, SCA, SAST, IaC scanning, container security, and runtime detection, all aggregated into DefectDojo for centralized vulnerability management.

## (0:30–2:00) Layers
Our security posture is built in layers:
- **Pre-commit**: We use Gitleaks to prevent secrets from ever hitting the repo and enforce SSH-signed commits for provenance.
- **Build**: Every build generates a CycloneDX SBOM via Syft, which is then scanned by Grype and Trivy for known vulnerabilities. We also run Semgrep for static analysis.
- **Pre-deploy**: We scan Terraform and Ansible manifests with Checkov and KICS. Before deployment, images are signed with Cosign and verified by a Conftest gate.
- **Runtime**: We use Falco with eBPF to detect anomalous behavior in the Kubernetes cluster in real-time.
- **Program**: All these findings flow into DefectDojo, where we apply an SLA matrix (24h for Critical) to track remediation and compute program metrics like MTTR.

## (2:00–3:00) Findings + Closures
In this run, we identified 385 unique findings. We have a strong correlation between tools; for example, the "Leaky Vessels" CVE was caught by both Trivy and Grype, which DefectDojo automatically deduplicated into a single actionable item. I've prioritized the 17 Criticals and 164 Highs for immediate remediation.

## (3:00–4:00) Metrics
Our current focus is on reducing the vulnerability age. While the initial backlog is high, the goal is to align with DORA Elite performance by targeting an MTTR of under 1 day for Critical issues. Currently, our SLA compliance is the key KPI we're tracking to ensure no High-severity issue stays open beyond 7 days.

## (4:00–4:30) Next Steps
If I had another quarter, I'd implement an automated "Security Gate" in the CI/CD pipeline that blocks merges if new Critical vulnerabilities are introduced. This moves us up the OWASP SAMM ladder from "reactive" to "preventative" defect management.

## (4:30–5:00) Q&A Anticipation
1. **"How would you handle a Log4Shell scenario?"**
   I would immediately query the aggregated SBOMs in DefectDojo to identify every service using the affected library version. This allows us to pinpoint the blast radius in seconds rather than manually scanning every repo.
2. **"Why didn't you use IAST/paid tools?"**
   For this project, I focused on best-of-breed open-source tools to prove the architectural pattern. IAST provides better accuracy but adds significant runtime overhead and complexity that wasn't required for the initial baseline.
