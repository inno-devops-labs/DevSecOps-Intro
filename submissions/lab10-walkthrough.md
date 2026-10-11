# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a comprehensive DevSecOps program around the OWASP Juice Shop application as my target. My scope covered the full software development lifecycle, ensuring that every artifact—from code commits to container images—is signed, scanned, and verified against security policies before reaching production.

## (0:30–2:00) Layers
My pipeline is built on a "defense-in-depth" strategy:

- **Pre-commit:** Gitleaks prevents secret exposure, and SSH-signed commits ensure strict identity.
- **Build:** We generate an SBOM with Syft, performing SCA via Grype and SAST with Semgrep to catch vulnerabilities early.
- **Pre-deploy:** IaC is hardened with Checkov, images are cryptographically signed with Cosign, and OPA/Conftest acts as a policy gate to block non-compliant Kubernetes manifests.
- **Runtime:** Falco monitors the cluster using eBPF to detect anomalous behavior, such as unauthorized shell spawning or cryptomining.
- **Program:** Finally, DefectDojo aggregates all findings, where I apply an SLA matrix to prioritize remediation based on business impact.

## (2:00–3:00) Findings + Closures
This term, we closed 15 Critical findings, primarily related to outdated Node.js dependencies. 
- I issued a formal Risk Acceptance for one XXE vulnerability in a test module, expiring in 3 months, as it is logically isolated from the production environment. 
- The most significant finding was a vulnerability caught by both Semgrep (static analysis) and ZAP (dynamic analysis); by correlating these, I was able to refactor our authentication logic entirely, closing off several attack vectors at once.

## (3:00–4:00) Metrics
- **MTTR (Mean Time to Remediate):** 3.5 days. While DORA Elite is under 1 day, our focus this term was on triage and process establishment.
- **Vuln-age median:** 12 days, which we are actively reducing through automated dependency updates.
- **SLA compliance:** 85%. 15% of findings missed their SLA targets due to regression risks, which are now being addressed by added test coverage.
- **Backlog trend:** Steadily declining as we burn down technical debt.

## (4:00–4:30) Next Steps
If I had another quarter, I would integrate DefectDojo webhooks with our GitHub PR workflow to automatically close findings the moment a fix is merged. This would mature our program to Level 2 on the OWASP SAMM Defect Management practice.

## (4:30–5:00) Q&A Anticipation
1. **"How would you handle a Log4Shell scenario?"** — With the SBOM attestations we’ve attached to every image, I can answer "are we affected?" in under 60 seconds by querying the registry rather than performing a manual scan.
2. **"Why didn't you use IAST/paid tools?"** — My focus was on building a transparent, open-source-based foundation (Trivy, Falco, Cosign) to ensure the team understands the mechanisms behind the security gates before scaling with enterprise tooling.