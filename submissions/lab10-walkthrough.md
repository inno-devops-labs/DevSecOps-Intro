# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps program around OWASP Juice Shop, a deliberately vulnerable Node.js application, to demonstrate how to integrate security across the entire software lifecycle. I used 8 open-source security tools: Semgrep, Trivy, Checkov, KICS, Grype, ZAP, Cosign, and Falco - aggregated all findings in DefectDojo, and applied an SLA-based remediation workflow to prioritize and track fixes.

## (0:30–2:00) Layers
- Pre-commit: I used gitleaks to prevent secrets from being committed, and enforced SSH-signed commits to ensure code integrity.
- Build: I generated an SBOM using Syft, scanned it with Grype (0 findings), and ran Semgrep for SAST (22 findings) to catch vulnerabilities in the source code.
- Pre-deploy: I scanned Kubernetes manifests with Checkov (80 findings) and KICS (10 findings) for IaC misconfigurations, signed the container image with Cosign, and enforced policy-as-code with Conftest to gate deployments.
- Runtime: I deployed Falco with eBPF to monitor container behavior in real time, detecting suspicious activity like terminal shells inside containers and file writes to sensitive directories.
- Program: I aggregated everything in DefectDojo, applied an SLA matrix (Critical: 1 day, High: 7, Medium: 30, Low: 90 days), and tracked MTTR, vuln-age, and backlog trends.

The key here is shifting left while maintaining runtime visibility - you catch bugs early, but you also detect anomalies in production.

## (2:00–3:00) Findings + Closures
We closed 2 Critical findings this term: one Trivy finding (CVE-2024-21626) and one Critical duplicate (CVE-2015-9235). We risk-accepted one Low-severity finding - CVE-2026-45446 - because it affects an outdated dependency with low exploitability and has an expiration date of 2026-07-29. The strongest correlated finding was the duplicate CVE-2015-9235 , which was caught by Trivy and later deduplicated automatically in DefectDojo - this confirms deduplication is working across scans.

## (3:00–4:00) Metrics
- MTTR: 1 day (based on 2 mitigated findings) - this is aligned with DORA Elite.
- Vuln-age median: 0 days - all open findings are fresh (< 1 day).
- SLA compliance: 100% - 2 out of 2 mitigated findings were closed within their SLA.
- Backlog trend: +0 vs. baseline - this is our first engagement, no historical backlog yet.

## (4:00–4:30) Next Steps
If I had another quarter, I'd ship reproducible builds + SLSA L3 to ensure artifact integrity from source to deployment, and mature our Defect Management practice from Initial to Defined by integrating DefectDojo with Jira for automated ticket assignment and SLA breach notifications.

## (4:30–5:00) Q&A Anticipation
**Q1: How would you handle a Log4Shell scenario?**
I'd query the SBOM to identify all instances of `log4j` across the organization, prioritize patching based on CVSS and EPSS, and trigger an emergency SLA for Critical findings (< 1 day). I'd also enrich the SBOM with runtime context to know which services are externally exposed and need immediate attention.

**Q2: Why didn't you use IAST or paid tools?**
I focused on open-source tools to demonstrate that a robust DevSecOps program is achievable without enterprise budgets. IAST would add runtime coverage, but the combination of SAST, SCA, IaC scanning, and runtime monitoring already provides deep visibility. For a production environment, I'd prioritize coverage and workflow integration over specific tools - and I'd evaluate paid tools based on their ability to reduce false positives and automate remediation.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: <4:55>
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view):
> *"The key here is shifting left while maintaining runtime visibility — you catch bugs early, but you also detect anomalies in production."*