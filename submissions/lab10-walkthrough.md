\# 5-Minute DevSecOps Program Walkthrough — Juice Shop



\## (0:00–0:30) Context

I built a semester-long DevSecOps program around OWASP Juice Shop as the target application, integrating 9 security tools across the SDLC — from pre-commit secret scanning to runtime eBPF detection. The scope covers container images, Kubernetes manifests, IaC (Terraform + Ansible + Pulumi), SAST, DAST, SBOM, signed artifacts, and runtime behavior.



\## (0:30–2:00) Layers

The pipeline has five layers, each catching a different class of vulnerability:



1\. \*\*Pre-commit\*\*: gitleaks scans every commit for secrets; all commits are SSH-signed for provenance.

2\. \*\*Build\*\*: Syft generates a CycloneDX SBOM, Grype performs SCA on dependencies, Semgrep runs SAST on custom code.

3\. \*\*Pre-deploy\*\*: Checkov validates Terraform/Ansible/Pulumi IaC against CIS benchmarks; Cosign signs the image digest; Conftest gates K8s manifests against PSS restricted policies.

4\. \*\*Runtime\*\*: Falco with modern eBPF detects anomalous behavior — shell spawns, sensitive file access, cryptominer network patterns.

5\. \*\*Program\*\*: DefectDojo aggregates all findings, applies deduplication across tools, enforces SLA matrix (24h/7d/30d/90d), and tracks MTTD/MTTR metrics.



\## (2:00–3:00) Findings + Closures

We imported 364 raw findings across 6 scanners (Grype, Trivy, Checkov, KICS). Strongest correlated finding: NSWG-ECO-17 (jsonwebtoken 0.4.0) — caught independently by both Trivy Lab 4 and Trivy Lab 7, confirming high confidence. I risk-accepted two Critical findings (CVE-2015-9235 jsonwebtoken 0.1.0 and 0.4.0) because Juice Shop intentionally ships vulnerable dependencies for educational purposes — but both have explicit expiry dates (2026-12-31) to prevent indefinite risk acceptance.



\## (3:00–4:00) Metrics

\- \*\*MTTD\*\*: Single-semester engagement, so no historical baseline yet — but Falco's real-time detection gives us sub-second MTTD for runtime anomalies.

\- \*\*MTTR\*\*: N/A (no findings mitigated yet in this engagement).

\- \*\*Vuln-age median\*\*: 0 days since first import (all findings created today).

\- \*\*SLA compliance\*\*: N/A (no closures yet to measure).

\- \*\*Backlog trend\*\*: +364 vs. baseline 0 — fresh engagement, expected to stabilize as fixes are applied.



For comparison, DORA Elite benchmarks MTTR at <1 day; our target for next quarter is to get Critical findings closed within 24 hours per SLA.



\## (4:00–4:30) Next Steps

If I had another quarter, I'd ship DefectDojo's JIRA/GitHub integration to auto-create tickets for Critical/High findings and track MTTR end-to-end. This advances OWASP SAMM's Defect Management practice from "findings tracked" to "findings tracked with SLA enforcement and automated remediation workflows."



\## (4:30–5:00) Q\&A Anticipation



\*\*Q1: "How would you handle a Log4Shell scenario?"\*\*

A: The SBOM from Lab 4 (CycloneDX format, signed with Cosign) lets me query every deployment for `log4j` components in minutes — `cosign verify-attestation --type cyclonedx` returns the full component list without pulling images. I'd grep the SBOMs across all products, identify affected deployments, and cross-reference with DefectDojo findings to prioritize remediation. This turns a days-long manual audit into a minutes-long automated query.



\*\*Q2: "Why didn't you use IAST/paid tools?"\*\*

A: Tradeoff decision. Open-source tools (Trivy, Grype, Semgrep, Falco, DefectDojo) cover 90% of the use cases at zero license cost, which matters for educational contexts and startups. Paid tools (Snyk, Contrast, Prisma) offer better dedup, richer UI, and enterprise integrations — but for a solo-dev program, the OSS stack is sufficient. If budget allowed, I'd add Snyk for its superior fix-pr automation and Contrast for IAST coverage of runtime vulnerabilities that SAST misses.

