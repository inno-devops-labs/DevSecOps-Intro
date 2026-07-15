# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps program around OWASP Juice Shop as the target application. The scope covers the full pipeline: source code, container image, infrastructure as code, Kubernetes manifests, and runtime behavior. The goal was not to run tools for their own sake, but to aggregate every finding into a single vulnerability program with SLAs and metrics.

## (0:30–2:00) Layers

The pipeline has five layers.

1. **Build artifacts:** Syft generates an SBOM, Grype scans it for CVEs, and Cosign signs the resulting image so we can verify provenance before deployment.
2. **Static analysis:** Semgrep runs SAST on the source code in CI, catching injection patterns and hardcoded secrets.
3. **Dynamic and infrastructure analysis:** OWASP ZAP performs DAST, Nuclei checks network exposure, and Checkov/KICS scan Terraform, Ansible, and Pulumi for cloud misconfigurations.
4. **Runtime:** Falco with the eBPF driver detects anomalous behavior inside the container, such as terminal shells, sensitive-file reads, and suspicious outbound connections.
5. **Program layer:** DefectDojo imports all scan outputs, deduplicates across tools, applies the SLA matrix, and produces the backlog, MTTR, and SLA-compliance metrics I report to stakeholders.

## (2:00–3:00) Findings and Closures

We imported 359 raw findings across seven scan types. After deduplication, the active backlog is 287 unique findings. The most urgent are 12 Critical CVEs, mostly in authentication and cryptography libraries like `jsonwebtoken` and `crypto-js`. One deduplication example is CVE-2023-46233 in `crypto-js`, which was flagged by Grype, Trivy Lab 4, and Trivy Lab 7 image scan, but counted as a single finding in DefectDojo. No findings have been risk-accepted yet; I avoid silent program killers by requiring an explicit expiry date on any accepted risk.

## (3:00–4:00) Metrics

- **Active backlog:** 287 unique findings
- **Severity split:** 12 Critical, 112 High, 103 Medium, 48 Low, 12 Info
- **SLA compliance:** 100% at baseline because nothing has aged yet
- **MTTR:** not available until the first finding is closed
- **DORA benchmark:** Elite teams remediate Critical vulnerabilities in less than one day; our 24-hour Critical SLA targets that bar

## (4:00–4:30) Next Steps

If I had another quarter, I would add a Falco-to-DefectDojo parser so runtime alerts enter the same SLA and MTTR clock as scan-time findings. This directly advances the OWASP SAMM **Defect Management** practice from ad-hoc tracking to measured, managed triage.

## (4:30–5:00) Q&A Anticipation

**Q1: "How would you handle a Log4Shell-style zero-day?"**

I would start with the SBOM. Instead of grepping repositories, I would query the SBOM for `log4j-core` versions and immediately know which images and deployments are affected. Then I would trigger emergency scans with Trivy/Grype, import the results into DefectDojo as a new engagement, and prioritize patches using the 24-hour Critical SLA.

**Q2: "Why open-source tools instead of paid?"**

Open-source tools cover the fundamentals — SAST, SCA, DAST, IaC scanning, runtime detection — and produce portable JSON output. For a learning project and a small team, they are enough to build the pipeline and demonstrate value. Paid tools make sense when scale or integration depth exceeds what the open-source stack can maintain, but the process and metrics are the same.
