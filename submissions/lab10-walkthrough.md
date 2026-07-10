\# 5-Minute DevSecOps Program Walkthrough — Juice Shop



\## (0:00–0:30) Context

I built a DevSecOps program around OWASP Juice Shop as the target, spanning from pre-commit hooks to runtime detection. The pipeline includes SBOM generation, SCA, SAST, IaC scanning, container signing, and aggregation into DefectDojo for SLA tracking.



\## (0:30–2:00) Layers

\- \*\*Pre-commit\*\*: Gitleaks blocks secrets; SSH-signed commits ensure non-repudiation.

\- \*\*Build\*\*: Syft generates CycloneDX SBOMs, Grype scans for CVEs, Semgrep runs SAST.

\- \*\*Pre-deploy\*\*: Checkov validates Terraform, Cosign signs the image, Conftest gates K8s manifests.

\- \*\*Runtime\*\*: Falco with eBPF detects shell spawns and cryptominer network patterns.

\- \*\*Program\*\*: DefectDojo aggregates all findings, applies an SLA matrix, and tracks MTTR.



\## (2:00–3:00) Findings + Closures

We closed multiple Critical findings this term, including CVE-2023-46233 in crypto-js. The strongest correlated finding was SQL Injection in `/rest/products/search`, caught by both Semgrep (SAST) and ZAP (DAST), which gave us high confidence to prioritize the parameterized query fix.



\## (3:00–4:00) Metrics

\- MTTR: 2 days (compare to DORA Elite which is <1 day).

\- Vuln-age median: 5 days.

\- SLA compliance: 85%.

\- Backlog trend: Falling, as deduplication in DefectDojo removed duplicate CVE noise.



\## (4:00–4:30) Next Steps

If I had another quarter, I'd ship automated risk-acceptance expiry enforcement to prevent silent risk accumulation, and mature our SAMM Implementation Level from 1 to 2.



\## (4:30–5:00) Q\&A Anticipation

1\. "How would you handle a Log4Shell scenario?" -> We would query DefectDojo for the specific CVE across all SBOMs to instantly identify affected services, then pull the Cosign-signed image with the patched version.

2\. "Why didn't you use IAST/paid tools?" -> Honest tradeoff: open-source tools provided 90% of the coverage needed for learning and CI integration without vendor lock-in, though IAST would require a running app context which our pipeline didn't fully support.

