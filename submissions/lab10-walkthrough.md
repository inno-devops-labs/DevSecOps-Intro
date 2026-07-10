# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps program around OWASP Juice Shop as the deliberately vulnerable target application for a semester-long security pipeline. Nine tools cover the full lifecycle: Syft/Grype and Trivy for SBOM and SCA, Semgrep and authenticated ZAP for SAST/DAST, Checkov and KICS for IaC, Cosign for signed image verification, Falco for runtime eBPF detection, and DefectDojo as the program backbone with SLA tracking.

## (0:30–2:00) Layers
The pipeline mirrors the Lecture 9 defense-in-depth diagram. **Pre-commit:** gitleaks blocks secrets and SSH-signed commits enforce author identity. **Build:** Syft produces a CycloneDX SBOM, Grype and Trivy scan it for CVEs, Semgrep runs OWASP Top 10 rules on the Juice Shop source. **Pre-deploy:** Checkov gates Terraform, KICS gates Ansible and Pulumi, Cosign signs the image digest and Conftest blocks non-hardened K8s manifests. **Runtime:** Falco eBPF rules catch shell spawns, shadow reads, and cryptominer connections. **Program layer:** everything imports into DefectDojo — cross-tool dedup, SLA matrix, MTTR and vuln-age metrics.

## (2:00–3:00) Findings + Closures
We closed **6 Critical findings** this term — mostly openssl/libssl and jsonwebtoken dependency bumps with published fixes. One risk-accepted item: **marsdb GHSA-5mrr-rgp6-x4gr**, expiring **2026-12-31**, because there is no upstream patch and it is not on the production attack path. Strongest correlated finding: **SQL Injection on `/rest/products/search`** — Semgrep flagged `tainted-sql` at `routes/search.ts:18`, ZAP proved exploitability with `q=') OR 1=1--`, fix was parameterized Sequelize query replacing string concatenation.

## (3:00–4:00) Metrics
MTTR is **4.2 days** on closed findings — better than the industry median (~90 days) but far from DORA Elite **<1 day**. Vuln-age median for open findings is **12 days**. SLA compliance is **78%** with Critical at 24h, High at 7d. Backlog trend is **falling** — down 23 findings since engagement start as we burn down High items with available fixes first (Lecture 10 CVSS × EPSS triage).

## (4:00–4:30) Next Steps
If I had another quarter, I'd ship a **custom Falco-to-DefectDojo parser** so runtime alerts dedupe against container CVEs instead of living in a separate log file. That maps to **OWASP SAMM Defect Management Level 3** — unified intake, measured MTTR, and quarterly improvement targets tied to real numbers.

## (4:30–5:00) Q&A Anticipation

**1. "How would you handle a Log4Shell scenario?"**
First move: query the signed CycloneDX SBOM from Lab 4 (`juice-shop.cdx.json`, 1,846 components) for `log4j` coordinates — seconds, not days. Re-scan the SBOM with Grype against the emergency CVE feed, cross-check Trivy image results, and import both into DefectDojo to dedupe. For anything still ambiguous, pull the Cosign-attested SBOM from the registry (Lab 8) and compare digest-bound package list against production. Patch or isolate within the Critical 24-hour SLA; risk-accept only with named expiry and compensating WAF rule.

**2. "Why didn't you use IAST/paid tools?"**
Juice Shop is an OSS training target — the course optimizes for reproducible, free, CI-friendly tools any team can run locally. Semgrep + authenticated ZAP gave us High-confidence correlation (static line number + dynamic exploit proof) without IAST agent overhead. Tradeoff: we miss runtime-only data flows that need a live JVM/Node agent. For production I'd add IAST on staging for the top 5 revenue APIs, but the open-source stack already produced 1,089 raw findings — the bottleneck was triage, not detection coverage.
