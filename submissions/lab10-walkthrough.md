# 5-Minute DevSecOps Program Walkthrough — OWASP Juice Shop

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around OWASP Juice Shop as the target application, covering the full lifecycle from pre-commit to runtime to program governance. Every artifact is signed, scanned, or verified: SSH-signed commits, an SBOM-backed dependency graph, SAST/DAST/IaC/container scans, a Cosign-signed image with SBOM + provenance attestations, Falco runtime detection, and all findings aggregated in DefectDojo under an SLA matrix.

## (0:30–2:00) Layers
I think of it as five gates, each catching a different class of risk:
- **Pre-commit:** gitleaks blocks secrets before they're committed, and every commit is SSH-signed so authorship is verifiable.
- **Build:** Syft generates a CycloneDX SBOM (1846 components), Grype does SCA against it, and Semgrep runs SAST on the source (22 findings, including the SQL-injection route I later correlated with DAST).
- **Pre-deploy:** Checkov and KICS scan the Terraform/Ansible/Pulumi IaC; the image is Trivy-scanned; then Cosign signs it by digest and Conftest/Rego policies gate the Kubernetes manifests so an unhardened pod can't merge.
- **Runtime:** Falco with a modern-eBPF probe watches syscalls — I wrote custom rules for writes to /tmp and for cryptominer-style egress to known pool ports, both of which fired live.
- **Program:** DefectDojo ingests all six scanners into one backlog with a 1/7/30/90-day SLA matrix, so the data becomes a managed program instead of a pile of reports.

## (2:00–3:00) Findings + Closures
This term I imported 333 findings across six tools and triaged from there. I closed two Critical jsonwebtoken findings (GHSA-c7hr-j4mj-j2w6) the same day they surfaced. One High — lodash 2.4.2 — I risk-accepted with a hard expiry of 2026-09-26, because it's a dev-only transitive dependency that isn't reachable in the production runtime; the expiry forces a re-review rather than letting it sit forever. My strongest correlated finding was SQL injection: Semgrep flagged it in the source AND ZAP confirmed it dynamically against the running app, so it was both reachable and real — that's the one I'd fix first.

## (3:00–4:00) Metrics
This is a baseline cycle, so I'm honest about what the numbers mean: MTTR on the two closed findings is ≈0 days (same-day close), vuln-age median is 0 (everything imported today), and SLA compliance is 100% only because nothing has aged past its window yet. The backlog baseline is 330 active findings. The real signal is the 72 CVEs found by both Grype and Trivy — that overlap is why dedup matters, and it's my headline number for next cycle. Against DORA Elite (MTTR under one day), the same-day closes are on track, but two closures isn't a trend yet.

## (4:00–4:30) Next Steps
If I had another quarter, I'd mature the OWASP SAMM **Defect Management** practice: enable cross-tool deduplication keyed on CVE+component+version to collapse those 72 Grype/Trivy overlaps, and wire Falco runtime alerts into DefectDojo via a custom parser so build-time and runtime findings share one backlog and one SLA clock.

## (4:30–5:00) Q&A Anticipation
**"How would you handle a Log4Shell scenario?"** — I'd query the SBOM first: because every image has a CycloneDX SBOM attached as a Cosign attestation, I can answer "are we affected, and where" in minutes instead of grepping production. A Kyverno/Sigstore admission policy can then block any image whose SBOM lists the vulnerable version, and Falco gives runtime detection for exploitation attempts while patches roll out.

**"Why didn't you use IAST or paid tools?"** — Honest tradeoff: this program is built entirely on open-source (Syft, Grype, Trivy, Semgrep, Checkov, KICS, Falco, Cosign, Conftest, DefectDojo) to keep it reproducible and zero-cost. IAST would add runtime-instrumented accuracy and cut Semgrep's false positives, but it needs an agent in the app and a license budget; I'd add it once the program's MTTR and SLA-compliance data justified the spend.