# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around OWASP Juice Shop as the target application, covering the full lifecycle from pre-commit through runtime. The program spans five scanning tools plus supply-chain signing and runtime detection, all aggregated into a single vulnerability-management platform (DefectDojo) with an SLA matrix and program metrics — everything is signed, scanned, or verified at some stage of the pipeline.

## (0:30–2:00) Layers
Walking the pipeline stage by stage:
- **Pre-commit:** gitleaks blocks secrets before they land, and every commit is SSH-signed so authorship is cryptographically verifiable.
- **Build:** Syft generates a CycloneDX SBOM, Grype runs SCA against that SBOM, and Semgrep runs SAST against the TypeScript source — that caught a raw SQL-injection sink in the product-search route.
- **Pre-deploy:** Checkov and KICS scan the Terraform, Ansible, and Pulumi IaC; Cosign signs the image by digest; and Conftest gates the Kubernetes manifests against a Rego policy that enforces non-root, read-only-root-filesystem, and dropped capabilities.
- **Runtime:** Falco with modern eBPF watches syscalls — I wrote custom rules for writes to /tmp and for cryptominer-style behavior (mining-pool ports plus the stratum+tcp handshake signature).
- **Program:** DefectDojo ingests every scanner's output, deduplicates across tools, and applies an SLA matrix of 1 / 7 / 30 / 90 days by severity.

## (2:00–3:00) Findings + Closures
Across the five tools I imported 391 raw findings that deduplicated to 343 unique — 12 Critical, 121 High. This session I closed two Criticals (a jsonwebtoken and a lodash CVE, both fixed by dependency bumps). One High — a lodash issue reachable only through a dev-dependency — I formally risk-accepted with a hard October expiry, so it resurfaces for re-review instead of silently persisting. My strongest correlated finding was a SQL injection in the search route that Semgrep flagged statically and ZAP corroborated dynamically at the same endpoint — SAST told me the exact line, DAST proved it was reachable.

## (3:00–4:00) Metrics
Being honest about the metrics: this is a point-in-time aggregation, so MTTR reads near-zero because import and remediation happened in one session — a real program measures that over weeks. What's real is the coverage and the discipline: five tools spanning SCA, SAST, IaC, and runtime; a live SLA matrix (Critical at 24 hours, matching what you'd tighten toward DORA-Elite's sub-day remediation); 100% SLA compliance today with zero breaches; and every risk-acceptance carrying a mandatory expiry. The dedup rate — 48 findings collapsed — is the number I'd track period over period to show the program getting smarter about noise.

## (4:00–4:30) Next Steps
With another quarter I'd wire the scanners into CI so every finding carries real commit-time and fix-merge timestamps, turning the placeholder MTTR into a genuine trend. That maps directly to maturing the OWASP SAMM Defect-Management practice from ad-hoc to measured — the single highest-leverage add being Falco runtime alerts as a DefectDojo finding source, extending coverage from build-time all the way to production runtime.

## (4:30–5:00) Q&A Anticipation
**"How would you handle a Log4Shell scenario?"** — Because every image has a signed CycloneDX SBOM attestation (Cosign attest, Lab 8), I don't re-scan anything: I query the attested SBOMs for the vulnerable coordinate and get an exact exposure list in minutes. The signature guarantees the SBOM is the authentic inventory for that exact image digest, so the answer is a database query, not an archaeology project — and a Kyverno admission policy can then block any image whose SBOM contains the bad version.

**"Why didn't you use IAST or paid tools?"** — Honest tradeoff: the free stack (Grype/Trivy/Semgrep/Checkov/KICS/Falco/Cosign/DefectDojo) covers SCA, SAST, IaC, secrets, runtime, and supply-chain — the breadth that matters most for a first program. IAST's runtime-instrumentation depth is real value, but it's a second-iteration investment once the breadth-first coverage and the metrics to justify spend are in place. I'd rather show a working five-layer program than a single expensive tool with gaps around it.
