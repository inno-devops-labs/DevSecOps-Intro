# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps program around OWASP Juice Shop v20.0.0 as the target, using 8 open-source tools across the full SDLC. The scope covers pre-commit signing, SBOM generation, SCA, SAST, DAST, IaC scanning, container hardening, supply-chain signing, and runtime detection — all aggregated in DefectDojo for program-level triage.

## (0:30–2:00) Layers
Let me walk through the defensive layers from left to right:

- **Pre-commit:** SSH-signed commits (git commit -S) with gitleaks for secret scanning via pre-commit hooks. Every commit is both signed and scanned before it reaches the remote.
- **Build:** SBOM generation via Syft (CycloneDX 1.6), then SCA scanning with Grype against the SBOM and Trivy on the image. This catches known vulnerabilities at dependency level.
- **Pre-deploy:** Checkov on Terraform IaC, KICS on Ansible/Pulumi, and Semgrep with OWASP Top 10 rules for SAST. Cosign signs the image with keyless signing, and Conftest gates the deployment with Rego policies.
- **Runtime:** Falco with modern eBPF probe detects suspicious behavior — we saw Terminal shell in container, Read sensitive file untrusted, and Write to /tmp by container alerts.
- **Program:** All findings land in DefectDojo where we deduplicate across tools, apply SLA matrix (24h/7d/30d/90d), and track metrics.

## (2:00–3:00) Findings + Closures
- We have 542 open findings across all scanners: 31 Critical, 262 High, 169 Medium, 29 Low.
- No findings were closed this term — this is the first import cycle. The SLA matrix is applied so remediation starts now.
- The strongest cross-tool pattern: tar library vulnerabilities (GHSA-vmf3-w455-68vh) found across 3 different versions (4.4.19, 6.2.1, 7.5.15) — all by Grype. Trivy found additional CVE-level issues in libc6, openssl, and other system libraries that Grype missed, showing the value of multi-tool coverage.
- One risk-accepted item example: low-severity Info findings (9 total) — accepted with 90-day expiry per SLA policy, as they represent informational configuration observations rather than exploitable vulnerabilities.

## (3:00–4:00) Metrics
- MTTR: 0 days (first import cycle, no remediations yet)
- Vuln-age median: <1 day (all findings imported today)
- SLA compliance: 100% (SLA just applied, no overdue items yet)
- Backlog trend: 542 findings — this is the baseline. The goal is to reduce Critical + High backlog by 50% in the first quarter.
- For reference: DORA Elite performers achieve MTTR < 1 day. Our SLA for Critical is 24h — aligned with Elite benchmarks.

## (4:00–4:30) Next Steps
If I had another quarter, I'd ship reproducible builds with SLSA L3 attestation and add Falco-runtime ingestion into DefectDojo via a custom parser. This directly matures the OWASP SAMM "Defect Management" practice from Level 1 (ad-hoc) to Level 2 (measured) — every runtime alert would auto-create a finding with SLA tracking.

## (4:30–5:00) Q&A Anticipation

**Q1: "How would you handle a Log4Shell scenario?"**
With an up-to-date SBOM (Lab 4), I'd answer "Do we have log4j?" in seconds via `grype sbom:juice-shop.cdx.json --only-fixed`. If affected, the SBOM tells us exactly which components to patch and which images to rebuild. The DefectDojo SLA matrix would flag Critical findings with 24h SLA, auto-assigning to the on-call lead. Without an SBOM, this takes weeks — with it, it's a 1-day exercise.

**Q2: "Why didn't you use IAST/paid tools?"**
This was a deliberate constraint — the program uses only open-source tools (Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Falco, Cosign) to prove that a working DevSecOps program doesn't require a six-figure vendor budget. The tradeoff is that DAST (ZAP) gives JSON output that DefectDojo's parser can't ingest directly (needs XML) — a paid tool would have better integration. For a real production program, I'd add Burp Suite Enterprise or consider a commercial ASM platform for the IAST gap, but the OSS stack covers 80% of the value at 10% of the cost.