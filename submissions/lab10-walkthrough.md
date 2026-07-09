# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps program around **OWASP Juice Shop v20.0.0** as the target — one deliberately vulnerable app, hardened incrementally across ten labs. Tools span pre-commit secrets, SBOM/SCA, SAST/DAST, IaC scanning, Cosign signing, Falco runtime detection, and DefectDojo for program governance.

## (0:30–2:00) Layers
**Pre-commit:** gitleaks blocks secrets; SSH-signed commits prove authorship (Lab 3).

**Build:** Syft CycloneDX SBOM + Grype/Trivy SCA on every image (Lab 4). Semgrep SAST on source (Lab 5).

**Pre-deploy:** Checkov/KICS on Terraform/Ansible (Lab 6). Cosign sign + SBOM attestations (Lab 8). Conftest gates K8s manifests at CI (Lab 9).

**Runtime:** Falco eBPF — shell-in-container, drift, custom `/tmp` write rule, cryptominer pattern (Lab 9).

**Program:** DefectDojo aggregates **379 raw findings → 331 after dedup** with SLA matrix (Critical 24h / High 7d / Medium 30d / Low 90d).

## (2:00–3:00) Findings + Closures
- **Closed 6 Medium** dependency findings in the capstone demo (same-day MTTR).
- **Risk-accepted 2 items** with expiry: Low cookie GHSA (expires **2026-12-31**) — dev instance only; Medium WS advisory (expires **2026-12-15**) — wait for upstream Juice Shop bump.
- **Strongest correlated finding:** CVE-2024-37890 caught by **both Lab 4 and Lab 7 Trivy** scans — DefectDojo deduped to **one canonical finding (id 210)**; fix is bump the `ws` package in the container base.

## (3:00–4:00) Metrics
- **MTTR:** 0 days on closed sample (DORA Elite targets <1 day for changes — we're in the right ballpark on the items we touched).
- **Vuln-age median:** 0 days (fresh import — realistic for a semester kickoff).
- **SLA compliance:** 100% on the 6 closures; 131 Critical+High still on the clock.
- **Backlog trend:** rising from zero → 323 active — expected first consolidated view; goal is flat/falling next quarter.

## (4:00–4:30) Next Steps
If I had another quarter, I'd **ship a custom Falco→DefectDojo importer** and wire it into CI — that's the SAMM Defect Management maturity step from "tools in silos" to "one program dashboard."

## (4:30–5:00) Q&A Anticipation

**Q1: How would you handle a Log4Shell scenario?**
We already generate a CycloneDX SBOM (Lab 4) and sign it with Cosign (Lab 8). On disclosure, I'd `grype sbom:juice-shop.cdx.json --only-fixed` to find affected Log4j components, patch the base image, re-scan, and re-import to DefectDojo. Dedup ensures one CVE row; SLA matrix escalates Critical to 24h remediation.

**Q2: Why didn't you use IAST/paid tools?**
Juice Shop is OSS and the course targets **repeatable, free pipelines**. Semgrep + ZAP + Trivy give 80% coverage at $0; the tradeoff is manual correlation (which we did in Lab 5) and no runtime IAST — Falco partially closes that gap at syscall level.
