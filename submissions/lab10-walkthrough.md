# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

Built a DevSecOps program around OWASP Juice Shop v20.0.0 across 9 labs. Stack: gitleaks + SSH signing → Syft/Grype/Trivy SBOM+SCA → Semgrep SAST + ZAP DAST → Checkov/KICS IaC → Cosign image signing → Falco runtime → DefectDojo aggregation. All open-source, Mac ARM, Docker-based.

## (0:30–2:00) Layers

**Pre-commit:** SSH-signed commits (ED25519, verified badge on GitHub). gitleaks blocks secrets — validated by staging a fake PAT, entropy 4.14, commit blocked.

**Build:** Syft → 3,068-component CycloneDX SBOM. Grype: 103 vulns (7 Critical). Trivy: 112 vulns + OS layer. in-toto v1 attestation ties SBOM to image digest.

**SAST/DAST:** Semgrep: 22 findings, top rules `express-sequelize-injection` (6 hits), `run-shell-injection` (5 hits). ZAP authenticated scan: SQL Injection at `/rest/products/search`. Correlated: same vuln caught by both tools.

**IaC:** Checkov: 78 failures on Terraform, top issue IAM wildcard (`*` actions/resources). KICS: 9 HIGH hardcoded secrets in Ansible. Custom Checkov rule `CKV2_CUSTOM_1` — RDS IAM auth — fired on 2 resources.

**Runtime:** Falco 0.43.1, modern eBPF. Custom rule "Write to /tmp by container" fired. Cryptominer rule triggered by renaming `/bin/sh` → `xmrig` — both our rule and built-in "Drop and execute new binary" fired simultaneously.

**Program:** DefectDojo — 390 findings from 8 scan types, SLA matrix applied (Critical 24h / High 7d / Medium 30d / Low 90d).

## (2:00–3:00) Findings + Closures

No findings remediated — Juice Shop is intentionally vulnerable. Two risk-accepted with 90-day expiry:
- `CVE-2026-5450` libc6 — no upstream fix, isolated network
- `GHSA-5mrr-rgp6-x4gr` marsdb — unmaintained package, lab-only scope

Strongest finding: SQL Injection at `/rest/products/search` — Semgrep caught it in source (`routes/search.ts:23`), ZAP confirmed it live with a working payload. Two independent signals = zero false-positive doubt.

## (3:00–4:00) Metrics

- **MTTD:** ~17 days (release → first scan)
- **MTTR:** undefined (no remediations)
- **Vuln-age median:** 17 days
- **SLA compliance:** 0% Critical/High — expected for a demo app with no remediation path
- **Backlog:** 390 findings, 17 Critical, 160 High

DORA Elite target: MTTR < 1 day. We're at SAMM SM1 — tracked but not measured.

## (4:00–4:30) Next Steps

DefectDojo↔Jira integration to auto-ticket every Critical/High on import + weekly MTTR tracking. Add Falco alerts as a live finding source via custom parser. Goal: SAMM SM1 → SM2 in one quarter.

## (4:30–5:00) Q&A Anticipation

**Q: "Log4Shell scenario?"**
SBOM query: `grype sbom:juice-shop.cdx.json` against updated DB — detects affected log4j version in under a minute across all 3,068 components. Full detection-to-triage under 30 minutes.

**Q: "Why not Snyk/Veracode?"**
Open-source tools demonstrate the same architecture (SBOM-first SCA, shift-left, runtime detection) with zero licensing cost. Skills transfer directly — Snyk replaces Grype, same mental model applies.
