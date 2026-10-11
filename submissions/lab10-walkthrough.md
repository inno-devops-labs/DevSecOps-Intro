# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a full DevSecOps program around OWASP Juice Shop v20.0.0 as the target application — a deliberately vulnerable Node.js app — covering the entire software lifecycle from pre-commit to runtime. The program spans 10 labs and 7 tool categories: secret scanning, SCA, SAST, IaC scanning, container security, supply chain signing, runtime detection, and unified vulnerability management — all feeding into DefectDojo as the single pane of glass.

## (0:30–2:00) Layers

The program has five distinct security layers, each catching a different class of problem:

**Pre-commit** — gitleaks blocks hardcoded secrets before they ever reach the repo. Every commit is SSH-signed with Cosign's key format, so the Git history is tamper-evident. A fake GitHub PAT committed to a test file was blocked in under 100ms.

**Build** — Syft generates a CycloneDX SBOM of the container image (3,068 components catalogued). Grype scans the SBOM for CVEs — 104 matches, 7 Critical, all with fix versions available. Semgrep runs the OWASP Top 10 ruleset against the Node.js source — 22 findings, the top being Sequelize injection across 6 route files. The SBOM is committed to the repo and signed as a Cosign attestation.

**Pre-deploy** — Checkov scans the Terraform IaC (80 findings, dominated by IAM wildcard policies). KICS catches hardcoded secrets in Ansible playbooks that Checkov missed. Conftest gates the Kubernetes manifests — any manifest missing `runAsNonRoot`, `readOnlyRootFilesystem`, or capability drops fails the CI check before it reaches the cluster.

**Runtime** — Falco runs with modern eBPF via Colima on macOS. Two baseline rules fire immediately: shell spawned in container and sensitive file read. A custom rule detects writes to `/tmp` (drift indicator) and a second custom rule fires on known cryptominer process names — tested by copying busybox as `xmrig` and executing it, which fired a Critical alert in under 2 seconds.

**Program** — DefectDojo aggregates 379 findings across 7 tool types. DefectDojo's dedup collapsed 7 separate "hardcoded password" findings from KICS Ansible and Pulumi scans into one deduplicated finding. The SLA matrix is applied: 17 Critical findings have a 24-hour remediation SLA.

## (2:00–3:00) Findings + Closures

We closed zero findings in this engagement period — it's a first-run baseline scan. But the analysis is clear: the 17 Critical findings are all SCA findings from Grype and Trivy with published fix versions, which means they're addressable by dependency upgrades without any architectural change.

The one finding I would risk-accept is CVE-2019-1010022 in libc6, which Debian marks as won't-fix — there's no exploit path in a containerized non-network-facing context. The risk acceptance would expire 2026-12-31, per the rule that every risk-accepted finding needs an explicit expiry date.

The strongest correlated finding is SQL Injection in `/rest/products/search` — caught by both Semgrep's `express-sequelize-injection` rule (static data flow: `req.query.q` flowing into a raw Sequelize query) and ZAP's authenticated active scanner (dynamic: SQL injection payload returned anomalous response). Two tools, two angles, one confirmed exploitable vulnerability. The fix is parameterized Sequelize replacements — one line change, closes 6 Semgrep findings simultaneously.

## (3:00–4:00) Metrics

- **MTTR:** Not yet measurable — no findings closed. Target is <30 days for High (per DORA Elite benchmark, which is <1 day — we're not there yet, but that's the direction).
- **Vuln-age median:** <1 day (first scan run today).
- **SLA compliance:** 100% — no findings have aged past their SLA window yet. The real test comes in 24 hours when the 17 Critical SLAs are due.
- **Backlog trend:** +379 from zero. The goal for next quarter is to drive Critical and High counts below 20 combined through dependency upgrades.
- **Dedup ratio:** 379 raw findings collapsed — the most impactful single dedup was 7→1 on the hardcoded password pattern across Ansible and Pulumi.

## (4:00–4:30) Next Steps

If I had another quarter, I'd ship Falco-to-DefectDojo ingestion via a custom parser — right now runtime alerts live only in Falco logs and aren't tracked in the program's SLA matrix. That closes the loop between detection and remediation tracking, which is the gap between OWASP SAMM Defect Management Level 1 (we have a tracker) and Level 2 (we track MTTR per severity tier with breach escalation).

## (4:30–5:00) Q&A Anticipation

**Q1: "How would you handle a Log4Shell scenario with this program?"**

When Log4Shell dropped in December 2021, teams spent 48+ hours manually checking every service. With this program, the answer is: query the SBOM attestation. The CycloneDX SBOM committed in Lab 4 and signed as a Cosign attestation in Lab 8 lists every component in the Juice Shop image. A single `cosign verify-attestation --type cyclonedx` call extracts the predicate, and `jq '.predicate.components[] | select(.name == "log4j-core")'` gives a yes/no in under 60 seconds — before anyone else has finished reading the advisory. The SBOM is the answer to "do my services depend on this library?" at incident speed.

**Q2: "Why didn't you use IAST or paid tools like Snyk or Veracode?"**

Honest answer: cost and scope. IAST requires instrumented runtime which adds operational complexity and latency to the application, and paid tools like Snyk or Veracode offer better managed DB feeds and IDE integrations that matter in an enterprise context. For this program — a course project demonstrating the discipline, not the specific vendor — the open-source toolchain (Grype + Semgrep + Falco + DefectDojo) covers every OWASP category and produces the same artifact types a paid tool would. The architectural patterns transfer directly: swap Grype for Snyk, swap Semgrep for Checkmarx, and the pipeline structure is identical. What I learned here is how to build the pipeline and interpret the output — the vendor choice is an ops decision, not a skills gap.
