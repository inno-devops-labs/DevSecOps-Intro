# 5-Minute DevSecOps Program Walkthrough — OWASP Juice Shop

> Delivery note: read aloud, this runs ~4:40. All figures are from the real DefectDojo run in
> Task 1/2 (395 raw → 347 unique findings across 6 tools).

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around **OWASP Juice Shop v20** as the target of record —
one product, tracked across its whole lifecycle. Every stage of the SDLC has a control: secrets and
signing at commit time, SBOM + SCA + SAST at build, IaC scanning + image signing + policy gates
before deploy, Falco at runtime, and **DefectDojo as the single system of record** that aggregates
all of it, deduplicates across tools, and holds everything to an SLA.

## (0:30–2:00) The layers (defense in depth)
I'll walk the pipeline top to bottom:
- **Commit** — SSH-signed commits (every commit shows GitHub "Verified"), and a `gitleaks`
  pre-commit hook that hard-blocks secrets. I proved it by planting a fake GitHub PAT — the commit
  aborted on the `github-pat` rule before the secret ever entered history.
- **Build** — `syft` generates a **CycloneDX SBOM (1,846 components)**; `grype` scans it
  (**105 findings, 7 Critical**); `semgrep` runs SAST over the source (**22 findings**, top rule =
  Sequelize SQL-injection). The SBOM is the artifact that makes the *next* Log4Shell a 30-second query.
- **Pre-deploy** — `checkov` + `KICS` scan the IaC (**78 Terraform misconfigs**, plus Ansible/Pulumi),
  with a **custom Checkov policy** for an org-specific tag rule. `cosign` **signs the image by digest**
  and attaches the SBOM as an attestation; a **Conftest/Rego gate** fails the PR if a manifest isn't
  PSS-`restricted` (non-root, drop ALL caps, no priv-esc, digest-pinned).
- **Runtime** — `Falco` with custom eBPF rules — container `/tmp`-write drift and a **cryptominer
  rule** (mining-pool port OR known-miner process name).
- **Program** — **DefectDojo** ingests every tool's output, dedups the same CVE across Grype + Trivy
  + Trivy-k8s into one finding, and applies the SLA matrix (24h / 7d / 30d / 90d).

## (2:00–3:00) Findings + closures
- Across **6 tools** I imported **395 raw findings that dedupped to 347 unique** — 48 collapsed, and
  that dedup ratio alone is the argument for a system of record over per-tool spreadsheets.
- **Strongest correlated finding:** SQL injection in `routes/login.ts` — **Semgrep flagged the sink
  statically** (tainted `req.body.email` concatenated into a raw `sequelize.query`) **and ZAP reached
  the same `/rest/user/login` endpoint dynamically**. Static says *where and why*, dynamic says *it's
  actually exposed*. Fix: parameterised queries. Two independent tools, two angles, one root cause.
- **Dedup war-story:** the same Lodash `CVE-2019-10744` came in from Trivy *and* from Grype — but
  Grype labelled it `GHSA-jf85-cpcp-j695`, so they *didn't* auto-merge. That GHSA-vs-CVE mismatch is
  exactly the hashcode-tuning a real program owns.
- I **risk-accepted one Low finding** (a cookie-parser advisory) **with a hard expiry of 2026-12-15** —
  so it auto-reactivates instead of silently rotting in the backlog.

## (3:00–4:00) Metrics
- This is the **program baseline** — first consolidated import — so I'm honest: **346 active findings
  (12 Critical, 122 High)**, MTTR not-yet-defined, SLA clock started today. No vanity numbers.
- The 12 Criticals sit on a **24h SLA** and are top of the queue; the fixable ones (`jsonwebtoken`,
  `lodash`, `crypto-js` bumps) are a one-sprint win I'd drive MTTR down with, benchmarked against
  DORA Elite (< 1 day).
- The point isn't the absolute numbers today — it's that they now *exist and trend*. A baseline with
  an SLA clock is a program; "we ran some scanners" is not.

## (4:00–4:30) Next steps
If I had another quarter I'd mature **OWASP SAMM → Defect Management**: wire Falco runtime alerts into
DefectDojo as a first-class finding source (custom parser), so runtime and scan-time findings share one
SLA and one MTTR clock — closing the loop between "detected in prod" and "tracked to remediation."

## (4:30–5:00) Q&A anticipation
**Q: "Walk me through how you'd handle a Log4Shell-style 0-day."**
Because every image carries a **signed CycloneDX SBOM**, I don't guess — I query DefectDojo / the
attested SBOM by component and version and get an exact list of affected services in seconds, verify it
against the *deployed* digest (not a stale side-channel SBOM), then drive fixes through the existing
SLA clock. The SBOM turns "are we affected?" from a week of archaeology into a query.

**Q: "Why only open-source tools — no IAST or paid SAST?"**
Honest tradeoff: the OSS stack (Syft/Grype/Semgrep/Trivy/Checkov/Cosign/Falco/DefectDojo) covers
SCA, SAST, IaC, signing, runtime, and aggregation with zero license cost and full CI portability —
which is the right call for establishing the *program discipline* first. IAST/paid SAST buy lower
false-positive rates and deeper dataflow, and I'd add them once the SLA/MTTR baseline exists and the
finding volume justifies the spend — not before, or you're paying for signal you can't yet action.
