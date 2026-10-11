# 5-Minute DevSecOps Program Walkthrough — Juice Shop

> Numbers below are filled from the DefectDojo capstone run. Target: ≤ 5:00.
> If you run long, cut from the "Layers" section first.

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around OWASP Juice Shop as the target application —
a deliberately vulnerable app, which makes it a realistic stress test for a security pipeline.
The program covers the full lifecycle: secrets and commit integrity at pre-commit, SBOM + SCA +
SAST at build, IaC scanning and image signing pre-deploy, eBPF runtime detection in production,
and a DefectDojo instance on top that aggregates every scanner into one governed backlog with an
SLA matrix.

## (0:30–2:00) Layers
I think about it as five layers, each a gate:
- **Pre-commit** — gitleaks blocks secrets before they enter history, and commits are SSH-signed
  so authorship is verifiable.
- **Build** — Syft generates an SBOM, Grype does SCA against that SBOM, and Semgrep runs SAST on
  the source. The SBOM matters later: it's what lets me answer "am I affected?" in minutes.
- **Pre-deploy** — Checkov and KICS scan the Terraform / Ansible / Pulumi IaC, Cosign signs the
  image, and a Conftest/Rego policy gates the Kubernetes manifests in CI — denying anything that
  runs as root, allows privilege escalation, skips dropping capabilities, or ships a `:latest` tag.
- **Runtime** — Falco with the modern eBPF probe watches syscalls and fires on drift: a shell in a
  container, a write to `/tmp`, a read of `/etc/shadow`, or an outbound connection to a known
  cryptominer port.
- **Program** — DefectDojo ingests all of the above via its importers, auto-dedupes the same issue
  reported by multiple scanners, applies the SLA matrix (24h / 7d / 30d / 90d for
  Critical / High / Medium / Low), and gives me MTTR, vuln-age, and SLA-compliance numbers.

## (2:00–3:00) Findings + Closures
Across 7 non-empty tools I imported 364 raw findings, which deduped to 316 unique issues — 48
duplicates collapsed.
- I remediated 2 High findings this session and closed them as mitigated.
- One risk decision I made explicit: I risk-accepted two transitive dev-only dependencies
  (moment 2.0.0 and lodash 2.4.2), expiring 2026-10-10, because they have no runtime exposure and
  are batched for a Q3 upgrade — and critically, they carry an expiry, so they come back for review
  instead of silently becoming permanent debt.
- My clearest cross-tool correlation was CVE-2026-45447 in libssl3 (a base-image CVE): the same
  issue surfaced from two independent container scans, and DefectDojo's dedup linked them into one
  canonical finding (#483, with #679 attached as its duplicate). The fix is to bump the base image
  to a patched digest, which clears every duplicate at once.

## (3:00–4:00) Metrics
- **MTTR**: roughly 0 days — but I'll be honest about why: everything was imported in a single
  session, so the two findings I closed were fixed the same day they were detected. DORA's Elite
  benchmark is under a day; my number is an artifact of a one-shot import, not a real detect-to-fix
  gap, and closing that measurement gap is exactly my next target.
- **Vuln-age median** (open findings): about 0 days — same single-import baseline.
- **SLA compliance**: 100% within SLA at this snapshot — the SLA clock started at import and nothing
  has aged out yet.
- **Backlog trend**: stable — baseline of 316 unique, 312 active after triaging 4. I track it against
  the import baseline so I can tell whether we're paying down debt or accumulating it.

## (4:00–4:30) Next Steps
If I had another quarter, I'd ship a custom DefectDojo parser to ingest Falco runtime alerts as a
first-class finding source, so detection and remediation live in one backlog, and wire the importer
into CI so every pipeline run refreshes findings automatically. That maps directly to advancing the
OWASP SAMM Defect Management practice from ad-hoc toward a measured, tool-integrated level — and it
gives MTTR a real detect-to-fix gap to measure instead of the near-zero artifact I have today.

## (4:30–5:00) Q&A Anticipation
**"How would you handle a Log4Shell scenario?"**
First question is "am I even affected?" — and because every build produces an SBOM, I can query
across all my SBOMs for the vulnerable `log4j-core` range in minutes instead of guessing. Grype
re-scanning the SBOM confirms exposure, DefectDojo tracks the finding against a 24-hour Critical
SLA, and the Conftest gate plus image re-signing make sure the patched build is the only one that
can deploy. The SBOM is the difference between a controlled response and a fire drill.

**"Why didn't you use IAST or paid tools?"**
Honest tradeoff: the goal was a reproducible, open-source pipeline anyone can stand up, so I
prioritized coverage across the lifecycle (SCA, SAST, DAST, IaC, runtime, program) over depth in
any single commercial tool. IAST would add runtime-informed SAST accuracy and paid scanners add
better triage and support — I'd reach for them once the program is mature enough that false-
positive triage cost, not coverage, is the bottleneck. Right now the open-source stack gets me
defense in depth end-to-end, which matters more early.
