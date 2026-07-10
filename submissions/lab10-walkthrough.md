# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around OWASP Juice Shop as the target application,
covering the full lifecycle from pre-commit to runtime to program governance. Across the pipeline I
signed every commit with SSH, scanned dependencies, code, IaC, and containers, cryptographically
signed the image and its SBOM with Cosign, added Falco runtime detection, and aggregated all findings
into DefectDojo with an SLA matrix — six scanners feeding one unified backlog of 276 findings.

## (0:30–2:00) Layers
Think of it as defense in depth, one control per pipeline stage:
- **Pre-commit** — SSH-signed commits (every commit shows GitHub "Verified", closing the STRIDE-R
  repudiation gap) plus a gitleaks pre-commit hook that blocks secrets before they leave the laptop.
  I proved it by planting a fake `ghp_` token — gitleaks caught it on the `github-pat` rule and
  aborted the commit.
- **Build** — Syft generates a CycloneDX SBOM (3069 components), Grype scans that SBOM for CVEs
  (decoupled SCA: one SBOM, many scans over time), and Semgrep runs SAST on the source.
- **Pre-deploy** — Checkov and KICS scan the Terraform, Ansible, and Pulumi IaC; Cosign signs the
  image by digest and attaches the SBOM as an attestation; a Conftest/Rego gate blocks any pod
  manifest missing runAsNonRoot, readOnlyRootFilesystem, dropped capabilities, or privilege-escalation
  controls.
- **Runtime** — Falco with eBPF watches for shell-in-container, sensitive-file reads, and a custom
  cryptominer rule combining mining-pool ports and known miner process names.
- **Program** — DefectDojo aggregates all six scanners, applies a 24h/7d/30d/90d SLA matrix, and
  tracks MTTR, vuln-age, and SLA compliance.

## (2:00–3:00) Findings + Closures
Across the term I remediated 3 Critical findings — crypto-js, lodash, and jsonwebtoken — each of
which had an upstream fix, so the fix was a dependency bump. I risk-accepted two no-fix Criticals:
`decompress` and `marsdb` (marsdb is unmaintained), both with a hard Q4 expiry of 2026-10-10 so they
auto-revert for re-evaluation rather than silently living forever. My strongest correlated finding was
the crypto-js weak-PBKDF2 flaw: Grype reported it as GHSA-xwcq-pm8m-c4vf and Trivy as CVE-2023-46233 —
the same bug under two identifiers — which taught me that cross-tool dedup needs GHSA↔CVE
normalization, because DefectDojo left them as two separate findings.

## (3:00–4:00) Metrics
- **MTTR**: the 3 closed findings were fixed same-session; in a real cadence I'd target ≤7 days for
  High to match the SLA — well above DORA Elite's sub-1-day, which is my improvement target.
- **Vuln-age median**: currently 0 days (fresh baseline); it becomes meaningful on the next scan cycle.
- **SLA compliance**: 100% on the closed set (3/3 under their Critical 24h deadline), 0 findings
  currently past-SLA.
- **Backlog**: 271 open findings establishing the baseline (8 Critical, 119 High) — the next run
  measures trend against this number.

## (4:00–4:30) Next Steps
If I had another quarter, I'd mature the SAMM Defect Management practice from ad-hoc to metrics-driven:
wire the scanners into CI so findings import continuously with real introduction dates (giving true
MTTD/MTTR), and build a Falco-runtime custom parser so runtime alerts feed the same DefectDojo backlog
— closing the gap between my six build/deploy-time tools and the runtime layer.

## (4:30–5:00) Q&A Anticipation
**"How would you handle a Log4Shell scenario?"** — I'd query the SBOM. Because I have a CycloneDX SBOM
per image, answering "are we exposed to this library and version?" is an instant grep across attested
inventories rather than a frantic re-scan of every service. The SBOM turns incident response from
hours of discovery into a single query, which is exactly the operational instrument Log4Shell proved
we needed. Then Grype re-scans the existing SBOM against the new advisory to confirm, no image re-pull
required.

**"Why didn't you use IAST or paid tools?"** — Honest tradeoff: this program is built entirely on
open-source (Syft, Grype, Trivy, Semgrep, Checkov, KICS, Cosign, Falco, DefectDojo) to stay
reproducible and free, and even at Gitleaks-level ~70% recall these tools stop the vast majority of
real issues. IAST and commercial SCA add runtime-context accuracy and lower false positives, which I'd
justify once the program has the metrics to show where FP triage time is actually being spent — I'd
buy the tool to solve a measured problem, not preemptively.
