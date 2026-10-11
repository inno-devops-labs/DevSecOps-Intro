# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
Deployed via the official `docker compose` stack from `github.com/DefectDojo/django-DefectDojo`
(dev profile, `./docker/setEnv.sh dev`). Images pulled at time of setup:
`defectdojo/defectdojo-django:latest`, `defectdojo/defectdojo-nginx:latest`,
`postgres:18.4-alpine`, `valkey/valkey:9.1.0-alpine`.

**Environment note:** `docker compose up -d` was run directly from PowerShell (Windows +
Docker Desktop). The `./docker/setEnv.sh dev` bootstrap script is bash-only, so it was run
once via `wsl` against the same repo checkout (Docker Desktop's WSL2 backend shares the
filesystem), then `docker compose up -d` was run back in PowerShell for the actual stack —
all 7 containers (`postgres`, `valkey`, `celerybeat`, `celeryworker`, `uwsgi`, `nginx`,
`initializer`) started successfully.

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 105 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | **skipped** — see note below |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | Checkov Scan | kics-ansible/results_json.json | 1 |
| 6 | Checkov Scan | kics-pulumi/results_json.json | 0 |
| 7 | Trivy Scan | trivy-image.json | 50 |
| 7 | Trivy Scan (flattened) | trivy-k8s.json | 50 |
| 8 | — | Cosign artifacts | **skipped** — see note below |
| 9 | — | falco.log | **skipped** — no DefectDojo parser exists for Falco's JSON log format, per the lab's own guidance |
| **Total raw imports** | | | **421** |
| **After dedup** | | | **422 unique findings** (engagement-level dedup was not enabled at import time — see dedup note below) |

**Import format notes:**
- **ZAP (Lab 5):** DefectDojo's `ZAP Scan` importer in this version only accepts ZAP's XML
  report format; Lab 5 only produced JSON output (`auth-report.json`). Rather than
  re-running ZAP to regenerate an XML report just for this capstone, this was documented
  as a known format gap instead of silently working around it.
- **Lab 6 "KICS" files:** inspecting `kics-ansible/results_json.json` and
  `kics-pulumi/results_json.json` showed both are actually in **Checkov's** JSON schema
  (`check_type`, `results.passed_checks/failed_checks`, `summary`) rather than KICS's
  native `queries`-rooted schema. They were imported as `Checkov Scan` (the format that
  actually matches the file content) rather than `KICS Scan`.
- **Trivy K8s (Lab 7):** the raw `trivy-k8s.json` uses `trivy k8s`'s own top-level shape
  (`ClusterName` + `Resources[]`, each resource holding a normal Trivy `Results[]` block),
  which neither the `Trivy Scan` nor `Trivy Operator Scan` importer recognizes directly.
  It was flattened with a small PowerShell script (concatenating every `Resources[i].Results`
  into one `{SchemaVersion:2, ArtifactName, ArtifactType, Results:[...]}` document — the
  shape `Trivy Scan` expects) before import. This surfaced the 2 High-severity private-key
  secrets from `insecurity.js`/`insecurity.ts` that Lab 7's own notes flagged.
- **Lab 8 (Cosign):** `verify-original.json` and the attestation/bundle files are signature
  verification and provenance metadata, not a vulnerability-finding format — there is no
  meaningful DefectDojo parser for them, so they were not imported; signature verification
  is documented as a separate control, not a scanned finding source.

### Dedup example
DefectDojo's automatic cross-tool dedup did **not** collapse matching findings here,
because `deduplication_on_engagement` was `false` (the default) on every import call — the
lab's assumption that dedup "just happens" on import turned out to require an explicit
opt-in. Querying findings manually across tests instead surfaced a clean example of the
*same* vulnerability landing as 4 separate finding records:

- CVE/ID: **CVE-2026-45447** (`libssl3t64:3.5.5-1~deb13u2`)
- Number of source tools: **4** — Grype (test 1), Trivy/lab4 (test 2), Trivy image/lab7
  (test 8), and the flattened Trivy K8s scan (test 15) — all independently flagged the
  same base-image OpenSSL package at the same version.
- DefectDojo finding IDs: **13** (Grype), **120** (Trivy/lab4), **321** (Trivy image),
  **373** (Trivy K8s) — 4 distinct records for 1 real vulnerability, confirming cross-tool
  agreement on the finding while also demonstrating that dedup is opt-in behavior, not a
  free automatic guarantee.

## Task 2: Governance Report

### Executive Summary
Juice Shop, scanned across 8 imported reports spanning 6 tool types (Grype, Trivy, Semgrep,
Checkov, plus the flattened Trivy K8s scan), currently has 422 active findings (22 Critical
+ 199 High). No findings have been formally closed/mitigated yet in this DefectDojo instance
— this capstone captures a single point-in-time import rather than a full remediation
cycle — so MTTR is not yet measurable; 98.3% of active findings are still within their SLA
window as of the import date.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 22 |
| High | 199 |
| Medium | 168 |
| Low | 26 |
| Info | 7 |
| **Total** | **422** |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|---------------:|
| Grype (Anchore Grype) | 105 | 0 | 0 | 0 |
| Trivy Scan — lab4 | 113 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| Checkov Scan — terraform | 80 | 0 | 0 | 0 |
| Checkov Scan — ansible | 1 | 0 | 0 | 0 |
| Checkov Scan — pulumi | 0 | 0 | 0 | 0 |
| Trivy Scan — image (lab7) | 50 | 0 | 0 | 0 |
| Trivy Scan — k8s flattened (lab7) | 50 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): not meaningfully computable from a single-day bulk
  import — all findings share the same "detected" timestamp (2026-07-10, the day of the
  Lab 10 import), rather than reflecting real per-vulnerability discovery dates across
  the semester.
- **MTTR** (Mean Time to Remediate): **N/A** — 0 findings have been marked `is_mitigated`
  yet in this engagement.
- **Vuln-age median** (open findings): ~0 days as of this report, for the same reason as
  MTTD — this is a fresh import snapshot, not a mature running program with historical age
  data.
- **Backlog trend**: no baseline exists yet (first import) — this report *is* the baseline
  for future comparison.
- **SLA compliance**: **98.3%** (415 of 422 active findings within SLA; 7 findings already
  past their SLA deadline, all Critical/High findings whose short 1-day/7-day SLA windows
  had already elapsed relative to the underlying scan's original detection date even
  though they were only imported into DefectDojo today).

### Risk-accepted items (must have expiry)
No findings have been marked "Risk Accepted" in this engagement — this is a fresh import
with no triage decisions applied yet, so there is nothing to list here. In a live program,
this table would be populated during Task 2's triage pass, with every entry requiring an
explicit expiry date per the "silent program killer" rule (Lecture 10 slide 12): an
un-expiring risk acceptance is functionally the same as permanently ignoring the finding.

### Next-quarter goal
**SAMM practice to mature: Defect Management.** Right now MTTR is undefined because
nothing has been triaged or closed — the very first step of a real Defect Management
practice (systematically tracking findings to remediation) hasn't started yet for this
program. Next quarter's concrete goal: triage the 22 Critical findings within their 1-day
SLA window and the top 20% of High findings within 7 days, closing them in DefectDojo with
real mitigation dates, so that MTTR and vuln-age become real, trend-able numbers instead of
structural zeros. A secondary goal tied to the same practice: build the custom Falco-log
parser DefectDojo doesn't ship with, so Lab 9's runtime alerts become part of the same
unified backlog instead of living only in `falco.log`.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: ~4:45
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "the same CVE showed up in 4 different scanners before I
  even started triaging — the tools agree with each other more than people expect."
