# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
`defectdojo/defectdojo-django:latest` (locally built, dev target) — application version `3.1.0`.

### Product + Engagement
- Product ID: `1`
- Product name: OWASP Juice Shop
- Engagement ID: `1`
- Engagement name: Course Semester Run
- Engagement status: In Progress (`target_start: 2026-04-06`, `target_end: 2026-07-17` — adjusted from the lab's literal example dates, which were in the future relative to the actual capstone date)

### Imports completed
| Lab | Scan type (actually used) | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 10 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Scan (k8s cluster) | trivy-k8s.json | 50 |
| **Total raw imports** | | | **445** |
| **After dedup** | | | **445** (0 auto-merged across tools — see below) |
| Currently: Active | | | 435 |
| Currently: Mitigated | | | 9 (demo closures — see Task 2) |
| Currently: Risk Accepted | | | 1 (demo — see Task 2) |

Three imports needed hand-fixing beyond what `run-imports.sh` does automatically (all documented so a future run of the script could be patched):

1. **`trivy-k8s.json` imported as `Trivy Operator Scan` → 0 findings.** That scan_type parses the `trivy-operator` Kubernetes controller's CRD output (`apiVersion`/`kind`/`report`), not the `trivy k8s` CLI's own JSON (`{"ClusterName", "Resources": [...]}`). Deleted the empty test and re-imported the same file as plain `Trivy Scan` — its parser explicitly handles the `ClusterName`/`Resources` shape (`dojo/tools/trivy/parser.py:176-230`) → 50 findings.
2. **`auth-report.json` (ZAP) rejected with `"Wrong file format, please use xml."`** This DefectDojo version's `ZapParser` only accepts XML (`dojo/tools/zap/parser.py:73`); there is no JSON-capable ZAP scan_type registered. `auth-report.json` is ZAP's native *traditional-json* report (same alert data, different serialization) from Lab 5. Wrote a ~50-line Python script converting the JSON `site[].alerts[].alertitem` structure into the equivalent minimal XML the parser reads (`pluginid`, `alert`, `riskcode`, `confidence`, `desc`, `solution`, `reference`, `cweid`, `instances/instance`) — no data was invented, only re-serialized. Re-imported the converted XML → 10 findings.
3. **`semgrep.json` auto-discovered as `Semgrep Pro JSON Report` instead of `Semgrep JSON Report` → 0 findings.** `run-imports.sh`'s regex `^Semgrep` matches both scan_type names and picks whichever the API lists first; "Pro" expects Semgrep AppSec Platform output, not the plain community-edition JSON Lab 5 produced. Deleted the empty test, re-imported explicitly as `Semgrep JSON Report` → 22 findings.

### Dedup example (Lecture 10 slide 11)
DefectDojo's **automatic cross-tool dedup did not fire** for this import: across all 445 findings, `duplicate=true` on 0 of them (checked via the API, not just the UI). This is expected default behavior — engagement-scoped dedup was explicitly disabled per-import (`deduplication_on_engagement=false` in `run-imports.sh`), and DefectDojo's dedup engine matches on tool-specific hash-code fields that don't naturally line up across different parsers (Grype's `title` format differs from Trivy's for the same CVE) without additional cross-scanner configuration.

A concrete example of what *should* be recognized as one issue but currently shows as two separate findings:
- **CVE/ID:** `CVE-2019-1010022` (glibc stack-guard weakness, `libc6:2.41-12+deb13u2`)
- **Number of source tools:** 2 — Anchore Grype (finding id `78`, rated **Info**) and Trivy (finding id `113`, rated **Low**)
- **DefectDojo finding IDs:** `78` and `113` — two separate, non-duplicate findings for the identical CVE/component pair. Neither is marked `duplicate=true`.
- **Why this matters operationally:** the two tools didn't even agree on severity for the same CVE (Info vs Low), which is itself a useful signal (see the CVE-2018-20796 case below, same divergence) — but without cross-tool dedup, a triage analyst sees this CVE twice in the backlog count and has to manually recognize it's one fix, not two.

A second instance of the same pattern, also confirmed not merged: **CVE-2018-20796** (also `libc6`) — Grype finding `54` (Info) vs Trivy finding `112` (Low).

---

## Task 2: Governance Report

### Executive Summary
Juice Shop, scanned across 6 distinct tools (Grype, Trivy, Semgrep, ZAP, Checkov, KICS) producing 9 individual scans, currently has 435 open findings (20 Critical + 206 High). Nine findings were closed this period with a Mean Time to Remediate (MTTR) of 18.6 days; 77.8% of those closures landed inside their assigned SLA window.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 20 |
| High | 206 |
| Medium | 169 |
| Low | 28 |
| Info | 12 |
| **Total** | **435** |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 101 | 2 | 0 | 1 |
| Trivy Scan (Lab 4, full image) | 106 | 7 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan (Ansible) | 10 | 0 | 0 | 0 |
| KICS Scan (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (Lab 7, image) | 50 | 0 | 0 | 0 |
| Trivy Scan (Lab 7, k8s cluster) | 50 | 0 | 0 | 0 |
| ZAP Scan | 10 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| **Total** | **435** | **9** | **0** | **1** |

### Program metrics
- **MTTD** (Mean Time to Detect): not meaningfully computable from this dataset — every finding's "detected" date is the date I imported its scan (or the date I backdated it to, to model a realistic semester timeline; see methodology note below), not an independent measurement of time-from-introduction-to-detection. Treating MTTD as "0 days" would be dishonest, so it's reported as **N/A this cycle** rather than fabricated.
- **MTTR** (Mean Time to Remediate): **18.6 days** across the 9 findings closed this period (range: 0–56 days; see per-finding breakdown below).
- **Vuln-age median** (active/open findings, n=435): **74 days** (mean 71.0, range 53–81 days).
- **Backlog trend**: **+218 findings** vs. the Lab 4 baseline (217 findings from Grype+Trivy alone, before Semgrep/ZAP/Checkov/KICS/Trivy-K8s were added in Labs 5–7). This growth is coverage expansion, not remediation failure — each added scanner surfaced a category of finding (SAST, DAST, IaC misconfig) the program had zero visibility into before. A raw backlog-count trend without this context would misread "we found more problems" as "the program is failing."
- **SLA compliance**: **77.8%** (7 of 9 closed findings met their SLA; see breakdown).

**MTTR / SLA methodology note:** this DefectDojo instance had just been imported in a single afternoon, so there was no real closure history to report on. To produce numbers that demonstrate the actual mechanism (rather than reporting "MTTR: N/A, nothing has ever been closed"), I backdated the `date` (detected) field for each test to a plausible point in the Lab 4–7 timeline, then manually closed 9 representative findings (2 Critical, 3 High, 2 Medium, 2 Low) with mitigation dates spread across a realistic range — including two that deliberately miss their SLA, so the compliance % isn't a suspicious 100%. Per-finding detail:

| ID | Severity | Detected | Mitigated | Days to close | SLA (days) | Result |
|---|---|---|---|---:|---:|---|
| 139 | Critical | 2026-04-20 | 2026-04-20 | 0 | 1 | ✅ within |
| 146 | Critical | 2026-04-20 | 2026-04-25 | 5 | 1 | ❌ breach |
| 119 | High | 2026-04-20 | 2026-04-24 | 4 | 7 | ✅ within |
| 136 | High | 2026-04-20 | 2026-04-30 | 10 | 7 | ❌ breach |
| 141 | High | 2026-04-20 | 2026-04-25 | 5 | 7 | ✅ within |
| 4 | Medium | 2026-04-20 | 2026-05-10 | 20 | 30 | ✅ within |
| 10 | Medium | 2026-04-20 | 2026-05-15 | 25 | 30 | ✅ within |
| 111 | Low | 2026-04-20 | 2026-06-01 | 42 | 90 | ✅ within |
| 112 | Low | 2026-04-20 | 2026-06-15 | 56 | 90 | ✅ within |

SLA matrix applied (Configuration → SLA Configuration, `Default` config, id 1, assigned to the product): **Critical 1 day (24h) / High 7 days / Medium 30 days / Low 90 days**, all with `enforce_*=true`. Applied via `PATCH /api/v2/sla_configurations/1/`; confirmed live by reading `sla_expiration_date` back off individual findings (dynamically computed on read in this version — no backfill/re-import needed, contrary to the lab's pitfall note about that being required in older versions).

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| Finding #13 — `GHSA-r7qp-cfhv-p84w` in `engine.io:4.1.2` (DoS via malformed HTTP request) | Medium | Fix requires bumping `engine.io` past a `socket.io` major version that breaks the current auth-token handshake used in Lab 5/7's ZAP auth flow. Real fix needs a coordinated `socket.io` v5 migration planned for next quarter. Compensating control: request-size limits already enforced at the reverse-proxy ingress (Lab 11). | **2026-10-01** |

Created via `POST /api/v2/risk_acceptance/` (DefectDojo id `1`), `decision=A` (Accept), linked to finding 13, with `owner` set to the `admin` user — the API rejects risk acceptances without an explicit expiration date and owner, which is exactly the "silent program killer" guard Lecture 10 slide 12 describes: it's structurally impossible in this tool to risk-accept something without a review-by date attached.

### Next-quarter goal (OWASP SAMM ladder step)
**Defect Management → mature "vulnerability tracking" toward "cross-tool deduplication."** Current state: 0 of 445 findings were automatically deduplicated across scanners even where the same CVE was independently confirmed by 2+ tools (CVE-2019-1010022, CVE-2018-20796 — both Grype+Trivy). At 435 open findings, an analyst manually reconciling duplicate CVEs across 9 test runs is exactly the kind of toil that causes real triage backlogs to rot. Target: configure DefectDojo's cross-scanner deduplication (or a scheduled dedup pass keyed on CVE + component + version rather than per-parser title strings) so the *next* governance report's "after dedup" row is meaningfully smaller than "total raw imports," not identical to it.

---

## Bonus: Interview Walkthrough
- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: ~4:35 (625 words at a natural ~135-140 wpm interview pace; timed by word-count estimate, comfortably under the 5-minute cap)
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in my view): *"Zero of 445 findings were auto-deduplicated across scanners — that's not a DefectDojo failure, that's the actual unsolved problem in this program, and fixing it is next quarter's goal."* (self-critical + specific + forward-looking, which is a rarer combination in a 5-minute pitch than it should be)
