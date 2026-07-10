# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: **3.1.0** (the current `defectdojo/defectdojo-django:latest` clone — newer
  than the v2.58.x the lab text pins, but the API + importer flow is identical).
- Ran with the **release** compose config (`./docker/setEnv.sh release`). The `dev` config failed
  because its containers look for `/entrypoint-uwsgi-dev.sh`, which isn't in the pulled image.
  Also had to delete `docker/extra_settings/README.md` — a non-empty `extra_settings/` makes the
  initializer try to copy it into `dojo/settings/` and die on a permission error.

### Product + Engagement
- Product ID: **1**
- Product name: OWASP Juice Shop
- Engagement ID: **2**
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 4 | Trivy Scan | trivy.json | 80 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 0 (import failed — see note) |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan | trivy-image.json | 50 |
| 7 | Trivy Scan | trivy-k8s.json (flattened) | 100 |
| **Total raw imports** | | | **456** |
| **After dedup** | | | **310 unique** (146 duplicates) |

Notes on the two files that needed handling:
- **ZAP (`auth-report.json`) — skipped.** DefectDojo's "ZAP Scan" parser only accepts ZAP's XML
  export; our Lab 5 file is JSON, so the import returns `Wrong file format, please use xml.`
  DefectDojo has no ZAP-JSON parser, so this source is documented-as-skipped (the lab allows this).
- **Trivy K8s (`trivy-k8s.json`) — flattened first.** The `trivy k8s` CLI wraps results in a
  `{ClusterName, Resources:[{...Results}]}` envelope that neither "Trivy Scan" nor "Trivy Operator
  Scan" parses. I flattened it into a standard `{Results:[...]}` doc with
  `jq '{SchemaVersion:2, ArtifactName:"juice-shop-cluster", ArtifactType:"container_image", Results:[.Resources[].Results[]?]}'`
  and imported as "Trivy Scan" (100 findings, almost all duplicates of the image scan — expected,
  since it's the same image running in the cluster).
- Lab 4's `grype-from-sbom.json` and `trivy.json` were regenerated from the Lab 4 SBOM
  (`grype sbom:...` and `trivy sbom ...`) since only the SBOM itself was kept.

### Dedup example (Lecture 10 slide 11)
- **CVE/ID:** CVE-2023-46233 (predictable salt in `crypto-js` — Critical)
- **Number of source detections:** 4 Trivy detections collapsed into 1 finding
- **DefectDojo's single surviving finding ID:** **447** (Trivy Scan, from the Lab 4 SBOM scan)
  - duplicate **643** — Trivy Scan (Lab 7 image) → points to 447
  - duplicate **693** — Trivy Scan (Lab 7 k8s) → points to 447
  - duplicate **743** — Trivy Scan (Lab 7 k8s) → points to 447

The interesting nuance: Grype **also** found this exact CVE (finding **359**), but DefectDojo kept
it as a *separate* active finding rather than merging it with the Trivy one. That's because
DefectDojo's default deduplication is **per-parser** (it compares a `hash_code` computed from
fields each parser populates differently), so it collapses the same CVE across multiple *Trivy*
runs but not across *different tools*. Visible at the aggregate level too: the Lab 7 Trivy image
scan added only **3** net-new findings and the k8s scan only **1** — the other 47 + 99 were
recognised as duplicates of the earlier Trivy SBOM scan. Deduplication had to be turned on first
(`system_settings.enable_deduplication = true` — it's off by default).

---

## Task 2: Governance Report

### Executive Summary
OWASP Juice Shop, scanned across 6 tools (Grype, Trivy, Semgrep, Checkov, KICS, + the flattened
Trivy K8s scan), currently has **305 open findings** — **11 Critical + 120 High** — after
deduplicating 456 raw results down to 310 unique. Three Critical dependency findings were
remediated this period and two low-severity findings were formally risk-accepted with a
re-review date. Because every finding was imported in a single point-in-time snapshot, MTTR and
vuln-age are near-zero and are reported below as illustrative rather than trend data.

### Findings by severity (active, deduplicated)
| Severity | Count |
|----------|------:|
| Critical | 11 |
| High | 120 |
| Medium | 156 |
| Low | 9 |
| Info | 9 |
| **Total active** | **305** |

### Findings by source tool
| Tool | Unique | Duplicates | Mitigated | Risk Accepted |
|------|-------:|----------:|----------:|--------------:|
| Anchore Grype (Lab 4) | 108 | 0 | 3 | 2 |
| Trivy Scan — SBOM (Lab 4) | 80 | 0 | 0 | 0 |
| Semgrep (Lab 5) | 22 | 0 | 0 | 0 |
| Checkov (Lab 6) | 80 | 0 | 0 | 0 |
| KICS — Ansible (Lab 6) | 10 | 0 | 0 | 0 |
| KICS — Pulumi (Lab 6) | 6 | 0 | 0 | 0 |
| Trivy Scan — image (Lab 7) | 3 | 47 | 0 | 0 |
| Trivy Scan — k8s (Lab 7) | 1 | 99 | 0 | 0 |

(The 3 mitigated + 2 risk-accepted findings all happen to be Grype findings, since Grype's copies
stayed as the active/authoritative ones for those CVEs.)

### Program metrics
- **MTTD** (Mean Time to Detect): not meaningfully measurable from a bulk import — every finding's
  detect date is the import date. In a live pipeline this would be `detect_time − introduce_time`.
- **MTTR** (Mean Time to Remediate): 3 findings closed, all mitigated the same day they were
  imported → **≈ 0 days**. Illustrative only (see exec summary); the point is the *workflow* works,
  not the number.
- **Vuln-age median** (open findings): **≈ 0 days** — this is a point-in-time snapshot; all
  findings share today's `first_seen`.
- **Backlog trend**: this import establishes the **baseline** (310 unique). No prior period to
  compare against yet.
- **SLA compliance**: **100%** currently — with SLA windows of Critical 1d / High 7d / Medium 30d /
  Low 90d and findings created today, nothing has breached its window yet. The value of the matrix
  shows up over time as the clock runs on the 11 Criticals (24h each).

### SLA matrix applied
Configured on the "Default" SLA config (applied to the product) per Lecture 9/10:
| Severity | Fix SLA |
|----------|---------|
| Critical | 24h (1 day) |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Risk-accepted items (all with expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #399 — GHSA-pxg6-pf52-xh8x in cookie 0.4.2 | Low | Not reachable in Juice Shop's config; low severity | 2026-10-10 |
| #426 — CVE-2026-48931 in node 24.15.0 | Low | Base-image CVE, low severity; tracked for next base bump | 2026-10-10 |

Both were accepted through a single DefectDojo Risk Acceptance object ("Accepted low-risk deps Q3")
with an explicit `expiration_date` — no open-ended acceptances (the "silent program killer" from
Lecture 10 slide 12).

### Next-quarter goal (OWASP SAMM)
Mature **Defect Management** (Implementation function) from Level 1 to Level 2. Right now findings
land in DefectDojo but dedup is only per-parser, so the same CVE from Grype and Trivy shows up as
two active findings (e.g. CVE-2023-46233 as #359 and #447) — inflating the 305 active count and
splitting triage. Concrete step: configure a cross-parser `hash_code` dedup (unique-id on CVE +
component) so Grype↔Trivy collapse like the Trivy scans already do, and wire the Lab 9 Falco
alerts in as a runtime finding source via a custom parser so the program covers detect-time as
well as build-time. Target: a single deduplicated finding per real vulnerability, and MTTR/vuln-age
that reflect actual fix latency once the pipeline runs across multiple periods.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see [`submissions/lab10-walkthrough.md`](lab10-walkthrough.md)
- Practiced runtime: ~4:45 read aloud (under the 5-minute budget)
- Two anticipated Q&A questions covered: yes (Log4Shell response via SBOM attestation; why no
  IAST/paid tooling)
- Strongest claim in the script (the line most likely to get a follow-up): *"456 raw findings
  deduplicated to 310 unique — 11 Critical and 120 High active,"* backed by the concrete
  CVE-2023-46233 cross-scan dedup example.
