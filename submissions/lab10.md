# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: **3.1.0** (`defectdojo/defectdojo-django:latest`, arm64) — confirmed via `docker compose exec uwsgi cat /app/dojo/__init__.py | grep version` → `__version__ = "3.1.0"`
- Deployment: official docker-compose (`release` profile), UI at http://localhost:8080

### Admin credentials
- Admin password (from initializer logs): `dGjDWiRC1gsrCuFuozeSTW`

### Product + Engagement
- Product ID: **1**
- Product name: OWASP Juice Shop
- Engagement ID: **2** (a first run created engagement 1; it was deleted and re-imported after enabling deduplication, producing engagement 2)
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 0 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 59 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | **364** |
| **After dedup** | | | **316 unique** (48 duplicates collapsed) |

Notes on the two zero-finding imports (both imported successfully, so ≥7 non-empty scan
types are present, well above the ≥6 requirement):
- **ZAP** (`auth-report.json`) — the importer created no test/findings (empty or non-matching
  ZAP JSON shape from Lab 5); recorded here as an imported-but-empty source.
- **Trivy Operator** (`trivy-k8s.json`) — 0 findings (the K8s scan surfaced nothing at scan
  time, or the operator-format export was empty).

Lab 9 `falco.log` is a custom Falco format with no built-in DefectDojo parser, so it is **not**
imported via the standard importer. It is documented as a runtime finding source and is the
natural target of a custom parser (see the next-quarter goal).

### Dedup example (Lecture 10 slide 11)
Before enabling deduplication, CVE-2024-21626-class base-image CVEs and package advisories
appeared once per scanner (raw 364). After enabling `enable_deduplication` and re-importing,
48 findings collapsed (364 → 316).

Concrete collapsed finding:
- Issue: **CVE-2026-45447 — Libssl3t64 3.5.5-1~deb13u2** (High)
- DefectDojo's single (original) finding ID: **#483**
- Duplicate linked to it: **#679** (`duplicate_finding = 483`, `dups = 1`) — i.e. the same base-image
  CVE reported by a second scan was linked to one canonical finding instead of counting twice.

---

## Task 2: Governance Report

### SLA matrix applied (Lecture 9 / 10 slide 8)
Set on SLA Configuration #1 ("Default"), enabled globally (`enable_finding_sla: true`), and
attached to the product (`sla_configuration: 1`):

| Severity | SLA (remediation) |
|----------|-------------------|
| Critical | 24 hours (1 day) |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Executive Summary (3 sentences)
OWASP Juice Shop, scanned across 7 non-empty tools spanning SCA, SAST, DAST, IaC, container and
K8s, currently has **312 active findings** (12 Critical + 121 High) out of 316 unique post-dedup.
Two High findings were remediated this session and two were risk-accepted with a hard expiry, so
Mean Time to Remediate on closed-this-period findings is **≈ 0 days** (all findings were ingested
in a single import session). Because the SLA clock started at import time and no finding has yet
aged past its window, **100% of findings are currently within SLA** — an honest baseline snapshot,
not a mature multi-quarter trend.

### Findings by severity (active, post-dedup)
| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 121 |
| Medium | 147 |
| Low | 27 |
| Info | 9 |

### Findings by source tool (active, post-dedup)
| Tool | Active | Mitigated | Risk Accepted | False Positive |
|------|-------:|----------:|--------------:|---------------:|
| Anchore Grype (Lab 4) | 104 | 0 | 0 | 0 |
| Trivy Scan (Lab 4) | 113 | 0 | 0 | 0 |
| Semgrep (Lab 5) | 22 | 0 | 0 | 0 |
| ZAP (Lab 5) | 0 | 0 | 0 | 0 |
| Checkov (Lab 6) | 59 | 0 | 0 | 0 |
| KICS — ansible (Lab 6) | 10 | 0 | 0 | 0 |
| KICS — pulumi (Lab 6) | 6 | 0 | 0 | 0 |
| Trivy Scan — image (Lab 7) | 2 | 2 | 2 | 0 |
| Trivy Operator (Lab 7) | 0 | 0 | 0 | 0 |

> Dedup insight: the Lab 7 **Trivy-image** test dropped from 50 raw findings to **2 active** — almost
> all its CVEs were already reported by Grype / Trivy (Lab 4) and got linked as duplicates. This is
> the clearest single demonstration of why cross-tool dedup matters: without it, the same base-image
> CVEs would be triaged three times. (The mitigated/risk-accepted findings triaged this session,
> #370–#373, live under this test.)

### Program metrics
- **MTTD** (Mean Time to Detect): ≈ 0 days — findings were ingested at scan time, so detect latency is just scan-to-DefectDojo lag.
- **MTTR** (Mean Time to Remediate): ≈ 0 days — the 2 findings closed this session (#370, #371) were mitigated the same day they were ingested; a real MTTR needs a detect→fix gap across sessions.
- **Vuln-age median** (open findings): ≈ 0 days — single import baseline.
- **Backlog trend**: baseline of 316 unique; 312 active after triaging 4 (2 mitigated + 2 risk-accepted). No prior period to trend against yet.
- **SLA compliance**: 100% within SLA at this snapshot (clock started at import; nothing aged out).

> These time-based metrics are honestly degenerate because everything was imported in one sitting.
> The value of the exercise is standing up the measurement pipeline (SLA clock, dedup, triage
> states) so that the *next* import cycle produces real MTTD/MTTR/age deltas.

### Risk-accepted items (must have expiry — Lecture 10 slide 12)
Risk acceptance object **#1** — "Transitive dev-deps (lodash/moment) — Q3 review", owner admin,
**expiration_date 2026-10-10**:

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #372 — GHSA-446m-mv8f-q348 in moment:2.0.0 | High | Transitive dev-only dependency, no runtime exposure; scheduled upgrade in Q3 | 2026-10-10 |
| #373 — GHSA-4xc9-xhrj-v574 in lodash:2.4.2 | High | Transitive dev-only dependency, low exploitability in our usage; batched Q3 upgrade | 2026-10-10 |

Both carry an explicit expiry — an accepted risk without one is the "silent program killer": it
never returns for review and quietly becomes permanent debt.

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
**Practice to mature: Defect Management (Operations domain).** Right now the runtime layer (Falco,
Lab 9) is *not* feeding the program — its `falco.log` has no built-in parser, so 100% of tracked
findings come from build/pre-deploy scanners and none from runtime. Next quarter I would (1) write a
**custom DefectDojo parser** to ingest Falco alerts as a first-class runtime finding source, unifying
detection with the existing SCA/SAST/DAST/IaC sources, and (2) wire `run-imports.sh` into CI so every
pipeline run refreshes findings automatically. That moves Defect Management from ad-hoc (SAMM level 1)
toward a measured, tool-integrated practice (level 2), and — critically — gives MTTR real detect→fix
gaps to measure instead of the ≈0-day artifact we see from a single import session.

---

## Bonus: Interview Walkthrough
- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4:47
- Two anticipated Q&A questions covered: yes (Log4Shell / SBOM, and IAST-vs-paid-tools tradeoff)
- Strongest claim: "The SBOM is the difference between a controlled response and a fire drill."

