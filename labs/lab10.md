# Lab 10 — Vulnerability Management with DefectDojo: The Capstone

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Vuln%20Management-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-DefectDojo-informational)

> **Goal:** Spin up DefectDojo locally, import every scan report from Labs 4–9, apply the SLA matrix from Lecture 9, compute program metrics, and (bonus) produce a 5-minute interview-walkthrough script.
> **Deliverable:** A PR from `feature/lab10` with `submissions/lab10.md` (governance report) and (bonus) `submissions/lab10-walkthrough.md` (interview script). Submit PR link via Moodle.

---

## Overview

This is the **capstone**. You have 9 labs of scan output. Lab 10 turns them into a **program**.

In this lab you will practice:
- **DefectDojo v2.58.x** (Lecture 10 slide 9) — setup, importers, dedup, SLA matrix
- **Cross-tool dedup** — same CVE found by Trivy + Grype + Trivy-K8s collapsing into one finding
- **CVSS + EPSS triage** (Lecture 10 slides 5-7) — the 2×2 prioritization matrix
- **Program metrics** (Lecture 10 slide 13) — MTTD/MTTR/vuln-age/backlog/SLA-compliance
- (Bonus) **5-minute interview walkthrough** — the deliverable that gets you hired

> If you've kept your Lab 4–9 outputs, this lab is doable in one sitting. If not, regenerate them before starting.

---

## Project State

**You should have from Labs 4-9** (regenerate if missing):
- Lab 4: `juice-shop.cdx.json`, `grype-from-sbom.json`, `trivy.json`
- Lab 5: `auth-report.json` (ZAP), `semgrep.json`
- Lab 6: `checkov-terraform/results_json.json`, `kics-ansible/results.json`, `kics-pulumi/results.json`
- Lab 7: `trivy-image.json`, `trivy-k8s.json`
- Lab 8: `verify-original.json` (Cosign verify output)
- Lab 9: `falco/logs/falco.log` (custom alerts)

**This lab adds:**
- A working DefectDojo instance
- A unified product/engagement with all imports + dedup applied
- A governance report with real metrics
- (Bonus) An interview-ready walkthrough script

---

## Setup

You need:
- **Docker + docker-compose** (DefectDojo runs as 7+ containers)
- **`jq`** + **`curl`**
- ~4 GB free memory (DefectDojo is heavyweight)

```bash
git switch main && git pull
git switch -c feature/lab10

mkdir -p labs/lab10/work
```

> **Plumbing provided** (in `labs/lab10/imports/`):
> - `run-imports.sh` — imports every Lab 4-7 report into DefectDojo (paths resolved
>   from the repo root; portable to stock macOS bash 3.2)
> - `env.sample` — the environment variables the script reads (`DD_URL`, `DD_TOKEN`, …)

---

## Task 1 — DefectDojo Setup + Import All Prior Findings (6 pts)

**Objective:** Run DefectDojo locally, get the admin credentials, create a Product + Engagement for "Juice Shop", import every Lab 4-9 report.

### 10.1: Clone + start DefectDojo

```bash
# DefectDojo's official compose deployment
cd labs/lab10/work
git clone https://github.com/DefectDojo/django-DefectDojo dd
cd dd

# Check compose version compatibility
./docker/setEnv.sh dev    # writes the .env file

# Pull + start (first run takes 5-10 minutes)
docker compose up -d
# Watch initializer logs until you see "Admin password: ..."
docker compose logs initializer | grep -i password

# UI: http://localhost:8080
```

### 10.2: Extract admin token

```bash
# Login UI at http://localhost:8080 — admin / <password from initializer logs>
# Go to: Profile → API v2 Key → copy your token

# Export for the importer
export DD_URL="http://localhost:8080"
export DD_TOKEN="<your-api-token>"

# Verify
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/products/" | jq .count
# Should print 0 (no products yet)
```

### 10.3: Create Product + Engagement

```bash
# Via API (also doable in UI)
PRODUCT_ID=$(curl -s -X POST "$DD_URL/api/v2/products/" \
  -H "Authorization: Token $DD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OWASP Juice Shop",
    "description": "DevSecOps-Intro capstone product",
    "prod_type": 1
  }' | jq -r .id)
echo "Product: $PRODUCT_ID"

ENGAGEMENT_ID=$(curl -s -X POST "$DD_URL/api/v2/engagements/" \
  -H "Authorization: Token $DD_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Course Semester Run\",
    \"product\": $PRODUCT_ID,
    \"target_start\": \"2026-09-01\",
    \"target_end\": \"2026-12-15\",
    \"engagement_type\": \"CI/CD\",
    \"status\": \"In Progress\"
  }" | jq -r .id)
echo "Engagement: $ENGAGEMENT_ID"
```

### 10.4: Import scan files

For each prior lab, run (from the repo root):

```bash
# Template — repeat for each scan type
curl -X POST "$DD_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DD_TOKEN" \
  -F "scan_type=Trivy Scan" \
  -F "engagement=$ENGAGEMENT_ID" \
  -F "file=@labs/lab7/results/trivy-image.json"
```

Scan-type names to use:

| Lab | File | DefectDojo scan_type |
|-----|------|----------------------|
| 4 | `grype-from-sbom.json` | `Anchore Grype` |
| 4 | `trivy.json` | `Trivy Scan` |
| 5 | `semgrep.json` | `Semgrep JSON Report` |
| 5 | `auth-report.json` | `ZAP Scan` |
| 6 | `checkov-terraform/results_json.json` | `Checkov Scan` |
| 6 | `kics-ansible/results.json` | `KICS Scan` |
| 6 | `kics-pulumi/results.json` | `KICS Scan` |
| 7 | `trivy-image.json` | `Trivy Scan` |
| 7 | `trivy-k8s.json` | `Trivy Operator Scan` |
| 9 | `falco/logs/falco.log` | (custom-format — skip if not supported, document instead) |

To automate all of the above, just run the importer — it reuses the `DD_URL` + `DD_TOKEN`
you exported in 10.2 (see `labs/lab10/imports/env.sample` for every variable it reads):

```bash
bash labs/lab10/imports/run-imports.sh
```

### 10.5: Verify import + dedup

```bash
# Count findings per scan source
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?engagement=$ENGAGEMENT_ID&limit=1" | jq .count
# Should be 100s

# Dedup is automatic — verify with: same CVE appearing once
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?engagement=$ENGAGEMENT_ID&cve=CVE-2024-21626" | jq '.results | length'
# Should be 1 if your image had this CVE (it's the runc Leaky Vessels CVE)
```

### 10.6: Document in `submissions/lab10.md`

```markdown
# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: <output of `docker compose images defectdojo-uwsgi | grep IMAGE`>

### Product + Engagement
- Product ID: <n>
- Product name: OWASP Juice Shop
- Engagement ID: <n>
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | <n> |
| 4 | Trivy Scan | trivy.json | <n> |
| 5 | Semgrep JSON Report | semgrep.json | <n> |
| 5 | ZAP Scan | auth-report.json | <n> |
| 6 | Checkov Scan | results_json.json | <n> |
| 6 | KICS Scan | kics-ansible/results.json | <n> |
| 6 | KICS Scan | kics-pulumi/results.json | <n> |
| 7 | Trivy Scan (image) | trivy-image.json | <n> |
| 7 | Trivy Operator Scan | trivy-k8s.json | <n> |
| **Total raw imports** | | | <SUM> |
| **After dedup** | | | <n unique findings> |

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: <e.g. CVE-2024-21626>
- Number of source tools: <e.g. 3 — Trivy image, Trivy k8s, Grype>
- DefectDojo's single finding ID: <n>
```

---

## Task 2 — Governance Report with Program Metrics (4 pts)

> ⏭️ Optional. Skipping won't affect future labs (there are none!), but the metrics work is what makes this Lab 10 different from "ran a tool."

**Objective:** Apply the SLA matrix from Lecture 9 / 10 slide 8, compute MTTD/MTTR/vuln-age/backlog, write a 1-page governance report.

### 10.7: Apply the SLA matrix

In DefectDojo UI:
- **Configuration → SLA Configuration**:
  - Critical: 24 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days
- Apply to your Engagement

OR via API. Document either way.

### 10.8: Compute metrics

```bash
# MTTR — for closed findings only
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?engagement=$ENGAGEMENT_ID&is_mitigated=true" | \
  jq '[.results[] | {detected: .date, closed: .mitigated, severity}]' \
  > labs/lab10/work/mttr-source.json

# Severity distribution
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?engagement=$ENGAGEMENT_ID&active=true" | \
  jq '[.results[] | .severity] | group_by(.) | map({severity: .[0], count: length})'

# SLA compliance — count findings per (active/mitigated, within/over SLA)
# Use the UI dashboards for the visual; API for the numbers
```

### 10.9: Write the governance report

```markdown
## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across <n> tools, currently has <n> open findings (<n> Critical + <n> High).
Mean Time to Remediate (MTTR) on closed-this-period findings is <n> days. <n>% of findings closed
within their SLA.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| ... |

### Program metrics
- **MTTD** (Mean Time to Detect): <n> days
- **MTTR** (Mean Time to Remediate): <n> days
- **Vuln-age median** (open findings): <n> days
- **Backlog trend**: <+/- n> findings vs. <baseline>
- **SLA compliance**: <n>%

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| ... (list all your "Risk Accepted" findings — they all must have expiry per Lecture 10 slide 12) |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
What ONE concrete SAMM practice would you mature next quarter, and why?
(2-3 sentences with specific data — e.g., "Defect Management — current MTTR for High
is X days, target Y; add Falco-runtime ingestion via custom parser.")
```

---

## Bonus Task — 5-Minute Interview Walkthrough Script (2 pts)

> 🌟 **The deliverable that gets you hired.** Many DevSecOps interviews are "talk me through your last program" for 5 minutes. This bonus produces exactly that script.

**Objective:** Write a 5-minute walkthrough following Lecture 10 slide 15 structure.

### B.1: Write the script

Create `submissions/lab10-walkthrough.md`:

```markdown
# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
[1 sentence: I built a DevSecOps program around OWASP Juice Shop as the target...
1 sentence: Tools used, scope, what's signed/scanned/verified.]

## (0:30–2:00) Layers
[Draw the diagram from Lecture 9 slide 18 in your words. Talk through:
- Pre-commit: gitleaks for secrets + SSH-signed commits
- Build: SBOM (Syft), SCA (Grype), SAST (Semgrep)
- Pre-deploy: Checkov on IaC, Cosign sign + Conftest gate
- Runtime: Falco eBPF detection
- Program: DefectDojo aggregation + SLA matrix + MTTR/age]

## (2:00–3:00) Findings + Closures
[Talk through:
- "We closed <n> Critical findings this term."
- "Here's one I risk-accepted — <name> — expiring <date>, why: <reason>."
- "Strongest correlated finding: <name> — caught by both Semgrep and ZAP, fix was <X>."]

## (3:00–4:00) Metrics
[Talk through:
- MTTR: <n> days (compare to DORA Elite which is <1 day, Lecture 9 slide 13)
- Vuln-age median: <n> days
- SLA compliance: <n>%
- Backlog trend: <stable/falling/rising>]

## (4:00–4:30) Next Steps
[1 sentence: "If I had another quarter, I'd ship..."
1 sentence: tied to OWASP SAMM ladder progression.]

## (4:30–5:00) Q&A Anticipation
Anticipate 2 likely questions and answer them in your script:
1. "How would you handle a Log4Shell scenario?" → 1-paragraph answer referencing the SBOM
2. "Why didn't you use IAST/paid tools?" → honest tradeoff
```

### B.2: Practice it

Read it out loud. Time yourself. If you're over 5 minutes, **cut something** — interviews don't pause.

### B.3: Document in `submissions/lab10.md`

```markdown
## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: <n minutes:seconds>
- Two anticipated Q&A questions covered: yes / no
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): <quote>
```

---

## How to Submit

```bash
git add submissions/lab10.md
git add submissions/lab10-walkthrough.md     # Bonus only
git commit -m "feat(lab10): defectdojo governance report + capstone walkthrough"
git push -u origin feature/lab10

# Cleanup
cd labs/lab10/work/dd && docker compose down -v
```

> **Do NOT commit** `labs/lab10/work/dd/` — it's the upstream DefectDojo source clone. Add to `.gitignore`.

PR checklist body:

```text
- [x] Task 1 — DefectDojo setup + imports + dedup proof
- [ ] Task 2 — Governance report with MTTD/MTTR/SLA/backlog
- [ ] Bonus — 5-minute walkthrough script with timed practice
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ DefectDojo running locally; admin password documented
- ✅ Product + Engagement created (IDs in submission)
- ✅ ≥6 scan types imported from Labs 4-9
- ✅ Imports-table populated with real counts
- ✅ ONE cross-tool dedup example documented (specific CVE + N source tools)

### Task 2 (4 pts)
- ✅ SLA matrix applied (24h / 7d / 30d / 90d for Critical / High / Medium / Low)
- ✅ Governance report has all 6 sections (Exec Summary, by severity, by tool, metrics, risk-accepted, next-quarter goal)
- ✅ ALL Risk-Accepted items have explicit expiry dates (Lecture 10 slide 12 — the "silent program killer" rule)
- ✅ Next-quarter goal references a concrete SAMM practice with rationale

### Bonus Task (2 pts)
- ✅ `submissions/lab10-walkthrough.md` exists with all 6 timed sections
- ✅ Script timed to ≤5 minutes when read aloud
- ✅ Anticipates ≥2 Q&A questions with answers prepared

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Setup + import | **6** | DefectDojo running + 6+ imports + dedup proof + counts |
| **Task 2** — Governance | **4** | SLA matrix + 6-section report + risk-accepted-with-expiry discipline + SAMM-aligned next step |
| **Bonus Task** — Walkthrough | **2** | Timed-to-5-min script + Q&A preparation |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [DefectDojo documentation](https://docs.defectdojo.com/) — Including importer formats
- [DefectDojo API v2 reference](https://docs.defectdojo.com/api/) — For automation
- [Supported scan types](https://docs.defectdojo.com/integrations/parsers/) — Match your file names to scan_type strings
- [OWASP SAMM v2.0](https://owaspsamm.org/) — For the next-quarter-goal section
- [DORA 2024 report](https://cloud.google.com/devops/state-of-devops/) — Benchmark MTTR against Elite performers

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`docker compose up -d` fails with OOM** — DefectDojo needs ~4GB RAM. Increase Docker Desktop memory or use a Linux host with more RAM.
- 🚨 **Initializer never prints admin password** — the initializer runs only on first start. If you missed it: `docker compose down -v && docker compose up -d` to reset, OR query the postgres directly (see DefectDojo docs).
- 🚨 **Import returns 400** — scan_type names are CASE-SENSITIVE. `Trivy Scan` (with space + capital T+S) is the canonical name. Use the Supported scan types reference link above.
- 🚨 **Import succeeds but no findings appear** — your scan output is in the wrong format. Trivy default JSON is different from "Trivy operator" JSON — match the exact format DefectDojo expects.
- 🚨 **SLA matrix doesn't apply to existing findings** — DefectDojo applies SLA at finding-creation time. Re-import (or use the bulk-update API) to back-fill SLAs on already-imported findings.
- 🚨 **Closing a finding still shows as "active"** — closing a finding requires `is_mitigated=true` PATCH, AND the engagement must have an SLA assigned for the close-time math to compute.
- 💡 **Skipping the bonus is a missed career opportunity.** The 5-minute walkthrough script is what you'll send recruiters in 6 months. Do it.

</details>

<details>
<summary>🪜 Looking ahead — outside this course</summary>

This is the capstone. There is no Lab 11/12 chain (the bonus labs 11 and 12 are different topics).
**Your portfolio next step:**
1. Save this DefectDojo dataset + governance report
2. Apply the same lab patterns to a real OSS project of your choice
3. The walkthrough script you produced today is what you'll customize for each interview

</details>
