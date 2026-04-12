# Lab 10 — Vulnerability Management & Response with DefectDojo

![difficulty](https://img.shields.io/badge/difficulty-intermediate-orange)
![topic](https://img.shields.io/badge/topic-Vulnerability%20Management-blue)
![points](https://img.shields.io/badge/points-10-orange)

> Goal: Stand up DefectDojo locally, import prior lab findings (ZAP, Semgrep, Trivy/Grype, Nuclei), and produce a stakeholder-ready reporting & metrics package.
> Deliverable: A PR from `feature/lab10` with `labs/submission10.md` summarizing setup evidence, import results, metrics snapshot highlights, and links to exported artifacts. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Standing up OWASP DefectDojo locally via Docker Compose
- Organizing findings across products/engagements/tests
- Importing findings from multiple tools (ZAP, Semgrep, Trivy, Nuclei)
- Generating reports that non-technical stakeholders can consume
- Deriving basic program metrics (open/closed status, severity mix, SLA outlook)

> Primary platform: OWASP DefectDojo (open source, 2025)

---

## Prerequisites

- Docker with Compose V2 (`docker compose` available)
- `git`, `curl`, `jq`
- Prior lab outputs available locally (paths below)

Create working directories:
```bash
mkdir -p labs/lab10/{setup,imports,report}
```

---

## Tasks

### Task 1 — DefectDojo Local Setup (2 pts)
Objective: Run DefectDojo locally and prepare the structure for managing findings.

#### 1.1: Clone and start DefectDojo
```bash
# Clone upstream
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo

# Optional: check compose compatibility
./docker/docker-compose-check.sh || true

# Build and start (first run can take a bit)
docker compose build
docker compose up -d

# Verify containers are healthy
docker compose ps
# UI: http://localhost:8080
```

#### 1.2: Get admin credentials (no manual superuser needed)
```bash
# Watch initializer logs until the admin password is printed
docker compose logs -f initializer
# In a second terminal, extract the password once available:
docker compose logs initializer | grep "Admin password:"

# Login to the UI at http://localhost:8080 with:
#   Username: admin
#   Password: <the value printed above>
```
---

### Task 2 — Import Prior Findings (4 pts)
Objective: Import findings from your previous labs into the engagement.

Use the importer script below; no manual API calls are required. The script will auto‑create the product type/product/engagement if missing.

#### 2.1: Get API token and set variables
```bash
# In the UI: Profile → API v2 Key → copy your token
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="b13e3f5487db1acceb5fac449a1f131882332b43"

# Target context (adjust names if you prefer)
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
# The import script will auto-detect importer names from your instance.
```

#### 2.2: Required reports (expected paths)
- ZAP: `labs/lab5/zap/zap-report-noauth.json`
- Semgrep: `labs/lab5/semgrep/semgrep-results.json`
- Trivy: `labs/lab4/trivy/trivy-vuln-detailed.json`
- Nuclei: `labs/lab5/nuclei/nuclei-results.json`
- Grype (optional): `labs/lab4/syft/grype-vuln-results.json`

#### 2.3: Run the importer script
```bash
bash labs/lab10/imports/run-imports.sh
```
The script auto-detects importer names, auto-creates context if missing, imports any reports found at the paths above, and saves responses under `labs/lab10/imports/`.
---

### Task 3 — Reporting & Program Metrics (4 pts)
Objective: Turn raw imports into an easy-to-understand report and metrics package that a stakeholder can consume without prior Dojo experience.

#### 3.1: Create a baseline progress snapshot
- From the engagement dashboard, note the counts for Active, Verified, and Mitigated findings.
- Use the “Filters” sidebar to group by severity; grab a screenshot or jot the numbers.
- Record the snapshot using the template below:
  ```bash
  mkdir -p labs/lab10/report
  cat > labs/lab10/report/metrics-snapshot.md <<'EOF'
  # Metrics Snapshot — Lab 10

  - Date captured: <enter date>
  - Active findings:
    - Critical: <enter number>
    - High: <enter number>
    - Medium: <enter number>
    - Low: <enter number>
    - Informational: <enter number>
  - Verified vs. Mitigated notes: <short summary>
  EOF
  ```

#### 3.2: Generate governance-ready artifacts
- In the Engagement → Reports page, choose a human-readable template (Executive, Detailed, or similar) and generate a PDF or HTML report.
  - Save it to `labs/lab10/report/dojo-report.pdf` or `.html`.
- Download the “Findings list (CSV)” from the same page and store it as `labs/lab10/report/findings.csv` for spreadsheet analysis.

#### 3.3: Extract key metrics for `labs/submission10.md`
- From the report or dashboard, capture:
  - Open vs. Closed counts by severity.
  - Findings per tool (ZAP, Semgrep, Trivy, Nuclei, and Grype).
  - Any SLA breaches or items due within the next 14 days.
  - Top recurring CWE/OWASP categories.
- Summarize these in prose (3–5 bullet points) inside `labs/submission10.md`.

Deliverables for this task:
- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.(pdf|html)`
- `labs/lab10/report/findings.csv`
- Metric summary bullets in `labs/submission10.md`

---

## Acceptance Criteria

- ✅ DefectDojo runs locally and an admin user can log in
- ✅ Product Type, Product, and Engagement are configured
- ✅ Imports completed for ZAP, Semgrep, Trivy (plus Nuclei/Grype if available)
- ✅ Reporting artifacts generated: metrics snapshot, Dojo report, findings CSV, and summary bullets in `labs/submission10.md`
- ✅ All artifacts saved under `labs/lab10/`

---

## How to Submit

1. Create a branch for this lab and push it to your fork:
```bash
git switch -c feature/lab10
# create labs/submission10.md with your findings
git add labs/lab10/ labs/submission10.md
git commit -m "docs: lab10 — DefectDojo vuln management"
git push -u origin feature/lab10
```
2. Open a PR from your fork’s `feature/lab10` → course repo’s `main`.
3. Include this checklist in the PR description:
```text
- [x] Task 1 — Dojo setup and structure
- [x] Task 2 — Imports completed (multi-tool)
- [x] Task 3 — Report + metrics package
```
4. Submit the PR URL via Moodle before the deadline.

---

## Rubric (10 pts)

| Criterion                                                    | Points |
| ------------------------------------------------------------ | -----: |
| Task 1 — DefectDojo local setup                              |    2.0 |
| Task 2 — Import prior findings (multi-tool)                  |    4.0 |
| Task 3 — Reporting & metrics package                         |    4.0 |
| Total                                                        |   10.0 |

---

## Guidelines

- Keep sensitive data out of uploads; use lab outputs only
- Prefer JSON formats for robust importer support
- If you explore deduplication, note the algorithm choice (helps explain numbers)
- Be explicit when marking false positives (add justification)
- Keep SLAs realistic but time-bound; reference calendar dates

<details>
<summary>References</summary>

- DefectDojo: https://github.com/DefectDojo/django-DefectDojo
- Importers list: check your UI Import Scan page for exact `scan_type` names
- Local API v2 docs: http://localhost:8080/api/v2/doc/ (after startup)
- Official docs (Open Source): https://docs.defectdojo.com/en/open_source/
- CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1

</details>
