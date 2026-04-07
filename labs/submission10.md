# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

### 1.1 Local deployment

DefectDojo was deployed locally with Docker Compose from the official repository:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
docker compose up -d
```

Core services started successfully (`nginx`, `uwsgi`, `postgres`, `celeryworker`, `celerybeat`, `valkey`).

### 1.2 Context creation

The following hierarchy was used for imports:

- Product Type: `Engineering`
- Product: `Juice Shop`
- Engagement: `Labs Security Testing`

Context creation was automated by import calls with `auto_create_context=true`.

---

## Task 2 — Import Prior Findings

### 2.1 Input files used

- ZAP: `labs/lab5/zap/zap-report-noauth.xml`
- Semgrep: `labs/lab5/semgrep/semgrep-results.json`
- Trivy: `labs/lab4/trivy/trivy-vuln-detailed.json`
- Nuclei: `labs/lab5/nuclei/nuclei-results.json`
- Grype: `labs/lab4/syft/grype-vuln-results.json`

Note: DefectDojo `ZAP Scan` parser accepted XML input. A JSON report was also generated for lab evidence, but import used XML.

### 2.2 Import evidence

Saved API responses:

- `labs/lab10/imports/import-zap-report-noauth.json`
- `labs/lab10/imports/import-semgrep-results.json`
- `labs/lab10/imports/import-trivy-vuln-detailed.json`
- `labs/lab10/imports/import-nuclei-results.json`
- `labs/lab10/imports/import-grype-vuln-results.json`

### 2.3 Import results by tool

| Tool | Active Imported | Critical | High | Medium | Low | Info |
|------|------------------|----------|------|--------|-----|------|
| ZAP | 12 | 0 | 0 | 2 | 6 | 4 |
| Semgrep | 10 | 0 | 0 | 10 | 0 | 0 |
| Trivy | 120 | 10 | 57 | 35 | 18 | 0 |
| Nuclei | 1 | 0 | 0 | 0 | 0 | 1 |
| Grype | 109 | 11 | 52 | 31 | 3 | 12 |

All required tool families for the task were imported into the same engagement.

---

## Task 3 — Reporting & Program Metrics

### 3.1 Metrics snapshot

Snapshot file:

- `labs/lab10/report/metrics-snapshot.md`

Current active findings in DefectDojo (API snapshot, 2026-04-07):

- Critical: 21
- High: 109
- Medium: 78
- Low: 27
- Informational: 17
- Total: 252

### 3.2 Governance artifacts

- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`

### 3.3 Key stakeholder metrics (summary)

- The vulnerability backlog is dominated by **High + Medium** findings (187/252), which should drive prioritization and SLA planning.
- **Critical findings (21)** are concentrated in SCA tools (Trivy/Grype), indicating dependency and base-image risk exposure.
- DAST/SAST/runtime imports are now present (ZAP, Semgrep, Nuclei), so reporting is no longer limited to container/package scanning only.
- No findings are mitigated yet in this lab dataset; next operational step is triage (verify, mark false positives, assign owners, set due dates).
- Unified import into one engagement enables centralized deduplication, ownership assignment, and SLA tracking in a single workflow.

---

## Acceptance Criteria Mapping

- DefectDojo runs locally and is reachable: **Done**
- Product Type / Product / Engagement configured: **Done**
- Imports completed for ZAP, Semgrep, Trivy (+ Nuclei, Grype): **Done**
- Reporting artifacts generated under `labs/lab10/report/`: **Done**
- `labs/submission10.md` includes setup, import evidence, metrics, and analysis: **Done**
