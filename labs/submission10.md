# Lab 10 Submission — Vulnerability Management with DefectDojo

## Task 1 — Local DefectDojo setup

- Cloned OWASP **django-DefectDojo** into `labs/lab10/setup/django-DefectDojo` (see `labs/lab10/setup/CLONE-INSTRUCTIONS.md`). The clone is listed in `labs/lab10/setup/.gitignore` so the full upstream tree is not committed to the course repo.
- Ran `./docker/docker-compose-check.sh` (supported Compose version).
- Built images with `docker compose build` and started the stack with `docker compose up -d`.
- **Evidence:** `labs/lab10/setup/compose-ps.txt` (nginx published on **localhost:8080**).
- **Admin access:** username `admin`; password is emitted once by the `initializer` container (`docker compose logs initializer | grep "Admin password:"`). It is intentionally **not** stored in this repository.
- After capturing metrics and CSV export, the stack was stopped with `docker compose down` (images/volumes remain for a faster `docker compose up -d` next time).

## Task 2 — Importing prior lab findings

- Set `DD_API=http://localhost:8080/api/v2` and created an API token with  
  `docker compose exec -T uwsgi python manage.py drf_create_token admin` (token used only for the import run; not committed here).
- Ran `bash labs/lab10/imports/run-imports.sh` from the repo root.

**Results:**

| Tool        | Source file | Result |
| ----------- | ----------- | ------ |
| ZAP         | `labs/lab5/zap/zap-report-noauth.json` | **Failed** — importer returned *“Wrong file format, please use xml.”* The default **ZAP Scan** type in this Dojo build expects XML, not the lab’s JSON export. |
| Semgrep     | `labs/lab5/semgrep/semgrep-results.json` | **Imported** (test id 2). |
| Trivy       | `labs/lab4/trivy/trivy-vuln-detailed.json` | **Imported** (test id 3). |
| Nuclei      | `labs/lab5/nuclei/nuclei-results.json` | **Skipped** — file not present in this workspace. |
| Grype       | `labs/lab4/syft/grype-vuln-results.json` | **Imported** (test id 4). |

- **API responses** from each `curl` import are saved under `labs/lab10/imports/` as `import-*.json` (including the ZAP error payload for audit).

## Task 3 — Reporting and program metrics

### Artifacts (as required by the lab)

| Deliverable | Path |
| ----------- | ---- |
| Metrics snapshot | `labs/lab10/report/metrics-snapshot.md` |
| Stakeholder HTML report | `labs/lab10/report/dojo-report.html` |
| Findings CSV | `labs/lab10/report/findings.csv` |

The HTML report is an **executive-style summary** built from the same figures as the API export (DefectDojo UI “Executive” PDF was not automated in this environment). The CSV was generated from the **Findings** API (`/api/v2/findings/?engagement=1`) for spreadsheet analysis.

### Metric highlights (3–5 bullets)

1. **292** active findings in engagement **Labs Security Testing** after successful imports (Semgrep + Trivy + Grype); **no ZAP DAST findings** in Dojo until XML (or another supported) ZAP output is imported.
2. **Severity mix:** 21 Critical, 152 High, 86 Medium, 21 Low, 12 Info — remediation focus should start with Critical/High, largely driven by container image scanners (Trivy/Grype overlap).
3. **Validation state:** 143 findings **verified**, 149 **not verified** — the backlog for analyst review is still substantial before treating counts as “production-ready.”
4. **SLAs:** No past-due SLA in the export; **21** findings have **≤ 14 days** remaining on their SLA clock (expiration **2026-04-16** in API data).
5. **Recurring CWE themes:** Top mapped CWEs include **1333**, **22**, **79**, and **407**; many items still have **CWE 0** (unmapped) and need manual taxonomy cleanup for leadership dashboards.

### Links to exported artifacts

- Metrics: [`lab10/report/metrics-snapshot.md`](lab10/report/metrics-snapshot.md)
- HTML summary: [`lab10/report/dojo-report.html`](lab10/report/dojo-report.html)
- CSV: [`lab10/report/findings.csv`](lab10/report/findings.csv)
- Import traces: [`lab10/imports/`](lab10/imports/)
- Compose evidence: [`lab10/setup/compose-ps.txt`](lab10/setup/compose-ps.txt)
