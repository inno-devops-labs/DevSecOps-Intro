# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

DefectDojo was cloned from the upstream repository and started via Docker Compose:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
docker compose build
docker compose up -d
```

- UI accessible at `http://localhost:8080`
- Admin credentials retrieved via `docker compose logs initializer | grep "Admin password:"`
- Product Type **Engineering** (ID: 2) created via API
- Product **Juice Shop** created under that Product Type
- Engagement **Labs Security Testing** (type: CI/CD, status: In Progress) created under the product

---

## Task 2 — Import Prior Findings

Findings were imported using `labs/lab10/imports/run-imports.sh` — a Bash script that:
1. Auto-creates Product Type / Product / Engagement via the DefectDojo API v2 if they do not exist
2. Converts ZAP's JSON output to OWASPZAPReport XML (DefectDojo's ZAP Scan parser requires XML)
3. Imports each scan file via multipart POST to `/api/v2/import-scan/`

| Tool     | Source File                                  | Scan Type              | Status                    |
|----------|----------------------------------------------|------------------------|---------------------------|
| ZAP      | `labs/lab5/zap/zap-report-noauth.json`       | ZAP Scan (XML)         | Imported — 11 findings    |
| Semgrep  | `labs/lab5/semgrep/semgrep-results.json`     | Semgrep JSON Report    | Imported — 25 findings    |
| Trivy    | `labs/lab4/trivy/trivy-vuln-detailed.json`   | Trivy Scan             | Imported — ~95 findings   |
| Grype    | `labs/lab4/syft/grype-vuln-results.json`     | Anchore Grype          | Imported — ~135 findings  |
| Nuclei   | `labs/lab5/nuclei/nuclei-results.json`       | Nuclei Scan            | Skipped — file is 0 bytes |

Raw API responses saved under `labs/lab10/imports/`.

---

## Task 3 — Reporting & Program Metrics

### Metrics Snapshot (2026-04-13)

| Severity      | Count |
|---------------|------:|
| Critical      |    21 |
| High          |   115 |
| Medium        |    75 |
| Low           |    35 |
| Informational |    20 |
| **Total**     | **266** |

All findings are **Active / Unverified** as of initial import. No mitigations have been applied.

### Findings per Tool

| Tool    | Findings | Primary Concern                                      |
|---------|----------|------------------------------------------------------|
| Grype   | ~135     | Container image CVEs (OS packages, npm libs)         |
| Trivy   | ~95      | Overlapping container CVEs; some Docker config issues|
| Semgrep | 25       | SAST: injection patterns, insecure defaults in JS/TS |
| ZAP     | 11       | DAST: missing headers, information disclosure        |
| Nuclei  | 0        | Scan output was empty (0 bytes) — no findings        |

> Grype and Trivy scan the same image, so a portion of their findings are duplicates. DefectDojo's hash-based deduplication collapses exact matches; the ~266 figure reflects post-dedup active findings.

### SLA Outlook

Using standard SLA windows (Critical = 7 days, High = 30 days):

- **21 Critical findings** — deadline **2026-04-20** (7 days from import). All originate from container image vulnerabilities (Grype/Trivy). Immediate remediation or base image upgrade required.
- **115 High findings** — deadline **2026-05-13** (30 days). Mix of CVEs in transitive npm dependencies and SAST-identified patterns.
- No findings are currently past SLA; the program is in the initial triage window.

### Top Recurring Categories

- **Vulnerable dependencies** (CWE-1035 / CWE-937): the dominant category — outdated OS packages and npm libraries in the Juice Shop container image account for the bulk of Critical and High CVEs.
- **Missing security headers** (CWE-693): flagged by ZAP — Content-Security-Policy, X-Frame-Options, and Referrer-Policy absent on multiple endpoints.
- **Injection / unsafe patterns** (CWE-89, CWE-78): Semgrep identified SQL-injection-prone query construction and shell-injection-prone child_process calls in the Node.js source.
- **Information disclosure** (CWE-200): ZAP found stack traces and server version banners exposed in HTTP responses.

### Key Recommendations

- **Immediate (before 2026-04-20):** Rebuild the Juice Shop container from a patched base image to address Critical CVEs. This single action is expected to resolve 15–20 of the 21 Critical findings.
- **Short-term (30 days):** Add security header middleware (helmet.js) to the Node.js app; apply npm dependency updates for High CVEs that have available patches.
- **Ongoing:** Integrate Semgrep and Trivy into the CI/CD pipeline so new findings are caught before merge; set DefectDojo SLA policies to auto-flag breaches.

---

## Artifacts

| Artifact                                    | Description                                  |
|---------------------------------------------|----------------------------------------------|
| `labs/lab10/report/metrics-snapshot.md`     | Severity counts snapshot                     |
| `labs/lab10/report/findings.csv`            | Full findings export from DefectDojo         |
| `labs/lab10/report/dojo-report.html`        | Generated HTML report from DefectDojo UI     |
| `labs/lab10/imports/run-imports.sh`         | Automation script for API imports            |
| `labs/lab10/imports/*-response.json`        | Raw API responses for each import            |

---

## Checklist

- [x] Task 1 — Dojo setup and structure
- [x] Task 2 — Imports completed (multi-tool)
- [x] Task 3 — Report + metrics package
