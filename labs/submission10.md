# Lab 10 — Vulnerability Management & Response with DefectDojo

**Name:** Baha Alimi
**Branch:** `feature/lab10`
**Target:** OWASP Juice Shop v19.0.0

---

## Task 1 — DefectDojo Local Setup

### 1.1 Deployment

DefectDojo was cloned and started via Docker Compose:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
docker compose build   # ~40 min first run
docker compose up -d
```

**Containers running (`docker compose ps`):**

| Container | Image | Status | Ports |
|-----------|-------|--------|-------|
| django-defectdojo-nginx-1 | defectdojo-nginx:latest | Up | 0.0.0.0:8080→8080, 0.0.0.0:8443→8443 |
| django-defectdojo-uwsgi-1 | defectdojo-django:latest | Up | — |
| django-defectdojo-celeryworker-1 | defectdojo-django:latest | Up | — |
| django-defectdojo-celerybeat-1 | defectdojo-django:latest | Up | — |
| django-defectdojo-postgres-1 | postgres:18.2-alpine | Up | 5432/tcp |
| django-defectdojo-valkey-1 | valkey:7.2.12-alpine | Up | 6379/tcp |

All 6 containers healthy. UI accessible at **http://localhost:8080**.

### 1.2 Admin Credentials

Admin password extracted from initializer logs:

```bash
docker compose logs initializer | Select-String "Admin password:"
# initializer-1  | Admin password: <redacted>
```

Login confirmed at http://localhost:8080 with `admin` / `<redacted>`.

### 1.3 Structure Created

- **Product Type:** Engineering
- **Product:** Juice Shop (OWASP Juice Shop v19.0.0)
- **Engagement:** Labs Security Testing (opened 2026-03-20, CI/CD type)

All created automatically via the import script using `auto_create_context=true`.

---

## Task 2 — Import Prior Findings

### 2.1 API Token & Variables

API token obtained from DefectDojo UI (Profile → API v2 Key):

```bash
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="<redacted>"
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
```

### 2.2 Import Script

Used the provided `labs/lab10/imports/run-imports.sh` bash script. The script:
- Auto-detects importer names from `/api/v2/test_types/`
- Uses `auto_create_context=true` to create product type/product/engagement if missing
- Imports all available report files and saves API responses under `labs/lab10/imports/`

ZAP required a separate step — DefectDojo's ZAP importer only accepts XML format, not JSON.
A fresh ZAP XML scan was generated against the running Juice Shop instance:

```bash
docker run --rm --network host \
  -v "//$(pwd)/labs/lab5/zap:/zap/wrk:rw" \
  zaproxy/zap-stable:latest \
  zap-baseline.py -t http://localhost:3000 \
  -x zap-report.xml -r zap-report-new.html
```

Trivy filename corrected from `trivy-vuln-detailed.json` to `juice-shop-trivy-detailed.json` and imported separately via direct API call.

### 2.3 Import Results

All 5 tools successfully imported into engagement **Labs Security Testing** (engagement_id=1):

| Tool | Scan Type | Test ID | Critical | High | Medium | Low | Info | Total |
|------|-----------|---------|----------|------|--------|-----|------|-------|
| ZAP | ZAP Scan | 5 | 0 | 0 | 2 | 6 | 4 | 12 |
| Semgrep | Semgrep JSON Report | 2 | 0 | 7 | 18 | 0 | 0 | 25 |
| Nuclei | Nuclei Scan | 3 | 0 | 0 | 1 | 1 | 23 | 25 |
| Grype | Anchore Grype | 4 | 11 | 52 | 31 | 3 | 12 | 109 |
| Trivy | Trivy Scan | 6 | 10 | 57 | 35 | 18 | 0 | 120 |
| **Total** | | | **21** | **116** | **87** | **28** | **39** | **291** |

Import responses saved under `labs/lab10/imports/`.

---

## Task 3 — Reporting & Program Metrics

### 3.1 Metrics Snapshot

Full snapshot saved at `labs/lab10/report/metrics-snapshot.md`.

- **Date captured:** 2026-03-20
- **Total active findings:** 291 across 5 tools
- **Severity breakdown:** 21 Critical | 116 High | 87 Medium | 28 Low | 39 Info
- **Verified:** 116 findings (Trivy auto-verified by scanner on import)
- **Mitigated:** 0 (baseline capture — no remediations applied yet)

### 3.2 Generated Artifacts

| Artifact | Path | Description |
|----------|------|-------------|
| Metrics snapshot | `labs/lab10/report/metrics-snapshot.md` | Severity counts, tool breakdown, SLA outlook |
| DefectDojo Finding Report | `labs/lab10/report/dojo-report.html` | Full finding report exported from DefectDojo UI |
| Findings CSV | `labs/lab10/report/findings.csv` | 291-row export with CVSSv3, SLA dates, component info |

### 3.3 Key Metrics Summary

- **Dependency vulnerabilities dominate the risk profile** — Grype and Trivy together account for 229 findings (79% of total). The application ships with severely outdated npm packages including `vm2@3.9.17` (deprecated, 4 Critical CVEs), `lodash@2.4.2` (6 major versions behind), and `jsonwebtoken@0.1.0` (8 major versions behind). No single dependency upgrade addresses more than 4 CVEs; a systematic dependency refresh is required.

- **SLA breach risk is immediate for 21 Critical findings** — All 21 Critical findings have a 7-day SLA deadline of 2026-03-27. The most exploitable are `vm2` sandbox escapes (CVSS 9.8, network-exploitable, no user interaction) and `jsonwebtoken` algorithm confusion (CVE-2015-9235), which combined with the hardcoded RSA private key baked into the image creates a trivially exploitable authentication bypass chain.

- **Source code vulnerabilities confirmed by SAST are independently validated by DAST** — Semgrep identified SQL injection in `login.ts:34` and `search.ts:23` as High severity; SQLmap (Lab 5) confirmed exploitation of the search endpoint with a boolean-based blind injection payload against a SQLite backend. This SAST/DAST correlation elevates confidence and prioritises these findings above their individual severity ratings.

- **Tool coverage gap reinforces multi-scanner approach** — ZAP and Nuclei found deployment/runtime misconfigurations (missing CSP, CORS wildcard, exposed `/metrics` endpoint) that SCA tools Grype and Trivy are structurally blind to, while Grype found 64 GHSA advisories not present in Trivy's NVD-focused database. No single tool provides complete coverage; the 291-finding aggregate is more actionable than any individual tool's output.

- **Trivy findings are 97% verified, Grype findings are 0% verified** — This reflects Trivy's auto-verification behaviour on import rather than manual confirmation. In a production vulnerability management program, verified status should be updated only after human triage to distinguish true positives from false positives, particularly for transitive dependencies where the vulnerable code path may not be reachable in the application.

---

## Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| ZAP importer rejected JSON format | Regenerated ZAP report in XML format using `zap-baseline.py -x` |
| Trivy filename mismatch in import script | Corrected path from `trivy-vuln-detailed.json` to `juice-shop-trivy-detailed.json` |
| Git Bash / PowerShell path conflicts | Used Git Bash for bash scripts, PowerShell for Windows API calls |
| Docker volume mount failing on Windows | Used `//$(pwd)/...` prefix in Git Bash to fix Windows path conversion |

---

## Repository Structure

```
labs/lab10/
├── setup/
│   └── django-DefectDojo/          # DefectDojo docker compose deployment
├── imports/
│   ├── run-imports.sh              # Bash import script (auto-creates context)
│   ├── import-zap-report.xml.json  # ZAP import API response
│   ├── import-semgrep-results.json.json
│   ├── import-nuclei-results.json.json
│   └── import-grype-vuln-results.json.json
└── report/
    ├── metrics-snapshot.md         # Severity counts, SLA outlook, tool breakdown
    ├── dojo-report.html            # DefectDojo Finding Report (exported from UI)
    └── findings.csv                # 291-finding export with CVSSv3, SLA dates
```
