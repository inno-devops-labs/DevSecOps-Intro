# Lab 10 — Vulnerability Management & Response with DefectDojo

## Environment

- Date: 2026-04-03
- OS: macOS (Darwin 25.3.0, arm64) / Docker Desktop
- Branch: `feature/lab10`
- Docker Compose: v5.0.2
- DefectDojo: latest (cloned from upstream, built locally)
- Target product: Juice Shop v19.0.0

---

## Task 1 — DefectDojo Local Setup (2 pts)

### 1.1 Clone and Start

DefectDojo was cloned from the upstream repository and started via Docker Compose:

```
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
./docker/docker-compose-check.sh   # "Supported docker compose version"
docker compose build
docker compose up -d
```

All six containers started successfully:

```
NAME                               STATUS      PORTS
django-defectdojo-nginx-1          Up          0.0.0.0:8080->8080/tcp, 0.0.0.0:8443->8443/tcp
django-defectdojo-uwsgi-1          Up
django-defectdojo-celeryworker-1   Up
django-defectdojo-celerybeat-1     Up
django-defectdojo-postgres-1       Up          5432/tcp
django-defectdojo-valkey-1         Up          6379/tcp
```

The UI became reachable at `http://localhost:8080` immediately after startup.

### 1.2 Admin Credentials

The initializer container printed the admin password on first boot:

```
docker compose logs initializer | grep "Admin password:"
# Output: Admin password: <REDACTED>
```

Login: `admin` / `<REDACTED>` at `http://localhost:8080`.

### 1.3 Product/Engagement Structure

The import script (Task 2) auto-created the following hierarchy via `auto_create_context=true`:

| Level          | Name                   |
|----------------|------------------------|
| Product Type   | Engineering            |
| Product        | Juice Shop             |
| Engagement     | Labs Security Testing  |

---

## Task 2 — Import Prior Findings (4 pts)

### 2.1 API Token

An API token was obtained programmatically:

```
curl -s -X POST http://localhost:8080/api/v2/api-token-auth/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<REDACTED>"}'
```

Environment variables were configured:

```
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="<token>"
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
```

### 2.2 Import Results

The importer script (`labs/lab10/imports/run-imports.sh`) auto-detected scan type names from the DefectDojo instance and imported all available reports:

| Tool           | Scan Type               | Source File                              | Findings | Notes |
|----------------|-------------------------|------------------------------------------|----------|-------|
| Semgrep        | Semgrep JSON Report     | `labs/lab5/semgrep/semgrep-results.json`  | 21       | 14 Medium, 7 High |
| Trivy          | Trivy Scan              | `labs/lab4/trivy/trivy-vuln-detailed.json`| 147      | 10 Critical, 83 High, 36 Medium, 18 Low |
| Nuclei         | Nuclei Scan             | `labs/lab5/nuclei/nuclei-results.json`    | 3        | 2 Info, 1 Low |
| Grype          | Anchore Grype           | `labs/lab4/syft/grype-vuln-results.json`  | 122      | 11 Critical, 64 High, 32 Medium, 3 Low, 12 Info |
| ZAP            | Generic Findings Import | `labs/lab5/zap/zap-report-noauth.json`    | 12       | Converted to CSV (DefectDojo ZAP Scan importer requires XML; JSON was converted via jq) |

**ZAP format note:** The ZAP JSON report produced by ZAP 2.17's automation framework was not accepted by DefectDojo's built-in "ZAP Scan" importer (which expects XML). The JSON was converted to Generic Findings CSV format using jq, preserving alert names, CWEs, URLs, and severity levels. The Generic Findings Import deduplicated 49 per-URL instances into 12 unique findings.

**Trivy scan type note:** The auto-detection initially selected "Trivy Operator Scan" which yielded 0 findings. A re-import with "Trivy Scan" correctly parsed the standard Trivy JSON output and yielded 147 findings.

### 2.3 Total Imported

- **305 active findings** across 5 tools
- **143 verified** (Trivy auto-verified based on CVE match confidence)
- **0 mitigated** (baseline import — no remediation yet)

---

## Task 3 — Reporting & Program Metrics (4 pts)

### 3.1 Metrics Snapshot

Full snapshot saved in `labs/lab10/report/metrics-snapshot.md`.

**Severity breakdown (all active):**

| Severity       | Count |
|----------------|------:|
| Critical       |    21 |
| High           |   154 |
| Medium         |    84 |
| Low            |    28 |
| Informational  |    18 |
| **Total**      | **305** |

### 3.2 Governance-Ready Artifacts

- **HTML Report:** `labs/lab10/report/dojo-report.html` — Generated via DefectDojo's engagement report API, contains executive summary and full findings table with severity, CWE, and status.
- **Findings CSV:** `labs/lab10/report/findings.csv` — 305 findings exported via API with ID, title, severity, CWE, component, tool, active/verified/mitigated status, and date.

### 3.3 Key Metrics Summary

- **Severity distribution is heavily skewed toward High (154, 50.5%):** Most high-severity findings come from Trivy (83) and Grype (64), indicating significant OS-level and dependency CVEs in the Juice Shop v19.0.0 container image based on Debian 12.11.

- **Top recurring CWEs point to systemic patterns:** CWE-1333 (ReDoS, 29 findings) and CWE-407 (algorithmic complexity, 13 findings) dominate, indicating widespread use of vulnerable regex patterns in dependencies. CWE-22 (path traversal, 11 findings) and CWE-89 (SQL injection, 6 findings) represent application-level code risks detected by Semgrep.

- **SCA tools (Trivy + Grype) account for 88% of findings (269/305):** This is expected for a container image scan against a Node.js application with a large dependency tree. Deduplication between Trivy and Grype was not enabled — enabling cross-tool dedup would reduce the total count significantly, as both tools scan the same image.

- **DAST coverage is limited but targeted:** ZAP found 12 unique web-layer issues (CSP headers, cookie security, information disclosure) and Nuclei identified 3 DNS/API exposure findings. These represent the attack surface visible to an external scanner without authentication.

- **No SLA breaches yet, but 305 findings are due for triage:** All findings were imported today (2026-04-03). With a default 120-day SLA for Critical and 180-day for High, the first SLA deadlines fall on 2026-08-01 (Critical) and 2026-10-01 (High). Immediate prioritization should focus on the 21 Critical findings — especially those with known exploits (CVE KEV matches).

---

## Appendix: Artifacts and Evidence

### File Structure

```
labs/lab10/
├── setup/
│   └── django-DefectDojo/          # Cloned DefectDojo repository
├── imports/
│   ├── run-imports.sh              # Batch import script
│   ├── zap-generic.csv             # ZAP findings converted to Generic CSV
│   ├── import-semgrep-results.json.json
│   ├── import-trivy-vuln-detailed.json.json
│   ├── import-nuclei-results.json.json
│   └── import-grype-vuln-results.json.json
└── report/
    ├── metrics-snapshot.md         # Severity/tool/CWE metrics
    ├── dojo-report.html            # DefectDojo engagement report
    └── findings.csv                # Full findings export (305 rows)
```

### Import Response Highlights

**Semgrep (21 findings):**
- 7 High: SQL injection (Sequelize), eval injection, hardcoded JWT secret
- 14 Medium: XSS, path traversal, open redirect, directory listing

**Trivy (147 findings):**
- 10 Critical, 83 High, 36 Medium, 18 Low
- Scanned `bkimminich/juice-shop:v19.0.0` container image
- 143 findings auto-verified based on CVE data

**Nuclei (3 findings):**
- 1 Low: DNS rebinding vulnerability
- 2 Info: Wildcard DNS detection, Swagger API exposure

**Grype (122 findings):**
- 11 Critical, 64 High, 32 Medium, 3 Low, 12 Info
- SCA analysis of the same Juice Shop image via Syft SBOM

**ZAP (12 findings via Generic Import):**
- 2 Medium: CSP header missing, X-Content-Type-Options missing
- 6 Low: Cookie security issues, server leaks, timestamp disclosure
- 4 Info: Non-storable content, storable/cacheable content patterns

### Platform Note

DefectDojo was run locally on macOS via Docker Desktop. The initializer container handled database migrations, admin user creation, and fixture loading automatically. All imports used the `/api/v2/import-scan/` endpoint with `auto_create_context=true` to streamline Product Type/Product/Engagement creation.
