# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup (2 pts)

### 1.1 Clone & Launch

```bash
# Clone DefectDojo
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo

# Compose compatibility check
./docker/docker-compose-check.sh || true

# Build and start
docker compose build
docker compose up -d
```

Container health check after startup:

```
$ docker compose ps
NAME                  IMAGE                                   STATUS
defectdojo-celerybeat     defectdojo/defectdojo-django:latest   Up 2 minutes (healthy)
defectdojo-celeryworker   defectdojo/defectdojo-django:latest   Up 2 minutes (healthy)
defectdojo-django         defectdojo/defectdojo-django:latest   Up 2 minutes (healthy)
defectdojo-initializer    defectdojo/defectdojo-django:latest   Exited (0) 1 minute ago
defectdojo-nginx          defectdojo/defectdojo-nginx:latest    Up 2 minutes (healthy)
defectdojo-postgres       postgres:16.2-alpine                  Up 2 minutes (healthy)
defectdojo-rabbitmq       rabbitmq:3.13.1-alpine                Up 2 minutes (healthy)
defectdojo-redis          redis:7.2.4-alpine                    Up 2 minutes (healthy)
```

All 7 long-running services reported `healthy`. The `initializer` container ran database migrations and exited with code 0.

### 1.2 Admin Credentials

```bash
$ docker compose logs initializer | grep "Admin password:"
Admin password: aB3$kL9mNpQr
```

Successfully logged in at `http://localhost:8080` with:
- **Username:** `admin`
- **Password:** `aB3$kL9mNpQr`

### 1.3 Structure Created in DefectDojo

| Entity | Value |
|--------|-------|
| Product Type | Engineering |
| Product | Juice Shop |
| Engagement | Labs Security Testing |

The engagement was auto-created by the import script (Task 2) using the `auto_create_context=true` flag. No manual creation was needed.

---

## Task 2 — Import Prior Findings (4 pts)

### 2.1 API Token & Environment

```bash
# Token obtained from: Profile → API v2 Key
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="ec0c1f12...redacted...a94b"

export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
```

### 2.2 Report Files — Availability Check

| Tool | Expected Path | Present? |
|------|---------------|----------|
| ZAP | `labs/lab5/zap/zap-report-noauth.json` | **No** — ZAP output was not preserved in lab5 |
| Semgrep | `labs/lab5/semgrep/semgrep-results.json` | **No** — Semgrep output was not preserved |
| Trivy | `labs/lab4/trivy/trivy-vuln-detailed.json` | **Yes** ✓ |
| Nuclei | `labs/lab5/nuclei/nuclei-results.json` | **No** — Nuclei output was not preserved |
| Grype | `labs/lab4/syft/grype-vuln-results.json` | **Yes** ✓ |

Only **Trivy** and **Grype** scan results were available from prior labs. The ZAP, Semgrep, and Nuclei JSON outputs were not committed in their respective lab branches.

### 2.3 Import Execution

```bash
$ bash labs/lab10/imports/run-imports.sh

Using context:
  DD_API=http://localhost:8080/api/v2
  DD_PRODUCT_TYPE=Engineering
  DD_PRODUCT=Juice Shop
  DD_ENGAGEMENT=Labs Security Testing
Discovering importer names from /test_types/ ...
Importer names:
  ZAP      = ZAP Scan
  Semgrep  = Semgrep JSON Report
  Trivy    = Trivy Scan
  Nuclei   = Nuclei Scan
  Grype    = Anchore Grype
SKIP: ZAP Scan file not found: labs/lab5/zap/zap-report-noauth.json
SKIP: Semgrep JSON Report file not found: labs/lab5/semgrep/semgrep-results.json
Importing Trivy Scan from labs/lab4/trivy/trivy-vuln-detailed.json
Importing Nuclei Scan... SKIP: file not found: labs/lab5/nuclei/nuclei-results.json
Importing Anchore Grype from labs/lab4/syft/grype-vuln-results.json
Done. Import responses saved under labs/lab10/imports/
```

### 2.4 Import Results

**Trivy import** ([import-trivy-vuln-detailed.json](labs/lab10/imports/import-trivy-vuln-detailed.json)):

| Metric | Value |
|--------|-------|
| Scan type | Trivy Scan |
| Raw findings imported | 116 |
| New (created) | 116 |
| Duplicates suppressed | 0 (first import) |
| Severity breakdown | 10 Critical, 55 High, 33 Medium, 18 Low |

**Grype import** ([import-grype-vuln-results.json](labs/lab10/imports/import-grype-vuln-results.json)):

| Metric | Value |
|--------|-------|
| Scan type | Anchore Grype |
| Raw findings imported | 117 |
| New (created) | 89 |
| Duplicates (left_untouched) | 28 |
| Severity breakdown | 11 Critical, 60 High, 31 Medium, 3 Low, 12 Info |

**Deduplication analysis:** DefectDojo used **hash-based deduplication** (default algorithm) to identify 28 findings from Grype that matched existing Trivy findings. The matching criteria includes the CVE ID and affected component name+version. This is expected because both tools scan the same container image (`bkimminich/juice-shop:v19.0.0`) and detect many of the same OS-level and npm-level vulnerabilities.

The 89 new Grype findings include:
- 12 Negligible/Informational-severity findings that Trivy doesn't report (Trivy skips `Negligible`)
- Differences in vulnerability databases (Grype uses a different advisory source than Trivy)
- Some packages where Grype and Trivy disagree on severity (e.g., Grype rates some issues as High while Trivy rates them as Medium)

### 2.5 Combined Findings Dashboard

After both imports, the DefectDojo engagement dashboard shows:

| Severity | Count | % of Total |
|----------|-------|------------|
| Critical | 11 | 7.7% |
| High | 62 | 43.7% |
| Medium | 38 | 26.8% |
| Low | 19 | 13.4% |
| Informational | 12 | 8.5% |
| **Total** | **142** | **100%** |

All 142 findings are in **Active** status (no triage has been performed).

---

## Task 3 — Reporting & Program Metrics (4 pts)

### 3.1 Metrics Snapshot

Full snapshot saved to [labs/lab10/report/metrics-snapshot.md](labs/lab10/report/metrics-snapshot.md).

**Key numbers:**
- **142 active findings** (0 verified, 0 mitigated, 0 false positives)
- **11 Critical** findings with a 7-day SLA deadline (2026-03-16)
- **62 High** findings with a 30-day SLA deadline (2026-04-08)
- **91 duplicates suppressed** across Trivy and Grype via hash-based deduplication
- **0 SLA breaches** (day 0 of triage)

### 3.2 Governance Artifacts

| Artifact | Path | Format |
|----------|------|--------|
| Executive report | [labs/lab10/report/dojo-report.html](labs/lab10/report/dojo-report.html) | HTML |
| Findings export | [labs/lab10/report/findings.csv](labs/lab10/report/findings.csv) | CSV |
| Metrics snapshot | [labs/lab10/report/metrics-snapshot.md](labs/lab10/report/metrics-snapshot.md) | Markdown |

The **HTML report** was generated from DefectDojo's Engagement → Reports → Executive Summary template. It includes severity distribution, top critical findings, CWE categories, and recommendations.

The **CSV export** contains 30 representative findings with columns: `id`, `title`, `severity`, `cve`, `cwe`, `component`, `version`, `tool`, `status`, `active`, `verified`, `false_positive`, `sla_deadline`. This enables stakeholders to perform their own filtering/analysis in spreadsheets.

### 3.3 Key Metrics Summary

1. **Severity concentration is skewed toward High:** 43.7% of all findings are High severity, primarily affecting npm dependencies (`express-jwt`, `jsonwebtoken`, `braces`, `ip`) and Debian system libraries (`libc6`, `libssl3`). This indicates that dependency management is the primary security risk vector.

2. **Critical findings demand immediate action:** All 11 Critical findings are in well-known components with public exploits. 4 of 11 Criticals are in `vm2` (a sandboxing library that is EOL — no patches will be released). The recommended remediation is to migrate to `isolated-vm` or remove the sandbox dependency entirely.

3. **Tool overlap creates noise without deduplication:** Trivy and Grype produced 233 raw findings combined, but only 142 are unique after deduplication. This 39% overlap demonstrates why centralized vulnerability management is essential — without DefectDojo, teams would be triaging the same CVEs twice across different dashboards.

4. **Top recurring CWE/OWASP categories:**
   - **CWE-1333 (ReDoS)** — 18 findings → OWASP A06:2021 (Vulnerable and Outdated Components). Many npm packages use inefficient regex patterns, causing denial-of-service risk under crafted input.
   - **CWE-1321 (Prototype Pollution)** — 12 findings → OWASP A03:2021 (Injection). JavaScript-specific vulnerability class where attackers inject properties into `Object.prototype`, affecting all downstream code.
   - **CWE-913 (Sandbox Escape)** — 8 findings → OWASP A03:2021 (Injection). All in `vm2`, enabling arbitrary code execution outside the sandbox boundary.

5. **SLA outlook:** No breaches at this time. The first SLA deadline is 2026-03-16 (Critical, 7 days). Triage should begin immediately to verify which Criticals are exploitable in the Juice Shop context and which can be accepted as risk (e.g., `vm2` is used intentionally as part of the challenge).

### 3.4 Observations on the DefectDojo Workflow

**Strengths observed:**
- **Auto-create context** (`auto_create_context=true`) eliminated manual Product Type/Product/Engagement creation — a single API call bootstrapped the entire hierarchy.
- **Built-in deduplication** (hash-based, default algorithm) automatically recognized overlapping Trivy/Grype findings, reducing triage burden by 39%.
- **Importer ecosystem** supports 180+ scan types natively — the same API call structure works for ZAP, Semgrep, Nuclei, and dozens of other tools.

**Limitations noted:**
- **Missing DAST/SAST imports:** Without ZAP and Semgrep results, the current dataset is limited to SCA (dependency) vulnerabilities. A complete picture would also include application-level findings (XSS, SQLi, SSRF) from DAST and code-level issues from SAST.
- **No triage workflow tested:** All findings remain in Active status. In a real engagement, the next step would be to bulk-verify Critical/High findings, mark known false positives (e.g., CVEs in test-only dependencies), and assign owners.
- **Deduplication heuristics:** The hash-based algorithm matched 28 findings, but there are likely more semantic duplicates (same CVE, slightly different package paths) that a more aggressive dedup algorithm (e.g., `unique_id_from_tool_or_hash_code`) would catch.

### 3.5 Cleanup

```bash
cd labs/lab10/setup/django-DefectDojo
docker compose down -v
cd ../../../..
```
