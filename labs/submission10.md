# Lab 10 — Vulnerability Management & Response with DefectDojo

---

## Task 1 — DefectDojo Local Setup

### 1.1 Clone and Start DefectDojo

DefectDojo was cloned from the upstream repository and started using Docker Compose:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
docker compose up -d
```

All containers started successfully:

```
NAME                               STATUS
django-defectdojo-celerybeat-1     Up
django-defectdojo-celeryworker-1   Up
django-defectdojo-nginx-1          Up (ports: 8080, 8443)
django-defectdojo-postgres-1       Up
django-defectdojo-uwsgi-1          Up
django-defectdojo-valkey-1         Up
```

The UI was accessible at `http://localhost:8080`.

### 1.2 Admin Credentials

The admin password was retrieved from the initializer logs:

```bash
docker compose logs initializer | grep "Admin password:"
```

Successfully logged in at `http://localhost:8080` with `admin` / `LmMoL7t9OIocowMpQLvZ09`.

The API token was obtained via the authentication endpoint:

```bash
curl -X POST http://localhost:8080/api/v2/api-token-auth/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}'
```

---

## Task 2 — Import Prior Findings (4 pts)

### 2.1 Context Configuration

The following DefectDojo context was auto-created by the import script:

| Field          | Value                   |
| -------------- | ----------------------- |
| Product Type   | Engineering             |
| Product        | Juice Shop              |
| Engagement     | Labs Security Testing   |

### 2.2 Imported Reports

Five scan tools were imported using `labs/lab10/imports/run-imports.sh`:

| Tool    | Source File                                | Scan Type           | Status  | Findings |
| ------- | ------------------------------------------ | ------------------- | ------- | -------: |
| ZAP     | `labs/lab5/zap/zap-report-noauth.xml`      | ZAP Scan            | ✅ OK   |        9 |
| Semgrep | `labs/lab5/semgrep/semgrep-results.json`    | Semgrep JSON Report | ✅ OK   |        8 |
| Trivy   | `labs/lab4/trivy/trivy-vuln-detailed.json`  | Trivy Scan          | ✅ OK   |      147 |
| Nuclei  | `labs/lab5/nuclei/nuclei-results.json`      | Nuclei Scan         | ✅ OK   |        8 |
| Grype   | `labs/lab4/syft/grype-vuln-results.json`    | Anchore Grype       | ✅ OK   |      122 |

**Total imported: 294 findings** across 5 test types.

The import script was adapted for macOS compatibility (the original used `mapfile` which requires bash 4+). It uses the DefectDojo `import-scan` API with `auto_create_context=true` to auto-provision the product type, product, and engagement.

Import response JSONs are saved under `labs/lab10/imports/`.

### 2.3 Import Details by Severity

| Severity       | ZAP | Semgrep | Trivy | Nuclei | Grype | **Total** |
| -------------- | --: | ------: | ----: | -----: | ----: | --------: |
| Critical       |   0 |       0 |    10 |      0 |    11 |     **21** |
| High           |   2 |       3 |    83 |      1 |    64 |    **153** |
| Medium         |   1 |       5 |    36 |      3 |    32 |     **77** |
| Low            |   4 |       0 |    18 |      1 |     3 |     **26** |
| Informational  |   2 |       0 |     0 |      3 |    12 |     **17** |

---

## Task 3 — Reporting & Program Metrics (4 pts)

### 3.1 Metrics Snapshot

Full metrics snapshot saved to [`labs/lab10/report/metrics-snapshot.md`](lab10/report/metrics-snapshot.md).

**Key numbers:**

- **294 total active findings** — all open, none closed or mitigated (initial baseline)
- **143 findings verified** (Trivy auto-verification)
- **21 Critical + 153 High** = 174 findings requiring priority attention (59.2% of total)
- **0 mitigated** — expected since this is the first import

### 3.2 Governance-Ready Artifacts

Generated artifacts in `labs/lab10/report/`:

| Artifact                 | Path                                  | Description                                  |
| ------------------------ | ------------------------------------- | -------------------------------------------- |
| Executive HTML Report    | `labs/lab10/report/dojo-report.html`  | Stakeholder-ready report with severity breakdown, tool breakdown, top CWEs, SLA outlook, and recommendations |
| Findings CSV             | `labs/lab10/report/findings.csv`      | 294 rows with ID, Title, Severity, CWE, Active status, Verified status, Test ID |
| Metrics Snapshot         | `labs/lab10/report/metrics-snapshot.md`| Baseline snapshot with severity counts, tool breakdown, top CWEs |

### 3.3 Key Metrics Summary

1. **Severity distribution is heavily skewed toward High:** 52% of all findings are High severity, driven by known CVEs in npm dependencies and Debian OS packages detected by Trivy (83 High) and Grype (64 High). Critical findings (21, or 7.1%) are primarily outdated library vulnerabilities with known exploits.

2. **Dependency scanners dominate the finding volume:** Trivy (50.0%) and Grype (41.5%) together account for 91.5% of all findings. This is expected for a containerized Node.js application like Juice Shop with many transitive dependencies. DAST tools (ZAP: 3.1%, Nuclei: 2.7%) and SAST (Semgrep: 2.7%) found fewer but higher-signal application-layer vulnerabilities.

3. **Top recurring CWE categories point to regex and input validation issues:** CWE-1333 (ReDoS, 29 findings) and CWE-407 (Algorithmic Complexity, 13 findings) are the most common — both relate to regex denial-of-service in npm packages. CWE-22 (Path Traversal, 12 findings) and CWE-79 (XSS, 6 findings) represent the most impactful application-level weaknesses.

4. **SLA outlook — 21 Critical findings at risk:** With a standard 7-day Critical SLA, all 21 Critical findings would breach by April 20, 2026. The 153 High findings would breach a 30-day SLA by May 13, 2026. Immediate dependency patching should be prioritized.

5. **Trivy/Grype overlap needs deduplication:** Both tools scan the same container image (`bkimminich/juice-shop:v19.0.0`), so many CVE findings are reported by both. Future engagement runs should enable DefectDojo's cross-scanner deduplication (hash_code algorithm) or use reimport to consolidate duplicates and present a cleaner picture.

---