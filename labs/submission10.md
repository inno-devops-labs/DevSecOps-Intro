## Task 1: DefectDojo Local Setup

- DefectDojo was started locally using Docker Compose in `labs/lab10/setup/django-DefectDojo`.
- All containers are running and healthy (`docker compose ps` output attached).
- Admin UI is available at http://localhost:8080 and login as admin was successful.
```
Polina@MagicBookX16 MINGW64 /c/devsec/DevSecOps-Intro/labs/lab10/setup/django-DefectDojo (master)
$ docker compose ps
NAME                               IMAGE                                       
                                                          COMMAND              
    SERVICE        CREATED         STATUS         PORTS
django-defectdojo-celerybeat-1     defectdojo/defectdojo-django:latest         
                                                          "/wait-for-it.sh pos…"   celerybeat     4 minutes ago   Up 2 minutes
django-defectdojo-celeryworker-1   defectdojo/defectdojo-django:latest                                                                   "/wait-for-it.sh pos…"   celeryworker   4 minutes ago   Up 2 minutes
django-defectdojo-nginx-1          defectdojo/defectdojo-nginx:latest                                                                    "/entrypoint-nginx.sh"   nginx          4 minutes ago   Up 2 minutes   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
django-defectdojo-postgres-1       postgres:18.2-alpine@sha256:035b9ab53cfa147d7202b61f5f7782b939ae815b7d6bc81c96b7b42ff1fca950          "docker-entrypoint.s…"   postgres       4 minutes ago   Up 4 minutes   5432/tcp
django-defectdojo-uwsgi-1          defectdojo/defectdojo-django:latest                                                                   "/wait-for-it.sh pos…"   uwsgi          4 minutes ago   Up 2 minutes
django-defectdojo-valkey-1         valkey/valkey:7.2.12-alpine@sha256:32860ea506d2dde08333d1cca2bf28c46bc84e9654308eabf801f77548f72573   "docker-entrypoint.s…"   valkey         4 minutes ago   Up 4 minutes   6379/tcp

Polina@MagicBookX16 MINGW64 /c/devsec/DevSecOps-Intro/labs/lab10/setup/django-DefectDojo (master)
```
---

## Task 2: Import Prior Findings

- API token generated in DefectDojo UI (Profile → API v2 Key).
- Environment variables set in PowerShell:
  - `DD_API`, `DD_TOKEN`, `DD_PRODUCT_TYPE`, `DD_PRODUCT`, `DD_ENGAGEMENT`
- Import script run via Git Bash:
  - `bash labs/lab10/imports/run-imports.sh`
- Findings imported from:
  - ZAP: `labs/lab5/zap/zap-report-noauth.json`
  - Semgrep: `labs/lab5/semgrep/semgrep-results.json`
  - Trivy: `labs/lab4/trivy/trivy-vuln-detailed.json`
  - Nuclei: `labs/lab5/nuclei/nuclei-results.json`
  - Grype: `labs/lab4/syft/grype-vuln-results.json`
- Import responses saved in `labs/lab10/imports/`
- All findings are now visible in the DefectDojo engagement dashboard.

---
## Task 3: Reporting & Program Metrics

### 3.1 Baseline Progress Snapshot

See `labs/lab10/report/metrics-snapshot.md`:

- Date captured: 2026-03-21
- Active findings:
  - Critical: 20
  - High: 87
  - Medium: 83
  - Low: 8
  - Informational: 35
- Verified vs. Mitigated notes: All findings are active, none mitigated yet.

---

### 3.2 Governance-Ready Artifacts

- Executive/Detailed report: `labs/lab10/report/dojo-report.pdf`
- Findings list (CSV): `labs/lab10/report/findings.csv`
---

### 3.3 Key Metrics Summary

- **Open vs. Closed Findings by Severity:**  
  All findings are currently open (Active).  
  - Critical: 20 open, 0 closed  
  - High: 87 open, 0 closed  
  - Medium: 83 open, 0 closed  
  - Low: 8 open, 0 closed  
  - Informational: 35 open, 0 closed

- **Findings per Tool:**   
  - Trivy: 74 findings (dependency vulnerabilities, mostly Critical/High/Medium)  
  - Grype: 86 findings (dependency vulnerabilities, similar to Trivy)  
  - ZAP: 0 findings (import attempted, but no findings were processed due to format incompatibility, should be `xml` but provided `json`)  
  - Semgrep: 25 findings (code-level issues, mostly Medium/Low)  
  - Nuclei: 6 findings (infrastructure/web exposures, mostly Informational/Low)

- **SLA Breaches / Upcoming Deadlines:**  
  No SLA breaches detected; all critical and high findings are still within their remediation windows. No items are due within the next 14 days.

- **Top Recurring CWE/OWASP Categories:**  
  - CWE-79: Cross-Site Scripting (XSS)  
  - CWE-89: SQL Injection  
  - CWE-200: Information Exposure  
  - CWE-20: Input Validation  
  - CWE-22: Path Traversal

*Note:* I deleted `django-DefectDojo` folder to avoid commiting to github
