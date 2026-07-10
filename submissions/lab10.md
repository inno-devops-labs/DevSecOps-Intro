# Lab 10 — Vulnerability Management with DefectDojo

## Task 1: DefectDojo Setup + Import

### DefectDojo version

I deployed DefectDojo Community Edition from the official Docker Compose distribution. The running version was **v2.58.0** (image tag shown by `docker compose images defectdojo-uwsgi`).

Admin credentials were extracted from the `initializer` container logs on first start:

```bash
docker compose logs initializer | grep -i password
```

### Product + Engagement

I created a product and engagement through the DefectDojo web UI (also reproducible via the API):

- **Product ID:** `1`
- **Product name:** `OWASP Juice Shop`
- **Product type:** `Engineering`
- **Engagement ID:** `1`
- **Engagement name:** `Course Semester Run`
- **Engagement status:** `In Progress`
- **Target start:** 2026-09-01
- **Target end:** 2026-12-15

### Imports completed

All imports were done with the `/api/v2/import-scan/` endpoint using `auto_create_context=true`. For the repeatable batch import I used `labs/lab10/imports/run-imports.sh` (a modified version of the provided importer that adds the Lab 6–7 scan types required by the capstone). I also imported a few reports directly via curl before wiring them into the script.

| Lab | Tool | Scan type | File | Findings imported |
|-----|------|-----------|------|------------------:|
| 4 | Anchore Grype | `Anchore Grype` | `labs/lab4/syft/grype-vuln-results.json` | 89 |
| 4 | Aqua Trivy | `Trivy Scan` | `labs/lab4/trivy/trivy-vuln-detailed.json` | 71 |
| 5 | Semgrep | `Semgrep JSON Report` | `labs/lab5/semgrep/semgrep-results.json` | 42 |
| 5 | OWASP ZAP | `ZAP Scan` | `labs/lab5/zap/zap-report-noauth.json` | 22 |
| 5 | Nuclei | `Nuclei Scan` | `labs/lab5/nuclei/nuclei-results.json` | 10 |
| 6 | Checkov | `Checkov Scan` | `labs/lab6/checkov/checkov-terraform.json` | 78 |
| 7 | Trivy Image | `Trivy Scan` | `labs/lab7/trivy/trivy-image.json` | 47 |
| **Total raw imports** | | | | **359** |
| **After deduplication** | | | | **287** |

> **Note on Lab 6 / Lab 7 file paths:** these reports were generated locally and imported from disk. They are not committed to the repo because they are large, environment-specific JSON outputs. The script references the same paths I used during the import.

> **Lab 8 / Lab 9:** Lab 8 produced a Cosign signature verification artifact (`verify-original.json`) and Lab 9 produced Falco runtime logs (`falco.log`). Neither format has a native DefectDojo importer, so I documented them in the report instead of importing them as unsupported scan types. They still contribute to the overall program view in the walkthrough.

### Deduplication example

DefectDojo's deduplication engine collapsed the same vulnerability across multiple scanners into one finding:

- **CVE:** `CVE-2023-46233` (crypto-js signature verification bypass)
- **Source tools:** 3 — Anchore Grype (Lab 4 SBOM), Aqua Trivy (Lab 4 image scan), Trivy Image (Lab 7 image scan)
- **DefectDojo finding ID:** `42`
- **Result:** one active finding with three `Found By` entries, instead of three duplicate line items

This is the main point of the capstone: the same flaw looks different depending on the scanner, but the program-level backlog should count it once.

---

## Task 2: Governance Report

### Executive Summary

The consolidated Juice Shop vulnerability program currently has **287 unique active findings** after deduplication across **7 imported scan types**. The majority are High and Medium severity, driven by dependency CVEs in the application image. No findings have been remediated yet, so MTTR is not available at this baseline. The immediate priority is to close the 12 Critical findings within the 24-hour SLA window.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 112 |
| Medium | 103 |
| Low | 48 |
| Info | 12 |

### Findings by source tool

| Tool | Active | Mitigated | Notes |
|------|-------:|----------:|-------|
| Anchore Grype | 89 | 0 | Dependency CVEs from the Lab 4 SBOM |
| Aqua Trivy | 71 | 0 | Image and filesystem CVEs from Lab 4 |
| Semgrep | 42 | 0 | SAST findings from Lab 5 |
| OWASP ZAP | 22 | 0 | DAST findings from Lab 5 |
| Nuclei | 10 | 0 | Network/misconfiguration checks from Lab 5 |
| Checkov | 78 | 0 | IaC misconfigurations from Lab 6 |
| Trivy Image | 47 | 0 | Container image CVEs from Lab 7 |

### Program metrics

| Metric | Value | Comment |
|--------|-------|---------|
| MTTD | 0 days | Scans were imported immediately after collection |
| MTTR | Not available | No findings closed yet |
| Median vulnerability age | 0 days | Initial import baseline |
| Active backlog | 287 | After deduplication |
| SLA compliance | 100% | No SLAs exceeded at baseline |
| Critical findings | 12 | Top remediation target |

### SLA matrix

I configured the SLA matrix in DefectDojo under **Configuration → SLA Configuration** and applied it to the engagement:

| Severity | SLA |
|----------|----:|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Risk-accepted items

No findings were risk-accepted at the time of submission. I kept the SLA clock running on all active items because accepting risk without an expiry date is the "silent program killer" described in Lecture 10 slide 12. If a finding is later accepted, it will have an explicit expiry date and a review owner.

| Finding | Severity | Risk accepted reason | Expiry date |
|---------|----------|----------------------|-------------|
| — | — | — | — |

### Next-quarter goal

The next quarter I would mature the **OWASP SAMM Defect Management** practice by adding **runtime ingestion from Falco** (Lab 9) into DefectDojo. Currently, runtime alerts live in `falco.log` outside the program dashboard. Building a small parser that maps Falco `Critical`/`Warning` alerts to DefectDojo findings would create a single SLA and MTTR clock for both scan-time and runtime detections, closing the last gap in the feedback loop.

---

## Bonus: Interview Walkthrough

- **Walkthrough script:** see `submissions/lab10-walkthrough.md`
- **Practiced runtime:** about 4:45
- **Anticipated Q&A questions covered:** 2 (Log4Shell-style response; open-source vs paid tools)
- **Strongest claim:** "The SBOM turns 'are we affected?' from a week of archaeology into a query."
