# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: **3.1.0** (release mode)
- Image: `defectdojo/defectdojo-django:latest`

### Product + Engagement
- Product ID: 1
- Product name: DevSecOps-Intro Labs
- Engagement ID: 1
- Engagement name: Labs 4-9 Capstone
- Engagement status: In Progress

### Admin token extraction

```bash
# Login via API
curl -s -X POST http://localhost:8080/api/v2/api-token-auth/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
# → {"token": "0e89c1e4..."}
```

### Imports completed

| Lab | Tool | Scan type | File | Findings |
|-----|------|-----------|------|---------:|
| 4 | Anchore Grype | `Anchore Grype` | `grype-from-sbom.json` | 104 |
| 4 | Trivy SCA | `Trivy Scan` | `trivy.json` | 113 |
| 5 | Semgrep SAST | `Semgrep JSON Report` | `semgrep.json` | 22 |
| 5 | OWASP ZAP | `ZAP Scan` | `auth-report.xml` (converted from JSON) | 12 |
| 6 | Checkov | `Checkov Scan` | `checkov-terraform/results_json.json` | 80 |
| 6 | KICS | `KICS Scan (SARIF)` | `kics-ansible/results.sarif` | 10 |
| 7 | Trivy Image | `Trivy Scan` | `trivy-image.json` | 50 |
| **Total** | | | | **391** |

> Note: ZAP's `auth-report.json` is in OWASPReport JSON format; DefectDojo's ZAP importer requires XML.
> The file was programmatically converted to OWASP ZAP XML before import. All 12 alerts imported.
>
> Lab 9 Falco log has no DefectDojo parser — documented via paste-in in submissions/lab9.md.
> Lab 8 Cosign verify output has no DefectDojo parser — no binary importer exists for signature verification.

### Dedup example (Lecture 10 slide 11)

**CVE-2023-46233** (`crypto-js 3.3.0`) appears in two independent scan sources:
- Finding ID 139 — Test 2 (Trivy SCA, lab4, `trivy.json`)
- Finding ID 332 — Test 7 (Trivy Image, lab7, `trivy-image.json`)

Both report the same Critical vulnerability (CVSS 9.3, prototype pollution in crypto-js 3.x).
DefectDojo surfaces both separately in the engagement view; the "same CVE across 2 Trivy runs targeting
different artifact types" is the cross-tool dedup pattern — one fix closes both.

---

## Task 2: Governance Report

### Executive Summary

Juice Shop, scanned across 7 tools (SCA × 2, SAST × 1, DAST × 1, IaC × 2, Image × 1), currently has
391 open findings (17 Critical + 163 High). No findings have been closed in this engagement (all imported
fresh), so MTTR is not yet computable — the programme is at Day 0 triage. 100% of findings are within
their SLA window since they were imported today (2026-07-09).

### SLA Matrix (Lecture 10 slide 8 / Lecture 9 slide 8)

| Severity | SLA Target | Applied via |
|----------|-----------|-------------|
| Critical | 24 hours | DefectDojo UI → Configuration → SLA Configuration |
| High | 7 days | same |
| Medium | 30 days | same |
| Low | 90 days | same |

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 163 |
| Medium | 170 |
| Low | 29 |
| Info | 12 |
| **Total** | **391** |

### Findings by source tool

| Tool | Lab | Category | Active | Mitigated |
|------|-----|----------|-------:|----------:|
| Anchore Grype | 4 | SCA | 104 | 0 |
| Trivy SCA | 4 | SCA | 113 | 0 |
| Semgrep | 5 | SAST | 22 | 0 |
| OWASP ZAP | 5 | DAST | 12 | 0 |
| Checkov | 6 | IaC | 80 | 0 |
| KICS (Ansible) | 6 | IaC | 10 | 0 |
| Trivy Image | 7 | Container | 50 | 0 |
| **Total** | | | **391** | **0** |

### Program metrics

- **MTTD** (Mean Time to Detect): ~0 days — findings detected at scan time within the CI/CD pipeline;
  all scans run in the same engagement window. MTTD would be measured from code-commit to
  first-alert if integrated into the PR gate.
- **MTTR** (Mean Time to Remediate): N/A — no findings have been closed yet. This is a fresh import
  from an ongoing course environment, not a production remediation cycle. Baseline MTTR target per SLA:
  Critical <1 day, High <7 days.
- **Vuln-age median** (open findings): ~0 days — all imported 2026-07-09. In a production context,
  vuln-age would be computed as `today − date_first_detected`.
- **Backlog trend**: +391 (initial baseline, no prior period to compare)
- **SLA compliance**: 100% — all findings within SLA window on import day.
  Critical findings (17): must close by 2026-07-10. High (163): by 2026-07-16.

### Top-priority findings (CVSS + EPSS triage — Lecture 10 slide 5)

Highest-risk Critical findings (High CVSS, high exploitability):

| Finding | Component | Severity | Source | Action |
|---------|-----------|----------|--------|--------|
| GHSA-xwcq-pm8m-c4vf | crypto-js:3.3.0 | Critical | Grype | Upgrade to crypto-js ≥ 4.2.0 |
| GHSA-c7hr-j4mj-j2w6 | jsonwebtoken:0.1.0 | Critical | Grype | Upgrade to jsonwebtoken ≥ 9.0.0 |
| CVE-2026-34182 | libssl3t64:3.5.5 | Critical | Grype | Rebuild base image with patched Debian |
| CVE-2026-5450 | libc6:2.41-12 | Critical | Grype | Rebuild base image with patched Debian |
| CVE-2023-46233 | crypto-js:3.3.0 | Critical | Trivy ×2 | Same fix as GHSA above |

### Risk-accepted items

None. All 391 findings are in active/unreviewed state. Per Lecture 10 slide 12 (the "silent program
killer" rule): any Risk Accept applied in a production context MUST carry an explicit expiry date and
business justification. No risk accepts have been granted at this time.

### Next-quarter goal (OWASP SAMM — Lecture 9 slide 15)

**Practice: Defect Management (SM.DM)** — Currently at Level 0 (no formal tracking).
Target: advance to Level 1 by automating MTTR measurement. Concrete action: wire Falco runtime
alerts into DefectDojo via a custom parser (Falco outputs structured JSON); add `is_mitigated` PATCH
calls from the deployment pipeline when images are rebuilt with patched base layers. This closes the
MTTD-to-MTTR loop for Critical container CVEs, which make up 8 of 17 Critical findings today.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: ~4 minutes 30 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: *"We went from zero visibility to 391 tracked findings across 7 scan
  layers in one semester — and the programme knows exactly which 17 need to be fixed by tomorrow."*
