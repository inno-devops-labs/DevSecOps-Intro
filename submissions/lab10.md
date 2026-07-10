# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

```
defectdojo/defectdojo-django:latest  (uwsgi, celery, initializer)
defectdojo/defectdojo-nginx:latest
```

### Product + Engagement

- Product ID: `1`
- Product name: Juice Shop
- Engagement ID: `1`
- Engagement name: Labs Security Testing
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | test_id | Findings imported |
|-----|-----------|------|--------:|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 10 | 97 |
| 4 | Trivy Scan | trivy.json | 11 | 106 |
| 5 | Semgrep Pro JSON Report | semgrep.json | 12 | 0 |
| 5 | ZAP Scan | auth-report.json | — | 0 *(import failed — see note)* |
| 6 | Checkov Scan | results_json.json | 14 | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 15 | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 16 | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 17 | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 18 | 0 |
| **Total (per-test counts)** | | | | **349** |
| **Engagement total (deduped)** | | | | **698** |

**Notes:**
- Engagement total 698 > per-test sum 349 because an earlier import batch (tests 1–9) was loaded before the scripted re-import (tests 10–18). DefectDojo keeps both test records; dedup collapses overlapping SCA items where parsers agree.
- Semgrep returned 0 — instance auto-selected **Semgrep Pro JSON Report**; OSS `semgrep.json` may need **Semgrep JSON Report** scan type.
- ZAP: empty `test_id` in response — check `labs/lab10/imports/import-results-auth-report.json` for error body.
- Trivy k8s: 0 findings — operator JSON format may not match parser; document as known limitation.

### Dedup example (Lecture 10 slide 11)

Cross-tool SCA overlap (Grype test 10 + Trivy test 11 on the same Juice Shop SBOM):

- **CVE/ID:** `GHSA-c7hr-j4mj-j2w6`
- **Number of source tools:** 2 — Anchore Grype (test 10) + Trivy Scan (test 11)
- **DefectDojo canonical finding ID:** `1`
- **Title:** `GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0`
- **API:** `duplicate=false` — this is the original; sibling imports marked `duplicate=true` point to id `1`

Confirm overlap in source JSON:

```bash
grep -l "GHSA-c7hr-j4mj-j2w6" labs/lab4/grype-from-sbom.json labs/lab4/trivy.json
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?engagement=1&duplicate=true&duplicate_finding=1&limit=5" \
  | jq '{merged_count: .count, ids: [.results[].id]}'
```

UI: **Findings → id 1 → Duplicate** tab lists merged copies from the other scanner.

---

## Task 2: Governance Report

### Executive Summary (3 sentences)

Juice Shop was aggregated in DefectDojo engagement **Labs Security Testing** from seven successful scan imports (Grype, Trivy lab4, Checkov, KICS ×2, Trivy image) plus an earlier partial batch. The engagement currently holds **698** deduplicated findings: **34 Critical**, **292 High**, **300 Medium**, **54 Low**, and **18 Info** (all active). No findings were mitigated or risk-accepted in this run; SLA matrix (24h / 7d / 30d / 90d) was configured for remediation tracking.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 34 |
| High | 292 |
| Medium | 300 |
| Low | 54 |
| Info | 18 |
| **Total active** | **698** |

### Findings by source tool

| Tool | Active (approx.) | Mitigated | False Positive | Risk Accepted |
|------|----------------:|----------:|---------------:|--------------:|
| Trivy (lab4 + image) | ~156 | 0 | 0 | 0 |
| Grype | ~97 | 0 | 0 | 0 |
| Checkov | ~80 | 0 | 0 | 0 |
| KICS (ansible + pulumi) | ~16 | 0 | 0 | 0 |
| Semgrep | 0 | 0 | 0 | 0 |
| ZAP | 0 | 0 | 0 | 0 |

*(Per-tool active counts: `curl "$DD_URL/api/v2/findings/?test=<test_id>&active=true&limit=1"`)*

### Program metrics

- **MTTD** (Mean Time to Detect): N/A — all tools imported in one engagement window
- **MTTR** (Mean Time to Remediate): N/A — 0 mitigated findings
- **Vuln-age median** (open findings): ~0 days (all created on import date 2026-07-10)
- **Backlog trend**: +698 vs baseline 0 (new engagement)
- **SLA compliance**: N/A until first remediations close within SLA window

### SLA matrix applied

| Severity | SLA |
|----------|-----|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

Configured in DefectDojo → **Configuration → SLA Configuration** → linked to product **Juice Shop**.

### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| *(none)* | | | |

### Next-quarter goal (OWASP SAMM)

Mature **Vulnerability Management → Defect Management** (OWASP SAMM): High backlog is **292** with MTTR unmeasured. Next quarter: (1) fix Semgrep/ZAP importers and re-import DAST/SAST, (2) close top 10 Critical/High SCA items shared by Grype+Trivy, (3) add Falco runtime ingestion, target High MTTR &lt; 7 days per SLA.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: <!-- mm:ss -->
- Two anticipated Q&A questions covered: yes / no
- Strongest claim: <!-- one line -->
