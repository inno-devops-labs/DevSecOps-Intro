# Lab 10 - Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- DefectDojo source: `django-DefectDojo` shallow clone at commit `a7eb77f`.
- Runtime image: `defectdojo/defectdojo-django:latest`, image id `aed7db86dd37`, platform `linux/arm64`.
- Nginx image: `defectdojo/defectdojo-nginx:latest`, image id `048ab31f4f53`, platform `linux/arm64`.
- Compose mode used: release. The dev override expected `*-dev.sh` entrypoints that were not present in the pulled release image.
- UI: `http://localhost:8080`
- Admin user: `admin`
- Admin password reset locally to: `DevSecOps-Lab10-2026!`

### Product + Engagement

- Product ID: `1`
- Product name: `OWASP Juice Shop`
- Product type: `Engineering`
- Engagement ID: `1`
- Engagement name: `Course Semester Run`
- Engagement status: `In Progress`
- Engagement dates: `2026-07-03` to `2026-12-15`

### Imports completed

| Lab | Scan type | File | Findings imported | Result |
|-----|-----------|------|------------------:|--------|
| 4 | Anchore Grype | `labs/lab4/grype-from-sbom.json` | 107 | Imported |
| 4 | Trivy Scan | `labs/lab4/trivy.json` | 113 | Imported |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | 22 | Imported |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | 0 | Skipped: this DefectDojo parser requires ZAP XML, Lab 5 output is JSON |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 80 | Imported |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 | Imported |
| 6 | KICS Scan | `labs/lab6/results/kics-pulumi/results.json` | 6 | Imported |
| 7 | Trivy Scan | `labs/lab7/results/trivy-image.json` | 50 | Imported, later deduped as duplicate of Lab 4 Trivy findings |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 | Imported successfully; no findings parsed |
| 8 | Cosign verify | `labs/lab8/results/verify-original.json` | 0 | Documented as supply-chain evidence; no vuln parser used |
| 9 | Falco custom log | `labs/lab9/falco/logs/falco.log` | 0 | Documented; custom runtime log format has no stock parser |
| **Total raw imports** | | | **388** | Successful parser findings before dedupe |
| **After dedup** | | | **338** | Active non-duplicate findings |

Successful DefectDojo scan types imported: Anchore Grype, Trivy Scan, Semgrep JSON Report, Checkov Scan, KICS Scan, Trivy Operator Scan.

### Dedup example

- Global DefectDojo deduplication was disabled by default, so I enabled it in `System_Settings` and ran `manage.py dedupe --dedupe_sync`.
- Raw findings before dedupe: 388.
- Duplicate findings after dedupe: 50.
- Active non-duplicate findings after dedupe: 338.

Concrete automatic dedup proof:

| CVE/ID | Duplicate finding | Source | Original finding | Source | Result |
|--------|------------------:|--------|-----------------:|--------|--------|
| `CVE-2021-23337` | `354` | Lab 7 Trivy image, test `8` | `163` | Lab 4 Trivy, test `2` | Finding `354` marked duplicate of `163` |
| `CVE-2019-10744` | `352` | Lab 7 Trivy image, test `8` | `161` | Lab 4 Trivy, test `2` | Finding `352` marked duplicate of `161` |

Cross-tool correlation note:

- `CVE-2021-23337` also appears in Anchore Grype as finding `1` (`GHSA-35jh-r3h4-6jhm in lodash:2.4.2`) and in Trivy as finding `163`.
- DefectDojo did not automatically mark the Grype finding as a duplicate because the default parser hash fields differ: `Anchore Grype` hashes title/severity/component/version, while `Trivy Scan` includes vulnerability IDs and description. I left the dataset honest and documented this as a parser-hash limitation.

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop was scanned across six successful DefectDojo parser types and produced 338 active non-duplicate findings after deduplication: 12 Critical and 119 High are the immediate remediation backlog. No findings were closed during this Lab 10 reporting period, so MTTR is not yet statistically meaningful. SLA compliance is currently 100% because all findings were detected on `2026-07-03` and none have passed the configured SLA deadline.

### SLA matrix applied

| Severity | SLA |
|----------|-----|
| Critical | 24 hours / 1 day |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

SLA configuration ID `1` was renamed to `Lab 10 SLA Matrix`, assigned to product `1`, and back-filled onto the 388 imported findings.

### Findings by severity (active, non-duplicate)

| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 119 |
| Medium | 169 |
| Low | 29 |
| Info | 9 |
| **Total** | **338** |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 107 | 0 | 0 | 0 |
| Trivy Scan | 113 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan | 16 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |
| ZAP Scan | 0 | 0 | 0 | 0 |

Note: Lab 7 Trivy image produced 50 findings, all marked duplicate after dedupe against Lab 4 Trivy. ZAP JSON was not accepted by the stock parser because this DefectDojo build expects ZAP XML.

### Program metrics

- **MTTD**: 0 days. Lab reports were imported into DefectDojo on the same day they were assessed for this capstone.
- **MTTR**: not established. There were 0 mitigated findings in this reporting period.
- **Vuln-age median**: 0 days for open findings on `2026-07-03`.
- **Backlog trend**: +338 active non-duplicate findings versus the pre-DefectDojo baseline of 0 tracked findings.
- **SLA compliance**: 100% currently within SLA; no active non-duplicate findings are overdue on import day.
- **Dedup efficiency**: 50 / 388 raw imported findings marked duplicate, reducing the active working backlog by 12.9%.

### Risk-accepted items

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| None | N/A | No findings were risk-accepted in this lab run | N/A |

Policy note: any future risk acceptance must include an owner, reason, compensating control, and expiry date. No permanent acceptances.

### Next-quarter goal (OWASP SAMM ladder step)

Next quarter I would mature **Defect Management** from ad-hoc aggregation to SLA-driven remediation workflow. The data shows 131 Critical/High active non-duplicate findings, so the concrete goal is to close or formally risk-accept every Critical finding within 24 hours and cut the High backlog by at least 50% before the next governance review. I would also add a custom ingestion path for Falco runtime alerts and convert ZAP JSON to parser-compatible XML so runtime and DAST findings participate in the same SLA dashboard.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime target: `4:45`
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "I treated the scanners as sensors, not as the program; DefectDojo is where the work becomes accountable."
