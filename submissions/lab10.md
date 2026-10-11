# Lab 10 — Vulnerability Management Capstone

## Task 1

### DefectDojo
- Version: **2.58.3** (clone pin `labs/lab10/work/dd`, `dojo/__init__.py`)
- Product: `OWASP Juice Shop` (type `Research and Development`)
- Engagement: `Course Semester Run`

### Imports (parser → file → active findings after import)

| Lab | File | Parser | Active |
|-----|------|--------|-------:|
| 4 | `labs/lab4/grype-from-sbom.json` | Anchore Grype | 230 |
| 4 | `labs/lab4/trivy.json` | Trivy Scan | 225 |
| 5 | `labs/lab5/results/semgrep.json` | Semgrep JSON Report | 27 |
| 5 | `labs/lab5/results/auth-report.json` → converted `auth-report.xml` | ZAP Scan | 12 |
| 6 | `labs/lab6/results/checkov-terraform/results_json.json` | Checkov Scan | 80 |
| 6 | `labs/lab6/results/kics-ansible/results.json` | KICS Scan | 10 |
| 6 | `labs/lab6/results/kics-pulumi/results.json` | KICS Scan | 6 |
| 7 | `labs/lab7/results/trivy-image.json` | Trivy Scan | 87 |
| 7 | `labs/lab7/results/trivy-k8s.json` | Trivy Operator Scan | 0 |
| 7 | same `trivy-k8s.json` (retry) | Trivy Scan | 175 |

Notes: DefectDojo’s ZAP parser rejected traditional JSON (`Wrong file format, please use xml`); converted Lab 5 auth JSON to traditional XML and imported that. `trivy k8s` JSON is not Trivy Operator CR format, so Operator import produced 0; re-imported as Trivy Scan so the cluster findings are still visible.

### Active findings by severity (API, after imports + one risk acceptance)
| Severity | Count |
|----------|------:|
| Critical | 66 |
| High | 436 |
| Medium | 282 |
| Low | 56 |
| Info | 11 |
| **Total active** | **851** |

### Duplicate titles
1. **`CVE-2026-93748 HTTP-Cache-Semantics 4.2.0`** (8×, all Trivy Scan) — same CVE/component, but **two distinct `hash_code` values** across Lab 4 SBOM Trivy, Lab 7 image Trivy, and Lab 7 k8s Trivy. Same issue rediscovered by different scan surfaces (SBOM vs image vs cluster), not eight unrelated bugs.
2. **`Secret Management: Passwords and Secrets - Generic Password`** (7×, KICS) — **seven different `hash_code`s**. Same rule title, separate locations in Ansible/Pulumi trees → seven findings to triage, not one issue counted seven times.

### Which labs matter this week
Act on **Lab 5 Semgrep** (real app-logic sinks like sequelize injection) and **Lab 7 image/k8s Trivy Critical/High** that map to the running artifact. Treat most of Lab 4’s 200+ SBOM CVEs as backlog noise until EPSS/KEV prioritization — volume without exploitability burns the SLA. Lab 6 IaC (Checkov/KICS) is actionable for the next infra PR, not a production fire this week. Labs 1–3 and 8–9 did not land as DefectDojo findings (no parsers / wrong layer).

## Task 2

### SLA (Default configuration)
| Severity | Default | Ours | Why |
|----------|--------:|-----:|-----|
| Critical | 7 | **3** | Internet-facing Juice Shop; critical means patch or isolate within a long weekend |
| High | 30 | **14** | Two-sprint cadence matches course/release rhythm |
| Medium | 90 | **45** | Still scheduled, not “park forever” |
| Low | 120 | **90** | Keep hygiene without pretending Low equals High |

### Active by severity and tool
Severity: Critical 66 / High 436 / Medium 282 / Low 56 / Info 11 (total 851).

By tool: Trivy Scan 487 · Anchore Grype 229 · Checkov 80 · Semgrep 27 · KICS 16 · ZAP 12.

### Age and SLA compliance
Query: paginated `GET /api/v2/findings/?active=true`, age = `now - finding.date` (days); SLA share = `sla_days_remaining >= 0`.

| Metric | Value | Method |
|--------|------:|--------|
| Median age of active findings | **0 days** | median of ages (all imported today) |
| Oldest active finding | **0 days** | max age |
| Share inside SLA | **100%** (840/840 with SLA fields) | `sla_days_remaining >= 0` |

Fresh import day: ages are zero and nothing has breached yet; the SLA change starts the clock for the next refresh.

### Labs 8 and 9 gap
Cosign signatures/attestations and Falco/Conftest evidence are not findings in DefectDojo. I would attach them as engagement notes / files and track “unsigned image” / “runtime CRITICAL alert” as manual findings or a separate gate in CI, not pretend the vuln DB covers supply-chain and runtime.

### Risk acceptance
- Finding **#117** — Info: `CVE-2018-20796 in libc6` (Grype)
- Decision: Accept (`decision=A`) via `/api/v2/risk_acceptance/` id=1
- Expiry: **2026-12-15**
- Compensating control: base image rebuild on a fixed cadence + monitor KEV/EPSS; Info/disputed libc issues do not block the semester demo without a concrete exploit path

### Executive summary
Juice Shop’s aggregated backlog is **851 active findings**, dominated by SCA/image noise (Trivy+Grype) rather than confirmed exploitable app bugs. The single biggest risk is **Critical/High issues on the running image and the Semgrep injection class findings**, not the raw CVE count. To close that risk we need a patched/rebuilt image digest (Lab 7/8 pipeline) plus tickets for the Semgrep sequelize sinks with owners and the new 3/14-day SLA.

## Bonus

Walkthrough script: `submissions/lab10-walkthrough.md`.

The hardest part of the semester to explain in five minutes is **why 800+ DefectDojo findings are not 800 fires** — scanners overlap, SBOM CVEs lack context, and Labs 8–9 never appear as rows. That tells me the next project needs a one-page “how we prioritize” note (KEV/EPSS, reachable artifact, SLA) written *before* the first import, not after the dashboard panics a manager.
