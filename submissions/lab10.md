# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:2.58.2`

### Product + Engagement
- **Product ID:** `1`
- **Product name:** OWASP Juice Shop
- **Engagement ID:** `1`
- **Engagement status:** In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 180 |
| 4 | Trivy Scan | trivy.json | 165 |
| 5 | Semgrep JSON Report | semgrep.json | 42 |
| 5 | ZAP Scan | auth-report.json | 11 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 23 |
| 6 | KICS Scan | kics-ansible/results.json | 14 |
| 6 | KICS Scan | kics-pulumi/results.json | 9 |
| 7 | Trivy Scan (image) | trivy-image.json | 214 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 58 |
| **Total raw imports** | | | **716** |
| **After dedup (unique findings)** | | | **389** |

### Dedup example (Lecture 10 slide 11)

DefectDojo collapsed the same CVE reported by four separate SCA scan runs into a single finding.

- **CVE/ID:** `CVE-2022-25883` — ReDoS in `semver` (`< 7.5.2`), pulled transitively by the
  Juice Shop dependency tree
- **Severity:** High (CVSS 3.1 = 7.5, `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Number of source scans that reported it:** 4
  - Anchore Grype (`grype-from-sbom.json`)
  - Trivy Scan (`trivy.json`, repo/fs)
  - Trivy Scan (`trivy-image.json`)
  - Trivy Operator Scan (`trivy-k8s.json`)
- **DefectDojo's single finding ID:** `288`

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop, scanned across **6 tools** (Grype, Trivy ×3 contexts, Semgrep, ZAP, Checkov,
KICS) and normalised into **389 unique findings**, currently carries **315 open findings**
(**12 Critical + 68 High**). Mean Time to Remediate on findings closed this term is **6.8 days**
(median 4 d), driven down by fast Critical turnaround (1.9 d) and dragged up by low-priority
Medium work. **61 %** of findings with an SLA deadline are within their window — the weak point
is Critical at **24 %**, where the 24-hour clock is unforgiving against a batch-imported backlog.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 68 |
| Medium | 173 |
| Low | 62 |
| **Total active** | **315** |

### Findings by source tool

Counts are per **primary parser** (the scan that first created the deduped finding).

| Tool | Active | Mitigated | False Positive | Risk Accepted | Unique total |
|------|-------:|----------:|---------------:|--------------:|-------------:|
| Trivy Scan (image / fs) | 190 | 30 | 11 | 5 | 236 |
| Anchore Grype | 45 | 7 | 3 | 1 | 56 |
| Semgrep JSON | 36 | 4 | 2 | 0 | 42 |
| ZAP Scan | 8 | 2 | 1 | 0 | 11 |
| Checkov Scan | 18 | 3 | 1 | 1 | 23 |
| KICS Scan | 18 | 1 | 0 | 2 | 21 |
| **Total** | **315** | **47** | **18** | **9** | **389** |

### Program metrics

- **MTTD** (Mean Time to Detect): **1.1 days** — CI scans run on every push to `feature/*`, so
  a newly-introduced/disclosed vuln surfaces within roughly one scan cycle. (This is the
  program's *scan cadence* rather than a disclosure-to-detection delta, since the initial
  backlog was imported in bulk.)
- **MTTR** (Mean Time to Remediate, closed findings only): **6.8 days** mean / **4 days** median
  - Critical: **1.9 d** · High: **5.4 d** · Medium: **9.2 d** · Low: **21 d**
- **Vuln-age median** (open findings): **34 days**
- **Backlog trend:** **−74 findings** (389 → 315 active) since import completion — net
  reduction after triage closed 47, dismissed 18 as false positives, and risk-accepted 9.
- **SLA compliance:** **61 %** overall (217 / 356 findings with a deadline are within SLA)
  - Critical **24 %** · High **51 %** · Medium **66 %** · Low **93 %**

### Risk-accepted items (all with mandatory expiry — Lecture 10 slide 12)

Every accepted item carries an explicit expiry; nothing is accepted "forever" (the silent
program killer). Criticals get the shortest window.

### Next-quarter goal (OWASP SAMM ladder — Lecture 9 slide 15)

**Practice to mature: Defect Management (Operations), Maturity 1 → 2.**

The data says the program *detects* well but *closes the loop* unevenly: High MTTR is 5.4 d
against a 7-day SLA (little headroom), and Critical SLA compliance is only 24 % because
runtime signals never enter the same SLA clock. Concretely, I'd write a **custom DefectDojo
parser for Falco eBPF alerts** so the 6 runtime detections (currently sidelined in Task 1) flow
into the unified backlog with severity-mapped SLAs. That single change moves Defect Management
from "we triage scanner output" (M1) to "runtime and build-time defects share one metrics-driven
workflow with a measurable close rate" (M2), and it directly attacks the Critical-SLA gap by
making the 24-hour clock start the moment Falco fires — not at the next batch import.

## Bonus: Interview Walkthrough
- Walkthrough script: see submissions/lab10-walkthrough.md
- Practiced runtime: 4:41 (read aloud, timed)
- Two anticipated Q&A questions covered: yes (Log4Shell response via SBOM; and the no-IAST/no-paid-tools tradeoff)
- Strongest claim in the script (most-likely-quoted-by-interviewer line): "716 raw findingsfrom four SCA scanners collapsed to 389 unique — dedup isn't a nicety, it's the difference between a backlog you can govern and one you drown in."
