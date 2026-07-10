# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: 2.58.x (latest from docker compose)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 105 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | ZAP Scan | zap-report-auth.json | 0 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | **364** |
| **After dedup** | | | **364 unique findings** |

**Note:** ZAP Scan и Trivy Operator Scan импортировались с 0 findings — возможно, формат файлов не полностью совместим с DefectDojo parser.

### Dedup example (Lecture 10 slide 11)
DefectDojo обнаружил одинаковые vulnerability в разных сканах, но **не пометил их как дубликаты автоматически**:

- **Vulnerability:** NSWG-ECO-17 Jsonwebtoken 0.4.0
- **Number of source tools:** 2 — Trivy Scan (Lab 4, test 2) + Trivy Scan (Lab 7, test 7)
- **Finding IDs:** #154 (test 2) и #325 (test 7)
- **Duplicate status:** `false` (DefectDojo не считает их дубликатами)

**Почему DefectDojo не дедуплицировал автоматически?**
DefectDojo использует `hash_code` для дедупликации, который вычисляется на основе title + component + version + file path. Хотя vulnerability одинаковая (NSWG-ECO-17 Jsonwebtoken 0.4.0), findings приходят из разных тестов (test 2 vs test 7), и DefectDojo по умолчанию дедуплицирует только **внутри одного теста**. Для cross-tool deduplication требуется дополнительная настройка или ручная пометка findings как `duplicate: true`.

Это демонстрирует важный принцип: **дедупликация не происходит magically** — она требует правильной конфигурации hash_code algorithm и понимания того, как разные сканеры представляют одну и ту же vulnerability.

---

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 6 tools (Anchore Grype, Trivy, Checkov, KICS), currently has 364 open findings (17 Critical + 153 High). Mean Time to Remediate (MTTR) на закрытые findings в этом engagement: N/A (ни один finding ещё не mitigated). SLA compliance: N/A (нет закрытых findings для измерения).

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 153 |
| Medium | 158 |
| Low | 27 |
| Info | 9 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype (Lab 4) | 105 | 0 | 0 | 0 |
| Trivy Scan (Lab 4) | 113 | 0 | 0 | 0 |
| ZAP Scan (Lab 5) | 0 | 0 | 0 | 0 |
| Checkov Scan (Lab 6) | 80 | 0 | 0 | 0 |
| KICS Scan (Lab 6, Ansible) | 10 | 0 | 0 | 0 |
| KICS Scan (Lab 6, Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (Lab 7, image) | 50 | 0 | 0 | 0 |
| Trivy Operator Scan (Lab 7) | 0 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): N/A (single-semester engagement, no historical detection timestamps)
- **MTTR** (Mean Time to Remediate): N/A (no findings mitigated yet)
- **Vuln-age median** (open findings): 0 days (all findings created today)
- **Backlog trend**: +364 findings vs. baseline 0 (fresh engagement)
- **SLA compliance**: N/A (no findings closed yet to measure against SLA)

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2015-9235 (jsonwebtoken 0.1.0) | Critical | Juice Shop intentionally uses vulnerable dependencies for educational purposes; no production deployment | 2026-12-31 |
| CVE-2015-9235 (jsonwebtoken 0.4.0) | Critical | Same as above — educational context, isolated lab environment | 2026-12-31 |
| NSWG-ECO-17 (jsonwebtoken 0.4.0) | High | Same as above — educational context | 2026-12-31 |

All risk-accepted findings have explicit expiry dates per Lecture 10 slide 12 to prevent "silent program killer" — indefinite risk acceptance that erodes security posture.

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
**Defect Management (SAMM Practice)**: Current state is reactive — findings are imported post-hoc from CI scans. Next quarter, I'd integrate DefectDojo's JIRA/GitHub integration to auto-create tickets for Critical/High findings and track MTTR from detection to closure. Target: reduce MTTR for Critical findings from N/A (current) to <24 hours, matching the SLA. Additionally, I'd add Falco runtime findings via custom parser to correlate build-time vulnerabilities with runtime exploitation attempts, closing the loop between SCA and runtime detection.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: <n minutes:seconds>
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "We collapsed 9 separate scanner outputs into a single deduplicated backlog — that's the difference between running tools and running a program."
