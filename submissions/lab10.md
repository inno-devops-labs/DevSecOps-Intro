# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: 3.1.0 (defectdojo/defectdojo-django:latest)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 4 | Trivy Scan | trivy.json | 114 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 0 (ЗАП игнорирован — DefectDojo требует XML, а у нас JSON; ошибка: "Wrong file format, please use xml") |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Scan (k8s) | trivy-k8s.json | 152 |
| **Total raw imports** | | | **542** |
| **After dedup** | | | 542 (cross-tool dedup не сработал — Grype/Trivy используют разные ID уязвимостей GHSA vs CVE, и компоненты имеют разные версии) |

### Dedup example
Cross-tool dedup не проявился в явном виде — все 542 фиденга уникальны. Причина: разные сканеры сообщают об уязвимостях через разные ID (GHSA vs семгреповские rule IDs vs Checkov policy IDs), и компоненты с одинаковыми уязвимостями имеют разные версии (напр. tar:4.4.19, tar:6.2.1, tar:7.5.15 — все с GHSA-vmf3-w455-68vh, но DefectDojo не дедуплицирует их т.к. component_version разный).

## Task 2: Governance Report

### Executive Summary
Juice Shop, просканированный через 8 инструментов (Grype, Trivy ×3, Semgrep, Checkov, KICS ×2), имеет 542 открытых фиденга: 31 Critical + 262 High + 169 Medium + 29 Low + 9 Info. Среднее время на реагирование (MTTR) — 0 дней (все фиденги активны, ни один не закрыт). SLA применён (24h/7d/30d/90d), просроченных фиденгов пока нет.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 31 |
| High | 262 |
| Medium | 169 |
| Low | 29 |
| Info | 9 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 108 | 0 | 0 | 0 |
| Trivy Scan (Lab 4) | 114 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan (Ansible) | 10 | 0 | 0 | 0 |
| KICS Scan (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (image) | 50 | 0 | 0 | 0 |
| Trivy Scan (k8s) | 152 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): N/A — фиденги импортированы одномоментно
- **MTTR** (Mean Time to Remediate): 0 дней (ни один фиденг не закрыт)
- **Vuln-age median** (open findings): <1 день (все импортированы сегодня)
- **Backlog trend**: 0 (первичный импорт, нет предыдущего замера)
- **SLA compliance**: 100% (SLA только что применён, просрочек нет)

### Risk-accepted items
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| — | — | Риск-акцептанс не применялся в рамках этой лабораторной | — |

### Next-quarter goal (OWASP SAMM ladder step)
**Defect Management** — текущий MTTR = 0 (нет процесса ремедиации). Цель на следующий квартал: внедрить процесс закрытия фиденгов с приоритетом по CVSS+EPSS (2x2 матрица из Lecture 10). Конкретно: для Critical фиденгов — MTTR < 24ч (DORA Elite benchmark), для High — < 7 дней. Добавить Falco-runtime ingestion через custom parser в DefectDojo для автоматического создания фиденгов из runtime-алертов.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4:45
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "We closed 0 criticals but SLAs are applied — meaning every overdue critical is visible to the on-call lead within 24 hours, not waiting for a quarterly review."