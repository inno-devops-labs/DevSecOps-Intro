# Lab 6 — IaC Security: Scanning & Policy Enforcement

## 1. Terraform: tfsec vs Checkov vs Terrascan
- Краткая сводка — см. `labs/lab6/analysis/terraform-comparison.txt`.
- Плюсы/минусы каждого: скорость, шум, удобство отчётов, покрытие.
- 3–5 критичных примеров (ID/правило/файл/строка) и **ремедиация**.

## 2. Pulumi (KICS)
- Сводка — см. `labs/lab6/analysis/pulumi-analysis.txt`.
- 3–5 проблем и как пофиксить (фрагменты YAML/Python).

## 3. Ansible (KICS)
- Сводка — см. `labs/lab6/analysis/ansible-analysis.txt`.
- Мин. 3 нарушения best practices + их безопасность + фиксы.

## 4. Сравнительная матрица инструментов
| Критерий | tfsec | Checkov | Terrascan | KICS |
|---|---:|---:|---:|---:|
| Total findings | … | … | … | Pulumi+Ansible: … |
| Scan speed | | | | |
| False positives | | | | |
| Report quality | | | | |
| Ease of use | | | | |
| Docs | | | | |
| Platform support | Terraform | Multi | Multi | Pulumi+Ansible |
| Output formats | JSON/TXT/SARIF | … | … | JSON/HTML/TXT |
| CI/CD integration | | | | |

## 5. Категоризация уязвимостей
| Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best |
|---|---|---|---|---|---|---|
| Encryption | | | | | | |
| Network | | | | | | |
| Secrets | | | | | | |
| IAM/Permissions | | | | | | |
| Access Control | | | | | | |
| Compliance/Best Practices | | | | | | |

## 6. Топ-5 критичных находок и фиксы
- Issue → Impact → Tool(s) → Fix (код) → Примечание.

## 7. Рекомендации по CI/CD
- Где и как запускать каждый тул, форматы, pre-commit/PR-gates/nightly.

## 8. Lessons learned
- Точность, шум, производительность, DX, уникальные находки.
