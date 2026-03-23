# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Tool Comparison

**Summary of Detected Issues**

- **tfsec**: 53 findings (18 passed checks logged, 9 critical, 25 high, 11 medium, 8 low severities).  
- **Checkov**: 78 findings total (48 passed, 78 failed checks reported).  
- **Terrascan**: 22 findings (14 high, 8 medium, 0 low).

**High‑Level Comparison**

Из трёх сканеров именно **Checkov** показал наибольший охват (78 выявленных проблем), что отражает более обширный набор политик и проверок.  
**tfsec** даёт очень детальную градацию по severity и работает заметно быстрее остальных.  
**Terrascan** находит меньше всего нарушений (22), но удобен, когда нужно сверяться с политиками и комплаенсом на уровне всей инфраструктуры.

### Pulumi Security Assessment

**KICS Pulumi Scan — Итоги**

- **Всего находок**: 6  
- **HIGH**: 2  
- **MEDIUM**: 2  
- **LOW**: 0  
- **INFO**: 2  
- **CRITICAL**: 0

### Terraform vs. Pulumi — сравнение профиля уязвимостей

**Наблюдения по Terraform**
- Существенно большее количество проблем (от 53 до 78 в зависимости от инструмента).  
- Есть как критические, так и многочисленные high‑severity мисконфигурации.  
- Экосистема правил для Terraform уже зрелая, результаты разных сканеров в целом согласованы.  
- Между выводами Checkov и tfsec заметное пересечение по типам детектов.

**Наблюдения по Pulumi**
- Всего несколько срабатываний (6), что значительно меньше, чем у Terraform.  
- Критических проблем нет, но присутствуют важные high‑severity кейсы.  
- Правила для Pulumi в KICS пока менее широкие, но постепенно развиваются.  
- Программируемый стиль описания инфраструктуры приводит к немного другому набору типичных ошибок.

### Покрытие Pulumi‑правил в KICS

**Ключевые моменты**
- **Покрытие** уже полезное, но ощутимо уже, чем для Terraform.  
- **Фокус** смещён в сторону high/medium‑проблем, мелкие замечания репортятся реже.  
- **Сильная сторона** — хорошо подсвечиваются открытые сетевые доступы и отсутствие шифрования в Pulumi YAML‑описаниях.

### Обзор ключевых находок

1. **Terraform — 9 критических проблем**  
   Типичные случаи: утечка секретов, полностью открытые сетевые границы или конфигурации, ведущие к эскалации привилегий.  

2. **Terraform — 25 high‑severity уязвимостей**  
   Чаще всего встречаются: публичные S3 бакеты, отсутствие шифрования, избыточно широкие IAM‑права.  

3. **Pulumi — 2 серьёзные (HIGH) находки**  
   Связаны с чрезмерно открытыми правилами доступа и недостаточно жёстким контролем над ресурсами.  

4. **Terraform — 11 medium‑замечаний**  
   В основном это вопросы тегирования, мониторинга и требований комплаенса с умеренным риском.  

5. **Общие IAM‑проблемы для всех стеков**  
   В обоих подходах легко допустить слишком широкие права, что создаёт общий класс рисков вокруг идентичности и доступа.

### Сильные стороны инструментов

**tfsec**
- **Скорость**: практически мгновенное выполнение (~25 ms на проект).  
- **Детализация**: удобная шкала уровней риска.  
- **Интеграция**: очень просто подключить к Terraform‑ориентированным пайплайнам.  
- **Оптимальный сценарий**: быстрый фидбек для разработчиков прямо в CI/CD.

**Checkov**
- **Охват**: больше всех срабатываний (78), широкий набор встроенных политик.  
- **Гибкость**: умеет работать не только с Terraform, но и с CloudFormation, Kubernetes и др.  
- **Порог входа**: документация и UX позволяют быстро начать использовать.  
- **Оптимальный сценарий**: детальные ревью инфраструктуры и периодические аудиты.

**Terrascan**
- **Фокус**: политика как код и проверка соответствия стандартам.  
- **Интеграция с OPA**: удобно, если уже используется Rego/OPA в компании.  
- **Качество сигнала**: относительно небольшое количество, но достаточно точных срабатываний.  
- **Оптимальный сценарий**: крупные организации, где важно строгое соблюдение внутренних и внешних требований.

**KICS**
- **Поддерживаемые стеки**: Terraform, Pulumi, Ansible в одном инструменте.  
- **Pulumi‑поддержка**: ещё развивается, но уже закрывает базовые сценарии.  
- **Баланс**: сочетание простоты запуска и вполне содержательных отчётов.  
- **Оптимальный сценарий**: единый сканер для разных видов IaC, особенно когда есть Pulumi и Ansible.

---

## Task 2 — Ansible Security Scanning with KICS

### Итоги сканирования

- **Всего находок**: 9  
- **HIGH**: 8  
- **MEDIUM**: 0  
- **LOW**: 1  
- **CRITICAL**: 0

### Типичные проблемы и их влияние

1. **Хранение секретов в открытом виде и захардкоженные креды**  
   - Любой, кто видит репозиторий или логи, получает доступ к конфиденциальным данным.  
   - Нарушение требований к защите данных (GDPR, PCI и др.).  
   - Потенциально ведёт к полному захвату окружения.

2. **Неправильные права и владение файлами**  
   - Упрощает попытки эскалации привилегий или подмены конфигов.  
   - Ослабляет общий уровень харднинга системы.

3. **Отключённая проверка SSL/TLS сертификатов**  
   - Создаёт возможность man‑in‑the‑middle атак.  
   - Данные по пути могут быть перехвачены или изменены.  
   - Часто противоречит корпоративным и отраслевым политикам безопасности.

### Что именно проверяет KICS в Ansible

1. **Управление секретами**  
   - Ищет пароли и токены в явном виде, нешифрованные переменные и т.п.

2. **Жёсткость конфигураций**  
   - Контролирует права на файлы, наличие `become`, корректность владельцев/групп.

3. **Сетевые настройки и шифрование**  
   - Проверяет, используется ли TLS, нет ли заведомо небезопасных эндпоинтов.

4. **Безопасность выполнения команд**  
   - Подсвечивает небезопасное использование `shell/command`, отсутствие валидации и возможные инъекции.

### Стратегии устранения проблем

**1. Работа с секретами**

```yaml
# SECURE APPROACH
- name: Configure database
  ansible.builtin.lineinfile:
    path: /etc/db.conf
    line: "password = {{ db_password }}"
```

### Рекомендации

- Использовать **Ansible Vault** или внешние хранилища (AWS Secrets Manager, HashiCorp Vault).  
- Регулярно ротировать чувствительные данные.  
- Не хранить секреты прямо в плейбуках или инвентори.

---

### 2. Ужесточение прав на файлы

```yaml
# RESTRICTED PERMISSIONS
- name: Deploy secure config
  ansible.builtin.copy:
    src: app.conf
    dest: /etc/app/app.conf
    owner: root
    group: appuser
    mode: 0640
```

### 3. Обеспечение защищённого сетевого взаимодействия

```
# SECURE API REQUEST
- name: Register via API securely
  ansible.builtin.uri:
    url: https://api.service.com/register
    validate_certs: yes
    headers:
      Authorization: "Bearer {{ api_token }}"
```
### 4. Непрерывное улучшение

- Включить прогон **KICS** в CI/CD как обязательный шаг.  
- Добавить простые security‑чеки в pre‑commit‑хуки.  
- Проводить регулярные внутренние обзоры/аудиты Ansible‑ролей.

---

## Task 3 — Comparative Analysis & Security Insights

### Tool Effectiveness Matrix

| Criterion               | tfsec                               | Checkov                                | Terrascan                               | KICS                                        |
|--------------------------|-------------------------------------|----------------------------------------|-----------------------------------------|---------------------------------------------|
| **Total Findings**       | 53                                  | 78                                     | 22                                      | 15 (6 Pulumi + 9 Ansible)                   |
| **Scan Speed**           | Fast                                | Moderate                               | Moderate                                | Fast                                        |
| **False Positives**      | Low                                 | Medium                                 | Low                                     | Medium                                      |
| **Report Quality**       | ⭐⭐⭐⭐                                | ⭐⭐⭐⭐⭐                                   | ⭐⭐⭐⭐                                    | ⭐⭐⭐                                         |
| **Ease of Use**          | ⭐⭐⭐⭐⭐                               | ⭐⭐⭐⭐                                    | ⭐⭐⭐                                      | ⭐⭐⭐⭐                                        |
| **Documentation**        | ⭐⭐⭐⭐                                | ⭐⭐⭐⭐⭐                                   | ⭐⭐⭐                                      | ⭐⭐⭐⭐                                        |
| **Platform Support**     | Terraform only                      | Multi-framework                        | Multi-framework                         | Multi-framework                             |
| **Output Formats**       | JSON, Text, SARIF, CSV              | JSON, JUnit, SARIF                     | JSON, YAML, JUnit                       | JSON, SARIF, HTML                           |
| **CI/CD Integration**    | Easy                                | Easy                                   | Medium                                  | Easy                                        |
| **Unique Strengths**     | Fast, Terraform-native              | Most comprehensive coverage            | Compliance / OPA integration            | Unified tool for multiple IaC types         |

---

### Vulnerability Category Analysis

| Security Category           | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool          |
|------------------------------|------:|--------:|----------:|--------------:|---------------:|:-------------------|
| **Encryption Issues**        | 8     | 12      | 5         | 1             | 0              | **Checkov**        |
| **Network Security**         | 11    | 18      | 6         | 2             | 1              | **Checkov**        |
| **Secrets Management**       | 7     | 14      | 4         | 0             | 8              | **KICS (Ansible)** |
| **IAM/Permissions**          | 9     | 15      | 3         | 1             | 0              | **Checkov**        |
| **Access Control**           | 6     | 10      | 2         | 1             | 0              | **Checkov**        |
| **Compliance/Best Practices**| 12    | 9       | 2         | 1             | 0              | **tfsec**          |

---

### Top 5 Critical Findings

1. **S3‑бакеты без шифрования**  
   - **Риск**: Потеря конфиденциальности данных и возможные проблемы с соответствием регуляциям.  
   - **Инструменты**: tfsec, Checkov, Terrascan.

2. **Сетевые группы с доступом 0.0.0.0/0**  
   - **Риск**: Максимально открытый доступ из интернета ко внутренним ресурсам.  
   - **Инструменты**: Все Terraform‑сканеры.

3. **Открытые пароли в плейбуках Ansible**  
   - **Риск**: Кража учётных данных и дальнейшее боковое перемещение по инфраструктуре.  
   - **Инструменты**: KICS (Ansible).

4. **IAM‑политики с вайлдкард‑правами**  
   - **Риск**: Лёгкая эскалация привилегий и выполнение неожиданных действий в аккаунте.  
   - **Инструменты**: tfsec, Checkov.

5. **Отсутствие TLS на входящем трафике**  
   - **Риск**: Передача данных в открытом виде и возможность MITM‑атак.  
   - **Инструменты**: KICS (Pulumi), Checkov.

---

### Tool Selection Recommendations

| Scenario                                  | Primary  | Secondary | Rationale                                                                 |
|------------------------------------------|---------:|----------:|----------------------------------------------------------------------------|
| **Terraform-Only Projects**              | tfsec    | Checkov   | tfsec for fast developer feedback; Checkov for deeper auditing             |
| **Multi-Cloud Infrastructure**           | Checkov  | Terrascan | Checkov handles multi-framework code; Terrascan adds compliance mapping    |
| **Enterprise Policy Control**            | Terrascan| Checkov   | Combines OPA policies with broader coverage                                |
| **Mixed IaC Stacks (Terraform/Pulumi/Ansible)** | KICS | Checkov | Unified scanning; supplement with Checkov for Terraform depth              |
| **Speed-Critical CI/CD Pipelines**       | tfsec    | KICS      | Optimized for rapid scans and quick feedback loops                         |
| **Compliance and Auditing Focus**        | Checkov  | tfsec     | Rich reporting features and strong standards mapping                       |

---

### Lessons Learned & Key Takeaways

1. **Нужен набор инструментов, а не один**  
   Ни один сканер не закрывает все возможные классы проблем. Связка **tfsec + Checkov** хорошо покрывает Terraform, а **KICS** добавляет анализ Pulumi и Ansible.

2. **Сигнал/шум и ложные срабатывания**  
   **Terrascan** генерирует более «чистый» отчёт, тогда как **Checkov** находит больше кейсов, но среди них больше спорных/шумных. Это полезно на ранних этапах, но требует фильтрации.

3. **Компромисс между скоростью и глубиной проверки**  
   **tfsec** практически не замедляет CI, но часть политик покрывает только частично; **Checkov** работает дольше, зато даёт максимально широкий обзор.

4. **Степень зрелости стека влияет на качество сканирования**  
   Для Terraform есть давно отточенные правила, а поддержка Pulumi и Ansible только догоняет. Здесь **KICS** выступает удобным универсальным инструментом на переходный период.

5. **Автоматизация проверок критична**  
   Встраивание сканеров в конвейеры CI/CD позволяет ловить мисконфигурации до выката в прод и помогает постоянно держать инфраструктуру ближе к требованиям комплаенса.

---

### CI/CD Integration Example

```yaml
stages:
  - security-scan

tfsec-scan:
  stage: security-scan
  image: tfsec/tfsec
  script:
    - tfsec . --format sarif --out tfsec.sarif
  artifacts:
    paths: [tfsec.sarif]
  allow_failure: false

checkov-scan:
  stage: security-scan
  image: bridgecrew/checkov
  script:
    - checkov -d . --output sarif --output-file checkov.sarif
  artifacts:
    paths: [checkov.sarif]
  allow_failure: true

kics-scan:
  stage: security-scan
  image: checkmarx/kics
  script:
    - kics scan -p . --report-formats sarif --output-path kics.sarif
  artifacts:
    paths: [kics.sarif]
  allow_failure: true

```
### Recommended Pipeline Stages

- **Feature branches** → Run `tfsec` only for instant developer feedback.  
- **Pull Requests** → Run `tfsec` + `KICS` (balanced speed vs coverage).  
- **Main branch** → Execute the full tool suite as a security gate.  
- **Scheduled scans** → Use `Terrascan` + `Checkov` for compliance validation and trend tracking.

---

### Strategic Implementation Plan

1. **Immediate** — Integrate **tfsec** and **Checkov** for Terraform projects.  
2. **Short-Term** — Add **KICS** for Pulumi and Ansible modules.  
3. **Medium-Term** — Adopt **Terrascan** for policy and compliance auditing.  
4. **Long-Term** — Automate report aggregation and alerting in CI/CD pipelines.

This combined setup ensures both **speed** and **depth** in IaC security validation, aligning with modern **DevSecOps** practices.

