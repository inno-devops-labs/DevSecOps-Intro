# Lab 2 Submission

## Task 1

### Baseline risk counts

Threagile baseline-модель была запущена для `labs/lab2/threagile-model.yaml`. Всего получилось **23 риска**.

| Severity | Count |
|---|---:|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |

### Top five risks

| # | Severity | Rule ID | Asset | STRIDE | Почему это относится к STRIDE |
|---:|---|---|---|---|---|
| 1 | elevated | `unencrypted-communication` | `user-browser` | I — Information Disclosure | Прямой HTTP-доступ к приложению передает session-id/token без шифрования, поэтому их можно перехватить. |
| 2 | elevated | `unencrypted-communication` | `reverse-proxy` | I — Information Disclosure | Связь от reverse proxy до приложения тоже идет без шифрования, и внутренний трафик с токенами может быть раскрыт. |
| 3 | elevated | `missing-authentication` | `juice-shop` | S — Spoofing | Если reverse proxy не аутентифицируется перед приложением, другой компонент может притвориться доверенным proxy. |
| 4 | elevated | `cross-site-scripting` | `juice-shop` | T — Tampering | XSS позволяет внедрить и выполнить чужой скрипт в браузере пользователя, то есть изменить поведение страницы. |
| 5 | medium | `missing-build-infrastructure` | `juice-shop` | T — Tampering | Без описанного защищенного build pipeline сложнее контролировать, что в контейнер попадает именно ожидаемый код. |

### Trust boundary crossing

Важная стрелка на `data-flow-diagram.png` — **`Direct to App (no proxy)` от `User Browser` к `Juice Shop Application`**. Она пересекает границу доверия от `Internet` к `Container Network` через `Host`, то есть идет от недоверенного клиента к приложению. Для атакующего эта стрелка интересна, потому что по ней передаются данные сессии, а в baseline она использует `http`, поэтому перехват или подмена трафика становится намного проще.

## Task 2

### Secure variant risk diff

В secure-варианте я изменил модель `labs/lab2/threagile-model-secure.yaml`: перевел оба входящих канала к приложению на `https`, добавил `client-certificate` и `technical-user` для связи reverse proxy с приложением, а также включил шифрование at rest для приложения и persistent storage через `data-with-symmetric-shared-key`.

| Severity | Baseline | Secure | Delta |
|---|---:|---:|---:|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

### Removed rule IDs

| Removed rule ID | Что изменилось в YAML | Почему правило исчезло |
|---|---|---|
| `unencrypted-communication` | `protocol: http` был заменен на `protocol: https` для `Direct to App (no proxy)` и `To App`. | Threagile больше не видит clear text traffic на входящих связях к приложению. |
| `missing-authentication` | Для `Reverse Proxy -> Juice Shop Application` поставлено `authentication: client-certificate`. | Внутренняя связь теперь явно показывает, как proxy аутентифицируется перед приложением. |
| `unencrypted-asset` | У `Juice Shop Application` и `Persistent Storage` поставлено `encryption: data-with-symmetric-shared-key`. | Активы больше не описаны как хранящие данные без шифрования. |

### Rules that still fire

| Rule ID | Почему осталось |
|---|---|
| `cross-site-scripting` | Шифрование трафика и диска не исправляет уязвимости в обработке пользовательского ввода и выводе HTML/JavaScript. Тут нужны исправления в коде, CSP и валидация/экранирование. |
| `server-side-request-forgery` | Модель все еще содержит server-side обращения: приложение может ходить к WebHook, а reverse proxy — к приложению. Чтобы закрыть SSRF, нужны allowlist, egress filtering и безопасная обработка URL, а не только смена `protocol`. |

После hardening количество рисков упало с 23 до 18, то есть примерно на пятую часть, но не до нуля. Остались в основном риски уровня приложения и процесса разработки: XSS, SSRF, CSRF, отсутствие WAF, отсутствие vault и build infrastructure. Такие риски нельзя полностью закрыть одной правкой YAML, потому что модель только описывает архитектуру, а не исправляет код Juice Shop и не добавляет реальные защитные сервисы. Например, **XSS в Juice Shop** никакой YAML-правкой не закрыть: нужно менять код приложения, ставить Content Security Policy и проверять пользовательский ввод.

## Bonus

### Auth flow risk counts

Для bonus я сделал отдельную небольшую модель `labs/lab2/threagile-model-auth.yaml` из stub-модели. В ней есть browser, login endpoint, token service, authorization check, admin endpoint и credential store; также отдельно описан data asset `JWT Signing Key`.

Всего получилось **34 риска**.

| Severity | Count |
|---|---:|
| critical | 0 |
| high | 0 |
| elevated | 5 |
| medium | 15 |
| low | 14 |

### Auth-specific risks

| Rule ID | STRIDE | Что показала модель | Mitigation |
|---|---|---|---|
| `sql-nosql-injection` | T — Tampering | Login endpoint проверяет credentials через credential store, поэтому SQL/NoSQL injection может изменить логику проверки логина. | Использовать parameterized queries/ORM, валидацию ввода и отдельные тесты на injection в login flow. |
| `missing-authentication-second-factor` | S — Spoofing | Для входа и вызова admin endpoint есть пароль или token, но нет второго фактора. | Добавить MFA для админов и рискованных операций. |
| `unguarded-access-from-internet` | E — Elevation of Privilege | Admin endpoint достижим из browser-модели, поэтому важно, чтобы доступ реально проходил через authorization check. | Ограничить прямой доступ к admin endpoint, проверять роль на сервере и покрыть это тестами. |

Feature-level модель показала детали, которых почти не видно в общей architecture-level модели: отдельно появились JWT signing key, token service и authorization check. Из-за этого стало понятнее, где именно может сломаться login/admin flow: при проверке credentials, выпуске JWT или проверке прав администратора.
