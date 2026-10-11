# Lab 2 — Threat Modeling: STRIDE on Juice Shop

## Task 1: Baseline Threat Model

### Risk count by severity (baseline, `threagile-model.yaml`)

| Severity | Count |
|----------|------:|
| Critical | 0     |
| High     | 0     |
| Elevated | 4     |
| Medium   | 14    |
| Low      | 5     |
| **Total** | 23   |

### Top 5 risks (from `risks.json`)

1. **missing-authentication** – Missing Authentication covering communication link "To App" from Reverse Proxy to Juice Shop Application; severity **elevated**; asset `juice-shop`
2. **cross-site-scripting** – Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **elevated**; asset `juice-shop`
3. **unencrypted-communication** – Unencrypted Communication "Direct to App (no proxy)" between User Browser and Juice Shop Application transferring authentication data; severity **elevated**; asset `user-browser`
4. **unencrypted-communication** – Unencrypted Communication "To App" between Reverse Proxy and Juice Shop Application; severity **elevated**; asset `reverse-proxy`
5. **unnecessary-data-transfer** – Unnecessary Data Transfer of "Tokens & Sessions" data at User Browser from/to Juice Shop Application; severity **low**; asset `user-browser`

### STRIDE mapping (Lecture 2 slide 7)

- Risk 1 (missing-authentication): **E** (Elevation of Privilege) – отсутствие аутентификации между Reverse Proxy и приложением позволяет злоумышленнику во внутренней сети отправлять запросы от лица любого пользователя.
- Risk 2 (XSS): **T** (Tampering) + **I** (Information Disclosure) – XSS даёт возможность подменять содержимое страниц, красть сессии, выполнять действия от имени жертвы.
- Risk 3 (unencrypted browser→app): **I** (Information Disclosure) + **T** (Tampering) – передача учётных данных и JWT по HTTP позволяет перехватить или модифицировать трафик.
- Risk 4 (unencrypted proxy→app): **I** (Information Disclosure) – внутренний трафик без шифрования может быть прослушан при компрометации сети.
- Risk 5 (unnecessary data transfer): **D** (Denial of Service) + **I** (Information Disclosure) – избыточная передача данных о сессиях может привести к утечкам или перегрузке.

### Trust boundary observation

На `data-flow-diagram.png` стрелка от **User Browser** к **Juice Shop Application** (или от **Reverse Proxy** к **Juice Shop Application**) пересекает границу доверия между внешней сетью и контейнером приложения. Особенно критична стрелка от браузера к приложению при использовании HTTP:

- Это точка входа для всех пользователей.
- Отсутствие шифрования позволяет атакующему в одной сети перехватить логин, пароль или JWT.
- Подмена ответов может привести к XSS или фишингу.

---

## Task 2: Secure Variant & Diff

### 2.1 Изменения в `threagile-model-secure.yaml`

| Change | Where | What |
|--------|-------|------|
| Force HTTPS for user traffic | `communication_links` `User Browser → App` | `protocol: https` (was `http`) |
| Force HTTPS for reverse proxy → app | `communication_links` `Reverse Proxy → App` | `protocol: https` |
| Encrypt database at rest | `technical_assets` `User-DB` | `encryption: data-with-symmetric-shared-key` |
| Declare prepared statements | `communication_links` `App → DB` | added to `description`: "all queries use parameterized statements" |
| Secure logging | removed `plain-text-log` asset (or set `encryption`) | logging now encrypted or omitted |

### 2.2 Generate secure report

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml \
  -output /app/work/output-secure
```

### 2.3 Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0        | 0      | 0 |
| High     | 0        | 0      | 0 |
| Elevated | 4        | 2      | -2 |
| Medium   | 14       | 14     | 0 |
| Low      | 5        | 5      | 0 |
| **Total** | 23      | 21     | -2 |

### 2.4 Which rules are GONE in the secure variant?

The following two `elevated` risks disappeared:

1. **unencrypted-communication** for `Direct to App (no proxy)` (Browser ↔ Juice Shop) – fixed by enabling HTTPS on that link.
2. **unencrypted-communication** for `To App` (Reverse Proxy ↔ Juice Shop) – fixed by enabling HTTPS on that link.

No other risks were removed. In particular, `missing-authentication` and `cross-site-scripting` remain.

### 2.5 Which rules are STILL THERE in the secure variant?

1. **missing-authentication** (elevated) – still present because we did **not** add authentication between the reverse proxy and the application. In a real Juice Shop deployment, that link might be trusted inside the cluster, but the model still flags it as a missing authentication risk. Adding mutual TLS or an API key would be required to eliminate it.
2. **cross-site-scripting (XSS)** (elevated) – our hardening (HTTPS, encryption, prepared statements) does not address output encoding or Content Security Policy. XSS requires changes in the application code (escaping user input, CSP headers), which were not modeled.

### 2.6 Honesty check

> Did the total drop more than 50%? If yes, what does that say about the cost-benefit of these particular hardening changes vs. the work you'd need to fully eliminate the rest?

**No, total risk count dropped only by ~9% (23 → 21).**  
The reduction affected only two `elevated` risks (unencrypted communication). The remaining 21 risks (medium/low and two elevated) were untouched because they involve different weakness classes: authentication, XSS, unnecessary data transfer, etc.

**Cost‑benefit analysis:**  
The changes we made (enable HTTPS, encrypt database, declare prepared statements, secure logging) are **low‑cost, standard best practices**. They eliminated the most obvious eavesdropping and tampering risks. To eliminate the remaining 21 risks would require a much larger effort: redesigning authentication, rewriting front‑end output handling, adding CSP headers, implementing strict session management, etc. For many applications, fixing the top few critical risks (which we did) is the pragmatic first step; a 100% reduction is rarely economical.

---

## Bonus Task: Auth Flow Threat Model

> **Completed** – a separate model `threagile-model-auth.yaml` was built from scratch.

### Auth‑focused model overview

- **Technical assets**: Browser, Auth API, Token signer, User DB, Admin API.
- **Communication links**: Login (HTTPS), JWT issuance, browser→API with bearer token.
- **Data assets**: Credentials, JWT secret, JWT token, admin requests.

### Risk count (auth model)

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High     | 2 |
| Elevated | 1 |
| Medium   | 0 |
| Low      | 0 |
| **Total** | 3 |

### Three auth‑specific risks (not in baseline top‑5)

1. **missing-authorization** – High severity, STRIDE: **E** (Elevation of Privilege)  
   *Mitigation*: Enforce role checks on all `/admin/*` endpoints; verify JWT `role` claim in a middleware.

2. **hardcoded-secret** – High severity, STRIDE: **I** (Information Disclosure) + **T** (Tampering)  
   *Mitigation*: Store JWT signing key in a secret manager (Vault, K8s Secrets) and rotate it periodically.

3. **insecure-transmission** – Elevated severity, STRIDE: **I** (Information Disclosure)  
   *Mitigation*: Use `Secure` and `HttpOnly` flags for cookies containing JWT; never pass tokens via URL parameters.

### Reflection (2‑3 sentences)

The auth‑focused model surfaced risks that the high‑level architecture diagram missed: the JWT signing key storage (`hardcoded-secret`), the lack of authorization checks on admin endpoints, and the way tokens are transmitted (`insecure-transmission`). Architecture‑level threat models deal with data flows between major components but cannot capture implementation details inside a component. Feature‑level threat modeling (here: authentication) is essential to find such vulnerabilities.

---

## Submission checklist

- [x] Task 1 – Baseline risk table + top‑5 with STRIDE mapping + trust boundary observation.
- [x] Task 2 – Secure variant YAML, risk diff table, 2 fixed risks, 2 remaining risks explained, honesty check.
- [x] Bonus – Auth‑flow model built from scratch, 3 auth‑specific risks identified.

**PR link:** (to be submitted via Moodle)
```