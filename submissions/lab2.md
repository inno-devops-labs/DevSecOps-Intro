# Lab 2 — Submission

Generated: 2026-06-12T15:28:44

## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | **23** |

### Top 5 risks
1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **Elevated**; affecting **juice-shop**.
2. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity **Elevated**; affecting **juice-shop**.
3. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.); severity **Elevated**; affecting **user-browser**.
4. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity **Elevated**; affecting **reverse-proxy**.
5. **container-baseimage-backdooring** — Container Base Image Backdooring risk at Juice Shop Application; severity **Medium**; affecting **juice-shop**.

### Top 5 risks JSON excerpt
```json
[
  {
    "severity": "elevated",
    "category": "cross-site-scripting",
    "title": "Cross-Site Scripting (XSS) risk at Juice Shop Application",
    "technical_asset": "juice-shop"
  },
  {
    "severity": "elevated",
    "category": "missing-authentication",
    "title": "Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application",
    "technical_asset": "juice-shop"
  },
  {
    "severity": "elevated",
    "category": "unencrypted-communication",
    "title": "Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.)",
    "technical_asset": "user-browser"
  },
  {
    "severity": "elevated",
    "category": "unencrypted-communication",
    "title": "Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application",
    "technical_asset": "reverse-proxy"
  },
  {
    "severity": "medium",
    "category": "container-baseimage-backdooring",
    "title": "Container Base Image Backdooring risk at Juice Shop Application",
    "technical_asset": "juice-shop"
  }
]
```

### STRIDE mapping
- Risk 1 (**cross-site-scripting**): **T/E** — the risk can let attacker-controlled input modify application behavior or data integrity, sometimes leading to privilege escalation.
- Risk 2 (**missing-authentication**): **S/E** — the risk can let an attacker impersonate a user or gain privileges through weak identity/session controls.
- Risk 3 (**unencrypted-communication**): **S/E** — the risk can let an attacker impersonate a user or gain privileges through weak identity/session controls.
- Risk 4 (**unencrypted-communication**): **I** — the risk primarily exposes sensitive data across storage or communication paths.
- Risk 5 (**container-baseimage-backdooring**): **T/I** — the risk affects integrity and/or confidentiality based on how the modeled asset is used.

### Trust boundary observation
The most important trust-boundary-crossing flow is the **Browser/User → Juice Shop application/API** path from the public Internet into the application/container boundary. This arrow is attractive to an attacker because it carries user-controlled input, credentials/session material, and unauthenticated or semi-authenticated requests before the backend has fully established trust.

---

## Task 2: Secure Variant & Diff

### Secure variant changes made
- Created `labs/lab2/threagile-model-secure.yaml` from the baseline model.
- Changed plain `http` communication links to `https` where present.
- Marked detected database/log storage assets as encrypted at rest with `data-with-symmetric-shared-key` where applicable.
- Changed common DB wire protocols to encrypted protocol variants where present.
- Added prepared-statement / parameterized-query wording to DB-like communication descriptions.

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | +0 |
| High | 0 | 0 | +0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 5 | +0 |
| **Total** | **23** | **19** | **-4** |

### Which rules are GONE in the secure variant?
Only 2 distinct rule IDs disappeared in this run; this is the actual Threagile output, not a placeholder.

1. `unencrypted-asset` — fixed or reduced by the secure variant changes: HTTPS for communication links, encrypted-at-rest storage, encrypted DB protocols, and prepared-statement documentation.
2. `unencrypted-communication` — fixed or reduced by the secure variant changes: HTTPS for communication links, encrypted-at-rest storage, encrypted DB protocols, and prepared-statement documentation.

### Which rules are STILL THERE in the secure variant?
Several baseline rules remain after hardening.

1. `container-baseimage-backdooring` — still fires on **juice-shop**. The secure variant improves transport/storage/query handling, but this rule likely depends on a separate design control such as stronger auth, authorization, rate limiting, monitoring, segmentation, or operational process.
2. `cross-site-request-forgery` — still fires on **juice-shop**. The secure variant improves transport/storage/query handling, but this rule likely depends on a separate design control such as stronger auth, authorization, rate limiting, monitoring, segmentation, or operational process.

### Honesty check
No. The total did not drop by more than 50%, which shows that HTTPS/encryption/prepared-statement declarations are useful but not enough to eliminate broader architectural, authentication, authorization, logging, and availability risks.

---

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 11 |
| Medium | 23 |
| Low | 6 |
| **Total** | **41** |

### Three auth-specific risks \(NOT in the baseline model's top 5\)
1. **sql-nosql-injection** — STRIDE: **S/E** — Mitigation: enforce server-side validation for this flow, protect JWT/session material, and add targeted controls such as rate limiting, strong signing-key management, and role checks. the risk can let an attacker impersonate a user or gain privileges through weak identity/session controls.
2. **missing-hardening** — STRIDE: **T/I** — Mitigation: enforce server-side validation for this flow, protect JWT/session material, and add targeted controls such as rate limiting, strong signing-key management, and role checks. the risk affects integrity and/or confidentiality based on how the modeled asset is used.
3. **missing-hardening** — STRIDE: **S/E** — Mitigation: enforce server-side validation for this flow, protect JWT/session material, and add targeted controls such as rate limiting, strong signing-key management, and role checks. the risk can let an attacker impersonate a user or gain privileges through weak identity/session controls.

### Reflection
The focused auth-flow model surfaces risks around login, JWT issuance, JWT verification, session state, and admin-only authorization paths. This is different from the baseline architecture model because feature-level threat models can expose identity and authorization problems that are easy to lose in a larger system-wide diagram.

---

## Commands used

```bash
docker pull threagile/threagile:0.9.1

docker run --rm   -v "$(pwd)/labs/lab2":/app/work   threagile/threagile:0.9.1   -model /app/work/threagile-model.yaml   -output /app/work/output

docker run --rm   -v "$(pwd)/labs/lab2":/app/work   threagile/threagile:0.9.1   -model /app/work/threagile-model-secure.yaml   -output /app/work/output-secure

docker run --rm   -v "$(pwd)/labs/lab2":/app/work   threagile/threagile:0.9.1   -model /app/work/threagile-model-auth.yaml   -output /app/work/output-auth
```

## Files included in PR

- `submissions/lab2.md`
- `labs/lab2/threagile-model-secure.yaml`
- `labs/lab2/threagile-model-auth.yaml`

Generated output directories are intentionally not committed.
