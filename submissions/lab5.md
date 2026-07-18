# Lab 5 — Submission

## Environment and tool versions

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
Git: git version 2.54.0
jq: jq-1.8.1-dirty
Juice Shop: bkimminich/juice-shop:v20.0.0
ZAP image: ghcr.io/zaproxy/zaproxy:stable
Semgrep: 1.164.0
```

Target runtime and source tag: `bkimminich/juice-shop:v20.0.0` / `v20.0.0`

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: **46 sec**
- Total alert instances: **42**
- Distinct alert titles: **10**

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 10 |
| Low | 21 |
| Informational | 11 |
| **Total** | **42** |

### Authenticated full scan

- Duration: **10 min 36 sec**
- Total alert instances: **28**
- Distinct alert titles: **6**

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 10 |
| Low | 13 |
| Informational | 5 |
| **Total** | **28** |

### The “10–20× more” claim

- Authenticated/baseline alert-instance ratio: **0.67×**

The observed ratio was **0.67×**, so this run did not fall inside the lecture's 10–20× range. The figure is directional rather than deterministic: crawler coverage, authentication state, rule versions, and scan duration affect counts.

### Two authenticated-only findings

1. **Content Security Policy (CSP) Header Not Set** — Medium  
   URI: `http://juice-shop:3000`  
   Why baseline missed it: The authenticated crawler reached this stateful route through the logged-in application surface, while the anonymous baseline did not discover it.
2. **Content Security Policy (CSP) Header Not Set** — Medium  
   URI: `http://juice-shop:3000/api`  
   Why baseline missed it: The authenticated crawler reached this stateful route through the logged-in application surface, while the anonymous baseline did not discover it.

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 20 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **30** |

### Top 10 rules by frequency

| Rule ID | Count | OWASP category | Severity |
|---------|------:|----------------|----------|
| `labs.lab5.rules.lab5.juice-shop.raw-sequelize-query-from-request` | 8 | A03 | ERROR |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A01 | ERROR |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A01 | ERROR |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 | ERROR |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A06 | WARNING |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A04 | WARNING |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 | WARNING |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07 | WARNING |

### Triage shortcut

I would address `labs.lab5.rules.lab5.juice-shop.raw-sequelize-query-from-request` first. It produced **8** findings at representative severity **ERROR**. Fixing the shared unsafe helper or pattern can close several findings at once.

### False-positive sample

`labs/lab5/semgrep/juice-shop/server.ts:281` — `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing`. This is only a suppression candidate; the data flow must be manually reviewed before adding a narrow finding-level ignore.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| — | — | No defensible cross-tool match in this run | — | — | — | Not claimed; rerun a longer targeted scan |

### Strongest correlation deep-dive

No strongest correlation is claimed because the reports did not contain a defensible SAST/DAST overlap. Extend the targeted ZAP scan against `/rest/products/search` and rerun.

### Reflection

In a real pull-request review, I would want the **SAST finding first** because it points
to the responsible file, line, and unsafe data flow. I would then attach the **DAST evidence**
as proof that the vulnerable path is reachable in the deployed application. Together they
provide implementation cause plus runtime exploitability.

## Final verification checklist

- [x] Baseline ZAP report parsed from actual JSON.
- [x] Authenticated ZAP used a real JWT through an Automation Framework replacer.
- [x] Authenticated active-scan report parsed from actual JSON.
- [x] Juice Shop source was pinned to `v20.0.0`.
- [x] Semgrep used OWASP Top 10, JavaScript, secrets, and a local correlation rule.
- [x] Correlation is claimed only when both reports contain compatible evidence.
- [x] Scanner output and source clone remain uncommitted.
