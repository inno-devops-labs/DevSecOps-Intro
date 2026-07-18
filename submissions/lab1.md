# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Windows 11
- Docker version: 29.5.3

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (`/api/Products`): returns 46 products, status "success"
- Application version: `{"version":"20.0.0"}`
- Container uptime: Up ~2 minutes, port 127.0.0.1:3000->3000/tcp

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes — Account menu in top-right corner
- Product listing/search present: [x] Yes — 46 products displayed on homepage
- Admin or account area discoverable: [x] Yes — Account menu visible, admin area likely accessible via /administration
- Client-side errors in DevTools console: [ ] No errors observed
- Pre-populated local storage / cookies: `loglevel: DEBUG` present in Local Storage

### Security Headers (Quick Look)

```text
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
Content-Type: text/html; charset=UTF-8
Cache-Control: public, max-age=0
```

Which of these are MISSING:
- [x] `Content-Security-Policy` — MISSING
- [x] `Strict-Transport-Security` — MISSING
- [ ] `X-Content-Type-Options: nosniff` — present
- [ ] `X-Frame-Options` — present (SAMEORIGIN)

### Top 3 Risks Observed

1. **Missing Content-Security-Policy** — The absence of CSP means the browser has no
restrictions on which scripts or resources can be loaded. This makes the app highly
vulnerable to Cross-Site Scripting (XSS) attacks where an attacker can inject malicious
scripts into pages viewed by other users. Maps to **A03:2025 – Injection**.

2. **Overly Permissive CORS (Access-Control-Allow-Origin: \*)** — The wildcard CORS header
allows any external website to make requests to the API and read the responses. Combined
with the unauthenticated product API endpoints, this exposes business data to any origin.
Maps to **A05:2025 – Security Misconfiguration**.

3. **Missing Strict-Transport-Security (HSTS)** — Without HSTS, the app does not instruct
browsers to always use HTTPS. In a real deployment this would allow downgrade attacks
where an attacker intercepts HTTP traffic. Maps to **A02:2025 – Cryptographic Failures**.

---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets/large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template

---

## GitHub Community

- Starred: course repository and `simple-container-com/api`
- Following: professor @Cre-eD, TAs @Naghme98 and @pierrepicaud, and 3+ classmates

Starring repositories serves as a public bookmark system — it helps you track interesting
projects and signals trust and popularity to the wider community, which encourages maintainers
to keep developing their work. Following developers lets you stay updated on their activity,
discover new tools through their contributions, and build professional connections that extend
beyond the classroom into the industry.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (green): https://github.com/ruslanglvv/DevSecOps-Intro/actions/runs/27401690324/job/80981014870?pr=1
- Workflow run duration: ~50s
- Curl response excerpt:
```
  HTTP status: 200
```
