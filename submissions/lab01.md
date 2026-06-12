# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0>
- Host OS: <macOS 14.8.3>
- Docker version: <29.2.1, build a5c7197>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No 
- Container restart policy: <default (no)>

### Health Check
- HTTP code on `/`: <200>
- Version check output: {"version":"20.0.0"}
- Container uptime:
      NAMES        STATUS         PORTS
      juice-shop   Up 10 minutes  127.0.0.1:3000->3000/tcp

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: <Account -> Login; "Not yet a customer?" = Registration>
- Product listing/search present: [x] Yes [ ] No — notes: <All Products grid + search icon>
- Admin or account area discoverable: [x] Yes [ ] No — notes: <Account menu>
- Client-side errors in DevTools console: [ ] Yes [x] No
- Pre-populated local storage / cookies: Local Storage empty; one cookie language=en with no Secure/HttpOnly/SameSite flags

### Security Headers (Quick Look)
Present:
- X-Content-Type-Options: nosniff
- X-Frame-Options: SAMEORIGIN
Missing:
- Content-Security-Policy
- Strict-Transport-Security

Top 3 Risks Observed
1. No Content-Security-Policy header. Without a CSP the browser has no allow-list for scripts, so any injected JavaScript (XSS) would just run. OWASP Top 10:2025 — A06 (Security Misconfiguration).
2. No Strict-Transport-Security (HSTS) header. The app does not force HTTPS, so the connection could be downgraded and traffic read in plain text. OWASP Top 10:2025 — A02 (Cryptographic Failures).
3. The exact app version is exposed to anyone at /rest/admin/application-version (it returned 20.0.0). Knowing the precise version makes it easy to look up matching public exploits. OWASP Top 10:2025 — A06 (Security Misconfiguration).


## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <clear title / no secrets / submission file exists>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community
"Starring" lets me bookmark interesting projects so I can find them again later, and the star count is a quick signal of how popular and active a project is. Following other developers helps me see what they are working on, and in a class team it is an easy way to keep track of classmates' work so it is simpler to team up on the next labs.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): <https://github.com/Nik-ari-ai/DevSecOps-Intro/actions/runs/27270463301>
- Workflow run duration: <~15s>
- Curl response excerpt:
      Juice Shop is up after ~4s
      HTTP/1.1 200 OK
      X-Content-Type-Options: nosniff
      X-Frame-Options: SAMEORIGIN
      Content-Type: application/json; charset=utf-8
      {"version":"20.0.0"}