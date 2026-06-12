# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe>
- Host OS: <Ubuntu 24.04 LTS>
- Docker version: <Docker version 29.4.0, build 9d7ad9f>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: <no>

### Health Check
- HTTP code on `/`: <200>
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T22:16:44.422Z"
  ```
- Container uptime: <7 minutes>

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: <...>
- Product listing/search present: [x] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [x] Yes [] No — notes: <...>
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: <I have not seen any client-side errors in DevTools console, even after performing some actions>
- Pre-populated local storage / cookies: <storage: key "loglevel" with value "DEBUG", cookies: language, continueCode...>

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 22:16:45 GMT
ETag: W/"26af-19eb8c25c6f"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 13:44:06 GMT
Connection: keep-alive
Keep-Alive: timeout=5

```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **<Unauthenticated /metrics and /ftp/ endpoints>** — <Internal DevOps data and backup files are exposed without access control. → A01: Broken Access Control>
2. **<Wildcard CORS & Missing Security Headers>** — <The server sends Access-Control-Allow-Origin: * and lacks Content-Security-Policy and HSTS, allowing any domain to make cross-origin requests and enabling XSS/SSL-stripping. → A06: Security Misconfiguration>
3. **<Missing CSP + HSTS headers>** — <No content security policy or HTTPS enforcement, enabling XSS and SSL-stripping attacks. → **A06: Security Misconfiguration**>


## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: 
  - [x] Title is clear (`feat(labN): <topic>` style)
  - [x] No secrets/large temp files committed
  - [x] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (screenshot or link to draft PR):
<img width="1611" height="779" alt="image" src="https://github.com/user-attachments/assets/dfe1b0c2-f222-4c17-babe-435ff52acc08" />

## GitHub Community

- Starred repositories: course repo, simple-container-com/api
- Followed: @Cre-eD, @Naghme98, @pierrepicaud, @MikeNovikoff, @jestersw, @ZeNik77

**Why starring repositories matters in open source:**
Stars help developers bookmark interesting projects for later reference and serve as a social signal of project quality and community trust. Star count indicates popularity and helps maintainers gauge interest in their work.

**How following developers helps in team projects and professional growth:**
Following developers allows you to discover new projects through their activity, stay updated on classmates' work for future collaboration, and build professional connections beyond the classroom. It creates a network effect where you can learn from others' contributions and coding patterns.