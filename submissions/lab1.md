# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `EndeavourOS`
- Docker version: `Docker version 29.5.2, build 79eb04c7d8`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: `no`

### Health Check

- HTTP code on `/`: `200`
- API check (first 200 chars of `/api/Products`):

  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T07:02:37.178Z"

  ```

- Container uptime:

  ```
  CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
  08ea6d552e23 bkimminich/juice-shop:v20.0.0 "/nodejs/bin/node /j…" 22 minutes ago Up 22 minutes 127.0.0.1:3000->3000/tcp juice-shop
  ```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No
- Product listing/search present: [x] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [ ] Yes [x] No — I wasn't able to discover admin or account-specific data or actions.
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: <...>
- Pre-populated local storage / cookies: `guestbasket: [], itemTotal: 0, language cookie: en, welcomeback cookie: dismissed, cookieconsent_status: dismissed`

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:

```

% Total % Received % Xferd Average Speed Time Time Time Current
Dload Upload Total Spent Left Speed

0 0 0 0 0 0 0 0 0
0 9903 0 0 0 0 0 0 0
0 9903 0 0 0 0 0 0 0
0 9903 0 0 0 0 0 0 0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: \*
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 07:02:38 GMT
ETag: W/"26af-19ebaa3cf79"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 07:37:43 GMT
Connection: keep-alive
Keep-Alive: timeout=5

```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. **Overly Permissive CORS Policy (`Access-Control-Allow-Origin: *`)** — Any external domain can read API responses, making credential theft possible; **A02:2025 - Security Misconfiguration**.
2. **Missing Strict-Transport-Security (HSTS)** — No encrypted-connection enforcement allows protocol downgrade and session hijacking; **A02:2025 - Security Misconfiguration**.
3. **Missing Content-Security-Policy (CSP)** — Unrestricted script execution leaves the application vulnerable to XSS attacks; **A06:2025 - Insecure Design**.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets/large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists

- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)
