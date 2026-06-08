# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Arch Linux
- Docker version: 29.5.2

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: `no` _(`--restart` flag was not used)_

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`):
  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-07T12:38:42.261Z"
  ```
- Container uptime: _"Up About an hour"_  
  Exact output:
  ```bash
  CONTAINER ID   IMAGE                           COMMAND                  CREATED        STATUS             PORTS                      NAMES
  f647ccef46a1   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   15 hours ago   Up About an hour   127.0.0.1:3000->3000/tcp   juice-shop
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: `Account` button in the top-right corner _(serves the login form on click)_. `Not yet a customer?` button serves the signup form.
- Product listing/search present: [x] Yes [ ] No — notes: when requesting `/`, the user is redirected to `/#/` where the products are listed. Clicking the search icon in the top-right corner and performing a search redirects to `/#/search?q=<query>`.
- Admin or account area discoverable: [x] Yes [ ] No — notes: account area is discoverable from the browser _(e.g. `/#/wallet` and `/#/order-history` routes)_. Admin area is not discoverable from browser.
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: when accessing `/#/wallet` being unauthorized, `401 Unauthorized` is thrown.
- Pre-populated local storage / cookies: cookie `language: en` is set on the first visit.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```HTTP
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed

  0      0   0      0   0      0      0      0                              0
  0   9903   0      0   0      0      0      0                              0
  0   9903   0      0   0      0      0      0                              0
  0   9903   0      0   0      0      0      0                              0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sat, 06 Jun 2026 20:26:37 GMT
ETag: W/"26af-19e9e9dbb4b"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Sat, 06 Jun 2026 20:58:03 GMT
Connection: keep-alive
Keep-Alive: timeout=5


```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **A07:2025 Identification & Authentication Failures** — to signup, a user must set a security question to regain control in case they forget the password. A security question is considered an anti-pattern since it is easily guessable and can be found in public sources.
2. **A05:2025 Security Misconfiguration** — `Content-Security-Policy` and `Strict-Transport-Security` headers are missing. Missing security headers reduce browser-side protections and may increase the impact of client-side attacks and insecure transport configurations.
3. **A01:2025 Broken Access Control** — the `/rest/basket/<ID>` endpoint does not validate if the user owns the basket `<ID>`. An attacker can access other users' baskets with `curl`: `curl -iX GET http://127.0.0.1:3000/rest/basket/<ID> -H "Authorization: Bearer <attackers JWT>`.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (feat(labN): <topic> style)
  - No secrets/large temp files committed
  - Submission file at submissions/labN.md exists
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

Starring repositories helps highlight useful open-source projects, increases their visibility, and signals community interest to maintainers and contributors.

Following developers helps stay informed about project activity, learn from experienced engineers, and improve collaboration within team and open-source projects.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/semyonnadutkin/DevSecOps-Intro/actions/runs/27148720620/job/80133614135
- Workflow run duration: 15s
- Curl response excerpt:
  ```
  HTTP/1.1 200 OK
  ```
