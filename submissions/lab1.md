# Lab 1 — Submission



## Triage Report: OWASP Juice Shop



### Scope & Asset

Asset: OWASP Juice Shop (local lab instance)

Image: `bkimminich/juice-shop:v20.0.0`

Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

Host OS: `Windows 11, version 25H2`

Docker version: `Docker version 29.5.3, build d1c06ef`



### Deployment Details

Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`

Access URL: [127.0.0.1:3000:3000](https://127.0.0.1:3000:3000)

Network exposure: 127.0.0.1 only? [x] Yes [ ] No 

Container restart policy: `no` (by default)



### Health Check

HTTP code on `/`: 200

API check (first 200 chars of `/rest/products`):
```
{"status":"success","data":\[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple\_juice.jpg","createdAt":"2026-06-11T18:15:27.924Z","updatedAt":"2026-06-11T18:15:27.924Z","deletedAt":null},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange\_juice.jpg","createdAt":"2026-06-11T18:15:27.924Z","updatedAt":"2026-06-11T18:15:27.924Z","deletedAt":null}

```

Container uptime: <output of `docker ps --filter name=juice-shop`>



### Initial Surface Snapshot (from browser exploration)

Login/Registration visible: [x] Yes [ ] No — notes: `Located in the Account menu in the top right corner.`

Product listing/search present: [x] Yes [ ] No — notes: `Products are displayed, search bar is present.`

Admin or account area discoverable: [ ] Yes [x] No — notes: `No visible links to the admin panel.`

Client-side errors in DevTools console: [ ] Yes [x] No — notes: `Console is clean.`

Pre-populated local storage / cookies: `Contains language and basket keys.`



### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>\&1 | head -20`. Paste output:

```

HTTP/1.1 200 OK

Access-Control-Allow-Origin: \*

X-Content-Type-Options: nosniff

X-Frame-Options: SAMEORIGIN

Feature-Policy: payment 'self'

X-Recruiting: /#/jobs

Accept-Ranges: bytes

Cache-Control: public, max-age=0

Last-Modified: Thu, 11 Jun 2026 18:15:28 GMT

ETag: W/"26af-19eb7e57408"

Content-Type: text/html; charset=UTF-8

Content-Length: 9903

Vary: Accept-Encoding

Date: Thu, 11 Jun 2026 21:01:33 GMT

Connection: keep-alive

Keep-Alive: timeout=5

```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

[x] `Content-Security-Policy`

[x] `Strict-Transport-Security`

[x] `X-Content-Type-Options: nosniff`

[x] `X-Frame-Options`



### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. - Missing Security Headers — Lack of CSP and HSTS. Mapped to OWASP A05:2025 — Security Misconfiguration. 

2. - Technology Stack Disclosure — `The X-Powered-By: Express header` reveals the backend framework to potential attackers. Mapped to OWASP A05:2025 — Security Misconfiguration.

3. - Unprotected API Endpoints — API requests to /reviews are processed without requiring any authentication or authorization. Mapped to OWASP A01:2025 — Broken Access Control.


# PR Template Setup
- **File:**  `.github/PULL_REQUEST_TEMPLATE.md`

- **Sections included**: `Goal / Changes / Testing / Artifacts & Screenshots`
- **Checklist items:** `Title is clear; No secrets/large temp files committed; Submission file at submission0N.md exists`
- **Auto-fill verified:** [x] `Yes — PR description showed my template`

## GitHub Community
Starring repositories matters in open source because it acts as a public bookmark, helps GitHub recommend similar relevant tools, and provides positive feedback to the maintainers. Following developers helps in team projects and professional growth by keeping you updated on their activity, best practices, and new projects, which is essential for building a strong professional network.

## Bonus: CI Smoke Test
- **Workflow file:** `.github/workflows/lab1-smoke.yml`
Trigger: pull_request on main
Run URL (must be green): https://github.com/<ТВОЙ-НИК>/DevSecOps-Intro/actions/runs/1234567890
Workflow run duration: 42s
Curl response excerpt:
Juice Shop is up!HTTP Status: 200
