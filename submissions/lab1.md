# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `Ubuntu 24.04`
- Docker version: `Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: `no` (default policy, since no `--restart` flag was specified in the run command)

### Health Check
- HTTP code on `/`: `200 OK`
- API check (first 200 chars of `/api/Products`):
  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T14:43:23.024Z"
  ```
- Container uptime: `Up 2 hours`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Accessible via the "Account" dropdown menu in the top right corner.
- Product listing/search present: [x] Yes [ ] No — notes: The main dashboard displays a grid of available products with a functional search bar at the top.
- Admin or account area discoverable: [x] Yes [ ] No — notes: While a standard account profile updates post-authentication, a dedicated administrative interface was discovered by directly navigating to the `/#/administration` path.
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: DevTools console catches a `401 Unauthorized` block on the `/api/Addresss` endpoint due to unauthenticated guest access, an Angular runtime error regarding a missing mandatory `"key"` parameter, and minor font asset loading failures (`FontMfizz`).
  <details>
  <summary>Click to view full console log snapshot</summary>

  ```text
  XHRGET [http://127.0.0.1:3000/api/Addresss](http://127.0.0.1:3000/api/Addresss) [HTTP/1.1 401 Unauthorized 1ms]
  ERROR Error: Parameter "key" is required and cannot be empty
      get [http://127.0.0.1:3000/chunk-GJJPXCX3.js:5](http://127.0.0.1:3000/chunk-GJJPXCX3.js:5)
      open [http://127.0.0.1:3000/chunk-524KQQJQ.js:264](http://127.0.0.1:3000/chunk-524KQQJQ.js:264)
      load [http://127.0.0.1:3000/chunk-JCQ5N7PA.js:422](http://127.0.0.1:3000/chunk-JCQ5N7PA.js:422)
      ngOnInit [http://127.0.0.1:3000/chunk-JCQ5N7PA.js:422](http://127.0.0.1:3000/chunk-JCQ5N7PA.js:422)
  downloadable font: no supported format found (font-family: "FontMfizz")
- Pre-populated local storage / cookies: Local Storage is completely empty upon initial unauthenticated navigation (`No data present for selected host`). However, Session Storage actively tracks the unauthenticated guest state, populating keys such as `guestBasket` (holding raw JSON object arrays of product IDs and quantities, e.g., ProductId 24, 52, 6) and `itemTotal` (tracking the current cart value, e.g., 5.87). Cookies contain framework-specific tokens for socket communication.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 14:43:28 GMT
ETag: W/"26af-19ebc49ba4f"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 17:22:15 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Absence of Content-Security-Policy (CSP)** — The application's HTTP headers completely lack a `Content-Security-Policy`. Testing the search bar with a basic iframe payload triggers an alert box, proving that the application executes arbitrary client-side scripts. This aligns directly with **A03:2025-Injection** (specifically Cross-Site Scripting).
2. **Exposed Internal Directory Listing (/ftp)** — Navigating directly to the `/ftp` path reveals an open directory containing sensitive application files, backup databases, and internal logs. This exposure allows unauthenticated users to download files that should be strictly internal, mapping directly to **A06:2025-Security Misconfiguration**.
3. **Information Disclosure via Application Headers and Endpoints** — The server leaks technology stack details through the `X-Powered-By: Express` header, and explicitly exposes the exact software version via the `/rest/admin/application-version` endpoint. This precise blueprint helps attackers research and map target-specific CVEs, falling under **A06:2025-Security Misconfiguration**.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (Link to my PR will be active upon opening the PR)

## GitHub Community

Starring open-source repositories is essential because it acts as a baseline metric for community trust and discovery, helping maintainers gain project visibility while signaling potential utility to other security practitioners. Following professors, teaching assistants, and classmates establishes an immediate professional network that aids in peer review tracking, technical collaboration, and long-term career growth within the cybersecurity and DevOps community.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/SamiKO228/DevSecOps-Intro/actions/runs/27437810782
- Workflow run duration: 18S
- Curl response excerpt:
  ```
   Homepage returned HTTP 200
  ```
