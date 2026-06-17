# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Ubuntu 26.04
- Docker version: Docker version 29.5.3, build d1c06ef

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes
- Container restart policy: no

### Health Check
- HTTP code on `/`: HTTP 200
- API check (first 200 chars of `/api/Products`):
  ```
  {
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "Apple Juice (1000ml)",
      "description": "The all-time classic.",
      "price": 1.99,
      "deluxePrice": 0.99,
      "image": "apple_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 2,
      "name": "Orange Juice (1000ml)",
      "description": "Made from oranges hand-picked by Uncle Dittmeyer.",
      "price": 2.99,
      "deluxePrice": 2.49,
      "image": "orange_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
    {
      "id": 3,
      "name": "Eggfruit Juice (500ml)",
      "description": "Now with even more exotic flavour.",
      "price": 8.99,
      "deluxePrice": 8.99,
      "image": "eggfruit_juice.jpg",
      "createdAt": "2026-06-17T04:56:59.932Z",
      "updatedAt": "2026-06-17T04:56:59.932Z",
      "deletedAt": null
    },
  ```
- Container uptime: 
````
CONTAINER ID   IMAGE                           COMMAND                  CREATED       STATUS       PORTS                      NAMES
fe313aa24257   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   2 hours ago   Up 2 hours   127.0.0.1:3000->3000/tcp   juice-shop
````

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes
- Product listing/search present: [x] Yes
- Admin or account area discoverable: [x] Yes — notes: Account menu visible in the top-right; admin pages are reachable when an admin token is used.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No persistent JavaScript console errors during normal browsing. Submitting crafted inputs to the login endpoint produced a server-side 500 error (see images/image.png), indicating server-side error handling issues rather than client-side JS errors.
- Pre-populated local storage / cookies: none observed for unauthenticated sessions (checked Application -> Local Storage / Cookies)

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
% Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0   9903   0      0   0      0      0      0                              0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 16 Jun 2026 15:22:44 GMT
ETag: W/"26af-19ed1071c3f"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 16 Jun 2026 17:25:56 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **A01 — Broken Access Control** — The `/api/Products` endpoint returns product data without authentication, and an admin token allowed access to `/api/Users` which returned user data. These behaviors indicate missing or inadequate authorization checks and map to OWASP Top 10:2025 A01.
2. **A04 — Injection** — The login form accepts input that appears to be interpreted by the server (tested using payloads like `' OR 1=1 --`), which produced a 500 and in some probes allowed bypassing normal auth logic. This is consistent with SQL injection and maps to A04 (Injection).
3. **A10 — Mishandling of Exceptional Conditions** — Supplying malformed or unexpected input to the login endpoint triggers a 500 internal server error and verbose responses that reveal application behavior. The application fails-open or leaks implementation details on error paths, which corresponds to A10 in the OWASP Top 10:2025.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (feat(labN): <topic> style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

Starring repositories helps signal useful projects, supports maintainers, and keeps a personal shortlist of tools relevant to course work. Following instructors, TAs, and classmates improves visibility into practical workflows and makes collaboration faster in team assignments.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): <add your GitHub Actions run URL after first successful PR run>
- Workflow run duration: <add duration from Actions UI, e.g. 45s>
- Curl response excerpt:
  ```
  HTTP/1.1 200 OK
  ```