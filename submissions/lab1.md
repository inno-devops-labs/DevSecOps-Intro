# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

* Asset: OWASP Juice Shop (local lab instance)
* Image: `bkimminich/juice-shop:v20.0.0`
* Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
* Host OS: Arch Linux (rolling), Linux kernel `7.0.12-arch1-1`
* Docker version: `Docker version 29.6.0, build fb59821d45`

### Deployment Details

* Run command used:

  ```bash
  docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
  ```
* Access URL: http://127.0.0.1:3000
* Network exposure: **[x] Yes** (bound only to `127.0.0.1`)
* Container restart policy: `no`

### Health Check

* HTTP code on `/`: `200`

* API check (first 200 chars of `/api/Products`):

  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-25T05:37:33.777Z"
  ```

* Container uptime:

  ```text
  CONTAINER ID   IMAGE                           COMMAND                  CREATED      STATUS          PORTS                      NAMES
  cbfabcc3b4f8   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   7 days ago   Up 27 seconds   127.0.0.1:3000->3000/tcp   juice-shop
  ```

### Initial Surface Snapshot (from browser exploration)

* Login/Registration visible: **[x] Yes** — The Account menu provides login and registration functionality.
* Product listing/search present: **[x] Yes** — The application displays a searchable product catalog with shopping basket functionality.
* Admin or account area discoverable: **[x] Yes** — An Account area is visible. During client-side JavaScript inspection, the hidden **Score Board** page was discovered through the route `/score-board`.
* Client-side errors in DevTools console: **[ ] Yes [x] No** — No client-side errors were observed during the initial exploration.
* Pre-populated local storage / cookies:

  * Local Storage: empty (`[]`)
  * Cookies:

    * `cookieconsent_status=dismiss`
    * `language=en`
    * `welcomebanner_status=dismiss`

### Security Headers (Quick Look)

Command used:

```bash
curl -I http://127.0.0.1:3000
```

Output:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 25 Jun 2026 05:37:35 GMT
ETag: W/"26af-19efd489f10"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 25 Jun 2026 05:37:36 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are **MISSING**?

* [x] `Content-Security-Policy`
* [x] `Strict-Transport-Security`
* [ ] `X-Content-Type-Options: nosniff`
* [ ] `X-Frame-Options`

### Top 3 Risks Observed

1. **Security Through Obscurity (Hidden Route)**
   The Score Board page was not accessible through the normal user interface, but it was easily discovered by inspecting the client-side JavaScript, where the route `/score-board` was exposed. Hiding functionality on the client side is not an effective security control because anyone can inspect the delivered code.
   **OWASP Top 10:2025:** A01 – Broken Access Control.

2. **Missing Security Headers**
   The application response does not include `Content-Security-Policy` or `Strict-Transport-Security`. Missing security headers reduce browser-side protections and may increase the impact of attacks such as Cross-Site Scripting (XSS) or insecure transport.
   **OWASP Top 10:2025:** A05 – Security Misconfiguration.

3. **Permissive Cross-Origin Resource Sharing (CORS)**
   The application returns the header `Access-Control-Allow-Origin: *`, allowing requests from any origin. While acceptable for a deliberately vulnerable training application, such a configuration could expose APIs unnecessarily in a production environment if sensitive resources are available.
   **OWASP Top 10:2025:** A05 – Security Misconfiguration.

## PR Template Setup

* File: `.github/PULL_REQUEST_TEMPLATE.md`
* Sections included:

  * Goal
  * Changes
  * Testing
  * Artifacts & Screenshots
* Checklist items:

  * Title is clear (`feat(labN): <topic>`)
  * No secrets/large temp files committed
  * Submission file at `submissions/labN.md` exists
* Auto-fill verified: **[ ] Yes** — Not verified because the assignment was submitted through the university LMS instead of a GitHub Pull Request.
