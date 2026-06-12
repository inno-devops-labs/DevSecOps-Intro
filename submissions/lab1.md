# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 26.2
- Docker version: `Docker version 29.2.1, build a5c7197`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no`

### Health Check

- HTTP code on `/`: `200`
- API check (first 200 chars of `/api/Products`; v20.0.0 moved from `/rest/products` to `/api/Products`):

```json
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T00:26:39.716Z"
```

- Product count from `/api/Products`: `46`

- Application version:

```json
{
  "version": "20.0.0"
}
```

- Container uptime:

```text
CONTAINER ID   IMAGE                           COMMAND                  CREATED         STATUS         PORTS                      NAMES
01b7c29b516f   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   6 minutes ago   Up 6 minutes   127.0.0.1:3000->3000/tcp   juice-shop
```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No — notes: The Account menu is visible in the top-right navigation bar. The Login page is available and contains email/password fields, "Forgot your password?", "Remember me", "Log in with Google", and a "Not yet a customer?" registration link.

- Product listing/search present: [x] Yes [ ] No — notes: Product cards are visible on the landing page with product images, names, prices, and Add to Basket buttons. A search icon is also visible in the top navigation bar.

- Admin or account area discoverable: [x] Yes [ ] No — notes: The Account menu and basket are visible in the top navigation bar. No admin panel was directly visible during the initial browsing check.

- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No red client-side errors were shown in the Console error filter during the initial page load.

- Pre-populated local storage / cookies: Local Storage for `127.0.0.1` was empty during the initial check. Cookies contained `cookieconsent_status=dismiss`, `language=en`, and `welcomebanner_status=dismiss`.

- Network observation: The lab text mentions `/api/Products/<id>/reviews`, but my browser Network tab captured `GET /rest/products/1/reviews` after clicking a product detail. The request returned `200 OK`, so reading product reviews did not require authentication during this initial check.

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:

```text
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                               Dload  Upload   Total   Spent    Left  Speed
0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 00:26:40 GMT
ETag: W/"26af-19eb412ee09"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 00:33:14 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed

1. **Missing Content Security Policy** — The response does not include a `Content-Security-Policy` header. This matters because CSP helps reduce the impact of client-side injection attacks such as XSS by restricting where scripts and other resources can be loaded from. This maps to OWASP Top 10:2025 A06: Security Misconfiguration.

2. **No Strict Transport Security header** — The response does not include `Strict-Transport-Security`. In this local lab the app is accessed over HTTP, but in a real deployment missing HSTS could allow downgrade or insecure transport-related attacks. This maps to OWASP Top 10:2025 A02: Cryptographic Failures or A06: Security Misconfiguration.

3. **Unauthenticated product review API access** — A product detail click triggered `GET /rest/products/1/reviews`, and it returned `200 OK` without logging in. Public read access to reviews may be expected for an online shop, but it still increases the observable API surface and should be protected by proper authorization, validation, and rate limiting where needed. This maps to OWASP Top 10:2025 A01: Broken Access Control or A05: Security Misconfiguration.


## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template

## GitHub Community

I starred the course repository and `simple-container-com/api` because stars help bookmark useful open-source projects and increase their visibility in the developer community. Following the professor, TAs, and classmates helps me stay connected with the course community, discover their work, and build useful professional connections for future team projects.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): To be added after opening the PR and running GitHub Actions.
- Workflow run duration: To be added after the workflow completes.
- Curl response excerpt:
  ```text
  To be added from the successful GitHub Actions run logs.
  ```
