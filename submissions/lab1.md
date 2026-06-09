# Lab 1 - Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `macOS Tahoe 26.5.1`
- Docker version: `Docker Engine - Community 29.5.3 (client), 29.5.2 (server)`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no` (default)

### Health Check
- HTTP code on `/`: `200`
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-08T21:10:44.629Z"
  ```
- Container uptime:
  ```
  juice-shop   Up 46 minutes   127.0.0.1:3000->3000/tcp
  ```
- Application version:
  ```json
  {
    "version": "20.0.0"
  }
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No - notes: Login and registration were visible in the UI and both flows worked during basic testing.
- Product listing/search present: [x] Yes [ ] No - notes: The landing page loaded correctly, products were listed, and search was available.
- Admin or account area discoverable: [x] Yes [ ] No - notes: Account-related functionality was discoverable from the UI, and browser network traffic showed endpoints such as `whoami`, `login`, `search`, and product-related requests.
- Client-side errors in DevTools console: [ ] Yes [x] No - notes: No obvious client-side errors were observed during basic interaction.
- Pre-populated local storage / cookies: `cookieconsent_status`, `language`, `token`, `welcomebanner_status` were present. A JWT-like authentication token was stored client-side, so the full token value is intentionally not included in this report.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 08 Jun 2026 21:10:44 GMT
ETag: W/"26af-19ea912d770"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 08 Jun 2026 21:11:45 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 - A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Content Security Policy** - The application response does not include a `Content-Security-Policy` header. This is a security hardening gap that weakens browser-side protection against injected scripts and can increase the impact of XSS-related issues. This maps to **OWASP Top 10:2025 A02: Security Misconfiguration**.
2. **No Strict-Transport-Security header** - The application does not send a `Strict-Transport-Security` header. In a real deployment, this would mean the browser is not instructed to enforce HTTPS for future connections, which reflects an insecure server-side security configuration. This maps to **OWASP Top 10:2025 A02: Security Misconfiguration**.
3. **Client-side storage of authentication token** - Browser storage contained a JWT-like token associated with the authenticated session. Storing sensitive session material in a client-accessible context increases the impact of XSS or client-side compromise and reflects a weak security design choice. This maps to **OWASP Top 10:2025 A06: Insecure Design**.

### Screenshots
- Screenshot 1 - Juice Shop landing page (attached in PR)
- Screenshot 2 - Login/Registration visible in the UI (attached in PR)
- Screenshot 3 - DevTools Network tab showing product/account-related requests (attached in PR)
- Screenshot 4 - DevTools Application/Storage view showing stored keys/cookies, with token redacted (attached in PR)

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: `Goal`, `Changes`, `Testing`, `Artifacts & Screenshots`
- Checklist items:
  - `Title is clear (feat(labN): <topic> style)`
  - `No secrets/large temp files committed`
  - `Submission file at submissions/labN.md exists`
- Auto-fill verified: [ ] Yes - PR description showed my template (screenshot or link to draft PR)

## GitHub Community

Starring repositories matters in open source because it helps signal that a project is useful, makes it easier to find again later, and gives maintainers visible community support. Following developers is helpful in team projects and professional growth because it gives better visibility into what others are building, how they work, and what tools or practices are worth learning from.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): `[paste GitHub Actions run URL here]`
- Workflow run duration: `[paste duration here]`
- Curl response excerpt:
  ```
  [paste the "HTTP/1.1 200 OK" excerpt from the workflow logs here]
  ```
