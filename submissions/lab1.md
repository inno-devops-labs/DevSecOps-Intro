# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `macOS`
- Docker version: `Docker version 29.4.0, build 9d7ad9f`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: `http://127.0.0.1:3000`
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no`

### Health Check

- HTTP code on `/`: `HTTP 200`

- API check (first 200 chars of `/api/Products`):

```json
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T17:13:54.109Z"
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
CONTAINER ID   IMAGE                            COMMAND                  CREATED          STATUS          PORTS                      NAMES
4cf4ae3bf6ab   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   57 minutes ago   Up 57 minutes   127.0.0.1:3000->3000/tcp   juice-shop
```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No — notes: Account menu is visible in the top-right navigation bar. Login and registration are available from this area.
- Product listing/search present: [x] Yes [ ] No — notes: The main page shows product cards, prices, and “Add to Basket” buttons. I observed products such as Apple Juice, Banana Juice, Basil Smoothie, Dragonfruit Juice, Eggfruit Juice, Elderflower Cordial, Fruit Press, Grape Juice, Green Smoothie and Lemon Juice.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account area is discoverable from the top navigation menu. Admin functionality was not directly shown on the initial page.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No blocking client-side errors were noticed during initial page loading and product browsing.
- Pre-populated local storage / cookies: No meaningful pre-populated local storage values were observed during initial browsing.

### Security Headers (Quick Look)

Run:

```bash
curl -I http://127.0.0.1:3000 2>&1 | head -20
```

Paste output:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 17:13:54 GMT
ETag: W/"26af-19ebcd37167"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 18:00:03 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING?

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed

1. **Missing browser security headers** — The response does not include `Content-Security-Policy` and `Strict-Transport-Security`. Missing security headers reduce browser-side protection against attacks such as script injection and insecure transport behavior. This maps to **A02:2025 — Security Misconfiguration**.

2. **Unauthenticated public API surface** — The `/api/Products` endpoint is accessible without authentication and returns product data in JSON format. This is normal for a public shop catalog, but exposed API endpoints still increase the attack surface and should be checked for authorization mistakes or excessive data exposure. This maps to **A01:2025 — Broken Access Control**.

3. **Intentionally vulnerable application running as a local service** — OWASP Juice Shop is designed to contain security vulnerabilities for training. If it were exposed using `-p 3000:3000` instead of `127.0.0.1:3000:3000`, other devices on the network could access the vulnerable application. This maps to **A02:2025 — Security Misconfiguration**.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template.

## GitHub Community

I starred the required repositories because stars help bookmark useful open-source projects and support their visibility in the community. Following developers helps me discover their work, stay connected with the course community, and build professional collaboration habits.
"""

