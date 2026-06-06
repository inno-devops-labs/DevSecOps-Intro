# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Windows 11
- Docker version: Docker version 29.5.2, build 79eb04c

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no` (no --restart flag used)

### Health Check
- HTTP code on `/`: 200
- API check (`/api/Products` product count): 46 products returned
- Container uptime: `juice-shop   Up 54 seconds   127.0.0.1:3000->3000/tcp`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes — notes: Account menu top-right with Login/Registration
- Product listing/search present: [x] Yes — notes: products and search icon visible on landing page
- Admin or account area discoverable: [x] Yes — notes: Account menu present
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: only an informational "Slow network / fallback font" warning, no critical errors
- Pre-populated local storage / cookies: Local Storage empty on first load; a "fruit cookies" consent banner is shown

### Security Headers (Quick Look)
Run: `curl.exe -I http://127.0.0.1:3000`. Output (relevant headers):
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
Content-Type: text/html; charset=UTF-8
```
Which of these are MISSING?
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff` (present)
- [ ] `X-Frame-Options` (present, SAMEORIGIN)

### Top 3 Risks Observed
1. **Missing Content-Security-Policy header** — Without a CSP, the browser has no restriction on which scripts it may execute, which makes cross-site scripting (XSS) attacks significantly easier to pull off and harder to contain. Maps to OWASP Top 10:2025 A06 (Security Misconfiguration).
2. **Missing Strict-Transport-Security header** — The app does not instruct browsers to enforce HTTPS, leaving users exposed to downgrade and man-in-the-middle attacks on untrusted networks. Maps to OWASP Top 10:2025 A06 (Security Misconfiguration).
3. **Overly permissive CORS (`Access-Control-Allow-Origin: *`)** — The API accepts cross-origin requests from any website, so a malicious site could interact with the API on behalf of a victim. Maps to OWASP Top 10:2025 A05 (Broken Access Control).

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: clear title; no secrets/large files; submission file exists
- Auto-fill verified: [ ] Yes — to confirm when opening the PR

## GitHub Community

Starring repositories bookmarks useful projects for later, signals trust and popularity to other developers, and helps maintainers gain visibility for their work. Following developers keeps me updated on what teammates and the wider community are building, helps me discover new projects through their activity, and builds professional connections useful for future collaboration.