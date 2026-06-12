# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `Ubuntu Server 24.04 VM on ESXi`
- Docker version: 29.1.3

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: no
- Notes: The container was bound to localhost only and accessed safely through SSH local port forwarding from my workstation to avoid exposing a deliberately vulnerable application on the LAN.

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
  ```shell
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99  
,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T00:04:01.029Z"
  ```
- Container uptime:
```
CONTAINER ID   IMAGE                   COMMAND                  CREATED          STATUS          PORTS                
                          NAMES  
6748c4262572   bkimminich/juice-shop   "/nodejs/bin/node /j…"   24 minutes ago   Up 24 minutes   0.0.0.0:3000->3000/  
tcp, [::]:3000->3000/tcp   keen_shannon
```
### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Login and Registration were available from the Account menu in the top-right area of the application
- Product listing/search present: [x] Yes [ ] No — notes: The landing page displayed a product catalog and search bar.
- Admin or account area discoverable: [x] Yes [ ] No — notes: An account area is clearly discoverable from the UI. Administrative functionality is not openly exposed in the navigation, but the app contains admin endpoints.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No blocking client-side errors were seen.
- Pre-populated local storage / cookies: After logon - my JWT token was seen.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```shell
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
                                Dload  Upload   Total   Spent    Left  Speed  
 0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: *  
X-Content-Type-Options: nosniff  
X-Frame-Options: SAMEORIGIN  
Feature-Policy: payment 'self'  
X-Recruiting: /#/jobs  
Accept-Ranges: bytes  
Cache-Control: public, max-age=0  
Last-Modified: Fri, 12 Jun 2026 00:04:01 GMT  
ETag: W/"26af-19eb9248e00"  
Content-Type: text/html; charset=UTF-8  
Content-Length: 9903  
Vary: Accept-Encoding  
Date: Fri, 12 Jun 2026 00:32:51 GMT  
Connection: keep-alive  
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Exposed client side state and token** — The application stores client-side state in browser storage, and authenticated sessions place a JWT token in `Local Storage`. This is risky because client side storage is accessible to JavaScript and becomes especially dangerous in the presence of XSS. `A07 Authentication Failures` (with possible exploitation via `A05 Injection`)
2. **Missing security hardening in HTTP response headers** — The application response is missing `Content-Security-Policy` and `Strict-Transport-Security`, while other headers such as `X-Content-Type-Options` and `X-Frame-Options` are present. This suggests partial hardening only: some browser side protections are enabled, but important controls against script execution policy abuse and transport security weakening are absent. `A02 Security Misconfiguration`.
3.  **Unauthenticated exposure of user review data** — Product review data is visible without authentication, and reviewer email addresses are exposed in the interface, including the administrator email address. This increases the application's information disclosure surface and helps attackers enumerate valid identities and application roles before deeper testing. `A01 Broken Access Control`.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - [x] Title is clear (`feat(labN): <topic>` style)
  - [x] No secrets/large temp files committed
  - [x] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template

## GitHub Community

I starred the course repository and other relevant repositories to bookmark useful projects and support their maintainers. Starring also helps track tools I may reuse later in AppSec or DevSecOps work.

Following other developers I'm interested in helps me see their activity, discover useful repositories, and stay aware of collaboration patterns in real projects. It is also helpful for professional growth and for building an engineering network.
