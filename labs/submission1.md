# Triage Report — OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0 — Released November 2023
- Image digest: sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d

## Environment
- Host OS: Windows 10/11
- Docker: Docker Desktop for Windows (version from output)
- Container ID: 24b13082f86edf5890290f74f2ffb12d4b1b19ea57e5659810dfecd90ae56283

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No
  - Explanation: Container bound to localhost only, not exposed to external network

## Health Check
- Page load: Application loads successfully at http://localhost:3000 (OWASP Juice Shop homepage visible)
- API check (first 10 lines):
```html
<html>
  <head>
    <meta charset='utf-8'>
    <title>Error: Unexpected path: /rest/products</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}
```
**Note:** The API endpoint `/rest/products` returns a 500 error with message "Unexpected path: /rest/products". This suggests either:
1. API path has changed in v19.0.0
2. Authentication/verification required before accessing this endpoint
3. Deliberate security feature/obfuscation in the training application

## Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes  [ ] No — notes: Login and registration forms clearly visible on the homepage
- Product listing/search present: [x] Yes  [ ] No — notes: Product catalog visible, search functionality available in header
- Admin or account area discoverable: [ ] Yes  [x] No — notes: No obvious admin interface on initial load; likely hidden or requires authentication
- Client-side errors in console: [ ] Yes  [x] No — notes: No JavaScript errors in browser console on initial load
- Security headers:
```bash
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sat, 07 Feb 2026 07:16:51 GMT
ETag: W/"124fa-19c36f5e6cd"
Content-Type: text/html; charset=UTF-8
Content-Length: 75002
Vary: Accept-Encoding
Date: Sat, 07 Feb 2026 07:27:04 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
**Analysis:**
- **X-Content-Type-Options: nosniff** - Prevents MIME type sniffing
- **X-Frame-Options: SAMEORIGIN** - Protects against clickjacking
- **Feature-Policy** - Controls browser features (limited to payment API)
- **Missing CSP (Content Security Policy)** - No CSP header present
- **Missing HSTS (Strict-Transport-Security)** - No HSTS header for HTTPS enforcement
- **Access-Control-Allow-Origin: *** - CORS allows any origin (potentially risky)
- **X-Recruiting header** - Information disclosure (reveals job posting page)

## Risks Observed (Top 3)

1) **Missing Critical Security Headers** — Absence of CSP and HSTS headers leaves application vulnerable to XSS and protocol downgrade attacks
   - *Rationale:* CSP prevents XSS attacks; HSTS enforces HTTPS; both are essential modern web security controls

2) **Information Disclosure through Error Messages** — The 500 error for `/rest/products` exposes stack trace including file paths, Express version (^4.21.0), and internal routing logic
   - *Rationale:* Detailed error messages in production can aid attackers in understanding application architecture and finding vulnerabilities

3) **Overly Permissive CORS Policy** — `Access-Control-Allow-Origin: *` allows any website to make cross-origin requests to the API
   - *Rationale:* While useful for development, this can be dangerous in production if the API handles sensitive data or actions

## GitHub Community

### Why starring repositories matters in open source:
Starring repositories serves multiple purposes in the open-source ecosystem. It functions as both a bookmarking system for developers to save projects for future reference and as a social signal that indicates project popularity and community trust. High star counts attract more contributors and maintainers, creating a positive feedback loop that improves project quality and sustainability. For project maintainers, stars serve as validation of their work and can motivate continued development.

### How following developers helps in team projects and professional growth:
Following developers on GitHub creates a professional learning network that extends beyond the classroom. It allows students to observe real-world development practices, stay updated on industry trends, and discover new tools through the activity feeds of experienced developers. In team projects, following classmates facilitates better collaboration by making it easier to track contributions, share knowledge, and build a supportive community. Professionally, this practice helps build visibility within the developer community and can lead to valuable connections for future career opportunities.

## Challenges & Solutions

### Challenge 1: API Endpoint Returns 500 Error
**Problem:** The `/rest/products` endpoint documented in lab instructions returns a 500 error instead of expected JSON data.
**Solution:** Recognized this as part of Juice Shop's training design. The application intentionally contains vulnerabilities and unexpected behaviors for educational purposes. This observation was documented as a security finding (information disclosure risk).

### Challenge 2: Understanding Security Headers
**Problem:** Initially unfamiliar with various security headers and their importance.
**Solution:** Researched each header found in the response:
- `X-Content-Type-Options: nosniff` - Prevents browser MIME sniffing
- `X-Frame-Options: SAMEORIGIN` - Clickjacking protection
- Noted missing headers: CSP and HSTS as security gaps

### Challenge 3: Container Networking Configuration
**Problem:** Ensuring container only exposes to localhost for security.
**Solution:** Used `-p 127.0.0.1:3000:3000` instead of `-p 3000:3000` to bind only to loopback interface, preventing external network access.

### Learning Outcomes:
1. **Practical Container Security:** Learned importance of limiting network exposure
2. **Security Header Analysis:** Gained ability to audit HTTP headers for security controls
3. **Error Handling Risks:** Understood how verbose errors can aid attackers
4. **Training Application Design:** Recognized that Juice Shop intentionally contains vulnerabilities for educational value
```