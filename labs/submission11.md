# Lab 11 — Reverse Proxy Security

## Goal
The goal of this lab was to secure a web application using an Nginx reverse proxy by enforcing HTTPS, applying security headers, and implementing rate limiting to protect against common web attacks.

## Task 1 — Reverse Proxy Setup
An Nginx reverse proxy was deployed in front of the OWASP Juice Shop application using Docker Compose.

### Implementation
- Juice Shop runs internally on port 3000
- Nginx acts as a reverse proxy
- Only Nginx exposes ports externally:
  - HTTP: 8080
  - HTTPS: 8443
- Juice container is not directly accessible from outside

### HTTPS Configuration
- Self-signed TLS certificate was generated using OpenSSL
- HTTP traffic is redirected to HTTPS (308 redirect)
- Secure access is enforced via HTTPS

## Task 2 — Security Headers and TLS

### HTTP → HTTPS Redirect
- HTTP requests return `308 Permanent Redirect`
- All traffic is forced over HTTPS

### Security Headers (HTTPS)
- Strict-Transport-Security enabled
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy configured
- Permissions-Policy configured
- Content-Security-Policy present (report-only)

### TLS Configuration
- Supported protocols: TLS 1.2, TLS 1.3
- Weak protocols disabled
- Strong cipher suites used:
  - TLS_AES_256_GCM_SHA384
  - ECDHE-RSA-AES256-GCM-SHA384
- Modern key exchange (X25519, P-256)

### Issues
- Self-signed certificate (not trusted)
- Domain mismatch (localhost)
- TLS rating capped due to trust issues

## Task 3 — Rate Limiting

### Test
The login endpoint `/rest/user/login` was tested with multiple rapid requests.

### Results
- First requests returned `401 Unauthorized`
- After threshold exceeded, responses returned `429 Too Many Requests`

### Evidence
- Rate limit test results stored in `analysis/rate-limit-test.txt`
- Nginx access log confirms `429` responses
- Logs stored in `analysis/rate-limit-429.log`

### Analysis
The reverse proxy successfully detects and blocks excessive login attempts. This reduces the risk of brute-force attacks.

### Trade-off
While rate limiting improves security, overly strict limits may impact legitimate users who retry login multiple times.

## Artifacts
- HTTP headers: `analysis/headers-http.txt`
- HTTPS headers: `analysis/headers-https.txt`
- TLS scan: `analysis/testssl.txt`
- Rate limit test: `analysis/rate-limit-test.txt`
- Rate limit logs: `analysis/rate-limit-429.log`
- Rate limit analysis: `analysis/rate-limit-summary.md`

## Conclusion
The reverse proxy setup effectively improves the security posture of the application by enforcing HTTPS, applying modern security headers, and limiting abusive request patterns. While the setup is suitable for development and testing, it would require a trusted certificate for production use.
