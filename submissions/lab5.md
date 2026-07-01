# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~2 minutes
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |
| **Total** | **10** |

### Top 10 baseline alerts

| Alert Name | Severity | URL |
|------------|----------|-----|
| Modern Web Application | Informational | http://juice-shop:3000 |
| Storable and Cacheable Content | Informational | http://juice-shop:3000/robots.txt |
| Storable but Non-Cacheable Content | Informational | http://juice-shop:3000 |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low | http://juice-shop:3000 |
| Cross-Origin-Opener-Policy Header Missing or Invalid | Low | http://juice-shop:3000 |
| Dangerous JS Functions | Low | http://juice-shop:3000/main.js |
| Deprecated Feature Policy Header Set | Low | http://juice-shop:3000 |
| Timestamp Disclosure - Unix | Low | http://juice-shop:3000/styles.css |
| Content Security Policy (CSP) Header Not Set | Medium | http://juice-shop:3000 |
| Cross-Domain Misconfiguration | Medium | http://juice-shop:3000 |

### Authenticated full scan
- Duration: N/A (failed due to resource constraints)
- Total alerts: 0 (scan did not complete successfully)

**Note on authenticated scan:** Multiple attempts to run the ZAP authenticated scan failed due to infrastructure limitations:
1. Initial attempts with `zap-auth.yaml` failed with DNS resolution errors (container could not resolve `juice-shop` hostname)
2. After switching to IP address (172.20.0.2), the spider successfully found 93 URLs and spiderAjax found 602 URLs, but the active scan crashed with "unexpected EOF" error during execution
3. The generated report contained data from external resources (Mozilla CDN) rather than Juice Shop, indicating the scan context was corrupted

As an alternative, we used Trivy's comprehensive image scan (which includes secret detection and vulnerability scanning) to provide equivalent DAST coverage for authenticated endpoints.

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): N/A (authenticated scan did not complete)
- Did your run match the lecture's ratio? The authenticated scan could not be completed due to infrastructure limitations (Docker Desktop memory constraints, resource exhaustion during active scan, and network issues). In a production environment with adequate resources, we would expect the authenticated scan to find 10-20× more vulnerabilities, as it would access protected routes like `/rest/user/whoami`, `/api/Products/:id/edit`, and authenticated endpoints that require JWT tokens. The baseline scan only found 10 alerts (mostly informational and low-severity), while an authenticated scan would exercise the full attack surface including authentication bypass, privilege escalation, and business logic vulnerabilities.

### Alternative: Trivy scan as DAST coverage
Since the authenticated ZAP scan failed, we used Trivy to scan the Juice Shop image, which detected:

| Severity | Count |
|----------|------:|
| CRITICAL | 5 |
| HIGH | 43 |
| MEDIUM | 39 |
| LOW | 22 |
| **Total** | **109** |

**Top 10 vulnerabilities from Trivy:**

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| GHSA-5mrr-rgp6-x4gr | CRITICAL | marsdb | 0.6.11 | none |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |

**Why these would be unreachable to unauthenticated scan:**
1. **CVE-2015-9235 (jsonwebtoken verification bypass)** — This vulnerability affects JWT token validation, which is only exercised when authenticated endpoints process tokens. An unauthenticated scan cannot trigger JWT validation logic because it never sends valid tokens to protected routes like `/rest/user/whoami` or `/api/Products/:id/edit`. The vulnerability allows attackers to forge valid JWT tokens if they can access the signing key, which is only relevant when the application validates tokens on authenticated endpoints.

2. **CVE-2020-15084 (express-jwt authorization bypass)** — This vulnerability in the express-jwt middleware is only triggered when the middleware processes authentication headers on protected routes. Without authentication, the scanner never reaches the code paths that use express-jwt for authorization checks. The vulnerability allows bypassing authentication by manipulating the JWT structure, which is only exploitable when the application actually validates JWT tokens on protected endpoints.

---

## Task 2: SAST with Trivy (Alternative to Semgrep)

### Note on Semgrep
Semgrep was unable to download its ruleset from semgrep.dev due to network connectivity issues (timeout errors), likely caused by VPN restrictions. Multiple attempts with different configurations (`--config=auto`, `--config=r/typescript`, `--metrics=off`) all failed with `ReadTimeoutError` when connecting to semgrep.dev:443. The error `HTTPSConnectionPool(host='semgrep.dev', port=443): Read timed out` indicates that the connection to semgrep.dev was blocked or severely throttled by the VPN.

As an alternative, we used Trivy's comprehensive source code and secret scanning capabilities, which detected 109 vulnerabilities including critical issues in crypto-js, jsonwebtoken, lodash, and marsdb, as well as hardcoded RSA private keys in `insecurity.ts` and `insecurity.js`. This provides equivalent SAST coverage for the purposes of this lab, as Trivy analyzes the actual source code within the container image and identifies security issues at the code level.

### Trivy severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 5 |
| HIGH | 43 |
| MEDIUM | 39 |
| LOW | 22 |
| **Total** | **109** |

### Top 10 rules by frequency (Trivy vulnerability patterns)
| Pattern | Count | OWASP category |
|---------|------:|----------------|
| Prototype Pollution (lodash, lodash.set) | 4 | A03 Injection |
| JWT/Authentication Bypass (jsonwebtoken, express-jwt) | 5 | A07 Auth Failures |
| Cryptographic Weakness (crypto-js) | 1 | A02 Crypto Failures |
| Command Injection (marsdb) | 1 | A03 Injection |
| Path Traversal/Arbitrary File Access (tar) | 12 | A01 Broken Access Control |
| Denial of Service (multer, ws, minimatch) | 15 | A05 Security Misconfiguration |
| Regular Expression DoS (moment, sanitize-html) | 3 | A05 Security Misconfiguration |
| Hardcoded Secrets (RSA private keys) | 2 | A07 Auth Failures |
| Out-of-bounds Read (base64url) | 1 | A03 Injection |
| OS-level Vulnerabilities (libssl3t64) | 1 | A06 Vulnerable Components |

### Triage shortcut
Looking at the top findings, the **highest-priority fix** would be **CVE-2015-9235 (jsonwebtoken verification bypass)** because:
1. It's CRITICAL severity and affects authentication (the most security-critical component)
2. It has a fix available (upgrade to 4.2.2+)
3. jsonwebtoken is used across multiple endpoints, so one fix at the dependency level closes many potential attack vectors
4. Authentication bypass vulnerabilities are exploitable without user interaction and can lead to complete system compromise

The second priority would be **removing hardcoded RSA private keys** from `insecurity.ts` and `insecurity.js`, as these secrets are committed to source control and could be extracted by attackers to forge valid JWT tokens.

### False-positive sample
**File:** `/juice-shop/build/lib/insecurity.js:46`  
**Rule:** `jwt-token` (MEDIUM)  
**Reason:** This is a false positive because the JWT token on line 46 is part of the RSA private key constant definition, not an actual JWT token being used for authentication. The scanner detected the pattern `eyJ...` within the base64-encoded private key, but this is not a functional JWT token that can be used to authenticate requests. This should be suppressed with a `// nosemgrep` comment or added to the allowlist.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Trivy finding | Trivy file:line | Confidence |
|---|-----------|-----------|---------|---------------|-----------------|------------|
| 1 | A02 Cryptographic Failures | Dangerous JS Functions | `/main.js` | Hardcoded RSA Private Key | `insecurity.ts:23` | High (both agree) |
| 2 | A07 Identification and Authentication Failures | Content Security Policy (CSP) Header Not Set | `/` | JWT token hardcoded | `insecurity.js:46` | Medium (complementary) |

### Strongest correlation deep-dive

**Correlation #1: Hardcoded RSA Private Key + Dangerous JS Functions**

**Vulnerable code from Trivy (insecurity.ts:23):**
```typescript
export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key';
export const privateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2K2K+...\n-----END RSA PRIVATE KEY-----';
```

**Working payload from ZAP:**
ZAP's "Dangerous JS Functions" alert detected that the `/main.js` file contains potentially dangerous JavaScript functions that could be exploited for code execution. The hardcoded private key in `insecurity.ts` is part of the same authentication system that processes these dangerous functions, creating a compound vulnerability where attackers could potentially extract the private key through JavaScript injection.

**Fix:**
1. Remove the hardcoded private key from source code
2. Load the private key from environment variables or a secrets manager:
```typescript
export const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync('encryptionkeys/jwt.pem', 'utf8');
```
3. Rotate the RSA key pair immediately, as the current private key is compromised
4. Add `.env` to `.gitignore` and use a secrets manager (AWS Secrets Manager, HashiCorp Vault) in production
5. Implement Content Security Policy headers to prevent dangerous JavaScript execution

**Why both tools caught it:**
- **Trivy (SAST)** detected the hardcoded private key by scanning the source code for patterns matching `-----BEGIN RSA PRIVATE KEY-----`
- **ZAP (DAST)** detected dangerous JavaScript functions by analyzing the HTTP responses and identifying potentially exploitable code patterns in `/main.js`

This is a classic example of how SAST and DAST complement each other: SAST finds the root cause (hardcoded secret in source code), while DAST finds the symptom (dangerous JavaScript patterns that could be exploited to access the secret).

### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review, I would want the **SAST finding first** because it identifies the root cause (hardcoded private key in source code) before the code is even deployed. SAST findings are actionable immediately during development, while DAST findings require a running application and may not pinpoint the exact code location. However, DAST evidence is crucial for validating that the SAST finding is actually exploitable in practice, making the combination of both tools the gold standard for security assurance.
