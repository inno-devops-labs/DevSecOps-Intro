# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~5 minutes
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: ~10 minutes
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.2×** (12 / 10)

- Did your run match the lecture's ratio?

  No. The authenticated scan found only slightly more findings than the unauthenticated scan (1.2× versus the 10–20× increase mentioned in the lecture). This is likely because OWASP Juice Shop exposes many routes and vulnerabilities even to anonymous users, so the unauthenticated scan already achieved substantial coverage. Authentication still revealed additional attack surface and higher-severity findings.

- Pick **two specific alerts** that only the authenticated scan found.

#### 1. SQL Injection (High)

- Severity: High
- Why was it unreachable to the unauthenticated scan?

  The authenticated scan gained access to additional API endpoints and application functionality that were not fully exercised during the unauthenticated crawl, allowing ZAP to discover SQL injection vectors in authenticated application flows.

#### 2. Authentication Request Identified (Informational)

- Severity: Informational
- Why was it unreachable to the unauthenticated scan?

  This finding was only visible after login because ZAP observed authenticated requests and session-related traffic that do not exist before user authentication.

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity  |  Count |
| --------- | -----: |
| ERROR     |     12 |
| WARNING   |     10 |
| INFO      |      0 |
| **Total** | **22** |

### Top 10 rules by frequency

| Rule ID                                                                                           | Count | OWASP category                                    |
| ------------------------------------------------------------------------------------------------- | ----: | ------------------------------------------------- |
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection       |     6 | A03: Injection                                    |
| yaml.github-actions.security.run-shell-injection.run-shell-injection                              |     5 | A03: Injection                                    |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing |     4 | A05: Security Misconfiguration                    |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile                       |     4 | A04: Insecure Design                              |
| javascript.express.security.audit.express-open-redirect.express-open-redirect                     |     1 | A10: Server-Side Request Forgery / Redirect Abuse |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret                                |     1 | A07: Identification and Authentication Failures   |
| javascript.lang.security.audit.code-string-concat.code-string-concat                              |     1 | A03: Injection                                    |

### Triage shortcut (Lecture 5 slide 8)

If I had time to fix only one rule, I would start with **javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection**. It is the most frequent finding in the scan (6 occurrences) and belongs to the OWASP A03 Injection category. Fixing the underlying unsafe query construction pattern in Sequelize would remove multiple findings at once and reduce the risk of database compromise.

### False-positive sample

**File:** `labs/lab5/semgrep/juice-shop/server.ts`

**Rule:** `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing`

**Reason:** The finding flags Express static file serving as a potential directory-listing risk. After reviewing the code, the application is intentionally configured as the OWASP Juice Shop training target, and the reported behavior is part of the application's deliberately vulnerable design rather than an accidental exposure requiring remediation.

