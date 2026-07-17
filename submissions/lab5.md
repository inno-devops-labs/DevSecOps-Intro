# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes 49 seconds
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: 15 minutes 42 seconds
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): 1.20× (12 / 10)

My run did not match the lecture's 10–20× ratio because the comparison methodology differed significantly: I compared a passive baseline scan against a full active authenticated scan, while the lecture likely compared two active scans (unauthenticated vs authenticated). Additionally, Juice Shop intentionally exposes many vulnerable endpoints publicly (like `/ftp/` and `/rest/products/search`), allowing the baseline scan to discover many issues without authentication, reducing the relative increase from authentication.

Two alerts found only by the authenticated full scan:

1. **SQL Injection — High**
   - The active scan was able to inject malicious SQL payloads into the search parameter, which is a functionality the passive baseline scan does not perform.

2. **Absence of Anti-CSRF Tokens — Medium**
   - User management endpoints like `/api/Users` require authentication to access, making them unreachable during the unauthenticated baseline scan.

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 11 |
| INFO | 0 |
| **Total** | **23** |

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03:2021 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03:2021 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A01:2021 Broken Access Control |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A04:2021 Insecure Design |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 2 | A01:2021 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07:2021 Identification and Authentication Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03:2021 Injection |

### Triage shortcut

My immediate triage priority would be `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` for three reasons:

1. **Frequency:** 6 occurrences across the codebase represent over 25% of all ERROR-level findings
2. **Impact:** SQL injection vulnerabilities can lead to complete database compromise, data theft, or authentication bypass
3. **Confirmed exploitability:** ZAP's DAST scan independently confirmed this vulnerability on `/rest/products/search`, making it a verified production risk rather than a theoretical code issue

### False-positive sample

`data/static/codefixes/dbSchemaChallenge_1.ts:5` was flagged by the Sequelize injection rule, but I consider this a false positive. After examining the project structure, this file is located in a `/codefixes/` directory that contains educational challenge examples. I traced import statements across the repository and confirmed that no production code imports from this path — it's purely documentation material for the Juice Shop CTF challenges. I would suppress findings in this directory in future Semgrep runs.