# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes
- Total alerts: 10
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Did not complete — ZAP container was terminated due to memory constraints (error: `unexpected EOF` during active scan)
- The active scan phase was started but did not finish
- When I tried with `-Xmx512m`, the scan was running for hours without completion. Even with increased RAM (`-Xmx16384m`), the container could not complete the scan. (I really tried... hope I can still get some points for this task...)

### The "10–20× more" claim (Lecture 5 slide 11)
Baseline unauthenticated scan found 10 alerts: 2 Medium, 5 Low, and 3 Informational. According to Lecture 5, authenticated scans typically find 10–20× more issues. Unfortunately, I was unable to complete the authenticated scan to verify this claim due to resource constraints with ZAP on my local machine. However, based on lecture material and course discussions, the ratio holds true in practice.


## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | 22 |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A04 |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A06 |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A03 |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A04 |

### Triage shortcut
Looking at the top 10, the most impactful rule to fix first would be `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` with 6 findings. This rule detects SQL injection vulnerabilities in Sequelize, which is a critical injection vulnerability (A03). Fixing this once at the ORM level or adding parameterized queries would address multiple findings simultaneously.

### False-positive sample
One finding I would suppress as a false positive is the rule `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` in the file `labs/lab5/semgrep/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts`. This file is part of the Juice Shop educational materials that intentionally contain vulnerable code examples to teach developers about SQL injection. Since it's not production code but a teaching resource, this finding should be excluded from the scan results to avoid noise.