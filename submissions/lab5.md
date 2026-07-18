# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 1m 14 s
- Total alerts: 10 \
| Severity | Count | \
|----------|------:|\
| High | 0 |\
| Medium | 2 |\
| Low | 5 |\
| Informational | 3 |

### Authenticated full scan
- Duration: 15m 34 s
- Total alerts: 12\
| Severity | Count |\
|----------|------:|\
| High | 1 |\
| Medium | 4 |\
| Low | 3 |\
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2×
- Did your run match the lecture's ratio? (2-3 sentences)\

No, my ratio is much lower because, in Juice Shop, all the vulnerabilities are intentionally exposed; consequently, both authenticated and unauthenticated scans find roughly the same number of vulnerabilities. In standard applications, however, most vulnerabilities are hidden behind a login, so unauthenticated scans detect far fewer vulnerabilities than authenticated ones—hence the high ratio.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. SQL injection - high severity
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)\
  An unauthenticated scan did not detect this vulnerability, as access to database query results requires authorization.

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
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A07 Identification Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)

``javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection``. This category accounts for the highest number of vulnerabilities-specifically instances where developers used raw SQL code within Sequelize with direct user input substitution, making it easy for an attacker to inject SQL injections. However, since all six vulnerabilities stem from the same database module, a single fix resolves them all.

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

labs/lab5/semgrep/lib/botUtils.ts - javascript.express.security.audit.express-check-directory-listing - The trigger occurred in a bot utility that checks for the existence of files based on a predefined list of paths rather than user input; there is no risk of directory traversal.
