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
- Duration: 6 minutes
- Total alerts: 47
| Severity | Count |
|----------|------:|
| High | 2 |
| Medium | 8 |
| Low | 12 |
| Informational | 25 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 4.7
- Did your run match the lecture's ratio? (2-3 sentences)
    Not really, just 4.7x. Perhaps it's because many vulnerabilities require high payloads or manual testing
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)

1. **SQL Injection** (High severity). Unreachable to the unauthenticated scan because it requires an active session, while unauthenticated scan only uses passive checks.
2. **Insecure Direct Object Reference** (Medium severity). Unreachable to the unauthenticated scan because it requires a JWT token. Unauthenticated scan got `401 Unauthorized` and failed to notice that.

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
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A04 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A04 |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A04 |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)

I would choose the first one, `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`, because it is the most frequent one and probably one of the most dangerous OWASP categories. One fix of the pattern would probably close many findings.

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

- **File:** `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml`
- **Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`
- **Reason:** The shell commands in this workflow are controlled by the repository maintainer and not by the user — they execute predefined CI/CD steps, making the injection risk negligible.