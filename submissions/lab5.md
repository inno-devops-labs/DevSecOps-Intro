# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: <2 min>
- Total alerts: <10>
| Severity | Count |
|----------|------:|
| High | <0> |
| Medium | <2> |
| Low | <5> |
| Informational | <3> |

### Authenticated full scan
- Duration: <7 min>
- Total alerts: <12>
| Severity | Count |
|----------|------:|
| High | <1> |
| Medium | <4> |
| Low | <3> |
| Informational | <4> |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): <1.2×>
- Did your run match the lecture's ratio? (2-3 sentences)
```
My run did not match the lecture's 10–20× ratio. The authenticated scan found only 2 more alerts than baseline, likely because Juice Shop v20.0.0 has a relatively small authenticated surface compared to larger applications, and the ZAP spider with the default 5-minute timeout may not have crawled deeply enough into authenticated routes. Additionally, many Juice Shop challenges are behind client-side JavaScript rendering that the passive scanner doesn't fully exercise.
```
- Pick **two specific alerts** that only the authenticated scan found. For each:
    1. SQL Injection (High) — Found at /rest/user/login (POST, param: email) and /rest/products/search (GET, param: q)
    Why unreachable to baseline: While the login endpoint is technically accessible anonymously, the authenticated scanner's active scan phase uses more aggressive SQL injection payloads and variations. The baseline spider didn't trigger the same depth of active testing on these endpoints, missing the SQL error responses (HTTP 500) that indicate injection points. 

    2. Private IP Disclosure (Low) — Found at /rest/admin/application-configuration (GET)
    Why unreachable to baseline: This endpoint requires admin authentication and returns HTTP 401 for anonymous requests. The baseline scanner never reached the response body containing the private IP addresses (192.168.99.100:3000, 192.168.99.100:4200), so it couldn't detect the information disclosure.


## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | <12> |
| WARNING | <10> |
| INFO | <0> |
| **Total** | <12> |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | N/A (CI/CD) |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)

```
I would fix **`express-sequelize-injection`** first. It has 6 findings, with 2 in production code (`routes/search.ts:23` and `routes/login.ts:34`) and 4 in educational examples (`data/static/codefixes/`). All follow the same pattern: user-controlled request parameters (`req.body.email`, `req.query.q`) passed directly into raw SQL queries via `models.sequelize.query()` with string interpolation. A single architectural fix — migrating to Sequelize's parameterized query API with `replacements` or `bind` options — would eliminate all 6 findings at once. This is the highest-impact rule because SQL injection is Critical severity, easily exploitable, and the pattern is consistent across the codebase.
```

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

```
**File:** `.github/workflows/update-challenges-www.yml:28`
**Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`
**Reason:** This is a CI/CD configuration issue, not an application vulnerability. While the finding is valid for supply-chain security (CICD-SEC-4), it's out of scope for this lab's application SAST analysis, which focuses on Juice Shop's runtime code. The fix belongs in a separate "CI hardening" task, not in the application codebase.
```

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High) | `/rest/products/search?q='(` | `express-sequelize-injection` | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection (High) | `/rest/user/login` (POST email) | `express-sequelize-injection` | `routes/login.ts:34` | High (both agree) |
| 3 | A03 Injection | — (not detectable by DAST) | — | `code-string-concat` (eval) | `routes/userProfile.ts:61` | SAST-only |

> Row 3 is SAST-only: ZAP can't detect `eval()` vulnerabilities dynamically because they only trigger on specific runtime inputs. Semgrep catches the anti-pattern statically.

### Strongest correlation deep-dive

**Vulnerable code** (`routes/search.ts:23`):
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR
  description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

### Reflection (2-3 sentences)
```
Building the focused auth model surfaced implementation-level risks like SQL injection and unguarded admin access that the baseline architecture model missed by treating authentication as a black box. This confirms that feature-level threat models are essential for revealing application-layer flaws, while architecture-level models are better suited for catching infrastructure risks. Ultimately, effective threat modeling must be iterative, combining both macro and micro views to achieve true defense-in-depth.
```