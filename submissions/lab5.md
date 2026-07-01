# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes
- Total alerts: 4
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 1 |
| Informational | 1 |

### Authenticated full scan
- Duration: 7 minutes
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 3x (12 vs 4 alerts, and 22 vs 12 unique URLs).
- Did your run match the lecture's ratio? While my strict alert ratio was 3x rather than 10-20x, the principle absolutely holds true. The authenticated spider (`spiderAjax`) found significantly more URLs (346 vs 93) because it could bypass the login screen and traverse the internal application state, successfully identifying a High-severity alert that was completely invisible to the baseline scan.
- Pick **two specific alerts** that only the authenticated scan found. For each:
    1. **SQL Injection [High]** 
        - *Why was it unreachable to the unauthenticated scan:* The scanner found this on `/rest/products/search` and `/rest/user/login` by actively injecting payloads (like `'(`) into authenticated or restricted API parameters that the baseline spider couldn't effectively fuzz or reach with a valid session context.
    2. **Private IP Disclosure [Low]**
        - *Why was it unreachable to the unauthenticated scan:* This was found on the `/rest/admin/application-configuration` endpoint, which is strictly restricted to administrative users and actively drops unauthenticated requests.
        
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
| javascript.sequelize.security.audit.sequelize-injection-express | 6 | A03 |
| yaml.github-actions.security.run-shell-injection | 5 | A03 |
| javascript.express.security.audit.express-check-directory-listing | 4 | A05 |
| javascript.express.security.audit.express-res-sendfile | 4 | A01 |
| javascript.express.security.audit.express-open-redirect | 1 | A01 |
| javascript.jsonwebtoken.security.jwt-hardcode | 1 | A07 |
| javascript.lang.security.audit.code-string-concat | 1 | A03 |

### Triage shortcut (Lecture 5 slide 8)
I would prioritize fixing the `javascript.sequelize.security.audit.sequelize-injection-express` rule first. It has the highest frequency (6 occurrences) among the critical code vulnerabilities and leads directly to SQL Injection (A03), which has massive impact. Fixing this by enforcing parameterized queries across the application resolves multiple critical findings with one architectural pattern.

### False-positive sample
`routes/userProfile.ts` triggered the `javascript.lang.security.audit.code-string-concat` rule on line 61 (`username = eval(code)`). While `eval()` is generally dangerous, in the context of the Juice Shop deliberately vulnerable application, this specific file uses it as an isolated challenge sandbox mechanism, rather than a standard, unintentional business logic flaw.

## Bonus: SAST/DAST Correlation

### Correlation table
### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=%27%28 | express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection | /rest/user/login | express-sequelize-injection | routes/login.ts:34 | High (both agree) |

### Strongest correlation deep-dive
*(Focusing on the `/rest/products/search` correlation)*

**Step 1: Vulnerable Code (Semgrep routes/search.ts:23)**

```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**Step 2: Working Payload (ZAP DAST report)**

```http
GET /rest/products/search?q=%27%28 HTTP/1.1
```
(ZAP injected the '( payload which broke the raw SQL syntax, resulting in a 500 Internal Server Error).

**Step 3: Proposed Remediation**

To fix this, we must stop using string interpolation (${criteria}) which allows arbitrary SQL commands to break out of the string context. We should use Sequelize's built-in parameterized queries (replacements):
```typescript
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :searchQuery OR description LIKE :searchQuery) AND deletedAt IS NULL) ORDER BY name',
  {
    replacements: { searchQuery: `%${criteria}%` },
    type: QueryTypes.SELECT
  }
)
```

**Step 4: Why both tools caught it**

Semgrep (SAST) caught it because the code pattern involves directly passing user-controlled variables via string interpolation (${criteria}) into a database execution function (sequelize.query), matching a known unsafe pattern. ZAP (DAST) caught it dynamically by injecting raw SQL control characters ('() into the q parameter and observing the application throw a database-level 500 error, confirming the parameter is not sanitized.

### Reflection (2-3 sentences)
In a real PR review, I would want the SAST finding first. SAST points exactly to the file and line number (`routes/search.ts:23`), allowing developers to immediately fix the root cause in the codebase. However, the DAST evidence is critical for prioritizing the fix—it proves that this specific line of code is actually reachable, weaponized, and exploitable from the outside, raising the priority of the SAST finding from "potential issue" to "active critical threat".
