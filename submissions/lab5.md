## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~ 0.5 minutes
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: ~ 7.5 minutes
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **1.2×**

- Did your run match the lecture's ratio?   
  The run did not match the lecture ratio. According to Lecture 5, Slide 11, authenticated scans typically find 10–20× more issues than unauthenticated scans due to the larger attack surface exposed after login. In the local run, however, the authenticated scan found only 1.2× more issues, which is significantly lower than the ratio presented in the lecture.

- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)

- **Session ID in URL Rewrite (medium severity):** The session ID appeared in Socket.IO URLs only after a user session was established through authentication.
- **Missing Anti-clickjacking Header (medium severity):** The alert was reported on Socket.IO endpoints that are created only after an authenticated user session is established.

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
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A05 |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A05 |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A02 |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A02 |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A04 |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A05 |


### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?

`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

The highest-frequency rule representing a clear SQL injection affecting search and authentication flows. An attacker may be able to extract sensitive user data or bypass authentication due to unsafe query construction. Fixing parameterized SQL queries removes the primary injection vector.

### False-positive sample
- **False positive finding:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`
- **File path:** `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml`
- **Reason:** The `${{ github.ref_name }}` variable is used only for controlled GitHub-provided branch metadata in CI logic and does not enable arbitrary shell command execution in this workflow context.

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A05 Injection | SQL Injection | /rest/products/search?q=%27%28 | javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A05 Injection | SQL Injection | /rest/user/login | javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | routes/login.ts:34 | High (both agree) |

### Strongest correlation deep-dive
For your strongest correlation (the one with highest severity in both reports):
1. **Paste the vulnerable code** from Semgrep's file:line

    ```ts
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR   
                  description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
    ```

2. **Paste a working payload**  
    `'(` _(URL: `http://juice-shop:3000/rest/products/search?q='(`)_

3. **Write the fix**

    ```ts
    models.sequelize.query(
      `SELECT * 
      FROM Products 
      WHERE (name LIKE :criteria OR description LIKE :criteria)
        AND deletedAt IS NULL
      ORDER BY name`,
      {
        replacements: {
          criteria: `%${criteria}%`
        }
      }
    );
    ```

4. **Why both tools caught it**

    OWASP ZAP (DAST) detected the vulnerability through dynamic analysis by sending crafted input to the running application and observing an abnormal server response. Semgrep (SAST) detected the issue through static analysis by identifying unsafe string interpolation in a SQL query.

### Reflection (2-3 sentences)
In a real PR review, I would prefer SAST findings first. As mentioned in Lecture 5, slide 15, DAST alone only confirms the existence of a vulnerability, whereas SAST can point to the exact line of code that may cause it. In addition, SAST is faster and more suitable for PR reviews, as full DAST scans can be resource-intensive, time-consuming, and frustrating for developers.
