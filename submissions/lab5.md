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
- Duration: 15 minutes
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2×
- Did your run match the lecture's ratio? (2-3 sentences)
The scan results did not show the expected 10-20× increase in alerts. This is likely due to the specific configuration of the `zap-auth.yaml` automation plan and the fact that Juice Shop v20.0.0 has a hardened codebase compared to earlier versions.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. SQL Injection (High). This issue was only detected after authenticated crawling reached search and login functionality.
  2. Session ID in URL Rewrite (Medium). This alert only appeared during authenticated testing because it requires an active user session.


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
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A01 |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 |
|javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 |

Only seven unique Semgrep rule IDs were reported.

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? 
I would prioritize fixing the `sequelize-injection` rule first. It appears 6 times and belongs to the Injection category (A03), which is a high-risk vulnerability. Fixing this at the module level using parameterized queries would resolve multiple findings with a single architectural change.


### False-positive sample
- File: `labs/lab5/semgrep/juice-shop/routes/fileServer.ts`
- Rule: `javascript.express.security.audit.express-check-directory-listing`
- Reason: The code contains hardcoded path validation and directory traversal protection, making this finding a false positive in the context of the current implementation.


## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search | sequelize-injection | routes/search.ts:23 | High |

### Strongest correlation deep-dive
1. **Vulnerable code**: 
```sql
models.sequelize.query(
    `SELECT * FROM Products
     WHERE name LIKE '%${criteria}%'`
)
```
2. **Working payload**: `q='(`
3. **Fix**: Use parameterized queries: 
```sql
models.sequelize.query(
  'SELECT * FROM Products WHERE name LIKE :name',
  { replacements: { name: `%${criteria}%` } }
)
```
4. **Why both caught it**: Semgrep detected potential SQL injection in routes/search.ts and routes/login.ts. OWASP ZAP confirmed these findings by identifying SQL Injection in the corresponding /rest/products/search and /rest/user/login endpoints, demonstrating consistency between static and dynamic analysis.

### Reflection (2-3 sentences)
In a real-world PR review, DAST evidence is arguably more valuable as it confirms the exploitability of the vulnerability in the running application. However, SAST remains essential for shifting security left and preventing vulnerabilities from ever reaching a deployable state.
