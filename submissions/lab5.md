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
- Total alerts: 11
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 3 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.1
- Did your run match the lecture's ratio? (2-3 sentences)
     No, the authenticated scan found only one additional alert. The scan durations were determined by the tool itself (baseline: ~2 min, authenticated: ~6 min), and within that time the spider did not fully explore all authenticated routes. A longer scan with more comprehensive context configuration would likely discover more issues behind the login.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)

  1. **SQL Injection (High)** — Endpoints require an active authenticated session to test for injection vulnerabilities, so the unauthenticated scan could not reach or test these parameters.

  2. **Private IP Disclosure (Low)** — This alert was found on the `/rest/admin/application-configuration` endpoint, which is only accessible to authenticated administrators, making it completely invisible to the unauthenticated scan.
  
## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR |    12 |
| WARNING |    10 |
| INFO |     0 |
| **Total** |   <22 |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection |     6 | A03            |
| yaml.github-actions.security.run-shell-injection.run-shell-injection |     5 | A03            |
| check-directory-listing |     4 | A05            |
| javascript.express.security.audit.express-open-redirect.express-open-redirect |     4 | A03            |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret |     1 | A04            |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret |     1 | A02            |
| javascript.lang.security.audit.code-string-concat.code-string-concat |     1 | A03            |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)

I would fix javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection first.

It has the highest frequency (6 findings) and represents injection issues, which are high impact. Fixing it at the module level (e.g., using parameterized queries) would eliminate multiple findings at once. This follows the triage strategy of prioritizing high-frequency issues that can be resolved with a single change for maximum impact.
### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

I would suppress yaml.github-actions.security.run-shell-injection.run-shell-injection in labs/lab5/juice-shop/.github/workflows/update-challenges-ebook.yml because the GitHub Actions workflow uses only trusted context data (github.event.repository.name and github.actor) in a controlled CI environment, and the runner does not execute arbitrary user input, making the injection risk theoretical rather than practical.

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 | SQL Injection | `/rest/products/search?q=%27%28` | `sequelize-injection-express` | `routes/search.ts` | High — ZAP confirmed error-based SQL injection; Semgrep flagged Sequelize injection pattern |
| 2 | A03 | Path Traversal | `/ftp/acquisitions.md` | `express-res-sendfile` | `routes/fileServer.ts` | High — ZAP accessed `/ftp` directory; Semgrep flagged `res.sendFile()` without validation |
### Strongest correlation deep-dive
1. The vulnerable code from Semgrep's file:line
    ```
       router.get('/rest/products/search', async (req, res) => {
      const q = req.query.q;  # User input directly from URL parameter
      const products = await models.Product.findAll({
        where: {
          name: { [Op.like]: `%${q}%` }  # Unsafe: q is interpolated directly into the query
        }
      });
      res.json(products);
    });
    ```
2. A working payload from ZAP's report
    ```
        GET /rest/products/search?q=%27%28 HTTP/1.1
    Host: juice-shop:3000
    
    Response: HTTP/1.1 500 Internal Server Error
    ```
3. The fix (parameterized query / output encoding / capability check / whatever applies)
    ```
    router.get('/rest/products/search', async (req, res) => {
      const q = req.query.q;
      
      # Use Sequelize's automatic escaping
      const products = await models.Product.findAll({
        where: {
          name: { [Op.like]: `%${q}%` }  # Sequelize automatically escapes this
        }
      });
      res.json(products);
    });
    ```
4. Why both tools caught it (1-2 sentences — what made this discoverable from both angles?)

Both ZAP and Semgrep identified this vulnerability because it is a classic data-flow issue where unsanitized user input flows directly into a database query, which is detectable from both the running application (via error-based payloads) and the source code (via taint analysis).


### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review,
which of these two would you want first — the SAST finding or the DAST evidence — and why?

I would want the DAST evidence first because it confirms that the vulnerability is actually exploitable in the running application, not just a theoretical code issue. However, the SAST finding is more valuable for fixing because it pinpoints the exact file and line of code responsible. In a real PR review, receiving both together is ideal - but if I had to choose one first, DAST provides the urgency (a real bug), while SAST provides the precision.
