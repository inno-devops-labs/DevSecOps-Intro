# Lab 5 — SAST and DAST: Reading the Code, Then Watching It Run

Target: `bkimminich/juice-shop:v20.0.0`. Tools: ZAP `stable` (Automation Framework), Semgrep 1.176.0. Source cloned at tag `v20.0.0`.

## Task 1

### Alert counts by risk level and duration

| Risk | Unauthenticated baseline | Authenticated full scan |
|------|------------------------:|------------------------:|
| High | 0 | **2** |
| Medium | 2 | 4 |
| Low | 5 | 3 |
| Info | 3 | 4 |
| **Total** | **10** | **13** |
| Unique URLs with findings | 16 | 24 |
| Wall-clock | ~2 min (119 s) | ~4 min (active scan capped at 10 min) |

### Which run found more, and which found the more serious ones
The **authenticated** run reported more alerts (13 vs 10) **and** found the more serious ones. The decisive detail is the highest risk level in each: the passive baseline topped out at **Medium (0 High)**, while the authenticated active scan surfaced **2 High** — a **SQL Injection** on `/rest/products/search` and a **Vulnerable JS Library**. So even a comparable total hides a qualitative gap: only the authenticated+active run reached the injectable, high-impact bug.

### Two authenticated-only alerts
1. **SQL Injection (High)** — `http://juice-shop:3000/rest/products/search?q=%27%28` (param `q`, attack `'(`, evidence `HTTP/1.1 500`). The baseline is *passive*: it only observes traffic and never sends an attack payload, so it can't trigger an injection that only manifests when the scanner actively appends `'(` to the query — only the active scan issues that malicious request.
2. **Private IP Disclosure (Low)** — `http://juice-shop:3000/rest/admin/application-configuration`. This config endpoint is surfaced through the admin area; the authenticated spider (logged in as `admin@juice-sh.op`) crawled the admin-linked surface and enumerated it, whereas the anonymous baseline crawl never reached the links that lead there.

### Why "number of alerts" is a bad comparison
The two totals (10 vs 13) are almost the same, yet they describe very different security postures: the passive baseline pads its count with per-URL header/caching **Info and Low** noise it re-reports on every page it sees, while the authenticated active scan spends its budget on a smaller surface and finds the one **High** that actually matters. Counting alerts rewards the noisier scan, not the more dangerous findings. To a team lead I'd report **the highest severity reached and the specific High/Medium findings with their endpoints** (here: an exploitable SQL injection on product search), not a total. The implication for a pipeline whose only DAST step is `zap-baseline.py` against staging is stark: it is passive and unauthenticated, so it would have shown **0 High and missed the SQL injection entirely** — a baseline-only gate gives false confidence; real coverage needs an authenticated active scan.

## Task 2

### Severity split, rule table, error count

Severity: **13 ERROR, 14 WARNING** (27 findings total). Parse errors: **38** (expected — timeouts/syntax on some TS files, does not invalidate the run).

Top rules by count:

| n | Rule |
|--:|------|
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell` |

### A workflow-file rule and its Lecture 4 link
`yaml.github-actions.security.run-shell-injection.run-shell-injection` fires on `.github/workflows/update-challenges-www.yml:27` (and `:36`, plus `update-challenges-ebook.yml:22`). It flags interpolating untrusted context (e.g. `${{ github.event... }}`) directly into a `run:` shell block — arbitrary command execution in CI. This is exactly Lecture 4's thesis that **the pipeline is an attackable system**: a workflow that expands attacker-influenced input into a shell step can be hijacked to run code on the runner, steal `GITHUB_TOKEN`/secrets, or poison artifacts — a CI/CD injection risk, not an app bug. (`github-actions-mutable-action-tag`, flagging `uses: actions/x@v4` instead of a pinned SHA, is the same lecture's supply-chain-pinning point.)

### A finding I would suppress as a false positive
**File `routes/keyServer.ts`, line 14, rule `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`.**
```ts
const file = params.file
if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))   // line 14, flagged
}
```
The rule warns that a non-literal argument to `res.sendFile` enables path traversal. Here it is wrong for *this* code: the argument is guarded by `if (!file.includes('/'))`, which rejects any input containing a slash before the `sendFile` is reached, and the base is a fixed `encryptionkeys/` directory. Without a `/` you cannot form a `../` traversal sequence, so an attacker cannot escape the directory — the traversal the rule predicts is unreachable. (Contrast `routes/fileServer.ts:33`, flagged by the same rule, which *is* the real path-traversal / poison-null-byte challenge and should **not** be suppressed.)

### One rule's worth of findings to fix this sprint
**`express-sequelize-injection`** (6 findings, and the top rule). It is the highest-severity class that maps to a live, demonstrated exploit — the same product-search SQL injection ZAP confirmed at runtime (below). Fixing it means replacing raw string-interpolated `sequelize.query()` calls with parameterized/bound queries in `routes/search.ts` and `routes/login.ts`, which closes an actual A03 Injection path rather than a theoretical one. (The `data/static/codefixes/` hits from this rule are teaching snippets and are excluded from that count of real app code.)

## Bonus — One bug, two tools

| OWASP | ZAP alert (URL) | Semgrep rule (`file:line`) |
|-------|-----------------|----------------------------|
| **A03 Injection** | SQL Injection (High) — `GET /rest/products/search?q=%27%28` | `express-sequelize-injection` — `routes/search.ts:23` |

### Strongest row
**Vulnerable source (`routes/search.ts:23`):**
```ts
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```
`criteria` comes straight from `req.query.q` and is interpolated into the SQL string — a textbook injection.

**The request ZAP used:** `GET http://juice-shop:3000/rest/products/search?q='(` (param `q`, payload `'(`), which broke the query and returned `HTTP/1.1 500 Internal Server Error` — ZAP's evidence the input reaches the SQL parser (CWE-89).

**The fix I would PR:** stop building SQL by string interpolation; use a bound/parameterized query so the input is data, never SQL:
```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { q: `%${criteria}%` }, model: ProductModel, type: QueryTypes.SELECT }
)
```

### What goes first in the PR
The **SQL injection** goes first. It is the only finding both tools reached independently — Semgrep proving it exists in the source and ZAP proving it is exploitable on the running app — so it is corroborated from two directions and carries the highest impact (full read of the products/users tables via UNION). Header and library findings are real but secondary to a confirmed injection that leaks data.
