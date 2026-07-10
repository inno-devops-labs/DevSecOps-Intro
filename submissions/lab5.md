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
- Duration: 7 minutes
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2x
- Did your run match the lecture's ratio? No. Lecture 5 slide 11 says authenticated DAST often finds 10-20x more issues because it can reach functionality behind login. My run reported 12 unique alert types in the authenticated scan vs. 10 in the unauthenticated baseline scan. However, authenticated scanning still improved coverage: it found findings on 22 unique URLs instead of 14 and discovered a High severity SQL Injection alert that was absent from the baseline report.

Authenticated-only alerts:

- **Session ID in URL Rewrite - Medium**

  Reason: the authenticated AJAX crawl established an application session and exercised Socket.IO traffic with a `sid` parameter (`http://juice-shop:3000/socket.io/?EIO=4&transport=polling&t=Py37uc9&sid=ZdK-TbhR0KkIMzCpAAHU`); the unauthenticated baseline crawl did not create the same logged-in browser session flow.

- **Private IP Disclosure - Low**

  Reason: this finding was on an admin/configuration API path (`http://juice-shop:3000/rest/admin/application-configuration`) that disclosed `192.168.99.100:3000`; the unauthenticated baseline scan did not crawl that authenticated application area.

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
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03:2021 - Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03:2021 - Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A06:2017 - Security Misconfiguration / A01:2021 - Broken Access Control |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A04:2021 - Insecure Design |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01:2021 - Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07:2021 - Identification and Authentication Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03:2021 - Injection |

### Triage shortcut (Lecture 5 slide 8)
I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It is the most frequent rule in the report, has `ERROR` severity, maps to OWASP A03 Injection, and appears in real runtime routes such as `routes/search.ts:23` and `routes/login.ts:34`. It also lines up with the authenticated ZAP SQL Injection finding, so this is higher-confidence than a SAST-only result.

### False-positive sample
I would suppress `labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5` for rule `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`: this file is a static training/code-fix snippet under `data/static/codefixes`, not the live Express route handling production traffic, so it is not a runtime vulnerability in the deployed app.
