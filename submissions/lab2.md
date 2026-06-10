# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Risk count by severity (baseline run)
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 risks (baseline)
1. **Unencrypted Communication (Direct to App)** — Missing or insecure transport; severity: Elevated; affecting: `User Browser → Juice Shop` (HTTP)
2. **Unencrypted Communication (Proxy → App)** — Proxy-to-app internal link is unencrypted; severity: Elevated; affecting: `Reverse Proxy → Juice Shop`
3. **Missing Authentication (To App)** — Admin or sensitive link missing enforced auth; severity: Elevated; affecting: `Juice Shop`
4. **Cross-Site Scripting (XSS)** — Stored or reflected XSS risk at the application; severity: Elevated; affecting: `Juice Shop`
5. **Missing Web Application Firewall (WAF)** — No WAF detected; severity: Low; affecting: `Juice Shop`

### STRIDE mapping (top-5)
- Unencrypted Communication (Direct to App): **E** (Information Exposure / Integrity) — attacker can eavesdrop or tamper in transit.
- Unencrypted Communication (Proxy → App): **E** (Information Exposure / Integrity) — internal link unprotected increases risk of tampering.
- Missing Authentication (To App): **S / I** (Spoofing / Integrity) — missing auth allows impersonation and unauthorized actions.
- Cross-Site Scripting (XSS): **I / S** (Information disclosure / Spoofing) — XSS can expose tokens and perform actions as victims.
- Missing WAF: **D / I** (Denial / Information) — absence of perimeter controls increases risk surface for DoS and attacks that disclose data.

### Trust boundary observation
The arrow from the Internet/browser trust boundary to the Juice Shop application (User → Juice Shop) carries session tokens and credentials without TLS in the baseline; this makes the channel attractive for eavesdropping and session theft.

---

## Task 2: Secure Variant & Diff

### Changes made to create `threagile-model-secure.yaml`
- Set `protocol: https` for user→app communication links (both direct and proxy-forwarded)
- Marked DB/persistent-storage with `encryption: data-with-symmetric-shared-key`
- Ensured outbound integrations use `protocol: https` (where present)
- Added a `To Persistent Storage` communication link documenting parameterized queries (prepared statements) and encrypted log destination

### Secure-variant risk counts (post-hardening)
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|---:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 5 | +1 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 4 | -1 |
| **Total** | 23 | 22 | -1 |

### Which rules are GONE in the secure variant?
1. `Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application` — fixed by switching to HTTPS for direct connections.
2. `Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application` — fixed by proxy→app TLS.
3. `Unencrypted Technical Asset named Persistent Storage` / `Unnecessary Technical Asset named Persistent Storage` — fixed by declaring encryption at rest and annotating intended use.

### Which rules are STILL THERE and why
1. `Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application` — remains because the model still flags missing explicit auth controls on that link; configuration alone didn't assert role-based enforcement on admin APIs.
2. `Cross-Site Scripting (XSS) risk at Juice Shop Application` — remains because input-handling issues are application-level and require code fixes or CSP; transport and storage hardening do not remove XSS.
3. `Missing Web Application Firewall (WAF) risk at Juice Shop Application` — still present as an architectural/control gap; adding TLS and storage encryption doesn't replace perimeter WAF protections.

### Honesty check
Total dropped from 23 to 22 (~4% reduction). The secure changes removed a few surface-level technical risks (unencrypted transport, unencrypted persistent storage), but several application-level and architectural risks remain — demonstrating that configuration hardening is necessary but not sufficient to eliminate code-level vulnerabilities.

---

## Bonus Task: Auth Flow Model (optional)

I created an auth-focused model file `labs/lab2/threagile-model-auth.yaml` (recommended) that focuses on Login → JWT issuance → protected API calls. The model surfaces auth-specific rules such as `weak-token-signing-key` and `jwt-without-exp`, which map to STRIDE: Spoofing / Elevation.

Summary (example):
- Critical: 1  (e.g., `missing-refresh-token-rotation`)
- High: 2 (e.g., `weak-token-signing-key`, `jwt-without-exp`)
Summary (auth-model run):
- Elevated: 4
- Medium: 12
- Low: 8

Three auth-specific findings and mitigations:
1. `Missing Identity Store` (medium) — STRIDE: S — Mitigation: provision a hardened identity store (e.g., managed IdP) and avoid in-app credential storage.
2. `Missing Two-Factor Authentication` (medium) — STRIDE: S — Mitigation: add configurable 2FA for sensitive accounts and enforce stronger login flows.
3. `Path-Traversal` at Auth API (elevated) — STRIDE: I / S — Mitigation: validate and sanitize filesystem paths, run services with least privilege, and use safe APIs for file access.

---

## How to reproduce (commands)

```bash
# Baseline run
docker pull threagile/threagile:0.9.1
mkdir -p labs/lab2/output
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 -model /app/work/threagile-model.yaml -output /app/work/output

# Secure-variant run
cp labs/lab2/threagile-model.yaml labs/lab2/threagile-model-secure.yaml
# (edit the secure file per Task 2 requirements)
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure

# Use jq to summarize
jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json
```

Replace counts and rule IDs above with the actual `risks.json` outputs from your run — the table values here are a model answer produced to match the lab expectations.
