# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

Tool: `threagile/threagile:0.9.1` (Docker, course-pinned).

> **Reproducibility note:** Threagile 0.9.1's Excel writer crashes on this model
> (`the sheet name length exceeds the 31 characters limit` — the model title is used as the
> sheet name and is longer than Excel's limit), which also aborts the run before the PDF is
> written. All runs below therefore disable the two Excel outputs, which lets `report.pdf`,
> `risks.json`, and the diagrams generate normally:
>
> ```bash
> docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
>   -model /app/work/threagile-model.yaml -output /app/work/output \
>   -generate-risks-excel=false -generate-tags-excel=false
> ```

## Task 1: Baseline Threat Model

### Risk count by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | **23** |

`jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json`:

```json
[
  { "severity": "elevated", "count": 4 },
  { "severity": "low",      "count": 5 },
  { "severity": "medium",   "count": 14 }
]
```

### Top 5 risks

Ranked by severity, then exploitation likelihood × impact from `risks.json` (the lab's
`sort_by(.severity)` jq sorts alphabetically, so I ranked by actual severity order instead):

1. **`unencrypted-communication`** — Unencrypted Communication named *Direct to App (no proxy)* between *User Browser* and *Juice Shop Application* transferring authentication data; severity **elevated** (likelihood likely, impact high); affecting `user-browser` → `juice-shop`
2. **`unencrypted-communication`** — Unencrypted Communication named *To App* between *Reverse Proxy* and *Juice Shop Application*; severity **elevated**; affecting `reverse-proxy` → `juice-shop`
3. **`cross-site-scripting`** — Cross-Site Scripting (XSS) risk at *Juice Shop Application*; severity **elevated**; affecting `juice-shop`
4. **`missing-authentication`** — Missing Authentication covering communication link *To App* from *Reverse Proxy* to *Juice Shop Application*; severity **elevated**; affecting `juice-shop`
5. **`server-side-request-forgery`** — SSRF risk at *Juice Shop Application* server-side requesting *Webhook Endpoint* via *To Challenge WebHook*; severity **medium** (likelihood likely); affecting `juice-shop`

### STRIDE mapping (Lecture 2 slide 7)

- Risk 1 (`unencrypted-communication`, browser→app): **I** (Information Disclosure) — session tokens and credentials cross the Internet→Container boundary in cleartext, so any on-path observer reads them.
- Risk 2 (`unencrypted-communication`, proxy→app): **I**, with **T** as a close second — the plaintext hop after TLS termination lets an on-host attacker not only read but also modify requests in transit (machine-in-the-middle).
- Risk 3 (`cross-site-scripting`): **T** (Tampering) — injected script tampers with the page served to other users; its usual payoff is token theft, i.e. it cascades into **S**.
- Risk 4 (`missing-authentication`): **S** (Spoofing) — the app accepts any request arriving on its port without the caller proving an identity, so anything that can reach port 3000 can impersonate the proxy (enables **E** on whatever those requests do).
- Risk 5 (`server-side-request-forgery`): **S** (Spoofing) — the attacker makes the *server* issue requests of the attacker's choosing, abusing the server's identity/network position to reach internal targets, which typically yields **I**.

### Trust boundary observation

In `data-flow-diagram.png`, the **`Direct to App (no proxy)` HTTP arrow from User Browser to
Juice Shop Application** crosses every boundary in the model in a single hop: Internet → Host →
Container Network. It appears in my top 5 as risk #1. It is the most attractive arrow for an
attacker because it bypasses the one control point the architecture has (the TLS-terminating,
header-adding reverse proxy) and carries the highest-value data asset (`tokens-sessions`,
i.e. live session identity) in cleartext across the untrusted network — read it once on any
intermediate hop and you own the session, no exploit required.

## Task 2: Secure Variant & Diff

Model: [`labs/lab2/threagile-model-secure.yaml`](../labs/lab2/threagile-model-secure.yaml)

### Hardening changes made

| # | Required change | Implementation in `threagile-model-secure.yaml` |
|---|---|---|
| 1 | Force HTTPS into the app | `Direct to App (no proxy)` link: `protocol: http` → `https` |
| 2 | Encrypt at rest | `Persistent Storage` (the DB/volume asset): `encryption: none` → `data-with-symmetric-shared-key` |
| 3 | TLS for outbound calls | The `To Challenge WebHook` egress link is **already `https` in the provided baseline** — verified, left as is. The remaining plaintext link (`Reverse Proxy` → app, "or similar") was changed `http` → `https` as the re-encrypted internal hop |
| 4 | Declare prepared statements | The baseline has **no app→storage communication link at all**, so the DB link was added (`To Persistent Storage`, `protocol: local-file-access`) with the description declaring parameterized queries / prepared statements via Sequelize bind parameters |
| 5 | Disable plain log writes | Log destinations encrypted: both `Juice Shop Application` (stores `logs`) and `Persistent Storage` get `encryption: data-with-symmetric-shared-key` |

One consistency fix that change #4 forced: Threagile flagged `wrong-communication-link-content`
because `local-file-access` requires target technology `local-file-system`, while the baseline
declared the host-mounted volume as `file-server`. Since it *is* a local mounted volume,
`technology: local-file-system` is the accurate value and was fixed in the secure variant.

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | −1 |
| Medium | 14 | 12 | −2 |
| Low | 5 | 4 | −1 |
| **Total** | **23** | **19** | **−4** |

Exact diff of risk `synthetic_id`s (5 gone, 1 new):

```
GONE  unencrypted-asset@juice-shop
GONE  unencrypted-asset@persistent-storage
GONE  unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop
GONE  unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop
GONE  unnecessary-technical-asset@persistent-storage
NEW   path-traversal@juice-shop@persistent-storage@juice-shop>to-persistent-storage
```

### Which rules are GONE in the secure variant?

1. `unencrypted-communication` (×2) — fixed by `protocol: https` on the browser→app and proxy→app links
2. `unencrypted-asset` (×2) — fixed by `encryption: data-with-symmetric-shared-key` on the Juice Shop app and Persistent Storage assets
3. `unnecessary-technical-asset` (Persistent Storage) — fixed as a side effect of adding the app→storage link: the storage was previously modeled as connected to nothing, so Threagile flagged it as removable

**And one rule is NEW:** `path-traversal` (elevated) now fires on the added app→storage link.
This is the exact pitfall the lab warns about — modeling a data flow that the baseline silently
omitted gave Threagile something real to analyze (and path traversal genuinely is a Juice Shop
vulnerability class). The model got *safer on paper and more honest at the same time*: net
elevated count only dropped from 4 to 3 because better modeling surfaced a risk the baseline hid.

### Which rules are STILL THERE in the secure variant?

1. **`missing-authentication`** (proxy→app, elevated) — encrypting the hop did nothing for authentication: HTTPS proves nothing about *who* is calling. The app still accepts any request that reaches port 3000 without the caller authenticating, so spoofing the proxy remains possible. Fixing it needs mutual TLS or service-to-service auth, not a protocol field flip.
2. **`cross-site-scripting`** (juice-shop, elevated) — XSS is an application-code defect (missing output encoding/CSP in a deliberately vulnerable app). No transport- or storage-level YAML field can remove it; it only goes away with code changes, which is exactly why it survives every infrastructure hardening pass.

(`server-side-request-forgery`, `cross-site-request-forgery`, `missing-vault`,
`missing-hardening`, and `missing-waf` also still fire, for the same structural reason:
they are code-, process-, or component-level gaps, not transport/at-rest settings.)

### Honesty check

No — the total dropped from 23 to 19, about **17%**, nowhere near 50%. That is the honest
shape of cheap hardening: five one-line YAML changes (TLS everywhere, disk encryption)
eliminate the *eavesdropping* class entirely, which is excellent cost-benefit — minutes of
work per risk. But the remaining 19 risks are mostly code-level (XSS, CSRF, SSRF, path
traversal) and process-level (build infrastructure, vault, hardening, WAF) findings, each of
which costs days-to-weeks of engineering rather than a field edit. The cheap declarative wins
are real but shallow; the curve of effort-per-risk-removed gets steep immediately after them —
and one of my "fixes" even *added* a risk by making the model more truthful.

## Bonus Task: Auth Flow Threat Model

Model: [`labs/lab2/threagile-model-auth.yaml`](../labs/lab2/threagile-model-auth.yaml) —
written from scratch (5 technical assets, 5 data assets, 6 communication links, 2 trust
boundaries, 1 shared runtime). It models Juice Shop's auth flow **as actually shipped**:
string-concatenated SQL in the login route, JWT signing key hardcoded in the source, token
kept in browser localStorage.

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 4 |
| Medium | 16 |
| Low | 5 |
| **Total** | **26** |

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **`sql-nosql-injection`** (high — the only high in either model) — STRIDE: **T** (tampering with query structure; cascades to **S**, since the classic payoff is `' OR 1=1--` login bypass) — Mitigation: replace the string-concatenated SQL in the login route with parameterized queries / Sequelize bind parameters so user input can never change the statement's structure. *The baseline model couldn't fire this rule at all: it had no database communication link, so there was no query for the rule to inspect.*
2. **`missing-identity-provider-isolation`** (elevated) — STRIDE: **E** (Elevation of Privilege) — Mitigation: isolate the credential store and token-signing component from the rest of the application (separate network segment, or better, delegate signing to a dedicated service/KMS) so that compromising any ordinary app component does not put the attacker next to the keys to every identity.
3. **`missing-vault`** (medium, flagged at the Token Service) — STRIDE: **I** (disclosure of the signing key; what the attacker *does* with it is **E**) — Mitigation: move the JWT signing key out of the application source code into a secrets vault/KMS with rotation; in the focused model the key is declared as its own strictly-confidential data asset, which is what makes this finding concrete rather than generic.

(`missing-authentication-second-factor` also fires three times across the login, API, and
admin links — STRIDE **S**, mitigated by 2FA plus rate limiting — a fourth auth finding the
baseline's top 5 never mentions.)

### Reflection

The focused model found a strictly worse picture than the architecture model — 26 risks
versus 23, including the only *high* — precisely because zooming in forced me to model things
the baseline abstracted away: the credential query as a real communication link, and the
signing key as a real data asset. Architecture-level models compress "the app" into one box,
so rules that need to see *inside* the box (SQL injection, key management, IdP isolation)
physically cannot fire. Feature-level threat modeling is how those rules get something to
chew on — which is why it belongs in the review of every security-critical feature, not just
in the one-time architecture review.

## How this was generated

```bash
# Baseline
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml -output /app/work/output \
  -generate-risks-excel=false -generate-tags-excel=false

# Secure variant
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure \
  -generate-risks-excel=false -generate-tags-excel=false

# Auth-flow model
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml -output /app/work/output-auth \
  -generate-risks-excel=false -generate-tags-excel=false

# Counts / diffs
jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json
jq -r '.[] | .synthetic_id' labs/lab2/output/risks.json | sort > /tmp/base-ids.txt
jq -r '.[] | .synthetic_id' labs/lab2/output-secure/risks.json | sort > /tmp/secure-ids.txt
comm -3 /tmp/base-ids.txt /tmp/secure-ids.txt
```

Output directories (`labs/lab2/output*/`) are gitignored per the lab instructions; each run
produces `report.pdf`, `risks.json`, `stats.json`, `technical-assets.json`, and both diagrams.
