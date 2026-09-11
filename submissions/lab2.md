# Lab 2 — Submission

## Task 1: Baseline Threat Model

Tool: Threagile v0.9.1 (Docker image `threagile/threagile:0.9.1`), run against the
provided `labs/lab2/threagile-model.yaml`. Counts below are taken directly from
`labs/lab2/output/risks.json`.

### Risk count by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | **23** |

### Top 5 risks

1. **`cross-site-scripting`** — *Cross-Site Scripting (XSS) risk at Juice Shop Application*; severity **elevated**; asset **juice-shop**.
2. **`unencrypted-communication`** — *Unencrypted Communication "Direct to App (no proxy)" between User Browser and Juice Shop Application, transferring authentication data (credentials, token, session-id)*; severity **elevated**; asset **user-browser**.
3. **`unencrypted-communication`** — *Unencrypted Communication "To App" between Reverse Proxy and Juice Shop Application*; severity **elevated**; asset **reverse-proxy**.
4. **`missing-authentication`** — *Missing Authentication covering communication link "To App" from Reverse Proxy to Juice Shop Application*; severity **elevated**; asset **juice-shop**.
5. **`missing-waf`** — *Missing Web Application Firewall (WAF)</b> risk at <b>Juice Shop Application*; severity **low**; asset **juice-shop**.

### STRIDE mapping (Lecture 2 slide 7)

- **Risk 1 — XSS:** **T** (Tampering) — attacker-controlled script alters the page rendered in the victim's browser; secondary **I** (Information Disclosure) by stealing session tokens.
- **Risk 2 — Unencrypted comm carrying credentials:** **I** (Information Disclosure) — cleartext HTTP lets anyone on the path read credentials/session IDs.
- **Risk 3 — Unencrypted comm proxy→app:** **I** (Information Disclosure) — internal traffic is sniffable; also **T** if an attacker on the host network rewrites it.
- **Risk 4 — Missing authentication:** **S** (Spoofing) — without auth on the link, a caller can impersonate a legitimate client; secondary **E** (Elevation of Privilege).
- **Risk 5 — SSRF:** **I** (Information Disclosure) — the app can be coerced into requesting internal resources; secondary **E** by reaching otherwise-protected endpoints.

### Trust boundary observation

In `data-flow-diagram.png`, the **User Browser → Juice Shop Application** arrow (the "Direct to App (no proxy)" link, labelled **`http`**) crosses  wo trust boundaries — **Internet → Host → Container Network** — to reach the app in plain text, carrying authentication data (Risk 2). By contrast, the parallel User Browser → Reverse Proxy arrow is `https`. This unencrypted arrow is especially attractive to an attacker because it is high value and low effort: anyone observing the network path (shared Wi-Fi, compromised router, ARP spoofing) can read credentials and session tokens in  leartext, with no TLS to defeat — instant account takeover without touching application logic.

## Task 2: Secure Variant & Diff
 
Hardened model: `labs/lab2/threagile-model-secure.yaml`. Changes applied (5):
 
1. **HTTPS user→app** — `Direct to App (no proxy)` link `protocol: http → https`.
2. **TLS proxy→app** — `To App` link `protocol: http → https`.
3. **Authenticated proxy→app** — `To App` link `authentication: none → client-certificate`, `authorization: none → technical-user`.
4. **Encrypt at rest** — `persistent-storage` `encryption: none → data-with-symmetric-shared-key`; `juice-shop` `encryption: none → transparent`.
5. **Prepared statements declared** — note added to the Juice Shop description that all DB access uses parameterized/prepared statements.
(The outbound WebHook link was already `https` in the baseline, so no change was needed there.)
 
### Risk count comparison
 
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | −3 |
| Medium | 14 | 12 | −2 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **−5** |
 
### Which rules are GONE in the secure variant?
 
1. **`unencrypted-communication`** (elevated, ×2) — fixed by setting `protocol: https` on both the `Direct to App (no proxy)` and `To App` links.
2. **`missing-authentication`** (elevated, ×1) — fixed by adding `authentication: client-certificate` + `authorization: technical-user` to the `To App` link.
3. **`unencrypted-asset`** (medium, ×2) — fixed by `encryption: data-with-symmetric-shared-key` on `persistent-storage` and `transparent` on `juice-shop`.
 
### Which rules are STILL THERE in the secure variant?
 
1. **`cross-site-scripting`** (elevated) — still fires because XSS is an application-code defect. Encrypting transport and storage or authenticating links does nothing for content rendered in the victim's browser, only code-level fixes in the app remove it.
2. **`server-side-request-forgery`** (medium, ×2) — still fires because the app still issues outbound requests. SSRF is about the app validating where it connects; switching that link to HTTPS encrypts the call but doesn't stop the app being coerced into reaching internal resources.
 
### Honesty check
 
The total dropped from 23 to 18 — about **−22%**, so not more than 50%.