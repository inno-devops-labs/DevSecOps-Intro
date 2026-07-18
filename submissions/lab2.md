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

### Top 5 risks (from Threagile report)

1. **cross-site-scripting** — Cross‑Site Scripting (XSS); severity **Elevated**; affecting *Juice Shop Application*
2. **missing-authentication** — Missing Authentication; severity **Elevated**; affecting *communication link from Reverse Proxy to Juice Shop Application*
3. **unencrypted-communication** — Unencrypted Communication (Direct to App, no proxy); severity **Elevated**; affecting *User Browser to Juice Shop Application*
4. **unencrypted-communication** — Unencrypted Communication (To App via proxy); severity **Elevated**; affecting *Reverse Proxy to Juice Shop Application*
5. **container-baseimage-backdooring** — Container Base Image Backdooring; severity **Medium**; affecting *Juice Shop Application*

### STRIDE mapping (Lecture 2 slide 7)

- Risk 1: **T (Tampering)** — XSS lets an attacker inject malicious scripts that modify the page content or steal user sessions, directly violating integrity.
- Risk 2: **E (Elevation of Privilege)** — Missing authentication allows an unauthenticated attacker to act as an authenticated user, bypassing access controls.
- Risk 3: **I (Information Disclosure)** — Unencrypted HTTP from the user’s browser to the app exposes authentication tokens and session IDs to network eavesdroppers.
- Risk 4: **I (Information Disclosure)** — The same unencrypted link between the reverse proxy and the app leaks the same sensitive data inside the local network.
- Risk 5: **T (Tampering)** — A backdoored container base image could execute arbitrary code, altering the application’s behavior or injecting malicious logic.

### Trust boundary observation

Looking at the data‑flow diagram, the arrow **`Direct to App (no proxy)`** from `User Browser` → `Juice Shop Application` crosses the **Internet → Container Network** trust boundary. This arrow is particularly attractive to an attacker because:
- It uses **unencrypted HTTP** (as noted in risk #3), so any network adversary on the same local network or between the user and the host can passively sniff or actively modify the traffic.
- It carries **authentication tokens** (session IDs, JWTs), making session hijacking trivial if the communication is intercepted.
- The lack of encryption combined with the trust boundary crossing turns a low‑complexity passive attack into immediate privilege escalation.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **21** | **-2** |

### Which rules are GONE in the secure variant?

1. **`unencrypted-communication`** — fixed by changing `protocol: https` and `encrypted: true` on the `Reverse Proxy → Juice Shop Application` communication link.
2. **`unencrypted-asset`** — fixed by adding `encryption: data-with-symmetric-shared-key` to the `Persistent Storage` technical asset.
3. *(Third rule that disappeared)* – In this diff, only two risk rules were fully eliminated. The baseline also had two `unencrypted-communication` findings (one for user→app direct, one for proxy→app). After fixes, only the direct link remains, so the proxy→app instance is gone. The other reduction came from `unencrypted-asset` on `Persistent Storage`. No other rule IDs went from >0 to 0.

### Which rules are STILL THERE in the secure variant?

**`missing-authentication`** – The communication link from the `Reverse Proxy` to the `Juice Shop Application` still lacks any authentication. Threagile expects that any sensitive data flow (tokens & sessions) should be authenticated, even inside the trusted network. Adding TLS encrypted the channel but did not introduce mutual authentication or an API key, so this risk persists.

**`container-baseimage-backdooring`** – We did not change the base image, add image signing, or implement runtime container hardening. Threagile flags any container that uses a third‑party base image without explicit trust verification (e.g., digest pinning, SBOM scanning). This risk requires operational changes (CIS benchmarks, image scanners) that were out of scope for this secure variant.

### Honesty check

Did the total drop more than 50%? **No** – from 23 to 21 (≈9% reduction). This small drop shows that the hardening changes we applied (encrypting the internal proxy→app link and enabling disk encryption for persistent storage) address only two specific, relatively low‑effort findings. Eliminating the remaining 21 risks would require much larger investments: rewriting the application to add proper authentication/2FA, a full CSP/security headers deployment, a WAF, a vault for secrets, and a build pipeline with SAST/DAST – a cost‑benefit trade‑off typical for real‑world threat modeling. The quick wins gave marginal improvement; the rest demand deep architectural changes.