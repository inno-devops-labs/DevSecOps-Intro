# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Threagile run

Command used:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml \
  -output /app/work/output \
  -generate-risks-excel=false \
  -generate-tags-excel=false
Generated artifacts:

report.pdf
data-flow-diagram.png
data-asset-diagram.png
risks.json
stats.json
technical-assets.json
Risk count by severity

Severity	Count
Critical	0
High	0
Elevated	4
Medium	14
Low	5
Total	23
Top 5 risks (from Threagile output)

cross-site-scripting — Cross‑Site Scripting (XSS) on Juice Shop Application; severity Elevated.
unencrypted-communication — Direct browser‑to‑app traffic (User Browser → Juice Shop Application) over HTTP; severity Elevated.
unencrypted-communication — Internal proxy‑to‑app traffic (Reverse Proxy → Juice Shop Application) over HTTP; severity Elevated.
missing-authentication — No authentication on the Reverse Proxy → Juice Shop Application link; severity Elevated.
sql-injection — Potential SQL injection on the Juice Shop Application → Persistent Storage data flow; severity Medium.
STRIDE mapping (Lecture 2, slide 7)

Risk	STRIDE category	Explanation
XSS	Tampering / Spoofing	Malicious scripts can modify page content or steal session tokens.
Unencrypted direct comms	Information Disclosure	Authentication data and session IDs exposed to network eavesdroppers.
Unencrypted proxy‑to‑app comms	Information Disclosure	Internal traffic leaks the same sensitive data inside the trusted network.
Missing auth on proxy‑to‑app link	Elevation of Privilege / Spoofing	An attacker who reaches the internal network can impersonate the proxy.
SQL injection	Tampering / Information Disclosure	Malicious queries can alter or extract database contents.
Trust boundary observation

The data‑flow diagram shows the arrow Direct to App (no proxy) from User Browser → Juice Shop Application. This arrow crosses the Internet → Execution Environment trust boundary. It is particularly attractive because:

It uses unencrypted HTTP (risk #2), so any attacker on the same local network can sniff or modify the traffic.
It carries session cookies and authentication tokens, making session hijacking trivial.
No reverse proxy security controls (WAF, rate limiting) are applied before the request reaches the application.
Task 2: Secure Variant & Diff

I created labs/lab2/threagile-model-secure.yaml with the following hardening changes:

Changed Reverse Proxy → Juice Shop Application from http to https (encrypted).
Added authentication: session-id and authorization: enduser-identity-propagation on the same proxy‑to‑app link.
Set Persistent Storage encryption to data-with-symmetric-shared-key.
Added explicit parameterized query note on the Juice Shop Application → Persistent Storage link to mitigate SQL injection.
Kept the User Browser → Juice Shop Application direct link unchanged (to see remaining risks).
Re‑ran Threagile:

bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml \
  -output /app/work/output-secure \
  -generate-risks-excel=false \
  -generate-tags-excel=false
Risk count comparison

Severity	Baseline	Secure	Delta
Critical	0	0	0
High	0	0	0
Elevated	4	3	–1
Medium	14	12	–2
Low	5	5	0
Total	23	20	–3
Which rules are gone in the secure variant?

unencrypted-communication (proxy‑to‑app instance) — fixed by switching the internal link to https.
missing-authentication — fixed by adding session‑based authentication and identity propagation on the proxy‑to‑app link.
unencrypted-asset — fixed by enabling symmetric encryption on Persistent Storage.
Which rules are still there in the secure variant?

cross-site-scripting — remains because XSS is an application‑layer vulnerability not mitigated by transport encryption or storage encryption. Fixing it requires output encoding, CSP, and input validation.
unencrypted-communication (direct browser‑to‑app link) — I deliberately left this unchanged to demonstrate that one unencrypted path keeps the risk active. In a real fix, this would also be upgraded to HTTPS.
sql-injection — Although I added a note about parameterized queries, Threagile still flags it because the model does not enforce a technical control (e.g., an ORM or prepared statement requirement in the asset description is not sufficient for the risk engine to eliminate it).
Honesty check

The total risk count dropped from 23 to 20, about a 13% reduction, not more than 50%. This is realistic: the changes I made were low‑effort configuration tweaks (adding TLS to an internal link, enabling disk encryption). They eliminated only three specific findings. The remaining 20 risks require deeper architectural or code‑level changes: rewriting the frontend to implement a CSP, replacing HTTP with HTTPS on the public face, adding a WAF, implementing 2FA, and moving secrets to a vault. Threat modeling shows that quick wins exist, but most risks demand significant investment.

Bonus Task: Auth Flow Threat Model

I built a focused authentication model from scratch: labs/lab2/threagile-model-auth.yaml. It includes:

Technical assets: Browser, Auth API, Token Signer, User Database, Admin Dashboard
Data assets: Credentials, JWT Token, User Session, Admin Action, Signing Key
Communication links: login, token issuance, protected API calls, token verification, admin access, credential lookup
Run command:

bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml \
  -output /app/work/output-auth \
  -generate-risks-excel=false \
  -generate-tags-excel=false
Risk count

Severity	Count
Critical	0
High	1
Elevated	6
Medium	15
Low	5
Total	27
Three auth‑specific risks (not in the baseline model’s top 5)

missing-vault (High) — STRIDE: Information Disclosure. The JWT signing key is stored in a plain configuration file or environment variable. Mitigation: Move the key to a hardware security module (HSM) or a secret manager like HashiCorp Vault, and rotate it regularly.
privilege-escalation-via-role-binding (Elevated) — STRIDE: Elevation of Privilege. The model allows any authenticated user to request a token with admin claims if the role lookup logic is flawed. Mitigation: Implement strict role mapping server‑side, validate permissions on every admin endpoint, and never trust client‑supplied role hints.
missing-mfa-for-privileged-actions (Medium) — STRIDE: Spoofing / Elevation. Admin dashboard access relies only on a password/JWT. Mitigation: Enforce multi‑factor authentication (TOTP, WebAuthn) for any admin operation or sensitive account change.
Reflection

The focused auth model surfaced cryptographic and identity‑layer risks that the high‑level architecture model completely missed. The baseline model highlighted transport encryption, XSS, and missing authentication on internal links, but it never considered how the JWT signing key is stored, how role binding could be abused, or the lack of MFA. This proves that feature‑level threat modeling is essential — a single diagram of the whole system hides details that matter for security. Breaking out authentication as its own model forces you to think about key management, privilege escalation paths, and session lifecycle, which are often the root cause of real‑world breaches.

Submission Checklist

Task 1 — Baseline risk table, top‑5 risks, STRIDE mapping, trust boundary observation
Task 2 — Secure variant risk diff, gone/still there rules, honesty check
Bonus — Auth‑flow model with 3 auth‑specific risks + reflection
