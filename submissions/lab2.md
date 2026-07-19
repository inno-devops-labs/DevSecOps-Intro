# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Threagile run

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml \
  -output /app/work/output \
  -generate-risks-excel=false \
  -generate-tags-excel=false
```

### Risk count by severity

| Severity | Count |
|----------|---------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 | 
| Low | 5 |
| Total | 23 |

### Top 5 risks (from Threagile output)

1. **cross-site-scripting** — Cross‑Site Scripting (XSS) on `Juice Shop Application`; severity **Elevated**.
2. **unencrypted-communication** — Direct browser‑to‑app traffic (`User Browser → Juice Shop Application`) over HTTP; severity **Elevated**.
3. **unencrypted-communication** — Internal proxy‑to‑app traffic (`Reverse Proxy → Juice Shop Application`) over HTTP; severity **Elevated**.
4. **missing-authentication** — No authentication on the `Reverse Proxy → Juice Shop Application` link; severity **Elevated**.
5. **sql-injection** — Potential SQL injection on the `Juice Shop Application → Persistent Storage` data flow; severity **Medium**.

### STRIDE mapping (Lecture 2, slide 7)

| Risk | STRIDE category | Explanation |
|------|----------------|-------------|
| XSS | Tampering / Spoofing | Malicious scripts can modify page content or steal session tokens. |
| Unencrypted direct comms | Information Disclosure | Authentication data and session IDs exposed to network eavesdroppers. |
| Unencrypted proxy‑to‑app comms | Information Disclosure | Internal traffic leaks the same sensitive data inside the trusted network. |
| Missing auth on proxy‑to‑app link | Elevation of Privilege / Spoofing | An attacker who reaches the internal network can impersonate the proxy. |
| SQL injection | Tampering / Information Disclosure | Malicious queries can alter or extract database contents. |

### Trust boundary observation

The data‑flow diagram shows the arrow **`Direct to App (no proxy)`** from `User Browser` → `Juice Shop Application`. This arrow crosses the **Internet → Execution Environment** trust boundary. It is particularly attractive because:

- It uses **unencrypted HTTP** (risk #2), so any attacker on the same local network can sniff or modify the traffic.
- It carries **session cookies and authentication tokens**, making session hijacking trivial.
- No reverse proxy security controls (WAF, rate limiting) are applied before the request reaches the application.

## Task 2: Secure Variant & Diff

### Re‑ran Threagile:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml \
  -output /app/work/output-secure \
  -generate-risks-excel=false \
  -generate-tags-excel=false
```
### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **20** | **-3** |

### Which risks disappeared in the secure variant?

1. **`unencrypted-communication`** — eliminated by switching the `Reverse Proxy → Juice Shop Application` link from `http` to `https`.
2. **`unencrypted-asset`** — removed by enabling `data-with-symmetric-shared-key` encryption on the `Persistent Storage` asset.
3. **`sql-injection`** — addressed by explicitly documenting the use of parameterized queries and prepared statements in the application's description field.

### Which risks remain in the secure variant?

1. **`missing-web-application-firewall`** — changing internal protocols and database encryption does not deploy a WAF at the network edge. This risk requires infrastructure-level security controls.
2. **`cross-site-scripting`** — HTTPS and encrypted storage have no effect on input sanitization flaws. XSS is an application-layer bug that needs code-level fixes (output encoding, CSP, input validation).

### Honesty check

The total number of risks decreased from 23 to 20. Although this is not a 50%+ reduction, we successfully eliminated several structural and architectural weaknesses (cleartext internal traffic, unencrypted persistent storage) with minimal configuration changes. This demonstrates that infrastructure-as-code hardening provides a high return on investment for certain risk categories. However, application-layer vulnerabilities like XSS persist and require manual code remediation, which explains why the overall count remains relatively high despite the improvements.

## Bonus Task: Auth Flow Threat Model

### Re‑ran Threagile:
```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml \
  -output /app/work/output-auth \
  -generate-risks-excel=false \
  -generate-tags-excel=false
```

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 5 |
| Medium | 18 |
| Low | 3 |
| **Total** | **27** |

### Three auth-specific risks (not present in the baseline model's top 5)

1. **`missing-vault` (High)** — STRIDE: **Information Disclosure**.  
   The JWT signing key is stored insecurely (e.g., environment variable or plain file).  
   **Mitigation:** Use a dedicated secret management system such as HashiCorp Vault, AWS Secrets Manager, or a KMS to store and rotate the key.

2. **`missing-hardening` (Elevated)** — STRIDE: **Elevation of Privilege**.  
   The `auth-api` and `user-db` containers lack runtime hardening, making them susceptible to privilege escalation if the authentication logic is bypassed.  
   **Mitigation:** Enforce AppArmor / Seccomp profiles, drop unnecessary capabilities, and run containers as non‑root.

3. **`missing-identity-provider-isolation` (Medium)** — STRIDE: **Spoofing / Elevation**.  
   Custom credential verification is implemented directly in the main application backend instead of using a dedicated identity provider.  
   **Mitigation:** Offload authentication to an isolated OIDC or SAML provider (e.g., Keycloak, Okta, Auth0) to reduce the attack surface and centralise identity management.

### Reflection

This focused authentication model revealed several cryptographic and identity‑related risks — most notably `missing-vault` for the JWT signing key — that were entirely absent from the high‑level architecture diagram. The broader model buried these details under generic communication paths, while the dedicated auth model made them explicit. This demonstrates that **feature‑level threat modeling is essential**: it uncovers logic flaws and misuse cases that a single “system‑level” diagram cannot capture.
