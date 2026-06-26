# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Threagile run

```pwsh
docker run --rm `                                                                                      
>>   -v "${PWD}/labs/lab2:/app/work" `
>>   threagile/threagile:0.9.1 `
>>   -model /app/work/threagile-model.yaml `
>>   -output /app/work/output `
>>   -generate-risks-excel=false `
>>   -generate-tags-excel=false
```

### Risk count by severity

| Severity | Count |
|----------|---------:|
| Critical | 0 |
| High | 7 |
| Elevated | 4 |
| Medium | 14 | 
| Low | 5 |
| Total | 23 |

[risks](e2\l20.png)

### Top 5 risks (paste from `jq` output)
1. **cross-site-scripting** — Cross-Site Scripting (XSS); severity Elevated; affecting Juice Shop Server
2. **unencrypted-communication** — Unencrypted Communication Link; severity Elevated; affecting Direct HTTP to App
3. **unencrypted-communication** — Unencrypted Communication Link; severity Elevated; affecting Forward to App
4. **missing-authentication** — Missing Authentication; severity Elevated; affecting Forward to App
5. **sql-injection** — SQL-Injection; severity Medium; affecting Juice Shop Server

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **T, S** (Tampering, Spoofing) — Malicious JS payloads can alter the page content and steal active session tokens from other users.
- Risk 2: **I** (Information Disclosure) — Traffic travels in plain text over the network, allowing any MITM attacker to sniff authentication cookies.
- Risk 3: **I** (Information Disclosure) — Internal traffic between the proxy and the app is unencrypted, exposing sensitive data if the host network is compromised.
- Risk 4: **E, S** (Elevation of Privilege, Spoofing) — The app blindly trusts the proxy without internal auth, allowing an attacker inside the network to forge requests.
- Risk 5: **T, I** (Tampering, Information Disclosure) — Crafted inputs can manipulate database queries to extract hidden records or modify existing data.

### Trust boundary observation
Looking at the data-flow diagram, the **`Direct HTTP to App`** arrow crosses the trust boundary from the **Internet** directly into the **Host Machine / Container Net**. 
This path is extremely attractive to an attacker because it completely bypasses the Reverse Proxy. Not only is the traffic sent over plain HTTP (exposing tokens to network sniffing), but it also evades any security headers, rate limiting, or WAF rules that the proxy might have enforced.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 7 | 7 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 30 | 27 | -3 |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` — fixed by changing the protocol from HTTP to HTTPS on the direct browser-to-app link.
2. `unencrypted-asset` — fixed by applying `data-with-symmetric-shared-key` encryption to the Persistent Storage volume.
3. `sql-injection` — fixed by declaring that the application uses parameterized queries in its description.

### Which rules are STILL THERE in the secure variant?
1. `cross-site-scripting` — This is an application-level code vulnerability. Hardening the infrastructure (like adding HTTPS or encrypting the DB at rest) doesn't fix bad code that renders user input without sanitization.
2. `missing-authentication` — Juice Shop is designed to have publicly accessible endpoints (like viewing the product catalog). Threagile will continue to flag this because the architecture intentionally allows unauthenticated access to certain flows.

### Honesty check
Did the total drop more than 50%? **No, it only dropped by 10% (from 30 to 27).**
This demonstrates the cost-benefit reality of threat modeling. Infrastructure-level hardening (flipping toggles for HTTPS and DB encryption) is a cheap, quick win. However, the vast majority of remaining risks are application-level vulnerabilities (XSS, missing auth, business logic flaws). Eliminating those requires developer time to rewrite the actual code, which is significantly more expensive and time-consuming than tweaking architectural configurations.

## Bonus Task: Auth Flow Threat Model
ну его