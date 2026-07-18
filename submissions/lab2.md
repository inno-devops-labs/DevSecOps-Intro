# Lab 2 - Submission

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

### Top 5 risks
1. **unencrypted-communication** - Unencrypted communication on `Direct to App (no proxy)` between `User Browser` and `Juice Shop Application` transferring authentication data; severity `elevated`; affecting `user-browser`.
2. **unencrypted-communication** - Unencrypted communication on `To App` between `Reverse Proxy` and `Juice Shop Application`; severity `elevated`; affecting `reverse-proxy`.
3. **cross-site-scripting** - Cross-Site Scripting risk at `Juice Shop Application`; severity `elevated`; affecting `juice-shop`.
4. **missing-authentication** - Missing authentication on communication link `To App` from `Reverse Proxy` to `Juice Shop Application`; severity `elevated`; affecting `juice-shop`.
5. **unnecessary-data-transfer** - Unnecessary transfer of `Tokens & Sessions` between `User Browser` and `Juice Shop Application`; severity `low`; affecting `user-browser`.

### STRIDE mapping
- Risk 1: **I** - Authentication data is sent over an unencrypted channel, so an attacker observing the traffic could read credentials or session material.
- Risk 2: **I/T** - Traffic between the reverse proxy and application is not protected, so it may be read or modified on that path.
- Risk 3: **T/I** - XSS allows attacker-controlled script execution in the browser, which can alter client-side behavior and steal sensitive data.
- Risk 4: **S/E** - Missing authentication means a caller may access a link without proving identity, which can enable impersonation or unauthorized access.
- Risk 5: **I** - Sending more token/session data than necessary increases the chance of exposing sensitive information.

### Trust boundary observation
One especially important trust-boundary crossing is the direct `User Browser -> Juice Shop Application` path over HTTP. It crosses from the Internet into the application environment while carrying session or authentication-related data, which makes it attractive to an attacker for interception, tampering, or session theft.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Delta |
|----------|---------:|-------:|------:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 4 | -1 |
| **Total** | **23** | **20** | **-3** |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` - fixed by changing the direct `User Browser -> Juice Shop Application` traffic from `http` to `https`.
2. `missing-authentication` - fixed by adding upstream authentication and authorization on the `Reverse Proxy -> Juice Shop Application` link.
3. `unencrypted-asset` - fixed by changing `Persistent Storage` encryption from `none` to `data-with-symmetric-shared-key`.

### Which rules are STILL THERE in the secure variant?
1. `cross-site-scripting` - The secure variant improves transport and storage settings, but it does not change the application behavior that allows attacker-controlled input to execute in the browser. XSS is an application-layer issue, so transport hardening alone does not eliminate it.
2. `server-side-request-forgery` - The model still includes an outbound webhook integration, so the application and proxy still have paths that can be abused for server-side requests. Switching the protocol to HTTPS protects confidentiality in transit, but it does not remove the SSRF attack surface itself.

### Honesty check
No, the total did not drop by more than 50%: it went from 23 risks to 20, which is only a modest reduction. That suggests these hardening changes are useful and cheap wins for transport and storage security, but they do not address the deeper application-design and application-logic issues that dominate the remaining risk set.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 3 |
| Elevated | 4 |
| Medium | 21 |
| Low | 1 |
| **Total** | **29** |

### Three auth-specific risks (NOT in the baseline model's top 5)
1. **missing-authentication-second-factor** - STRIDE: **S/E** - Mitigation: Require MFA for privileged routes such as the admin API and for sensitive account actions. That raises the bar for attackers even if a password or bearer token is stolen.
2. **missing-identity-propagation** - STRIDE: **S/E** - Mitigation: Propagate the verified end-user identity and role context from the entry API to downstream services instead of relying only on service-to-service trust. This makes it harder for internal calls to execute privileged actions without a user-bound security context.
3. **unguarded-access-from-internet** - STRIDE: **E** - Mitigation: Put the admin API behind stricter network and application controls, such as gateway filtering, dedicated admin access paths, and stronger server-side authorization checks. Admin functionality should not be broadly reachable from the public Internet with only minimal edge protection.

### Reflection (2-3 sentences)
The focused auth model surfaced issues that the broader baseline architecture model did not emphasize, especially around MFA, identity propagation, and direct exposure of privileged admin flows. That shows the value of feature-level threat modeling: when the model is scoped tightly to authentication and authorization, it reveals control gaps that can stay hidden in a larger, more generic architecture view.
