## Task 1: Baseline Threat Model

### Risk count by severity

- Elevated: 2
- Medium: 4
- Low: 2

### Top 5 risks

1. **cross-site-scripting@juice-shop** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity Elevated; affects application layer
2. **unencrypted-communication@user-browser** — HTTP communication without TLS between user and app; severity Elevated; exposes tokens/session data
3. **unencrypted-communication@reverse-proxy** — insecure internal communication; severity Elevated; impacts confidentiality of session data
4. **missing-hardening@juice-shop** — missing security hardening controls; severity Medium; increases attack surface
5. **container-baseimage-backdooring@juice-shop** — risk of vulnerable base image; severity Medium

---

### STRIDE mapping

- XSS -> Information Disclosure + Tampering
- Unencrypted communication -> Information Disclosure
- Missing hardening -> Elevation of Privilege
- Base image backdooring -> Tampering
- WAF missing -> Denial of Service / Exploit facilitation

---

### Trust boundary observation

The most critical risk is the communication between the user browser and the Juice Shop application across the internet trust boundary. This is attractive to attackers because it directly exposes authentication tokens and session identifiers.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|----------|--------|---|
| Critical | 0        | 0      | 0 |
| High     | 0        | 0      | 0 |
| Elevated | 4        | 4      | 0 |
| Medium   | 14       | 14     | 0 |
| Low      | 5        | 5      | 0 |
| **Total**| 23       | 23     | 0 |

---

### Which rules are gone in secure variant

1. No rules were eliminated — secure model is structurally equivalent to baseline
2. Changes are configuration-level only, not threat-model reductions

---

### Which rules are STILL there in secure variant

1. **cross-site-scripting** — still present because client-side rendering still processes unsafe input
2. **unencrypted-communication** — still present due to assumed internal trust boundaries in architecture

---

### Honesty check

The secure variant did NOT reduce total risk count. This indicates that the applied “hardening” changes were either:
- non-functional for threat elimination, or
- purely structural without affecting actual attack surface.

True risk reduction requires architectural changes rather than model duplication.
