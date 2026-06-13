\# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile



\## Task 1: Baseline Threat Model



\### Risk count by severity



| Severity  |  Count |

| --------- | -----: |

| Critical  |      0 |

| High      |      0 |

| Elevated  |      4 |

| Medium    |     14 |

| Low       |      5 |

| \*\*Total\*\* | \*\*23\*\* |



\### Top 5 risks



1\. \*\*unencrypted-communication\*\* — Unencrypted communication between User Browser and Juice Shop Application; severity: Elevated; affecting asset: User Browser.

2\. \*\*unencrypted-communication\*\* — Unencrypted communication between Reverse Proxy and Juice Shop Application; severity: Elevated; affecting asset: Reverse Proxy.

3\. \*\*cross-site-scripting\*\* — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity: Elevated; affecting asset: Juice Shop Application.

4\. \*\*missing-authentication\*\* — Missing authentication on communication link between Reverse Proxy and Juice Shop Application; severity: Elevated; affecting asset: Juice Shop Application.

5\. \*\*missing-vault\*\* — Missing secret storage (Vault) for Juice Shop Application; severity: Medium; affecting asset: Juice Shop Application.



\### STRIDE Mapping



\* Risk 1: \*\*I (Information Disclosure)\*\* — Credentials and session information may be intercepted over unencrypted communication.

\* Risk 2: \*\*I (Information Disclosure)\*\* — Traffic between proxy and application can be observed or modified by an attacker.

\* Risk 3: \*\*T (Tampering)\*\* — XSS allows attackers to inject and execute malicious code in user browsers.

\* Risk 4: \*\*S (Spoofing)\*\* — Missing authentication enables unauthorized entities to impersonate trusted components.

\* Risk 5: \*\*E (Elevation of Privilege)\*\* — Secrets stored without proper vaulting can be abused to gain elevated access.



\### Trust Boundary Observation



One important trust-boundary crossing is the communication link between \*\*User Browser\*\* and \*\*Juice Shop Application\*\* (`user-browser > direct-to-app-no-proxy`).



This communication appears in the top risks because it transfers authentication-related information across a trust boundary. Attackers can target this path using traffic interception, credential theft, or man-in-the-middle techniques when communication is not properly protected.

## Task 2: Secure Variant & Diff

### Changes made in the secure variant

I created `labs/lab2/threagile-model-secure.yaml` from the baseline model and applied the following hardening changes:

- Changed HTTP communication links to HTTPS.
- Changed unencrypted asset storage to `data-with-symmetric-shared-key`.
- Added a secure-variant note that database access uses parameterized queries / prepared statements.
- Re-generated the Threagile report in `labs/lab2/output-secure`.

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 14 | 0 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **21** | **-2** |

### Which rules are gone in the secure variant?

The secure variant reduced the number of Elevated risks from 4 to 2. The main fixed rule category was `unencrypted-communication`.

1. `unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop` — fixed by changing the direct user-to-application communication from HTTP to HTTPS.
2. `unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop` — fixed by changing the reverse-proxy-to-application communication from HTTP to HTTPS.
3. `unencrypted-communication` — fixed as a broader rule category by removing plaintext HTTP communication from the model.

Only two concrete risk instances disappeared, so the third item is the fixed rule category rather than a third separate instance. This is a limitation of this model's output: the secure changes removed two Elevated findings, not three distinct risk instances.
### Which rules are still there in the secure variant?

1. `cross-site-scripting` — This risk still appears because switching transport from HTTP to HTTPS does not remove browser-side script injection issues. XSS requires input validation, output encoding, and content security controls.

2. `missing-authentication` — This risk still appears because the secure variant did not add a new authentication mechanism between the reverse proxy and the Juice Shop application. HTTPS protects the channel, but it does not prove that the caller is authorized.

### Honesty check

The total risk count did not drop by more than 50%. It dropped from 23 to 21, which shows that HTTPS and encryption are useful but only address a narrow part of the threat model. Fully reducing the remaining risks would require more specific controls such as authentication, input validation, hardening, secret management, and application-level security fixes.

