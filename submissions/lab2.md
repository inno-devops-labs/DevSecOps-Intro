# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Risk count by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 risks

1. **cross-site-scripting@juice-shop** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity Elevated; affecting Juice Shop Application.
2. **missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity Elevated; affecting Juice Shop Application / Reverse Proxy communication.
3. **unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity Elevated; affecting User Browser → Juice Shop Application.
4. **unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity Elevated; affecting Reverse Proxy → Juice Shop Application.
5. **container-baseimage-backdooring@juice-shop** — Container Base Image Backdooring risk at Juice Shop Application; severity Medium; affecting Juice Shop Application.

### STRIDE mapping

- Risk 1: **T — Tampering.** XSS allows attacker-controlled script execution that can modify browser-side behavior and user-visible data.
- Risk 2: **E — Elevation of Privilege.** Missing authentication on an application communication path can allow unauthorized access to protected functionality or data.
- Risk 3: **I — Information Disclosure.** Unencrypted direct user-to-app traffic can expose credentials, tokens, or session identifiers in transit.
- Risk 4: **I — Information Disclosure.** Unencrypted proxy-to-app communication can expose sensitive data moving between internal components.
- Risk 5: **T — Tampering.** A backdoored container base image can introduce unauthorized code or alter application runtime behavior.

### Trust boundary observation

One trust-boundary-crossing arrow visible in the data-flow diagram is **User Browser → Juice Shop Application** via **Direct to App (no proxy)**. This arrow is attractive to an attacker because it crosses from the Internet/user-controlled side into the application container and transfers authentication/session data. If the link is unencrypted or weakly protected, it becomes a high-value place for credential theft, session interception, and request manipulation.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 20 | -3 |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop` — fixed by changing direct browser-to-application traffic from HTTP to HTTPS.
2. `unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop` — fixed by changing reverse-proxy-to-application traffic to HTTPS.
3. One `unencrypted-technical-assets` finding was reduced by declaring encrypted storage for the persistent storage asset.

### Which rules are STILL THERE in the secure variant?

1. `cross-site-scripting@juice-shop` — still present because enabling HTTPS and storage encryption does not automatically sanitize output, encode user-controlled content, or remove DOM/browser-side injection risks. This still requires development-side XSS controls.
2. `missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop` — still present because transport encryption does not create an authentication or authorization mechanism. The model still needs explicit authentication/identity controls for sensitive application paths.
3. `missing-vault@juice-shop` — still present because encrypted communication/storage does not introduce a dedicated secrets-management component. A vault or equivalent secret storage design would be a separate architectural control.

### Honesty check

The total risk count dropped from **23** to **20**, which is about **13.0%**. This is less than 50%, so the secure-variant changes are useful but not a complete fix. HTTPS, encrypted storage, prepared statements, and log hardening remove several obvious infrastructure weaknesses, but the remaining risks show that authentication, identity-store modeling, WAF placement, container hardening, secrets management, and application-level validation still require additional work.

## Commands used

```powershell
docker run --rm -v "<repo>/labs/lab2:/app/work" threagile/threagile:0.9.1 -model /app/work/threagile-model.yaml -output /app/work/output -generate-risks-excel=false -generate-tags-excel=false

docker run --rm -v "<repo>/labs/lab2:/app/work" threagile/threagile:0.9.1 -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure -generate-risks-excel=false -generate-tags-excel=false

## Generated artifacts

- Baseline model: `labs/lab2/threagile-model.yaml`
- Secure model: `labs/lab2/threagile-model-secure.yaml`
- Baseline report generated locally: `labs/lab2/output/report.pdf`
- Secure report generated locally: `labs/lab2/output-secure/report.pdf`
- Baseline JSON report: `labs/lab2/output/risks.json`
- Secure JSON report: `labs/lab2/output-secure/risks.json`

## Note on Excel output

`risks.xlsx` generation was disabled with `-generate-risks-excel=false` / `-generate-tags-excel=false` because the local Threagile XLSX generation failed on an Excel worksheet name length limit. PDF, JSON, and diagram generation completed successfully, and the risk counts were verified from the generated PDF reports and `risks.json`.

