# Lab 2 - Submission

## Task 1: Baseline Threat Model

### Run Evidence

- Model: `labs/lab2/threagile-model.yaml`
- Output directory: `labs/lab2/output/`
- Generated files: `report.pdf`, `risks.json`, `stats.json`, `technical-assets.json`, `data-asset-diagram.png`, `data-flow-diagram.png`
- Command used:
  ```bash
  docker run --rm -v "$(pwd)/labs/lab2:/app/work" threagile/threagile:0.9.1 \
    -model /app/work/threagile-model.yaml \
    -output /app/work/output \
    -generate-risks-excel=false \
    -generate-tags-excel=false
  ```
- Note: the pinned image reports Threagile `Version: 1.0.0 (20240730113903)` and failed while generating Excel with `the sheet name length exceeds the 31 characters limit`. I disabled Excel output and kept JSON/PDF/diagrams enabled.

### Risk Count By Severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 Risks

1. **cross-site-scripting** - Cross-Site Scripting (XSS) risk at Juice Shop Application; severity `elevated`; affecting `juice-shop`.
2. **missing-authentication** - Missing Authentication covering communication link `To App` from Reverse Proxy to Juice Shop Application; severity `elevated`; affecting `juice-shop`.
3. **unencrypted-communication** - Unencrypted Communication named `To App` between Reverse Proxy and Juice Shop Application; severity `elevated`; affecting `reverse-proxy`.
4. **unencrypted-communication** - Unencrypted Communication named `Direct to App (no proxy)` between User Browser and Juice Shop Application transferring authentication data; severity `elevated`; affecting `user-browser`.
5. **container-baseimage-backdooring** - Container Base Image Backdooring risk at Juice Shop Application; severity `medium`; affecting `juice-shop`.

### STRIDE Mapping

- Risk 1: **T/E** - XSS can tamper with client-side execution and can become elevation of privilege when it steals session tokens or performs actions as another user.
- Risk 2: **S/E** - Missing authentication on a service-to-service link allows spoofing a trusted component and can lead to unauthorized access to app behavior.
- Risk 3: **I/T** - Unencrypted proxy-to-app traffic can disclose tokens or request data and allow modification in transit on the internal link.
- Risk 4: **I/T** - Direct browser-to-app HTTP carrying session/authentication data exposes credentials or JWTs and makes tampering easier across the trust boundary.
- Risk 5: **T/E** - A backdoored container base image can alter application behavior before runtime and may give an attacker elevated control inside the container.

### Trust Boundary Observation

The `User Browser -> Direct to App (no proxy) -> Juice Shop Application` arrow crosses from the Internet trust boundary into the Container Network and appears in the top-5 unencrypted communication risk. It is attractive because it carries authentication/session data across the least-trusted boundary; if it is not protected with HTTPS, an attacker on the path can observe or alter high-value requests before they reach the app.

## Task 2: Secure Variant & Diff

### Secure Variant Changes

- File: `labs/lab2/threagile-model-secure.yaml`
- Changed direct browser-to-app traffic from `http` to `https`.
- Changed reverse-proxy-to-app traffic from `http` to `https`.
- Added `authentication: token` and `authorization: technical-user` to the reverse-proxy-to-app link.
- Changed Juice Shop Application encryption from `none` to `transparent`.
- Changed Persistent Storage from unencrypted `file-server` to encrypted `local-file-system` with `encryption: data-with-symmetric-shared-key`.
- Added a `To Persistent Storage` local-file-access link documenting prepared statements/parameterized queries and sanitized encrypted log writes.
- Clarified the outbound WebHook description as `HTTPS POST`; its protocol was already `https` in the baseline model.

### Risk Count Comparison

| Severity | Baseline | Secure | Delta |
|----------|---------:|-------:|------:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 4 | -1 |
| **Total** | 23 | 18 | -5 |

### Which Rules Are Gone In The Secure Variant?

1. `missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop` - fixed by adding service-token authentication and `technical-user` authorization to the proxy-to-app link.
2. `unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop` - fixed by changing direct app access from `http` to `https`.
3. `unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop` - fixed by changing the internal proxy-to-app link from `http` to `https`.
4. `unencrypted-asset@persistent-storage` - fixed by changing Persistent Storage to `encryption: data-with-symmetric-shared-key`.
5. `unencrypted-asset@juice-shop` - fixed by changing Juice Shop Application encryption to `transparent`.

### Which Rules Are Still There In The Secure Variant?

1. `cross-site-scripting@juice-shop` still fires because transport encryption and storage encryption do not remove application-layer injection risk. The model still describes Juice Shop as a custom-developed web application accepting JSON/user input, so XSS needs input validation, output encoding, CSP, and review-level mitigations.
2. `missing-authentication-second-factor@browser>direct-to-app-no-proxy@user-browser@juice-shop` still fires because HTTPS protects transport but does not add MFA. The hardening improved confidentiality and service authentication, but account takeover risk still needs MFA or stronger adaptive authentication.

### Honesty Check

The total did not drop more than 50%; it dropped from 23 to 18, a 5-risk reduction. That says the selected hardening is high-value for transport/storage hygiene, but it does not eliminate core application risks such as XSS, CSRF, MFA gaps, hardening, build infrastructure, and supply-chain controls.

## Bonus Task: Auth Flow Threat Model

### Run Evidence

- Model: `labs/lab2/threagile-model-auth.yaml`
- Output directory: `labs/lab2/output-auth/`
- Generated files include `report.pdf`, `risks.json`, `stats.json`, `technical-assets.json`, `data-asset-diagram.png`, and `data-flow-diagram.png`.
- The model was written from scratch for the auth flow and contains 5 technical assets, 5 data assets, and 7 communication links.

### Risk Count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 15 |
| Low | 4 |
| **Total** | 23 |

### Three Auth-Specific Risks Not In The Baseline Top 5

1. **sql-nosql-injection@auth-api@user-credential-store@auth-api>credential-lookup** - STRIDE: **T/E** - Mitigation: keep credential lookup parameterized, validate input at the Auth API boundary, and test the login query path with SAST/DAST because auth queries are high-impact even when the model says they are parameterized.
2. **missing-authentication-second-factor@browser>admin-request@browser@admin-endpoint** - STRIDE: **S/E** - Mitigation: require MFA or step-up authentication before issuing or accepting admin-capable JWTs, then enforce the admin role server-side on every admin request.
3. **missing-vault@token-service** - STRIDE: **S/E** - Mitigation: store JWT signing keys in a vault or HSM-backed secret store, rotate them, and keep verification strict so attackers cannot forge admin tokens after config or image disclosure.

### Reflection

The focused auth model surfaced risks that the architecture model only hinted at: signing-key storage, admin MFA, and the credential lookup path. The baseline model is good for network and deployment boundaries, but the auth model makes feature-level trust decisions visible, especially where JWT claims turn into authorization.
