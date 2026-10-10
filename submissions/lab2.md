# Lab 2 — STRIDE Threat Modeling with Threagile

Date: 2026-09-11. Branch: `feature/lab2`.

## Scope and reproduction

All counts below come from actual local runs of `threagile/threagile:0.9.1`, image digest `sha256:abb9eccb111a2059c4876759a24245db02ad295b1608d3a4634ec250f38d9640`. The binary reports version `1.0.0 (20240730113903)`, as expected for this image. Each of the three runs exited successfully and produced `risks.json`, `stats.json`, `report.pdf`, `risks.xlsx`, and both diagrams; the Fontconfig cache warnings did not prevent generation.

The supplied [baseline](../labs/lab2/threagile-model.yaml) was preserved unchanged. Its YAML defines **three** trust boundaries (Internet, Host, Container Network), although the assignment says four; the Docker Host shared runtime is not a fourth boundary. It also describes Juice Shop v19.0.0, while Lab 1 used v20.0.0, and omits the application's storage communication link. These are limitations of the supplied architecture model, not verified properties of the deployed application. In particular, an isolated storage node explains the `unnecessary-technical-asset` warning; it does not mean persistent storage should actually be deleted.

The secure model is a proposed design: changing YAML does not deploy TLS, provision certificates, encrypt disks, or fix Juice Shop. The bonus is a logical decomposition of the login feature, with intended authorization checks explicitly labeled; it is not evidence that those checks are correctly implemented. The generic Internet/browser representation also does not prove the localhost-only Lab 1 deployment is publicly reachable.

The following PowerShell commands were run from the repository root (Docker Desktop had to be started first):

```powershell
docker pull threagile/threagile:0.9.1
New-Item -ItemType Directory -Force labs/lab2/output,labs/lab2/output-secure,labs/lab2/output-auth | Out-Null
docker run --rm -v C:/Documents/DevSecOps-Intro/labs/lab2:/app/work threagile/threagile:0.9.1 -model /app/work/threagile-model.yaml -output /app/work/output
docker run --rm threagile/threagile:0.9.1 -list-types
docker run --rm -v C:/Documents/DevSecOps-Intro/labs/lab2:/app/work threagile/threagile:0.9.1 -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure
docker run --rm -v C:/Documents/DevSecOps-Intro/labs/lab2:/app/work threagile/threagile:0.9.1 -create-stub-model -output /app/work/output-auth
# Author threagile-model-auth.yaml from the generated stub's schema and fields.
docker run --rm -v C:/Documents/DevSecOps-Intro/labs/lab2:/app/work threagile/threagile:0.9.1 -model /app/work/threagile-model-auth.yaml -output /app/work/output-auth
docker run --rm threagile/threagile:0.9.1 -explain-risk-rules
```

Output directories are intentionally ignored by Git and can be regenerated with these commands. The stub was generated under `output-auth/` to keep temporary material out of the deliverable directory.

## Task 1

### Baseline counts

```powershell
$baseline = Get-Content labs/lab2/output/risks.json -Raw | ConvertFrom-Json
$baseline.Count
$baseline | Group-Object severity | Select-Object Name,Count
```

Observed total: **23**. All risks have status `unchecked`; zero-count severities are included below for completeness.

| Severity | Count |
| --- | ---: |
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

### Top five and STRIDE mapping

The explicit severity ranking avoids alphabetic sorting. Equal-severity rows retain their order in the captured JSON file; the fifth row is not claimed to outrank every other medium risk.

```powershell
$order = @('critical','high','elevated','medium','low')
$baseline | Sort-Object -Stable {$order.IndexOf($_.severity)} |
  Select-Object -First 5 severity,category,most_relevant_technical_asset
```

| # | Severity | Rule ID | Most relevant technical asset | STRIDE | Reason |
| ---: | --- | --- | --- | --- | --- |
| 1 | elevated | `missing-authentication` | `juice-shop` | S — Spoofing | Without authenticating the proxy-to-application link, an attacker able to reach the backend can impersonate a trusted caller. |
| 2 | elevated | `cross-site-scripting` | `juice-shop` | T — Tampering | Injected scripts can modify trusted page behavior and perform actions within a victim's browser session. |
| 3 | elevated | `unencrypted-communication` | `user-browser` | I — Information disclosure | The direct HTTP link exposes session tokens to an attacker able to observe that traffic. |
| 4 | elevated | `unencrypted-communication` | `reverse-proxy` | I — Information disclosure | HTTP forwarding exposes session tokens on the proxy-to-application hop even if the browser-facing connection uses TLS. |
| 5 | medium | `missing-build-infrastructure` | `juice-shop` | T — Tampering | Omitting the build pipeline hides opportunities to alter application code or dependencies before deployment. |

These are reasoned STRIDE mappings for the selected attack scenarios; a rule can relate to more than one STRIDE category. The missing-build-infrastructure entry is a model-coverage warning, not proof of a compromised build system.

### Trust-boundary crossing

I inspected `labs/lab2/output/data-flow-diagram.png`. The arrow **Reverse Proxy → Juice Shop Application**, named `To App` (`reverse-proxy>to-app`), crosses from **Host into Container Network**. It appears in rows 1 and 4: the baseline declares `protocol: http` and `authentication: none`, while carrying `tokens-sessions`. An attacker with access to that host/network path could steal reusable session credentials or impersonate the proxy, making the arrow valuable even when the external hop uses HTTPS; this attack requires that access and is not automatically possible from the public Internet.

## Task 2

The [secure variant](../labs/lab2/threagile-model-secure.yaml) changes both application ingress links to `https`, gives the proxy-to-app link `authentication: client-certificate`, and changes the application and persistent-storage assets to `encryption: transparent`. All values were confirmed using `-list-types`; the title is `Juice Shop Secure Model` (23 characters). The asset topology and data classifications remain the same.

### Counts and deltas

| Severity | Baseline | Secure | Delta (secure − baseline) |
| --- | ---: | ---: | ---: |
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

The reduction is **5 / 23 = 21.7%**. Both JSON severity tables also match the corresponding `stats.json` counts.

```powershell
$secure = Get-Content labs/lab2/output-secure/risks.json -Raw | ConvertFrom-Json
$secure.Count
$baseRules = @($baseline.category | Sort-Object -Unique)
$secureRules = @($secure.category | Sort-Object -Unique)
'gone:'
$baseRules | Where-Object {$_ -notin $secureRules}
'new:'
$secureRules | Where-Object {$_ -notin $baseRules}
```

Observed output:

```text
18
gone:
missing-authentication
unencrypted-asset
unencrypted-communication
new:
```

| Removed rule ID | Field change responsible | Removed instances |
| --- | --- | ---: |
| `missing-authentication` | `technical_assets.Reverse Proxy.communication_links.To App.authentication`: `none` → `client-certificate` | 1 |
| `unencrypted-communication` | `protocol`: `http` → `https` on `User Browser → Direct to App (no proxy)` and `Reverse Proxy → To App` | 2 |
| `unencrypted-asset` | `encryption`: `none` → `transparent` on `Juice Shop Application` and `Persistent Storage` | 2 |

The client-certificate declaration represents mutual TLS with certificate validation; implementation would need appropriate listeners, keys, trust stores and rotation. The browser's direct TLS listener must support its separate session-based authentication path. Disk encryption requires deployment work covering the actual application storage and host volume. Proxy client authentication does not establish end-user authorization: the proxy link still declares `authorization: none`.

### Risks that remain

| Remaining rule ID | Why these edits cannot remove it |
| --- | --- |
| `cross-site-scripting` | Transport and disk encryption do not prevent unsafe HTML rendering or script execution; contextual output encoding, safe DOM APIs, sanitization where necessary, and browser regression tests are needed. |
| `container-baseimage-backdooring` | The application still runs as a container, and encryption says nothing about the origin or integrity of its image layers; trusted provenance, digest pinning, scanning and controlled updates are needed. |

The remaining 18 risks include application behavior, supply-chain exposure, missing defensive controls and gaps in model coverage. Addressing them requires changes to application code and deployment practices, plus evidence from code review, security tests and operational verification. For example, an actual stored-XSS vulnerability cannot be closed by editing YAML: the unsafe rendering path must be fixed and retested. Expanding the model to include the real build pipeline and storage access may uncover additional risks, so a lower modeled count is not proof that the running application is secure.

## Bonus

The [authentication model](../labs/lab2/threagile-model-auth.yaml) was authored from the generated stub, without copying or pruning the baseline. It contains **6 technical assets, 6 communication links and 7 data assets**. The issuer and admin handler use `technology: library` because they are in-process components; the credential-store links represent embedded SQL access, not a newly deployed database service.

| Technical asset | Responsibility |
| --- | --- |
| `browser` | Submit credentials and present a bearer JWT. |
| `login` | Validate credentials before invoking the issuer. |
| `token-issuer` | Issue a signed JWT using the private signing key. |
| `token-verifier` | Verify JWT signature and claims, then enforce the admin role guard. |
| `credential-store` | Store credential records, account identities and roles. |
| `admin-endpoint` | Handle administrative operations after the guard succeeds. |

The data assets are credentials, credential records, JWT access token, **JWT signing key**, public JWT verification key, verified identity/role and admin data. Only the issuer processes and stores `jwt-signing-key`; no communication link transfers it. The verifier holds a separate public verification key.

Every link explicitly contains both `authentication` and `authorization`. `none` on in-process calls and embedded database authentication records the absence of a separate transport identity rather than inventing database credentials. The initial login has `authorization: none` because no authenticated end-user identity exists yet; the emitted `missing-identity-propagation` warning at login needs this contextual triage rather than a fictitious authorization declaration.

The check is explicit at `technical_assets.Token Verifier.communication_links.Authorized Admin Call`: `authentication: token`, `authorization: enduser-identity-propagation`, and the description **require a valid JWT and verified role == admin; deny otherwise**. That link is the admin handler's only incoming edge; the browser has no direct edge to it. The field alone cannot encode an admin-role predicate, so the description and security requirement state the required guard; implementation and negative tests remain necessary to verify it.

### Severity counts

| Severity | Count |
| --- | ---: |
| critical | 0 |
| high | 2 |
| elevated | 6 |
| medium | 18 |
| low | 5 |
| **Total** | **31** |

These counts were read from `labs/lab2/output-auth/risks.json` and checked against `stats.json`; all statuses are `unchecked`. There are no `wrong-communication-link-content` warnings in the final run. The 31 risks cannot be treated as a regression against the baseline: this model has a different scope, asset granularity and sensitivity classification.

### Three risks absent from the baseline

The following rule IDs occur in the authentication output and are absent from the baseline output; these are built-in Threagile findings, not manually inserted risk categories.

| Rule ID | Auth-model evidence | STRIDE | One-sentence mitigation |
| --- | --- | --- | --- |
| `sql-nosql-injection` | High risk at `login` via `Check Credentials` against `credential-store` (also reported at the admin handler). | T — Tampering | Use parameterized credential queries and verify that malicious login input cannot alter query semantics or bypass password verification. |
| `missing-identity-provider-isolation` | Elevated risk at the highly sensitive `credential-store`, co-located with lower-protected application components. | E — Elevation of privilege | Move identity storage and authentication into an independently protected service with narrowly authorized access, so compromising a public handler does not expose identity-management privileges. |
| `missing-network-segmentation` | Medium risk at `credential-store` in the shared Application Host boundary. | I — Information disclosure | After separating the embedded store into a service, enforce network policy allowing only required authenticated callers to reach credential data. |

The last two findings overlap but describe different control objectives: isolation of identity responsibilities and restriction of network reachability. Because the current model uses an embedded store in a shared runtime, drawing an extra network box alone cannot implement either mitigation; architectural separation must come first.

The feature-level model exposes the credential-query path, signing-key ownership and exact authorization handoff that the baseline's single application node could not express. It therefore surfaces authentication-specific review targets, while still requiring source review and negative tests to establish whether JWT verification, credential handling and admin authorization actually resist attacks.
