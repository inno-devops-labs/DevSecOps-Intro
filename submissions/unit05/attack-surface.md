# Attack-surface inventory

## Scope and discovery method

The target for this exercise is the local OWASP Juice Shop instance used for Lab 5.3, not a third-party or university-hosted system. The inventory must reconcile browser-visible routes, source-code route registration, unauthenticated status checks, and the local OWASP ZAP baseline report. Only endpoints confirmed against the actual local instance should be described as observed.

## Candidate routes to reconcile

The routes below are candidates from the supplied worked example and Juice Shop route patterns. Treat them as a starting inventory, not as proof that the same version/configuration is running locally. Confirm method, response status, authentication requirement, and whether each path appears in the DFD.

| Method | Path | Expected exposure class | Data or capability | Discovery source to check | Security concern |
|---|---|---|---|---|---|
| POST | `/rest/user/login` | Public | Credentials | ZAP, browser DevTools, source | Brute force and credential handling. |
| POST | `/api/Users` | Public registration | User profile and credentials | DevTools, source | Input validation and account abuse. |
| GET | `/rest/products/search` | Public | Search query | Browser DevTools, source | Injection and output encoding. |
| GET | `/api/Products` | Public | Product data | ZAP, source | Unnecessary data exposure. |
| GET | `/rest/basket/:id` | Authenticated | Basket identifier and contents | Source, local requests | Broken object-level authorization. |
| POST | `/api/BasketItems` | Authenticated | Product and quantity | DevTools, source | Authorization and quantity validation. |
| POST | `/api/Feedbacks` | Public or challenge-protected | Comment and rating | DevTools, source | Abuse and stored XSS. |
| GET | `/api/Users` | Administrative/sensitive | User records | Source, local request | Excessive data exposure. |
| GET | `/rest/user/whoami` | Authenticated | Caller identity | DevTools, source | Token/session handling. |
| GET | `/api/Complaints` | Authenticated or role-limited | Complaint records | Source, local request | Record-level authorization. |
| GET | `/rest/order-history/orders` | Administrative/role-limited | Order history | Source, local request | Privilege escalation and privacy. |
| GET | `/ftp` | Public if route exists | Static files | ZAP and local curl | Backup or file disclosure. |
| GET | `/metrics` | Internal/administrative if enabled | Runtime metrics | Local curl, configuration | Operational information disclosure. |
| POST | `/rest/user/reset-password` | Public workflow | Password-reset data | DevTools, source | Account recovery abuse. |
| GET | `/rest/wallet/balance` | Authenticated | Wallet balance | DevTools, source | Broken object-level authorization. |
| POST | `/b2b/v2/orders` | Authenticated/integration | Order XML/JSON | Source code | Separate API boundary and input validation. |
| GET | `/api/Quantitys` | Administrative/role-limited | Inventory quantities | Source, local request | Role enforcement. |

## Reconciliation rules

1. Use three or more discovery methods: ZAP baseline report, source-code route extraction, and browser DevTools or local `curl` status checks.
2. Record the actual status code and whether authentication was present. Do not infer access control solely from a route name.
3. Add any discovered route missing from the DFD, or document why it is intentionally omitted.
4. Mark routes that are identity-checked but not resource-entitlement-checked. A valid JWT is not proof that a caller owns the requested object.
5. Remove or restrict unnecessary public routes. The worked example specifically highlights `/ftp` and `/metrics` as candidates requiring review.

## Choke-point audit

The most important review question is whether the central authorization helper provides both identity verification and resource-level entitlement. The worked example identifies `/rest/basket/:id` as a defect: authentication middleware validates the token but does not compare the requested basket owner with the authenticated user. It also identifies the architectural risk of routes such as `/api/Recycles/:id` being registered without a shared middleware. Confirm these findings against the checked-out source version before stating line numbers or route counts.

## Reduction decision

Remove an unnecessary public file-serving route such as `/ftp`, and place operational metrics behind an internal or authenticated monitoring path. These reduce information exposure, but they do not replace object-level authorization, secure webhook handling, or protected deployment identity. Related threats are T-13 and T-15; see ADR-018.
