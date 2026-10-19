# ADR-011: Central resource-entitlement check

- **Status:** Proposed pending local validation
- **Context:** Invariant I-1; threat T-01; F1 across TB-1 → TB-4. Authentication proves caller identity but does not prove entitlement to a requested object.
- **Decision:** Require resource-level entitlement checks in shared authorization middleware for every protected route. Compare the authenticated caller’s identity with the requested record owner or applicable role. Add a route-registration check with an explicit reviewed allowlist so new routes cannot silently bypass enforcement.
- **Alternatives rejected:** Per-endpoint ownership checks alone are easy to omit and duplicate inconsistently. Authentication-only middleware does not enforce object ownership. Database row-level security can help but does not cover every non-database path by itself.
- **Consequences accepted:** Shared middleware becomes a critical choke point and must fail closed. Every new route needs an explicit authorization rule and tests.
- **Validation:** Positive test: caller reads their own record. Negative test: caller requests another user’s record and receives 403 or explicit denial. Store both outputs under `evidence/I-1/`.
- **Residual risk:** A route can bypass the shared middleware unless route registration is audited. Owner: application maintainer. Review after route changes and monthly.
