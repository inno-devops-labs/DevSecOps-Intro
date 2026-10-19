# Peer review given — prepared review findings

Use these as the five specific findings to raise when reviewing a classmate’s architecture submission. Before sending, replace the artifact references with the exact line, flow, or evidence location in that classmate’s version so the review is grounded in their work.

## F-1 — High — Pipeline trust boundary

**Observation:** The pipeline-to-cloud identity transition is a security boundary. If the diagram places the Actions workflow entirely inside the Azure boundary or does not show the F3 crossing, the model hides where a GitHub identity becomes an Azure identity.

**Evidence to cite:** DFD placement of GitHub Actions, Azure identity/token exchange, and container registry; compare with the architecture text’s description of F3.

**Suggested action:** Place the workflow in the GitHub/pipeline boundary and draw F3 crossing into the Azure subscription and registry boundary. Link the crossing to the spoofing/tampering threat and the federated-identity ADR.

## F-2 — High — Authentication is not resource entitlement

**Observation:** A route can validate a JWT and still allow one authenticated user to read another user’s record. Identity verification alone does not enforce ownership.

**Evidence to cite:** Invariant catalog and route inventory for basket, order, or user-specific records; identify a route where the owner is not compared with the authenticated caller.

**Suggested action:** Add a resource-level entitlement check at a shared choke point and a negative cross-user test that expects denial.

## F-3 — Medium — Negative test must prove the intended control

**Observation:** A test that fails because an environment variable is missing, a dependency is unavailable, or a command is malformed does not prove that the intended security control rejected the request.

**Evidence to cite:** The negative-test log and the specific expected denial reason.

**Suggested action:** Re-run with valid test configuration and show that the request fails specifically because the wrong branch, identity subject, permission, or missing entitlement is rejected.

## F-4 — Medium — Open choke-point threat needs ownership

**Observation:** A threat against a central authorization or deployment choke point is not actionable if it remains Open without a named responsible role, a planned mitigation, and a review date.

**Evidence to cite:** Threat-register row for the choke point’s outage, fail-open behavior, or dependency failure.

**Suggested action:** Assign an owner role, record fail-closed behavior, add an outage/negative test, and set a review date.

## F-5 — Low — Attack-surface discovery needs independent sources

**Observation:** A route inventory built from only one source can miss routes that are registered in code but not exercised by the browser, or routes that a scanner discovers but the diagram omits.

**Evidence to cite:** The inventory’s discovery-method description and “found by” column.

**Suggested action:** Reconcile at least three sources: local ZAP baseline output, source-code route extraction, and browser DevTools or local `curl` checks. Update the DFD for any unexplained entry point.
