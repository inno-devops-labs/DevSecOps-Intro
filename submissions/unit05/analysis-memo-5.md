# Analysis Memo 5 — Threat Assessment and Security Architecture

## Distinct but complementary practices

OWASP SAMM’s Threat Assessment practice systematically identifies and evaluates threats to a system, using its assets, actors, entry points, data flows, and trust boundaries to ask how an attacker could compromise confidentiality, integrity, availability, or control. Security Architecture examines whether the system’s structure and enforcement mechanisms make the required security properties hold consistently, including whether controls are centralized, bypassable, understandable, and supported by evidence.

## A problem threat modeling can find that an architecture review can miss

The pipeline identity threat in T-07 is a useful example. The application architecture may show a sensible App Service, container registry, Key Vault, and database, with a clear network boundary. A STRIDE review of flow F3 asks what happens when a GitHub Actions workflow crosses from the repository/pipeline boundary into the Azure subscription. A workflow running on an untrusted branch could attempt to obtain a production identity or push an image that production later runs. That attack depends on the boundary crossing and the identity assertion, not only on the application’s internal structure. The threat register therefore connects T-07 to a federated-identity control, restricted registry permissions, and a negative test in which the wrong workflow subject is rejected. The control is not proven merely because an OIDC step appears in YAML: the evidence must show the actual identity configuration and the actual rejection reason.

## A problem architectural review can find that threat modeling can miss

The resource-entitlement defect in T-01/I-1 illustrates the reverse. A flow-based threat model may record that a basket endpoint requires a valid token and conclude that authentication is present. Architectural review asks whether every route uses the same enforcement mechanism and whether that mechanism checks the property the system actually requires. A valid token establishes who the caller is; it does not establish that the caller owns the requested basket. In the supplied worked example, a cross-user basket request succeeds because the central token check does not compare the caller with the record owner. The architecture review exposes a structural weakness: authorization is not enforced as a consistent choke point across every relevant route. The remedy is a shared resource-entitlement check, a route-registration audit, and paired positive/negative tests. The violation remains open until the corrected local implementation demonstrates that a user can access their own record but cannot access another user’s record.

## Process change

I would make the assurance workflow traceable in both directions. Every important invariant should link to the threat it addresses, the architectural decision that implements it, and a positive and negative test. Every newly discovered entry point should be reconciled with the data-flow diagram, and every model risk removed by a YAML change should be paired with configuration evidence rather than treated as automatically resolved. This reduces the chance that a diagram, scanner report, or successful login is mistaken for proof of authorization or deployment integrity.

## Evidence limitation

This memo is based on the Unit 05 lab’s reference architecture and the supplied worked-example scenario. Before final submission, align the examples with the actual Threat Dragon model, local route inventory, Threagile reports, and test evidence produced for this repository. Do not claim an illustrative example log as a run performed in this lab.
