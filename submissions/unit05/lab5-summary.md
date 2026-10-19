# Lab 5 summary: assurance claims and evidence plan

## Claim 1 — Protected source changes

**Claim:** No commit reaches the default branch except through a pull request whose required validation check passes, and force-pushes and branch deletion are blocked.

- **Threat:** T-02, Tampering, F2, workstation → GitHub repository boundary TB-2.
- **Control:** Repository ruleset requiring a pull request and required status check; block force-push and deletion; ADR-015; invariant I-3.
- **Evidence source:** Exported ruleset configuration and terminal output from the positive pull-request test and negative direct-push, force-push, and failing-check tests under `evidence/T-02/`.
- **Positive validation:** A pull request with a passing required check should merge through the permitted path.
- **Negative validation:** Direct push, force-push, and merge with the required check failing should each be rejected by the corresponding rule. The actual output must be captured after testing the target repository.
- **Limitations:** A successful ruleset test does not prove that repository administrators cannot change or bypass the rule, and it does not test every workflow path.
- **Residual risk:** Repository administrators may alter protection settings. Owner: repository maintainer. Review: monthly and after repository permission changes.

## Claim 2 — Production identity is restricted

**Claim:** Only the intended repository workflow running in the production environment can obtain the deployment identity, and that identity has only the permissions required for the deployment.

- **Threat:** T-03, Spoofing, and T-07, Tampering, F3, GitHub Actions → Azure identity/registry boundary TB-2 → TB-3.
- **Control:** Federated identity credential pinned to the intended repository and production environment, least-privilege role assignments, and digest-based deployment; ADR-014; invariants I-2 and I-6.
- **Evidence source:** Federated credential configuration, role-assignment export, trusted workflow run, and negative wrong-subject/wrong-branch run logs under `evidence/T-07/`.
- **Positive validation:** The intended production workflow obtains the expected identity and can perform only the intended permitted operation.
- **Negative validation:** A wrong subject or untrusted branch is denied at token exchange or environment protection; an out-of-scope write is denied by Azure RBAC.
- **Limitations:** A token-exchange test does not prove that the built artifact is the deployed artifact. A separate digest comparison is required.
- **Residual risk:** Repository or cloud administrators may change identity configuration. Owner: repository/cloud maintainer. Review after identity changes and monthly.

## Claim 3 — User data is scoped to its owner

**Claim:** An authenticated user can read their own basket but cannot read another user’s basket or record.

- **Threat:** T-01, Information Disclosure, F1, Internet → App Service boundary TB-1 → TB-4.
- **Control:** Central authorization middleware performs resource-level entitlement checks; ADR-011; invariant I-1.
- **Evidence source:** Positive own-record request and negative cross-user request logs under `evidence/I-1/`.
- **Positive validation:** User A requests User A’s record and receives the expected success response.
- **Negative validation:** User A requests User B’s record and receives 403 or another explicit denial. The supplied worked example shows this invariant being violated when a valid token is accepted without an owner check; that example is not evidence from this repository run.
- **Limitations:** One tested endpoint does not prove that every route uses the same enforcement mechanism. The route inventory must be reconciled with source registration.
- **Residual risk:** A newly added route could bypass the shared middleware. Owner: application maintainer. Review after route changes and monthly.

## Tool evidence and status

The source files in this package provide the analysis, controls, and test design. Actual tool results must be collected from this repository and the local lab environment. Do not copy illustrative logs or example risk counts from the worked-example ZIP into the evidence folder as if they were captured from your run.

- Threat Dragon: export `threat-model.json` and `architecture-v2.png` from the model you create.
- Threagile: run baseline and hardened models from the actual Lab 2 YAML, compare the generated reports, and update the evidence-gap section in `threat-register.md` with actual counts and rule changes.
- ZAP and route inventory: scan only your own local Juice Shop instance and preserve the report/logs you cite.
- GitHub ruleset and optional cloud identity tests: preserve the actual positive and negative output, including the reason each negative test was rejected.
