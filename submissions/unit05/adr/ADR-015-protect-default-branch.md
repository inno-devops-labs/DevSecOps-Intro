# ADR-015: Protect the default branch with a ruleset

- **Status:** Proposed pending repository test evidence
- **Context:** Invariant I-3; threat T-02; flow F2 from developer workstation into the GitHub organization boundary.
- **Decision:** Configure a repository ruleset for the default branch that requires a pull request and the named validation check, blocks force-pushes and branch deletion, and has no unnecessary bypass actors. Use the actual check name configured by the repository.
- **Alternatives rejected:** An honor-system policy is not enforcement. A rule that is configured but in Evaluate mode does not block prohibited actions. A required check name that does not match the workflow provides no reliable gate.
- **Consequences accepted:** Changes take an extra review/CI step, and a broken required check can temporarily block merges. The check and bypass configuration must be maintained.
- **Validation:** Positive pull request with a passing check is merged. Negative direct push, force-push, and merge with failing required check are rejected for the expected rule. Preserve actual command output and ruleset export under `evidence/T-02/`.
- **Residual risk:** Repository administrators may change or bypass policy depending on permissions. Owner: repository maintainer. Review monthly and after permission changes.
