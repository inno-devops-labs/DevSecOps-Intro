# ADR-014: Federated pipeline identity and digest-based deployment

- **Status:** Proposed pending configuration evidence
- **Context:** Invariants I-2 and I-6; threats T-03, T-04, and T-07; flow F3 crosses TB-2 → TB-3/TB-7.
- **Decision:** Use a federated identity credential pinned to the intended repository and production environment instead of a long-lived client secret. Grant only the registry/deployment permissions required. Deploy by immutable image digest and retain evidence linking the build digest to the deployed digest.
- **Alternatives rejected:** A stored service-principal secret is long-lived and can be exfiltrated from a workflow. A broadly privileged identity increases the impact of workflow compromise. Deployment by mutable tag alone does not establish artifact identity.
- **Consequences accepted:** Environment protection and identity configuration add setup and review work. Incorrect subject strings can stop deployments, which is preferable to silently falling back to a stored credential.
- **Validation:** Positive trusted production workflow obtains the expected identity. Negative wrong-subject/wrong-branch workflow is rejected. Confirm an out-of-scope operation is denied and compare build/deployed digests. Store actual logs under `evidence/T-07/`.
- **Residual risk:** Administrators can alter identity or role configuration, and a trusted workflow can still contain a build flaw. Owner: repository/cloud maintainer. Review monthly and after workflow or role changes.
