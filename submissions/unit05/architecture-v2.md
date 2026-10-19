# Architecture v2 — CPS 5981 Reference System

Repository: `balouchn/DevSecOps-Intro`  
Branch: `feature/lab5`

## System overview

The reference system is a web application whose source is maintained in GitHub, built by GitHub Actions, packaged as a container image, and deployed to Azure App Service. The application retrieves secrets from Azure Key Vault, stores application data in Azure SQL, and calls an external payment API. OWASP Juice Shop is the representative application for the route and authorization exercises.

## Trust boundaries

| Boundary | Contents | Security significance |
|---|---|---|
| TB-1 — Internet | Customers and other external callers | All requests are untrusted until authenticated, validated, and authorized. |
| TB-2 — GitHub organization and pipeline | Repository, pull requests, GitHub Actions workflows, production environment | Source and workflow changes can affect what code is built and deployed. |
| TB-3 — Azure subscription and artifact services | Container registry, App Service resource, Key Vault, Azure SQL, Entra ID identity configuration | Azure roles, registry permissions, and service configuration determine deployment and data blast radius. |
| TB-4 — Application network | App Service ingress and private service connectivity | Network placement and access restrictions limit reachable services. |
| TB-5 — Managed identity | App Service identity and its assigned Azure roles | Identity permissions must be scoped to the minimum resources and operations. |
| TB-6 — External payment service | Payment API and its responses or callbacks | External payloads must be authenticated and treated as untrusted input. |
| TB-7 — Artifact registry | Container image repository and immutable image digests | The deployed artifact must be the same artifact that passed the build and validation process. |

## Data flows

| Flow | From → to | Boundary crossing | Security concern |
|---|---|---|---|
| F1 | Internet user → App Service | TB-1 → TB-4 | Authentication, input validation, authorization, rate limiting, and logging. |
| F2 | Developer workstation → GitHub repository | Workstation → TB-2 | Source integrity and prevention of unreviewed changes reaching the default branch. |
| F3 | GitHub Actions → Azure identity / container registry | TB-2 → TB-3 and TB-7 | A workflow must not obtain production credentials from an untrusted branch or repository context. |
| F4 | Container registry → App Service | TB-7 → TB-3/TB-4 | Deployment should identify an immutable image digest, not a mutable tag alone. |
| F5 | App Service → Key Vault and Azure SQL | TB-4 → TB-3 through TB-5 | Managed identity and least-privilege permissions protect secrets and stored data. |
| F6 | App Service ↔ payment API | TB-3 → TB-6 | Payment responses and webhooks require signature, schema, and replay validation. |

## Choke points

1. **Central authorization middleware** — every protected application route must pass through authentication and resource-level entitlement checks. If the check is unavailable, the application fails closed. Related invariant I-1 and ADR-011; threat T-01 and availability threat T-08.
2. **Protected default branch and required CI check** — all changes to the default branch must arrive through a pull request and pass the required check. Related invariant I-3 and ADR-015; threat T-02.
3. **GitHub Actions production environment and federated identity** — the workflow identity must be restricted to the intended repository/environment, with no long-lived client secret. Related invariant I-2 and ADR-014; threats T-03 and T-07.
4. **Container registry and digest-based deployment** — the production deployment identifies the exact image digest built by the trusted workflow. Related threat T-04 and ADR-014.
5. **Azure managed identity and RBAC** — App Service can access only the required Key Vault secrets and database operations. Related threat T-09.

## Architecture mismatches to resolve against earlier unit artifacts

- The registry must be shown as a separate artifact store rather than as part of App Service; otherwise the build-to-deploy integrity flow is invisible.
- The pipeline and the Azure identity/token exchange must be placed on opposite sides of the TB-2/TB-3 boundary, with F3 crossing that boundary.
- The identity matrix must include the CI/deployment identity and state its permitted registry and deployment operations.
- The order-history and basket requirements must distinguish identity (“who is calling?”) from entitlement (“may this caller access this record?”).
- Every externally reachable route discovered during the Lab 5.3 inventory must be represented in the DFD or explicitly documented as a deliberate exception.

## Architecture assurance claim

**Claim:** Only source changes that pass the repository’s required validation path can reach the production deployment workflow, and the production service runs the intended image digest.

The claim is falsifiable through branch-protection tests, workflow identity tests, and a build-digest/deployed-digest comparison. A diagram alone does not prove that the controls are configured or effective.

## Assumptions and residual risks

| Assumption | If false | Follow-up |
|---|---|---|
| Production credentials are not stored as long-lived repository secrets. | A compromised workflow or maintainer could reuse the credential outside the intended environment. | Verify the workflow and federated credential configuration. |
| The SCM/Kudu endpoint receives the same or stricter access restrictions as the application endpoint. | Deployment could bypass the intended pipeline. | Verify SCM access restrictions and disable basic publishing credentials where supported. |
| All protected routes use the central authorization mechanism. | A route may expose another user’s data even when other routes are secure. | Compare route registration against the route inventory and add a CI check. |
| Payment callbacks are signed and validated. | Forged callbacks could mark unpaid orders as paid. | Verify signature, timestamp, replay protection, and payload schema. |
| The registry supports immutable digests and the deployment references one. | A mutable tag could point to an unexpected image. | Record build and deployed digest evidence. |

## Required generated artifacts

`architecture-v2.png` and `threat-model.json` must be exported from OWASP Threat Dragon after creating and reviewing the DFD. They are intentionally not replaced by a hand-made or illustrative export in this package.
