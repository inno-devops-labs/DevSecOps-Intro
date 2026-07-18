# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 40 | 39 |
| **Total** | 45 | 43 |

(OS: Debian 13.4; scanned `bkimminich/juice-shop:v20.0.0` for HIGH + CRITICAL.)

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| CVE-2021-23337 | HIGH | lodash | 2.4.2 | 4.17.21 |
| CVE-2025-47935 | HIGH | multer | 1.4.5-lts.2 | 2.0.0 |
| CVE-2024-37890 | HIGH | ws | 7.4.6 | 5.2.4, 6.2.3, 7.5.10, 8.17.1 |

### Dockerfile misconfig scan (Trivy config)
Ran `trivy config` against a sample bad Dockerfile (`FROM node:latest`, `USER root`, `EXPOSE 22`, `ADD <url>`). Trivy found 4 misconfigurations:

| ID | Severity | Issue |
|----|----------|-------|
| DS-0002 | HIGH | Last USER command should not be `root` (container-escape risk) |
| DS-0001 | MEDIUM | `FROM` image `node` has no pinned tag (`:latest`) |
| DS-0004 | MEDIUM | Port 22 exposed (allows SSH into the container) |
| DS-0026 | LOW | No `HEALTHCHECK` instruction |

This demonstrates Trivy's `config` mode on Dockerfiles — the same misconfiguration-scanning workflow Checkov applied to Terraform in Lab 6. At a HIGH,CRITICAL CI gate only DS-0002 would block; the MEDIUM/LOW findings are advisory.

### Compared to Lab 4's Grype scan
1. **Tool-agreed CVE — CVE-2019-10744 (lodash, CRITICAL).** Both Grype (Lab 4) and Trivy flag this prototype-pollution flaw in lodash 2.4.2. It's an old, well-documented CVE with a clear affected-version range and a fixed version (4.17.12), so both tools' databases carry identical, unambiguous matching data — when the vulnerability is mature and the package coordinates are exact, scanners converge.
2. **Tool-divergent CVE — CVE-2025-65945 (jws, HIGH), Trivy-only.** Trivy reports this 2025 jws advisory that my Lab 4 Grype scan did not surface. The difference is database freshness and source: Trivy's vuln DB was updated days before this scan (June 2026) and pulls from a different advisory feed, so a recently-published CVE appears in Trivy first. Grype and Trivy also match packages slightly differently (GitHub Security Advisories vs Trivy's aggregated sources), so newer or feed-specific entries show up in one tool before the other. This is exactly the DB-freshness / feed-difference effect Lectures 4 and 7 describe — neither tool is "wrong," they just sync different data at different times.

## Task 2: Kubernetes Hardening

### Manifests (key snippets)

`namespace.yaml` — all three PSS labels set to `restricted`:

    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted

`deployment.yaml` — pod-level securityContext:

    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      fsGroup: 1000
      seccompProfile:
        type: RuntimeDefault

`deployment.yaml` — container-level securityContext:

    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]

`networkpolicy.yaml` — default-deny with explicit ingress/egress:

    policyTypes: [Ingress, Egress]
    ingress:
      - from: [{ namespaceSelector: {} }]
        ports: [{ protocol: TCP, port: 3000 }]
    egress:
      - to: [{ namespaceSelector: {} }]
        ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
      - to: []
        ports: [{ protocol: TCP, port: 443 }]

### Pod is running
The pod runs 1/1 Ready with 0 restarts under the `restricted` enforce profile (i.e. it satisfies PSS restricted — a non-compliant pod would have been rejected at creation):

    NAME                         READY   STATUS    RESTARTS   AGE
    juice-shop-8cdc9bf4f-fgtvs   1/1     Running   0          95s

Live container securityContext confirms the hardening:

    {"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}

### Trivy K8s scan
`trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL`:

| Category | Critical | High |
|----------|------:|-----:|
| Vulnerabilities (image CVEs) | 10 | 80 |
| Misconfigurations | 0 | 0 |
| Secrets | 0 | 4 |

The **0 misconfigurations** result is the point: the PSS-restricted securityContext, dropped capabilities, non-root user, and read-only root filesystem leave Trivy's Kubernetes misconfig scanner with nothing to flag on the workload. The remaining Critical/High counts are image CVEs (the same vulnerable packages found in Task 1's image scan) plus secrets baked into the deliberately-vulnerable Juice Shop image — neither is a manifest hardening issue.

### What broke and how I fixed it
`readOnlyRootFilesystem: true` broke Juice Shop's startup. The app rewrites files in its working directory at boot — it copies seed data to `/juice-shop/ftp`, creates a SQLite DB under `/juice-shop/data`, writes `.well-known/csaf/*`, and rewrites `frontend/dist/frontend/*` for title/easter-egg customization. With a read-only root every one of these threw `EROFS`. The fix: an initContainer copies the entire `/juice-shop` directory from the image into an `emptyDir` volume, which the main container then mounts back at `/juice-shop` (plus a separate `emptyDir` at `/tmp`). The root filesystem stays read-only — writes are confined to explicit, ephemeral volumes — so the security property holds while the app still works.

## Bonus: Conftest Policy

### Policy (labs/lab7/policies/pod-hardening.rego)

    package main

    import rego.v1

    podspec := input.spec.template.spec

    deny contains msg if {
        input.kind == "Deployment"
        not podspec.securityContext.runAsNonRoot == true
        msg := "Pod securityContext.runAsNonRoot must be true"
    }

    deny contains msg if {
        input.kind == "Deployment"
        some c in podspec.containers
        not c.securityContext.readOnlyRootFilesystem == true
        msg := sprintf("Container %q must set readOnlyRootFilesystem: true", [c.name])
    }

    deny contains msg if {
        input.kind == "Deployment"
        some c in podspec.containers
        not c.securityContext.allowPrivilegeEscalation == false
        msg := sprintf("Container %q must set allowPrivilegeEscalation: false", [c.name])
    }

    deny contains msg if {
        input.kind == "Deployment"
        some c in podspec.containers
        not drops_all(c)
        msg := sprintf("Container %q must drop ALL capabilities", [c.name])
    }

    drops_all(c) if {
        some cap in c.securityContext.capabilities.drop
        cap == "ALL"
    }

### Output: PASS on hardened manifest

    conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
    4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

### Output: FAIL on bad manifest
A Deployment with a bare `nginx` container and no securityContext fails all four rules:

    FAIL - main - Container "app" must drop ALL capabilities
    FAIL - main - Container "app" must set allowPrivilegeEscalation: false
    FAIL - main - Container "app" must set readOnlyRootFilesystem: true
    FAIL - main - Pod securityContext.runAsNonRoot must be true
    4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions

### What this prevents at CI time
This policy catches the class of bug where a pod ships without baseline hardening — running as root, a writable root filesystem, privilege escalation allowed, or full Linux capabilities — exactly the misconfigurations that turn a single app-level RCE into a container escape (Lecture 7 slide 16's admission-control flow). Catching it at **CI time** (in the pull request, before merge) is better than relying solely on admission-time enforcement because the failure lands on the developer who wrote the manifest, with the full diff in front of them, while the change is cheap to fix — rather than being rejected later by the cluster's admission controller, where the feedback loop is slower, the author may have moved on, and a missing or misconfigured admission webhook could let it through entirely. CI-time gating shifts the check left so insecure manifests never reach the cluster in the first place.