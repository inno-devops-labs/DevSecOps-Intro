# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 5 |
| High | 43 | 41 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Compared to Lab 4's Grype scan

1. **CVE-2026-45447 (libssl3t64)** — Found by BOTH Grype and Trivy. This is a Debian OpenSSL vulnerability present in the base OS layer. Both tools detect it because they scan the same OS package database (Trivy via its built-in Debian advisory DB, Grype via NVD/GitHub Advisory). Agreement is expected for OS-level CVEs.

2. **CVE-2023-46233 (crypto-js)** — Found by Trivy but NOT by Grype. Trivy's vulnerability database includes npm advisory data that Grype's SBOM-based scan missed. Grype scanned the CycloneDX SBOM from Lab 4, which may have had incomplete package metadata for transitive dependencies. Trivy scans the actual image layers and detects the vulnerable `crypto-js@3.3.0` directly.

---

## Task 2: Kubernetes Hardening

### Manifests

**`namespace.yaml` PSS labels:**
```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```

**`deployment.yaml` securityContext sections:**
```yaml
# Pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

# Container-level
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

**`networkpolicy.yaml` ingress + egress:**
```yaml
policyTypes:
  - Ingress
  - Egress
ingress:
  - from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
    ports:
      - protocol: TCP
        port: 3000
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
    ports:
      - protocol: UDP
        port: 53
      - protocol: TCP
        port: 53
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - protocol: TCP
        port: 443
      - protocol: TCP
        port: 3000
```

### Pod is running
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-674d7dcd5c-h4qsd   1/1     Running   0          30s
```

### Trivy K8s scan
| Severity | Vulnerabilities | Misconfigs | Secrets |
|----------|------:|------:|------:|
| Critical | 10 | 0 | 0 |
| High | 86 | 0 | 4 |
| Medium | 78 | 2 | 4 |
| Low | 44 | 6 | 0 |

### What broke and how you fixed it

`readOnlyRootFilesystem: true` broke Juice Shop in multiple ways. The app writes to several directories at startup:
1. `/juice-shop/ftp/` — copies static files for FTP challenges
2. `/juice-shop/data/` — creates SQLite database
3. `/juice-shop/logs/` — writes access logs
4. `/juice-shop/i18n/` — copies localization files
5. `/juice-shop/frontend/dist/frontend/assets/public/videos/` — restores video files

**Fix:** Used an init container (`copy-app`) with the same Juice Shop image to copy the entire `/juice-shop` directory to an `emptyDir` volume mounted at `/juice-shop`. This makes the application directory writable while keeping the container filesystem read-only. A separate `/tmp` volume handles temporary file writes. The init container uses `/nodejs/bin/node` to run a recursive copy script since the image has no shell (distroless-like).

---

## Bonus: Conftest Policy

### Policy
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  pod := input.spec.template.spec
  not pod.securityContext.runAsNonRoot
  msg := "Pod must set securityContext.runAsNonRoot: true"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation
  msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.capabilities
  msg := sprintf("Container '%s' must define securityContext.capabilities", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.capabilities
  not has_drop_all(container)
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

has_drop_all(container) {
  container.securityContext.capabilities.drop[_] == "ALL"
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
  msg := "Pod must set automountServiceAccountToken: false"
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.seccompProfile
  msg := "Pod must define seccompProfile in securityContext"
}
```

### Output: PASS on hardened manifest
```
7 tests, 7 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - main - Container 'app' must define securityContext.capabilities
FAIL - main - Container 'app' must set securityContext.readOnlyRootFilesystem: true
FAIL - main - Pod must define seccompProfile in securityContext
FAIL - main - Pod must set automountServiceAccountToken: false
FAIL - main - Pod must set securityContext.runAsNonRoot: true
7 tests, 2 passed, 0 warnings, 5 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches pods missing critical Pod Security Standards controls **before** `kubectl apply` runs. It enforces the `restricted` profile requirements: non-root execution, read-only filesystem, no privilege escalation, dropped capabilities, no service account token mounting, and seccomp profile. Catching at CI-time is better than admission-time because it provides immediate feedback to developers in the PR workflow, before the code is merged. Admission controllers (like kube-apiserver's Pod Security Admission) can be bypassed in misconfigured clusters or with `--namespace` exceptions, while CI gates are harder to circumvent and catch issues at the earliest possible stage.
