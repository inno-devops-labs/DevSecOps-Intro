
# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 5 |
| High | 35 | 35 |
| **Total** | 40 | 40 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | >=4.2.2 |

### Compared to Lab 4's Grype scan
**CVE-2026-45447 (libssl3t64)**
Both Grype and Trivy found this vulnerability because it is a Debian package issue with a clear package name/version match and a well-established CVE identifier. The overlap shows that both scanners can detect OS-level vulnerabilities in the same image when the package metadata and advisory mapping are aligned.

**NSWG-ECO-428 (base64url)**
Trivy found NSWG-ECO-428, but Grype did not report it in the Lab 4 SBOM-based output, likely because Trivy’s vulnerability database includes this npm advisory ID and its npm package matching is more current for this library. Grype’s result set can differ due to DB freshness and advisory coverage differences, especially for non-CVE or ecosystem-specific advisory IDs in JavaScript dependencies.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
...
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL
```
- `networkpolicy.yaml` ingress + egress:
```yaml
ingress:
- from:
  - podSelector: {}
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: kube-system
egress:
- to:
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: kube-system
    podSelector:
      matchLabels:
        k8s-app: kube-dns
  ports:
  - protocol: UDP
    port: 53
- ports:
  - protocol: TCP
    port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
juice-shop-7db7ccf4fc-hj5px ready=true phase=Running restarts=0
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 20 |
| High | 172 |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` caused Juice Shop to fail when it tried to write runtime files under `/juice-shop/frontend/dist/frontend/index.html` and related frontend assets. I fixed it by mounting `emptyDir` volumes for the writable application paths, including `/tmp`, `/usr/src/app/logs`, `/juice-shop/logs`, `/juice-shop/ftp`, `/juice-shop/data`, `/juice-shop/i18n`, and `/juice-shop/frontend/dist`, while keeping the container root filesystem read-only.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

# Helper: true if array arr contains value v
has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := "pod spec must set spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - container "app" must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - pod spec must set spec.securityContext.runAsNonRoot: true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)
This policy catches insecure pod definitions before `kubectl apply` reaches the cluster by validating manifest hardening rules at PR/CI time. Catching these issues in CI prevents insecure workloads from being deployed at all, which is stronger than admission-time detection because it avoids risk and review churn before the cluster sees the resource.

