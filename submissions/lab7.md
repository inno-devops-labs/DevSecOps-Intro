# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2026-45447 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | High | base64url | 0.0.6 | >=3.0.0 |
| CVE-2023-46233 | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2020-15084 | High | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | High | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2022-23539 | High | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | High | jsonwebtoken | 0.1.0 | >=4.2.2 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2022-23539 | High | jsonwebtoken | 0.4.0 | 9.0.0 |

### Compared to Lab 4's Grype scan
1. `CVE-2026-45447` was found by both Trivy and Grype in `libssl3t64` version `3.5.5-1~deb13u2`, with the same fixed version `3.5.6-1~deb13u2`. This is a direct match because both tools mapped the Debian package and advisory ID the same way.
2. `CVE-2026-24842` was found by Trivy and missed by Grype in the Lab 4 comparison. The likely reason is different package matching and advisory mapping: Trivy detected this vulnerability in the `tar` package and linked it to advisory `GHSA-34x7-hfp2-rc4v`, while Grype did not report the same CVE in its results.

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
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

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
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: juice-shop
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
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
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - protocol: TCP
        port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-7f8f796ccb-s7wkv   1/1     Running   0          4m38s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` blocked Juice Shop startup writes to `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/i18n`, `/juice-shop/frontend/dist/frontend`, `/juice-shop/.well-known/csaf`, `/juice-shop/logs`, and `/tmp`. I fixed this with `emptyDir` volumes and an init container that copies bundled image data into writable mounts before the main container starts. The pod then reached `Ready 1/1` with zero restarts while keeping `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, and `seccompProfile: RuntimeDefault`.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

has_value(arr, value) if {
  some i
  arr[i] == value
}

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

deny contains msg if {
  input.kind == "Deployment"
  not pod_spec.securityContext.runAsNonRoot == true
  msg := "pod must set spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  input.kind == "Deployment"
  c := pod_spec.containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %q must set readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := pod_spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := pod_spec.containers[_]
  security_context := object.get(c, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  drop := object.get(capabilities, "drop", [])
  not has_value(drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
exit=0
```

### Output: FAIL on bad manifest
```
FAIL - C:\Users\stepa\AppData\Local\Temp\bad-pod-lab7.yaml - main - container "app" must drop ALL capabilities
FAIL - C:\Users\stepa\AppData\Local\Temp\bad-pod-lab7.yaml - main - container "app" must set allowPrivilegeEscalation: false
FAIL - C:\Users\stepa\AppData\Local\Temp\bad-pod-lab7.yaml - main - container "app" must set readOnlyRootFilesystem: true
FAIL - C:\Users\stepa\AppData\Local\Temp\bad-pod-lab7.yaml - main - pod must set spec.securityContext.runAsNonRoot: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
exit=1
```

### What this prevents at CI time (2-3 sentences)
This policy catches insecure pod specs before `kubectl apply` reaches the Kubernetes admission-control path shown in Lecture 7 slide 16. CI-time failure is better because the developer gets feedback in the pull request, before a bad manifest is merged or rejected by the cluster API server. It prevents missing non-root execution, writable root filesystems, privilege escalation, and retained Linux capabilities from becoming deployable artifacts.
