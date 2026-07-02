# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| `CVE-2026-45447` | High | `libssl3t64` | `3.5.5-1~deb13u2` | `3.5.6-1~deb13u2` |
| `NSWG-ECO-428` | High | `base64url` | `0.0.6` | `>=3.0.0` |
| `CVE-2023-46233` | Critical | `crypto-js` | `3.3.0` | `4.2.0` |
| `CVE-2020-15084` | High | `express-jwt` | `0.1.3` | `6.0.0` |
| `CVE-2022-25881` | High | `http-cache-semantics` | `3.8.1` | `4.1.1` |
| `CVE-2015-9235` | Critical | `jsonwebtoken` | `0.1.0` | `4.2.2` |
| `CVE-2022-23539` | High | `jsonwebtoken` | `0.1.0` | `9.0.0` |
| `NSWG-ECO-17` | High | `jsonwebtoken` | `0.1.0` | `>=4.2.2` |
| `CVE-2015-9235` | Critical | `jsonwebtoken` | `0.4.0` | `4.2.2` |
| `CVE-2022-23539` | High | `jsonwebtoken` | `0.4.0` | `9.0.0` |

### Sample Dockerfile config scan
I created the intentionally bad sample Dockerfile from the lab instructions and scanned it with Trivy. On this Trivy version, the direct file-path variant did not detect the Dockerfile, so I re-ran it from a directory with the file named `Dockerfile`, which produced one High finding:

| Check | Severity | Meaning |
|-------|----------|---------|
| `DS-0002` | High | Last `USER` command in the Dockerfile should not be `root` |

### Compared to Lab 4's Grype scan
1. One CVE that both tools found: the `jsonwebtoken` issue surfaced in both tools, but under different identifiers. Trivy reported `CVE-2015-9235` for `jsonwebtoken 0.1.0` and `0.4.0`, while Lab 4's Grype results reported the corresponding GitHub advisory `GHSA-c7hr-j4mj-j2w6` for the same package versions. This is a good example of identifier aliasing rather than a substantive disagreement: both tools were effectively pointing at the same vulnerable component.
2. One issue where the tools diverged: Lab 4's Grype results included `GHSA-35jh-r3h4-6jhm` for `lodash 2.4.2`, while this Trivy image run did not report that exact identifier. The most likely reason is advisory-source normalization and database mapping differences: Grype preserved the GHSA record directly, while Trivy favored a different identifier set and did not emit that exact advisory label in this run.

## Task 2: Kubernetes Hardening

### Manifests (relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

- `deployment.yaml` securityContext sections (pod + container):
```yaml
spec:
  serviceAccountName: juice-shop-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: juice-shop
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
```

- `networkpolicy.yaml` ingress + egress:
```yaml
spec:
  podSelector:
    matchLabels:
      app: juice-shop
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: juice-shop
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
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-6c886d8d66-cl8jk   1/1     Running   0          12m
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

The Trivy K8s summary showed the workload itself still carries vulnerable packages and a few high-severity secret detections, but the Kubernetes resource misconfiguration section for the hardened manifests was clean at High/Critical severity.

### What broke and how you fixed it
`readOnlyRootFilesystem: true` broke Juice Shop in several places because this image mutates content at startup instead of treating its filesystem as immutable. I fixed that by keeping the root filesystem read-only, then adding `emptyDir` mounts for `/tmp`, `/juice-shop/logs`, `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/i18n`, `/juice-shop/frontend/dist/frontend`, `/juice-shop/frontend/dist/frontend/assets/public/videos`, and `/juice-shop/.well-known`, plus an `initContainer` that pre-copied the original application data into the writable overlays before the main container started.

## Bonus: Conftest Policy

### Policy
```rego
package main

pod_spec := object.get(object.get(input.spec, "template", {}), "spec", {})

deny contains msg if {
  input.kind == "Deployment"
  object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
  msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  container := pod_spec.containers[i]
  object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
  name := container.name
  msg := sprintf("Container %q must set readOnlyRootFilesystem to true", [name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  container := pod_spec.containers[i]
  object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false
  name := container.name
  msg := sprintf("Container %q must set allowPrivilegeEscalation to false", [name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  container := pod_spec.containers[i]
  drops := object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
  not "ALL" in drops
  name := container.name
  msg := sprintf("Container %q must drop capability ALL", [name])
}
```

### Output: PASS on hardened manifest
```text
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```text
FAIL - /tmp/bad-pod.yaml - main - Container "app" must drop capability ALL
FAIL - /tmp/bad-pod.yaml - main - Container "app" must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - Container "app" must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - Deployment must set spec.template.spec.securityContext.runAsNonRoot to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time
This policy catches pod-hardening regressions before anyone gets to `kubectl apply`, which means insecure manifests can be blocked directly in the developer workflow or CI pipeline. Catching them at CI time is better than waiting for admission-time rejection because it gives faster feedback, keeps bad configs out of deployment reviews entirely, and avoids wasting cluster-side cycles on manifests that never should have been proposed for deployment.
