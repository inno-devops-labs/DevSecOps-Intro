# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 47 | 46 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235  | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235  | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428   | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |


### Compared to Lab 4's Grype scan
**1. CVE that BOTH Grype and Trivy found**

Both tools found **CVE-2023-46233** (`GHSA-xwcq-pm8m-c4vf`) in the `crypto-js` package. Since this vulnerability was disclosed in 2023, it has been included in the vulnerability databases of both Trivy and Grype for some time, so both scanners were able to detect it.

**2. CVE that ONE tool found and the OTHER missed**

Trivy detected **CVE-2026-53550** in the `js-yaml` package, while Grype did not. A likely explanation is that Trivy's vulnerability database was more up to date at the time of the scan, allowing it to identify this recently disclosed CVE before it became available in Grype's database.

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
  # Pod
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    fsGroup: 0
    seccompProfile:
      type: RuntimeDefault

  # Container
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
  ```

- `networkpolicy.yaml` ingress + egress:
  ```yaml
  ingress:
    - {}
  egress:
    - to:
      - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
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
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-64d854c986-8n47n   1/1     Running   0          19s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

### What broke and how you fixed it (2-3 sentences)
Enabling `readOnlyRootFilesystem: true` caused the Juice Shop pod to continuously restart. The only practical solution was to remove this setting, as fixing the issue by mounting writable directories would require detailed knowledge of the application's filesystem requirements. To access the application, port `3000` was forwarded to the host using `kubectl -n juice-shop port-forward deploy/juice-shop 3000:3000`.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

drops_all(container) if {
    container.securityContext.capabilities.drop[_] == "ALL"
}

deny contains msg if {
    input.kind == "Deployment"

    not input.spec.template.spec.securityContext.runAsNonRoot

    msg := "Pod must set spec.securityContext.runAsNonRoot=true"
}

deny contains msg if {
    input.kind == "Deployment"

    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem

    msg := sprintf("Container %q must set securityContext.readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"

    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation != false

    msg := sprintf("Container %q must set securityContext.allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"

    container := input.spec.template.spec.containers[_]
    not drops_all(container)

    msg := sprintf("Container %q must drop ALL capabilities", [container.name])
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Container "app" must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - Container "app" must set securityContext.readOnlyRootFilesystem=true
FAIL - /tmp/bad-pod.yaml - main - Pod must set spec.securityContext.runAsNonRoot=true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)
This policy catches Kubernetes security misconfigurations (policy-as-code violations), such as pods that do not run as a non-root user, allow privilege escalation, or do not use a read-only root filesystem, before they are ever submitted to the cluster. Running these checks in CI provides faster feedback to developers, prevents invalid manifests from reaching the Kubernetes API server, and avoids failed deployments that would otherwise be rejected only during admission control.
