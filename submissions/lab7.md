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
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:
**1. One that BOTH Grype and Trivy found:** `CVE-2019-10744` (in the `lodash` package). 
Both scanners reliably detect this because it is a highly ubiquitous, well-documented vulnerability in the National Vulnerability Database (NVD). Since both Anchore's feed (Grype) and Aqua's Vulnerability DB (Trivy) aggregate baseline NVD data and standard OS package indices, core ecosystem flaws are matched equally well by both tools.

**2. One that ONE tool found and the OTHER missed:** `NSWG-ECO-428` (in the `base64url` package).
Trivy detected this ecosystem-specific advisory, while Grype often misses non-standard identifiers. This highlights a difference in database aggregation: Trivy is notably more aggressive at pulling in developer-centric feeds like GitHub Security Advisories (GHSA) and Node Security Working Group (NSWG) trackers. Grype tends to rely more heavily on formal CVE assignments and strict package-to-CPE matching, which can sometimes cause it to overlook language-specific ecosystem alerts that haven't been fully migrated to the standard NVD format.

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

        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
```
- `networkpolicy.yaml` ingress + egress:
```yaml
  ingress:
  - ports:
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
  - ports:
    - protocol: TCP
      port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-6479846b85-2qrgx   1/1     Running   0          2m36s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

### What broke and how you fixed it (2-3 sentences)
Setting `readOnlyRootFilesystem: true` broke the Juice Shop application because it dynamically generates and modifies files at startup across multiple directories. To fix this, I mounted ephemeral `emptyDir` volumes to the required paths (e.g., `/juice-shop/data`, `/juice-shop/frontend`, `/juice-shop/.well-known`). Since the distroless image lacks standard shell utilities, I also added an `initContainer` with an inline Node.js script to recursively clone the original image files into these empty volumes before the main container starts.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

import rego.v1

all_containers contains c if {
    c := input.spec.template.spec.containers[_]
}
all_containers contains c if {
    c := input.spec.template.spec.initContainers[_]
}

deny contains msg if {
    input.kind == "Deployment"
    pod_spec := input.spec.template.spec
    not pod_spec.securityContext.runAsNonRoot == true
    msg := sprintf("Deployment '%s' missing pod-level runAsNonRoot=true", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := all_containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' is missing readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := all_containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' must have allowPrivilegeEscalation set to false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := all_containers[_]
    not drops_all_capabilities(container)
    msg := sprintf("Container '%s' must drop 'ALL' capabilities", [container.name])
}

drops_all_capabilities(container) if {
    container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' is missing readOnlyRootFilesystem=true
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop 'ALL' capabilities
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must have allowPrivilegeEscalation set to false
FAIL - /tmp/bad-pod.yaml - main - Deployment 'bad-app' missing pod-level runAsNonRoot=true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions

```

### What this prevents at CI time (2-3 sentences)
This policy catches infrastructure misconfigurations—specifically missing `securityContext` boundaries—during the CI pipeline before `kubectl apply` sends them to the cluster. As illustrated in the admission control diagram (Lecture 7 slide 16), catching these flaws at CI-time enables a true "shift-left" approach, providing instant feedback to developers rather than relying on late-stage admission webhooks to reject the deployment.
