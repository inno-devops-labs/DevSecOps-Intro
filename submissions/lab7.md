# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|-------------------:|
| Critical |     5 |                  4 |
| High |    43 |                 42 |
| **Total** |     48 |                 46 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix             |
|-----|----------|---------|---------|-----------------|
|CVE-2023-46233|CRITICAL|crypto-js| 3.3.0   | 4.2.0           |
|CVE-2015-9235|CRITICAL|jsonwebtoken| 0.1.0   | 4.2.2           |
|CVE-2015-9235|CRITICAL|jsonwebtoken| 0.4.0   | 4.2.2           |
|CVE-2019-10744|CRITICAL|lodash| 2.4.2 | 4.17.12         |
|CVE-2026-45447|HIGH|libssl3t64| 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
|NSWG-ECO-428|HIGH|base64url| 0.0.6 | \>=3.0.0        |
|CVE-2020-15084|HIGH|express-jwt| 0.1.3 | 6.0.0           |
|CVE-2022-25881|HIGH|http-cache-semantics| 3.8.1 | 4.1.1           |
|CVE-2022-23539|HIGH|jsonwebtoken| 0.1.0 | 9.0.0           |
|NSWG-ECO-17|HIGH|jsonwebtoken| 0.1.0 | \>=4.2.2        |


### Compared to Lab 4's Grype scan
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:
1. One that BOTH Grype and Trivy found
2. One that ONE tool found and the OTHER missed
For each: explain why the tools differ (DB freshness? Different package matching?
EPSS scoring? Lecture 7 + Lecture 4 give context.) (2-3 sentences per CVE.)

CVE-2023-46233 (crypto-js). Both tools correctly identified this high-profile vulnerability in the crypto-js library because it is a well-known, published CVE with a clear signature that both databases index. The tools likely agree here because the vulnerability is mature, the affected package is popular, and both scanners reliably detect it using direct version matching against their vulnerability feeds.

CVE-2026-45447 (libssl3t64). This CVE was found by Trivy (from the OS package scan) but is missing in Grype. This discrepancy likely stems from different detection scopes: Trivy scans both application dependencies (Node.js) and OS-level packages (libssl), while Grype's SBOM from Syft (which by default focuses on application-layer packages) might not have included the base OS layer or the CVE was not yet in Grype's vulnerability database at the time of scanning. This shows that Trivy's broader scanning scope for container images (including OS packages) gives it an edge in detecting system-level vulnerabilities that Grype might overlook.

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
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```
- `networkpolicy.yaml` ingress + egress:
```yaml
spec:
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: juice-shop
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: TCP
          port: 3000
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
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
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
juice-shop-6d5b546c44-qdjsd   1/1     Running   0          14m
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical |     5 |
| High |    43 |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` likely broke Juice Shop. What paths did it need to write?
How did you fix it (which emptyDir mounts)?

readOnlyRootFilesystem: true broke Juice Shop because the application needs to write to directories like /tmp, /usr/src/app/logs, /usr/src/app/data, /usr/src/app/frontend/dist, and /usr/src/app/uploads for caching, logging, and temporary file storage during runtime.

To fix it without disabling the security policy, I added emptyDir volumes for these exact paths (/tmp, /usr/src/app/logs, /usr/src/app/data, /usr/src/app/frontend/dist, and /usr/src/app/uploads) and mounted them as writable directories in the container, allowing the app to run while still maintaining a read-only root filesystem. This approach follows the principle of least privilege and keeps the hardened security posture intact.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

import future.keywords.if

# Helper function to check if a container drops all capabilities
has_drop_all(container) if {
    some cap in container.securityContext.capabilities.drop
    cap == "ALL"
}
deny contains msg if{
    input.kind == "Deployment"
    spec := input.spec.template.spec
    not spec.securityContext

    msg := "Pod-level securityContext is missing (runAsNonRoot required)"
}
# Deny if runAsNonRoot is not true at pod level
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    spec.securityContext
    not spec.securityContext.runAsNonRoot == true
    msg := sprintf("Pod-level securityContext.runAsNonRoot is not true; got %v", [spec.securityContext.runAsNonRoot])
}

# Deny if ANY container has readOnlyRootFilesystem != true
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    some container in spec.containers
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' is missing readOnlyRootFilesystem: true", [container.name])
}

# Deny if ANY container has allowPrivilegeEscalation != false
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    some container in spec.containers
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' has allowPrivilegeEscalation != false", [container.name])
}

# Deny if ANY container is missing "ALL" in capabilities.drop
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    some container in spec.containers
    not has_drop_all(container)
    msg := sprintf("Container '%s' is missing 'ALL' in capabilities.drop", [container.name])
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

```

### Output: FAIL on bad manifest
```
FAIL - /project/labs/lab7/policies/bad-pod.yaml - main - Container 'app' has allowPrivilegeEscalation != false
FAIL - /project/labs/lab7/policies/bad-pod.yaml - main - Container 'app' is missing 'ALL' in capabilities.drop
FAIL - /project/labs/lab7/policies/bad-pod.yaml - main - Container 'app' is missing readOnlyRootFilesystem: true
FAIL - /project/labs/lab7/policies/bad-pod.yaml - main - Pod-level securityContext is missing (runAsNonRoot required)

5 tests, 1 passed, 0 warnings, 4 failures, 0 exceptions


```

### What this prevents at CI time (2-3 sentences)
Reference Lecture 7 slide 16 (admission control diagram). What Class of bug does this
policy catch BEFORE `kubectl apply` runs? Why is catching at CI-time better than at admission-time?

This policy catches misconfiguration bugs — specifically, pods that violate security best practices by running as root, allowing privilege escalation, or having overly permissive capabilities. By catching these at CI-time (during the pull request or merge request), you can prevent faulty manifests from ever reaching the cluster, rather than relying on admission controllers like Gatekeeper or Kyverno to reject them during kubectl apply. Catching issues earlier reduces feedback loops, saves developers from waiting for admission rejection, and prevents misconfigured workloads from even being scheduled, which is especially critical in environments with strict compliance or security requirements.