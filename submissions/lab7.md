# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity  |  Total | With fix available |
| --------- | -----: | -----------------: |
| Critical  |      5 |                  4 |
| High      |     43 |                 42 |
| **Total** | **48** |             **46** |

### Top 10 CVEs with fixes

| CVE            | Severity | Package              | Installed       | Fix             |
| -------------- | -------- | -------------------- | --------------- | --------------- |
| CVE-2023-46233 | Critical | crypto-js            | 3.3.0           | 4.2.0           |
| CVE-2015-9235  | Critical | jsonwebtoken         | 0.1.0           | 4.2.2           |
| CVE-2015-9235  | Critical | jsonwebtoken         | 0.4.0           | 4.2.2           |
| CVE-2019-10744 | Critical | lodash               | 2.4.2           | 4.17.12         |
| CVE-2026-45447 | High     | libssl3t64           | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428   | High     | base64url            | 0.0.6           | >=3.0.0         |
| CVE-2020-15084 | High     | express-jwt          | 0.1.3           | 6.0.0           |
| CVE-2022-25881 | High     | http-cache-semantics | 3.8.1           | 4.1.1           |
| CVE-2022-23539 | High     | jsonwebtoken         | 0.1.0           | 9.0.0           |
| NSWG-ECO-17    | High     | jsonwebtoken         | 0.1.0           | >=4.2.2         |

### Compared to Lab 4's Grype scan

1. **CVE found by both Grype and Trivy (CVE-2019-10744):**

   This vulnerability in `lodash 2.4.2` was detected by both scanners, though Grype reported it as `GHSA-jf85-cpcp-j695` while Trivy used the `CVE-2019-10744` identifier. Both tools correctly identified the vulnerable package version because this is a well-documented prototype pollution flaw present in multiple advisory databases (NVD, GitHub Security Advisories, npm advisory). The identifier difference simply reflects each tool's primary reference source — Grype prefers GitHub Security Advisory IDs, while Trivy normalizes to CVE numbers — but both point to the exact same underlying vulnerability with identical remediation (upgrade `lodash` to 4.17.19+).

2. **CVE found only by Trivy (CVE-2026-45447):**

   This OpenSSL vulnerability was detected only by Trivy, while Grype reported a different CVE (`CVE-2026-34182`) for the same package in Lab 4. This discrepancy demonstrates how vulnerability scanners depend on different advisory databases and mapping strategies — Trivy's database (Aqua Security) and Grype's database (Anchore) may ingest vulnerabilities at different times or from different sources (distro-specific advisories vs. upstream CVE feeds). The same underlying package issue can receive different CVE identifiers depending on which advisory source published it first, illustrating why running multiple scanners provides better coverage than relying on a single tool.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)

- `namespace.yaml` PSS labels:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

- `deployment.yaml` securityContext sections (pod + container):

Pod-level security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
```

Container-level security context:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
  runAsNonRoot: true
  runAsUser: 1000
```

- `networkpolicy.yaml` ingress + egress:

```yaml
ingress:
  - from:
      - namespaceSelector: {}
    ports:
      - port: 3000
        protocol: TCP
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
    ports:
      - port: 53
        protocol: UDP
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - port: 443
        protocol: TCP
```

### Pod is running

Output of `kubectl get pod -n juice-shop -l app=juice-shop`:

```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-bc46cb56f-l9x9z    1/1     Running   0          37s
```

### Trivy K8s scan

| Severity | Count |
| -------- | ----: |
| Critical |     5 |
| High     |    43 |

### What broke and how you fixed it (2-3 sentences)

`readOnlyRootFilesystem: true` likely broke Juice Shop. What paths did it need to write?
How did you fix it (which emptyDir mounts)?

The `readOnlyRootFilesystem: true` setting broke Juice Shop because it needs to write to several directories: `/tmp` for temporary files, `/usr/src/app/logs` for application logging, and `/usr/src/app/data` for the SQLite database. I fixed this by mounting three emptyDir volumes at these paths, which creates temporary writable directories that exist for the pod's lifetime. This maintains the security benefit of read-only root filesystem while providing the necessary writable locations the application requires.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)

```rego
package main

import future.keywords

is_deployment {
    input.kind == "Deployment"
}

deny[msg] {
    is_deployment
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := "Pod must set spec.securityContext.runAsNonRoot to true"
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' must set readOnlyRootFilesystem to true", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' must set allowPrivilegeEscalation to false", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    caps := container.securityContext.capabilities
    not caps.drop
    msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    caps := container.securityContext.capabilities
    not "ALL" in caps.drop
    msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container '%s' must set runAsNonRoot to true", [container.name])
}
```

### Output: PASS on hardened manifest

```
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set runAsNonRoot to true
FAIL - /tmp/bad-pod.yaml - main - Pod must set spec.securityContext.runAsNonRoot to true

6 tests, 2 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)

Reference Lecture 7 slide 16 (admission control diagram). What Class of bug does this
policy catch BEFORE `kubectl apply` runs? Why is catching at CI-time better than at admission-time?

This policy catches pods missing critical hardening controls (`runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation`, capabilities drop) before `kubectl apply`, preventing insecure workloads from ever reaching the cluster. CI-time gating is superior to admission-time enforcement because it shifts security feedback to the pull request stage — developers get immediate rejection during code review rather than after deployment, eliminating the window where a misconfigured pod could briefly exist in the cluster. As Lecture 7 slide 16 illustrates, admission control sits at the API server, but CI-side policy gates sit even earlier, stopping non-compliant manifests before they leave the developer's machine.
