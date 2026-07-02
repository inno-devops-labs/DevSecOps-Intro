# Lab 7 - Submission

## Task 1: Trivy Image + Config Scan

### Tool versions

```text
Trivy 0.69.3
Conftest 0.68.0
kubectl v1.34.1 client
k3d v5.9.0 with rancher/k3s:v1.33.0-k3s1
```

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|-------------------:|
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
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.4.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Dockerfile config scan

The sample Dockerfile scan found one high-severity misconfiguration:

```text
DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
```

### Compared to Lab 4's Grype scan

`CVE-2023-46233` / `GHSA-xwcq-pm8m-c4vf` was found by both tools for `crypto-js@3.3.0`, and both reported the same fixed version, `4.2.0`. This is a straightforward agreement case: both vulnerability databases mapped the package and vulnerable version range the same way.

`CVE-2015-9235` is a good divergence example at the identifier layer: Trivy emitted the CVE for `jsonwebtoken`, while the Lab 4 Grype report showed the matching issue as `GHSA-c7hr-j4mj-j2w6`. That is not necessarily a true miss; it is advisory alias normalization and database presentation. In a real triage queue I would normalize CVE/GHSA aliases before deciding that one scanner uniquely found the issue.

## Task 2: Kubernetes Hardening

### Namespace PSS labels

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

### Deployment securityContext sections

```yaml
serviceAccountName: juice-shop
automountServiceAccountToken: false
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
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

### NetworkPolicy ingress + egress

```yaml
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

```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-857795c66c-qbtwn   1/1     Running   0          56s
```

### Trivy K8s scan

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

### What broke and how it was fixed

`readOnlyRootFilesystem: true` first broke Juice Shop because the container writes to more than `/tmp`: it restores files into `/juice-shop/ftp`, writes SQLite/data state, updates frontend public assets, and touches `.well-known/csaf/provider-metadata.json`. Mounting only `/tmp` and logs was not enough. The final manifest uses an initContainer to copy `/juice-shop` into an `emptyDir` and mounts that writable copy back at `/juice-shop`, while the container root filesystem remains read-only and PSS restricted controls stay enabled.

## Bonus: Conftest Policy

### Policy

```rego
package main

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot
	msg := "deployment must set spec.template.spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem
	msg := sprintf("container %q must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("container %q must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not drops_all_capabilities(container)
	msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

drops_all_capabilities(container) if {
	container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```text
FAIL - /tmp/bad-pod-lab7.yaml - main - container "app" must drop ALL Linux capabilities
FAIL - /tmp/bad-pod-lab7.yaml - main - container "app" must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod-lab7.yaml - main - deployment must set spec.template.spec.securityContext.runAsNonRoot to true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### What this prevents at CI time

The policy catches insecure pod specs before `kubectl apply` or admission control sees them: missing non-root execution, writable root filesystems, privilege escalation, and undeclared capability drops. CI-time failure is cheaper than admission-time rejection because the developer gets feedback in the PR, before a release job or deployment pipeline starts touching a cluster.
