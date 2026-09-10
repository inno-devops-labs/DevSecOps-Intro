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
1. `CVE-2015-9235` was found by both Trivy and Grype for `jsonwebtoken`
(`0.1.0` and `0.4.0`). Trivy reports the CVE ID directly as a Critical
npm vulnerability with fix `4.2.2`; Grype reports the matching GitHub
advisory `GHSA-c7hr-j4mj-j2w6` and links it to the same CVE. This is a
straightforward match where both tools identify the same vulnerable package,
but prefer different primary advisory identifiers.

2. `CVE-2026-34182` was present in the Lab 4 Grype output for Debian package
`libssl3t64` `3.5.5-1~deb13u2`, fixed in `3.5.6-1~deb13u2`, but it was not
present in the current Trivy image JSON. The likely reason is vulnerability
database and advisory-source freshness: Grype's result set includes more
Debian/OpenSSL advisories for this package, while this Trivy run only reported
`CVE-2026-45447` for the same package under the selected High/Critical filter.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```
- `serviceaccount.yaml` dedicated ServiceAccount:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: juice-shop
  namespace: juice-shop
automountServiceAccountToken: false
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
spec:
  template:
    spec:
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
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: logs
              mountPath: /juice-shop/logs
            - name: ftp
              mountPath: /juice-shop/ftp
            - name: data
              mountPath: /juice-shop/data
            - name: i18n
              mountPath: /juice-shop/i18n
            - name: frontend
              mountPath: /juice-shop/frontend/dist/frontend
            - name: well-known
              mountPath: /juice-shop/.well-known
```
- `networkpolicy.yaml` ingress + egress:
```yaml
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
        podSelector:
          matchLabels:
            k8s-app: kube-dns
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
```
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-544d5d89d-2pq8r   1/1     Running   0          2m9s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 45 |

Command used with this Trivy version:
```bash
trivy k8s --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
```

Breakdown from the summary report: 5 Critical vulnerabilities, 43 High vulnerabilities, and 2 High secret findings for `Deployment/juice-shop`.

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` initially made Juice Shop crash because the app writes runtime state under paths such as `/juice-shop/data`, `/juice-shop/ftp`, `/tmp`, logs, frontend assets, and `.well-known`. I fixed it by mounting `emptyDir` volumes at the writable paths while keeping the container root filesystem read-only. An initContainer copies the required seed data from the image into writable `emptyDir` volumes before the main container starts.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

import rego.v1

pod_spec := input.spec.template.spec if {
	input.kind == "Deployment"
}

workload_containers contains container if {
	container := pod_spec.containers[_]
}

workload_containers contains container if {
	container := pod_spec.initContainers[_]
}

deny contains msg if {
	input.kind == "Deployment"
	object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
	msg := "pod spec must set securityContext.runAsNonRoot: true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
	msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false
	msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := workload_containers[_]
	not "ALL" in object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
	msg := sprintf("container %q must drop all Linux capabilities with capabilities.drop: [\"ALL\"]", [container.name])
}
```

### Output: PASS on hardened manifest
```
$ ~/go/bin/conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies --no-color

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
$ ~/go/bin/conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies --no-color
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop all Linux capabilities with capabilities.drop: ["ALL"]
FAIL - /tmp/bad-pod.yaml - main - container "app" must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - pod spec must set securityContext.runAsNonRoot: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)
This policy catches insecure Kubernetes workload manifests before `kubectl apply` reaches the cluster admission path. It prevents regressions such as running as root, writable root filesystems, privilege escalation, and retained Linux capabilities from entering review or deployment. CI-time feedback is faster and cheaper than admission-time rejection because developers get a deterministic failure in the PR pipeline instead of discovering the problem during deployment.
