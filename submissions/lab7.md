# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Severity distribution from image scan
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

### Top 10 vulnerabilities with available patches
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

### Comparison with Lab 4’s Grype results
1. Both scanners identified `CVE-2015-9235` for `jsonwebtoken` (versions 0.1.0 and 0.4.0). Trivy reports it directly as a Critical npm vulnerability with fix version `4.2.2`, while Grype presents the corresponding GitHub advisory `GHSA-c7hr-j4mj-j2w6` which references the same CVE. The two tools agree on the vulnerable package but highlight different advisory identifiers.

2. `CVE-2026-34182` appeared in the Lab 4 Grype output for the Debian package `libssl3t64` `3.5.5-1~deb13u2`, with a fix in `3.5.6-1~deb13u2`, but it did not appear in this Trivy image scan. The most probable explanation is database and advisory-source freshness: Grype pulled more Debian/OpenSSL advisories for this package, whereas Trivy under the High/Critical severity filter only reported `CVE-2026-45447` for the same package.

## Task 2: Kubernetes Hardening

### Manifest excerpts (relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```
serviceaccount.yaml dedicated ServiceAccount:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: juice-shop
  namespace: juice-shop
automountServiceAccountToken: false
```
deployment.yaml securityContext sections (pod + container):
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
networkpolicy.yaml ingress + egress:
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
## Pod running confirmation

Output of kubectl get pod -n juice-shop -l app=juice-shop:

```text
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-544d5d89d-2pq8r   1/1     Running   0          2m9s
```
## Trivy Kubernetes scan

```text
Severity	Count
Critical	5
High	45
```
Command used with this Trivy version:

```bash
trivy k8s --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
```
From the summary: 5 Critical vulnerabilities, 43 High vulnerabilities, and 2 High secret findings in Deployment/juice-shop.

## What broke and how it was resolved

Setting readOnlyRootFilesystem: true initially prevented Juice Shop from starting because the application writes to directories such as /juice-shop/data, /juice-shop/ftp, /tmp, log paths, frontend assets, and .well-known. The solution was to mount emptyDir volumes on those writable locations while retaining a read-only container root filesystem. An initContainer copies the necessary seed data from the image into the ephemeral volumes before the main container begins execution.

## Bonus: Conftest Policy

Policy (labs/lab7/policies/pod-hardening.rego)

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

```text
$ ~/go/bin/conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies --no-color

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```
### Output: FAIL on a non-compliant manifest

```text
$ ~/go/bin/conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies --no-color
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop all Linux capabilities with capabilities.drop: ["ALL"]
FAIL - /tmp/bad-pod.yaml - main - container "app" must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - pod spec must set securityContext.runAsNonRoot: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```
## What this prevents during CI

This policy intercepts insecure Kubernetes workload definitions before kubectl apply reaches the cluster’s admission flow. It stops regressions like running as root, writable root filesystems, privilege escalation, and leftover Linux capabilities from entering code review or deployment. Providing feedback at CI time is faster and more cost‑effective than relying on admission-time rejection, because developers see a deterministic failure in the pull request pipeline rather than discovering issues during deployment.
