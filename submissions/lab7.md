# Lab 7 — Submission

## Environment

- Trivy: 0.71.1
- kubectl client: v1.34.1
- Docker: 29.2.0
- kind: v0.32.0
- conftest: dev / OPA 1.15.2
- jq: 1.7.1

Note: `kindest/node:v1.33.0` repeatedly failed locally with `containerd://Unknown` and `failed to recover state` errors after pod sandbox creation. I verified the final manifests on `kindest/node:v1.31.0`, where the node stayed Ready with containerd 1.7.18. The Kubernetes hardening controls and PSS labels are the same.

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|-------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | Critical | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | High | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | High | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | High | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | High | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | High | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Dockerfile config scan

The sample Dockerfile scan completed and found one HIGH misconfiguration: `DS-0002`, because the last `USER` instruction was `root`. This matches the lab point that non-root containers reduce blast radius if an application bug becomes code execution.

### Compared to Lab 4's Grype scan

`CVE-2026-45447` was found by both tools for Debian package `libssl3t64` version `3.5.5-1~deb13u2`, with fix `3.5.6-1~deb13u2`. This is a straightforward OS package match where both scanners can map the installed dpkg package to the Debian advisory data, so the result agrees.

`CVE-2023-46233` was found by Trivy for npm package `crypto-js` version `3.3.0`, fixed in `4.2.0`, but it was not present in the Lab 4 Grype SBOM scan output. The difference is likely from package/advisory matching and database freshness: Trivy's npm matching reported the vulnerable package from the image filesystem, while the older Grype-from-SBOM result did not include that CVE for the same image artifact.

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` PSS labels:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext sections and writable mounts:

```yaml
serviceAccountName: juice-shop
automountServiceAccountToken: false
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
initContainers:
  - name: prepare-db-file
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    command:
      - /nodejs/bin/node
      - -e
      - require("fs").cpSync("/juice-shop/data", "/work/data", {recursive:true, force:true}); require("fs").cpSync("/juice-shop/.well-known", "/work/well-known", {recursive:true, force:true}); require("fs").cpSync("/juice-shop/frontend/dist/frontend", "/work/frontend", {recursive:true, force:true})
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    volumeMounts:
      - name: data
        mountPath: /work/data
      - name: well-known
        mountPath: /work/well-known
      - name: frontend
        mountPath: /work/frontend
containers:
  - name: juice-shop
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
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

`networkpolicy.yaml` ingress + egress:

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

Output of `kubectl get pod -n juice-shop -l app=juice-shop` after a 3-minute stability check:

```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-797b455bd7-r5z9f   1/1     Running   0          3m25s
```

### Trivy K8s scan

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

Trivy summary for `Deployment/juice-shop` reported 10 critical vulnerabilities, 86 high vulnerabilities, and 4 high secrets. No high/critical Kubernetes misconfigurations were reported for the hardened deployment.

### What broke and how I fixed it

`readOnlyRootFilesystem: true` initially broke Juice Shop because the application writes runtime state and startup-customized files under `/tmp`, `/juice-shop/logs`, `/juice-shop/ftp`, `/juice-shop/data`, `/juice-shop/i18n`, `/juice-shop/.well-known`, and `/juice-shop/frontend/dist/frontend`. Mounting an emptyDir directly on `/juice-shop/data` hid required static files, so I added an initContainer that copies the image's original `/juice-shop/data`, `.well-known`, and frontend dist tree into emptyDir volumes before the main container starts. The final deployment keeps the root filesystem read-only and provides explicit writable emptyDir mounts only for the paths Juice Shop needs.

## Bonus: Conftest Policy

### Policy

```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := "pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not drops_all(container)
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}

drops_all(container) if {
  container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```text
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation=false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem=true
FAIL - /tmp/bad-pod.yaml - main - pod securityContext.runAsNonRoot must be true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches missing pod hardening controls before `kubectl apply`, including root-capable pods, writable root filesystems, privilege escalation, and retained Linux capabilities. Catching this in CI is better than admission-time only because the developer gets feedback before merge/deploy, and the insecure manifest never reaches a cluster-specific admission path.
