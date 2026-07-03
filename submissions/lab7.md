# Lab 7 - Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity  |  Total | With fix available |
| --------- | -----: | -----------------: |
| Critical  |      5 |                  4 |
| High      |     43 |                 42 |
| **Total** | **48** |             **46** |

The image was scanned using Trivy 0.69.3:

```text
bkimminich/juice-shop:v20.0.0
```

Pinned image digest:

```text
sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Top 10 CVEs with fixes

| CVE              | Severity | Package              | Installed | Fix       |
| ---------------- | -------- | -------------------- | --------- | --------- |
| CVE-2015-9235    | Critical | jsonwebtoken         | 0.1.0     | 4.2.2     |
| CVE-2019-10744   | Critical | lodash               | 2.4.2     | 4.17.12   |
| CVE-2016-1000223 | High     | jws                  | 0.2.6     | >=3.0.0   |
| CVE-2017-18214   | High     | moment               | 2.0.0     | 2.19.3    |
| CVE-2018-16487   | High     | lodash               | 2.4.2     | >=4.17.11 |
| CVE-2020-15084   | High     | express-jwt          | 0.1.3     | 6.0.0     |
| CVE-2021-23337   | High     | lodash               | 2.4.2     | 4.17.21   |
| CVE-2022-23539   | High     | jsonwebtoken         | 0.1.0     | 9.0.0     |
| CVE-2022-24785   | High     | moment               | 2.0.0     | 2.29.2    |
| CVE-2022-25881   | High     | http-cache-semantics | 3.8.1     | 4.1.1     |

### Dockerfile config scan

Trivy detected one HIGH-severity Dockerfile misconfiguration:

```text
Dockerfile (dockerfile)
=======================
Tests: 20 (SUCCESSES: 19, FAILURES: 1)
Failures: 1 (HIGH: 1, CRITICAL: 0)

DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
```

The finding shows that the test Dockerfile would run the container as the root user. Running an application as a non-root user reduces the impact of a container compromise and is required by the restricted Pod Security Standards profile used later in this lab.

### Compared to Lab 4's Grype scan

#### CVE found by both tools: CVE-2026-45447

Both Trivy and Grype detected `CVE-2026-45447` in the Debian package `libssl3t64`. Both scanners reported the installed version as `3.5.5-1~deb13u2`, the fixed version as `3.5.6-1~deb13u2`, and the severity as High.

The tools agreed because the operating-system package and its version were represented clearly in the image metadata and could be matched directly against the Debian vulnerability data. This type of exact package-version match is generally consistent across vulnerability scanners.

#### CVE found only by Trivy: CVE-2015-9235

Trivy detected `CVE-2015-9235` in the npm package `jsonwebtoken`, including installed versions `0.1.0` and `0.4.0`, with version `4.2.2` listed as the fix. The Lab 4 Grype result contained zero matches for this CVE.

One reason for the difference is database freshness: the Grype database used in Lab 4 was built on June 19, 2026, while Trivy downloaded an updated database on July 3, 2026. The scanners also used different package discovery paths: Grype scanned the generated SBOM, while Trivy inspected the image filesystem and application package metadata directly, so Trivy could match nested npm dependencies that were absent or represented differently in the SBOM. EPSS data may influence Grype's risk prioritization and sorting, but it does not create a vulnerability match when the affected package is missing from or differently represented in the package inventory.

## Task 2: Kubernetes Hardening

### Manifests

#### `namespace.yaml` PSS labels

```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```

#### `serviceaccount.yaml`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: juice-shop-sa
  namespace: juice-shop
automountServiceAccountToken: false
```

#### `deployment.yaml` securityContext sections

Pod-level security context:

```yaml
spec:
  serviceAccountName: juice-shop-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
```

Init-container security context:

```yaml
initContainers:
  - name: seed-data
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

Main-container security context and resources:

```yaml
containers:
  - name: juice-shop
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

Writable volume mounts:

```yaml
volumeMounts:
  - name: runtime-tmp
    mountPath: /tmp
  - name: runtime-logs
    mountPath: /juice-shop/logs
  - name: runtime-data
    mountPath: /juice-shop/data
  - name: runtime-well-known
    mountPath: /juice-shop/.well-known
  - name: runtime-frontend
    mountPath: /juice-shop/frontend/dist/frontend
  - name: runtime-ftp
    mountPath: /juice-shop/ftp
```

Health probes:

```yaml
readinessProbe:
  tcpSocket:
    port: http
  initialDelaySeconds: 10
  periodSeconds: 10

livenessProbe:
  tcpSocket:
    port: http
  initialDelaySeconds: 30
  periodSeconds: 20
```

#### `networkpolicy.yaml` ingress and egress

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
    - ports:
        - protocol: TCP
          port: 443
```

The policy selects only pods with the `app=juice-shop` label. It restricts ingress to the ingress-controller namespace on TCP port 3000 and restricts egress to DNS over UDP port 53 in `kube-system` and HTTPS over TCP port 443.

### Pod is running

Output of `kubectl get pod -n juice-shop -l app=juice-shop`:

```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-848fb984dd-w7l4h   1/1     Running   0          112s
```

The namespace was verified to contain all three restricted PSS labels:

```text
juice-shop   Active   kubernetes.io/metadata.name=juice-shop,pod-security.kubernetes.io/audit=restricted,pod-security.kubernetes.io/enforce=restricted,pod-security.kubernetes.io/warn=restricted
```

The effective pod-level security context was:

```json
{
  "fsGroup": 1000,
  "runAsGroup": 1000,
  "runAsNonRoot": true,
  "runAsUser": 1000,
  "seccompProfile": {
    "type": "RuntimeDefault"
  }
}
```

The effective container-level security context was:

```json
{
  "allowPrivilegeEscalation": false,
  "capabilities": {
    "drop": [
      "ALL"
    ]
  },
  "readOnlyRootFilesystem": true
}
```

### Trivy K8s scan

| Severity | Count |
| -------- | ----: |
| Critical |    10 |
| High     |    86 |

Trivy reported the image vulnerabilities for both the main application container and the init container, because both use the same pinned Juice Shop image. The summary also contained four High-severity secret findings, while no High or Critical Kubernetes misconfiguration findings were shown for the workload.

### What broke and how it was fixed

Enabling `readOnlyRootFilesystem: true` initially caused `EROFS` errors because Juice Shop writes to `/tmp`, `/juice-shop/logs`, `/juice-shop/data`, `/juice-shop/.well-known`, `/juice-shop/frontend/dist/frontend`, and `/juice-shop/ftp`. These paths were mounted as writable `emptyDir` volumes, and an init container copied the original data, frontend files, CSAF metadata, and FTP content from the read-only image into the writable volumes before the application started.

The original HTTP probes used `/`, but Juice Shop returned HTTP 404 for that probe path even though the server was listening correctly on port 3000. The readiness and liveness probes were therefore changed to `tcpSocket` checks on the named `http` port, after which the pod reached `Running 1/1` with zero restarts.

## Bonus: Conftest Policy

### Policy

Contents of `labs/lab7/policies/pod-hardening.rego`:

```rego
package main

import rego.v1

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

deny contains msg if {
  input.kind == "Deployment"
  security_context := object.get(pod_spec, "securityContext", {})
  object.get(security_context, "runAsNonRoot", false) != true
  msg := "Pod must set securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  some container in pod_spec.containers
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("Container %q must use readOnlyRootFilesystem", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in pod_spec.containers
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("Container %q must disable privilege escalation", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in pod_spec.containers
  context := object.get(container, "securityContext", {})
  capabilities := object.get(context, "capabilities", {})
  drops := object.get(capabilities, "drop", [])
  not "ALL" in drops
  msg := sprintf("Container %q must drop ALL capabilities", [container.name])
}
```

### Output: PASS on hardened manifest

Command:

```bash
conftest test labs/lab7/k8s/deployment.yaml \
  --policy labs/lab7/policies
```

Output:

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

Exit code:

```text
0
```

### Output: FAIL on bad manifest

Command:

```bash
conftest test /tmp/bad-pod.yaml \
  --policy labs/lab7/policies
```

Output:

```text
FAIL - C:/Users/user/AppData/Local/Temp/bad-pod.yaml - main - Container "app" must disable privilege escalation
FAIL - C:/Users/user/AppData/Local/Temp/bad-pod.yaml - main - Container "app" must drop ALL capabilities
FAIL - C:/Users/user/AppData/Local/Temp/bad-pod.yaml - main - Container "app" must use readOnlyRootFilesystem
FAIL - C:/Users/user/AppData/Local/Temp/bad-pod.yaml - main - Pod must set securityContext.runAsNonRoot to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

Exit code:

```text
1
```

### What this prevents at CI time

The Conftest policy blocks Kubernetes Deployments that do not enable `runAsNonRoot`, do not use a read-only root filesystem, allow privilege escalation, or fail to drop all Linux capabilities. These are configuration and security-hardening defects that can be detected before the manifest is submitted to the Kubernetes API server.

Catching the problem during CI gives developers immediate feedback and prevents an insecure manifest from reaching the cluster at all. Admission control should still be used as a final enforcement layer, but CI-time validation detects the same class of problem earlier and reduces failed deployments and policy violations in the cluster.
