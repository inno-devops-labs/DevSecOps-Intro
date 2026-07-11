# Lab 7 — Container Security: Trivy + Pod Security Standards + Policy Gate

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity  |  Total | With fix available |
| --------- | -----: | -----------------: |
| Critical  |      5 |                  4 |
| High      |     43 |                 42 |
| **Total** | **48** |             **46** |

The scan covered OS packages, Node.js dependencies, and embedded secrets. Trivy also reported two HIGH secret findings: an RSA private key present in both the Juice Shop source and built JavaScript. This is expected for the intentionally vulnerable training image, but it would require immediate removal and rotation in a production image.

### Dockerfile misconfiguration scan

The intentionally insecure sample Dockerfile produced one HIGH finding:

| Check   | Severity | Finding                                                                          |
| ------- | -------- | -------------------------------------------------------------------------------- |
| DS-0002 | High     | The final Dockerfile `USER` is `root`; containers should run as a non-root user. |

The other intentionally insecure lines were not reported by the current Trivy checks bundle, but `USER root` was correctly detected as a high-severity container hardening issue.

### Top 10 CVEs with fixes

| CVE              | Severity | Package              | Installed       | Fix             |
| ---------------- | -------- | -------------------- | --------------- | --------------- |
| CVE-2023-46233   | Critical | crypto-js            | 3.3.0           | 4.2.0           |
| CVE-2015-9235    | Critical | jsonwebtoken         | 0.1.0           | 4.2.2           |
| CVE-2015-9235    | Critical | jsonwebtoken         | 0.4.0           | 4.2.2           |
| CVE-2019-10744   | Critical | lodash               | 2.4.2           | 4.17.12         |
| CVE-2026-45447   | High     | libssl3t64           | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2020-15084   | High     | express-jwt          | 0.1.3           | 6.0.0           |
| CVE-2022-25881   | High     | http-cache-semantics | 3.8.1           | 4.1.1           |
| CVE-2022-23539   | High     | jsonwebtoken         | 0.1.0           | 9.0.0           |
| CVE-2016-1000223 | High     | jws                  | 0.2.6           | >=3.0.0         |
| CVE-2018-16487   | High     | lodash               | 2.4.2           | >=4.17.11       |

### Compared to Lab 4 Grype scan

**CVE found by both tools — CVE-2026-45447 (`libssl3t64`).**
Grype and Trivy both reported this OpenSSL-related vulnerability for installed version `3.5.5-1~deb13u2` and both identified `3.5.6-1~deb13u2` as the fixed version. This agreement indicates that both tools matched the same Debian package metadata and had a relevant vulnerability advisory in their databases.

**CVE found only by Grype — CVE-2026-42764 (`libssl3t64`).**
The Lab 4 Grype SBOM scan reported this CVE, while the Lab 7 Trivy image report did not (`Grype: 1`, `Trivy: 0`). The difference is plausibly caused by different vulnerability data sources, database update timing, advisory/CVE normalization, or package-matching rules; EPSS is useful for prioritization but does not guarantee identical detection results. Findings should therefore be compared and triaged rather than assuming that one scanner is complete.

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` applies the Pod Security Standards restricted profile:

```yaml
metadata:
  name: juice-shop
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` applies the pod-level and main-container security contexts:

```yaml
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
          memory: "256Mi"
          cpu: "100m"
        limits:
          memory: "512Mi"
          cpu: "500m"
```

A dedicated ServiceAccount is used with `automountServiceAccountToken: false`. The image is pinned by digest:

```yaml
image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

`networkpolicy.yaml` enforces a default-deny model for the Juice Shop Pod and only allows loopback ingress on TCP/3000, DNS to CoreDNS, and HTTPS egress:

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
        - ipBlock:
            cidr: 127.0.0.0/8
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

```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-56b8b845bc-tgq4b   1/1     Running   0          75s
```

The deployed application was verified through a local port-forward:

```text
HTTP 200
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)"...
```

### Trivy K8s scan

| Category          | Critical |   High |
| ----------------- | -------: | -----: |
| Vulnerabilities   |       10 |     86 |
| Misconfigurations |        0 |      0 |
| Secrets           |        0 |      4 |
| **Total**         |   **10** | **90** |

The image is scanned twice because it is used by both the initContainer and the application container, so the image CVE and secret counts are doubled. The important hardening result is that Trivy reported **0 HIGH/CRITICAL Kubernetes misconfigurations**. The remaining vulnerabilities and secret findings belong to the intentionally vulnerable Juice Shop image, not to the Kubernetes security configuration.

### What broke and how I fixed it

`readOnlyRootFilesystem: true` initially caused the application to fail because Juice Shop needs writable state for SQLite data and modifies files during startup. Directly mounting an empty volume over `/juice-shop/data` hid required files such as `securityQuestions.yml` and `legal.md`; leaving it unmounted caused `SQLITE_CANTOPEN`. I kept the root filesystem read-only and added an initContainer that copies the original image contents into writable `emptyDir` volumes for the required paths (`/juice-shop/data`, `/juice-shop/frontend/dist`, `/.well-known`, and `/juice-shop/i18n`), while also using `emptyDir` for `/tmp`, `/juice-shop/logs`, and `/juice-shop/ftp`.

## Bonus: Conftest Policy

### Policy

```rego
package main

has_all_drop(container) if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])
  "ALL" in dropped
}

deny contains msg if {
  input.kind == "Deployment"
  pod_spec := input.spec.template.spec
  pod_security_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_security_context, "runAsNonRoot", false) != true
  msg := "Deployment pod template must set spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %q must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not has_all_drop(container)
  msg := sprintf("container %q must drop Linux capability ALL", [container.name])
}
```

### Output: PASS on hardened manifest

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```text
FAIL - /tmp/bad-pod.yaml - main - Deployment pod template must set spec.securityContext.runAsNonRoot: true
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop Linux capability ALL
FAIL - /tmp/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

The policy catches missing non-root execution, writable root filesystems, privilege escalation, and retained Linux capabilities before `kubectl apply` reaches the cluster. Catching these issues in CI gives developers faster feedback and prevents insecure manifests from entering deployment workflows; admission control remains a useful second enforcement layer for anything that bypasses CI.
