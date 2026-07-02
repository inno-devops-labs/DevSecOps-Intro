# Lab 7 — Submission

## Environment

The work was executed against a local `kind` cluster on 2 July 2026.

| Tool | Version |
|---|---:|
| Docker CLI | 27.5.1 |
| Trivy | 0.69.2 |
| kubectl | 1.33.0 |
| kind | 0.29.0 |
| Conftest | 0.68.0 |
| OPA | 1.15.1 |
| jq | 1.7.1 |
| Grype fallback | 0.114.0 |

The scanned image was pinned to the following immutable multi-platform digest:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

The image scan was restricted to `HIGH` and `CRITICAL` findings.

| Severity | Total | With fix available |
|---|---:|---:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

A fixed version exists for 46 of the 48 findings. Remediation should therefore begin with fixed critical vulnerabilities and then continue with fixed high-severity vulnerabilities.

### Top 10 vulnerabilities with fixes

| CVE/advisory | Severity | Package | Installed | Fix |
|---|---|---|---|---|
| CVE-2015-9235 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | Critical | lodash | 2.4.2 | 4.17.12 |
| CVE-2023-46233 | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2016-1000223 | High | jws | 0.2.6 | >=3.0.0 |
| CVE-2017-18214 | High | moment | 2.0.0 | 2.19.3 |
| CVE-2018-16487 | High | lodash | 2.4.2 | >=4.17.11 |
| CVE-2020-15084 | High | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2021-23337 | High | lodash | 2.4.2 | 4.17.21 |
| CVE-2022-23539 | High | jsonwebtoken | 0.1.0 | 9.0.0 |

The repeated `CVE-2015-9235` rows are separate package instances. The image contains vulnerable `jsonwebtoken` versions `0.1.0` and `0.4.0`.

### Dockerfile config scan

The intentionally insecure sample Dockerfile was scanned with Trivy's Dockerfile misconfiguration analyzer. Because the file uses the non-standard name `Dockerfile-bad`, the analyzer was selected explicitly with `--file-patterns`:

```bash
trivy config labs/lab7/results \
  --misconfig-scanners dockerfile \
  --file-patterns 'dockerfile:.*Dockerfile-bad$' \
  --severity HIGH,CRITICAL \
  --format table
```

Trivy detected one configuration file and executed 20 checks:

```text
Target: Dockerfile-bad
Type: dockerfile
Tests: 20
Successes: 19
Failures: 1
High: 1
Critical: 0
```

The failed rule was:

```text
DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
Dockerfile-bad:2
2 [ USER root
```

Running the container as `root` increases the impact of a container breakout or application compromise. The remediation is to create or select an unprivileged user and make the final effective `USER` instruction reference that account. The other intentionally suspicious lines in this minimal sample were not classified as `HIGH` or `CRITICAL` by Trivy 0.69.2 under the selected severity filter.

The hardened Kubernetes manifests were also scanned with `trivy config`; all four manifests returned zero high or critical misconfigurations.

### Compared with Grype

The previous Lab 4 Grype JSON was not present in the repository, so Grype 0.114.0 was rerun against the same pinned Juice Shop image. The comparison produced 2 common advisory IDs, 34 Trivy-only IDs, and 92 Grype-only IDs.

#### Finding detected by both tools: CVE-2026-45447

Both scanners detected `CVE-2026-45447` in Debian package `libssl3t64` version `3.5.5-1~deb13u2`. Both identified `3.5.6-1~deb13u2` as the fixed version. This is an exact package, installed-version, advisory, and fixed-version match.

#### Finding detected by Grype but absent from Trivy: CVE-2026-34182

Grype reported `CVE-2026-34182` as Critical for `libssl3t64` version `3.5.5-1~deb13u2`, with `3.5.6-1~deb13u2` as the fix. Trivy 0.69.2 did not report this advisory even though it discovered the same package. The divergence is therefore most plausibly caused by advisory-feed freshness or different Debian/OpenSSL advisory normalization rather than package inventory discovery. Grype attached an EPSS value of `0.00237`; EPSS can help prioritize remediation, but it does not control whether a scanner maps a package to a vulnerability.

## Task 2: Kubernetes Hardening

### Namespace PSS labels

```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```

The live namespace reported the enforced profile as:

```text
restricted
```

An intentionally non-compliant Pod was rejected by Pod Security Admission because it lacked `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `runAsNonRoot: true`, and an allowed seccomp profile.

### Dedicated ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: juice-shop-sa
  namespace: juice-shop
automountServiceAccountToken: false
```

### Pod and container security context

```yaml
spec:
  serviceAccountName: juice-shop-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    fsGroupChangePolicy: OnRootMismatch
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
          cpu: 250m
          memory: 512Mi
        limits:
          cpu: 500m
          memory: 1Gi
```

The image is pinned by digest rather than a mutable tag. The workload also disables automatic ServiceAccount token mounting at both the ServiceAccount and Pod levels.

### Writable paths with a read-only root filesystem

Juice Shop modifies several directories at runtime, but those directories also contain seed files shipped in the image. Mounting an empty `emptyDir` directly over them makes the directory writable while hiding the original files.

The final Deployment therefore uses a hardened init container to copy the image contents into writable `emptyDir` volumes before the main container starts. The main container mounts the prepared volumes over these paths:

```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: data
    mountPath: /juice-shop/data
  - name: ftp
    mountPath: /juice-shop/ftp
  - name: i18n
    mountPath: /juice-shop/i18n
  - name: logs
    mountPath: /juice-shop/logs
  - name: frontend-dist
    mountPath: /juice-shop/frontend/dist
  - name: csaf
    mountPath: /juice-shop/.well-known/csaf
```

The init container itself also uses `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, resource limits, and the Pod-level `RuntimeDefault` seccomp profile.

### NetworkPolicy

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
        - podSelector: {}
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
        - ipBlock:
            cidr: 127.0.0.1/32
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

The selected Pod is isolated for both ingress and egress. DNS is limited to CoreDNS in `kube-system`, while general outbound connectivity is restricted to TCP port 443.

### Pod is running

The corrected Deployment rolled out successfully, and the final Pod was ready with zero restarts:

```text
NAME                          READY   STATUS    RESTARTS   AGE     IP           NODE
juice-shop-68cd775696-7wcq8   1/1     Running   0          4m32s   10.244.0.6   lab7-control-plane
```

The compact verification output was:

```text
NAME                          READY   PHASE     RESTARTS
juice-shop-68cd775696-7wcq8   true    Running   0
```

Application logs confirmed successful initialization and startup:

```text
info: Entity models 21 of 21 are initialized (SUCCESS)
info: Port 3000 is available (SUCCESS)
info: Server listening on port 3000
```

### Trivy Kubernetes scan

The live-cluster scan completed successfully. Because the same image is used by both the init container and the main container, Trivy's workload summary counts each image finding twice.

| Finding type | Critical | High |
|---|---:|---:|
| Workload aggregate | 10 | 86 |
| Unique image findings | 5 | 43 |
| Kubernetes misconfigurations | 0 | 0 |
| Workload secrets | 0 | 4 |
| Unique image secrets | 0 | 2 |

The remaining vulnerability and secret findings originate from the deliberately vulnerable application image. No high or critical Kubernetes misconfigurations were reported for the hardened workload.

### What broke and how it was fixed

The first read-only-root implementation mounted an empty `emptyDir` directly at `/juice-shop/data`. This hid files already present in the image, including `/juice-shop/data/static/legal.md` and `/juice-shop/data/static/securityQuestions.yml`. Juice Shop then failed during security-question initialization and entered `CrashLoopBackOff`.

The corrected Deployment performs a copy-up operation in an init container. It copies the original contents of `data`, `ftp`, `i18n`, `logs`, `frontend/dist`, and `.well-known/csaf` into writable `emptyDir` volumes before the main container starts. This preserves the required seed files while keeping the main container's root filesystem read-only.

## Bonus: Conftest Policy Gate

### Policy

```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  pod_spec := input.spec.template.spec
  pod_security_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_security_context, "runAsNonRoot", false) != true
  msg := "pod must set spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %q must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "allowPrivilegeEscalation", null) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  drop_list := object.get(capabilities, "drop", [])
  not "ALL" in drop_list
  msg := sprintf("container %q must drop the ALL capability set", [container.name])
}
```

### PASS on the hardened manifest

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### FAIL on an intentionally insecure Deployment

```text
FAIL - container "app" must drop the ALL capability set
FAIL - container "app" must set allowPrivilegeEscalation to false
FAIL - container "app" must set readOnlyRootFilesystem to true
FAIL - pod must set spec.securityContext.runAsNonRoot to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

The policy rejects insecure pod-template configuration before `kubectl apply`: root-capable execution, writable container root filesystems, privilege escalation, and retained Linux capabilities. CI-time enforcement gives immediate feedback in the pull request and prevents a known-bad manifest from reaching cluster admission control, reducing deployment churn and limiting reliance on consistent admission-policy configuration across clusters.

