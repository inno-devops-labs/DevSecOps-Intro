# Lab 7 - Submission

## Task 1: Trivy Image + Config Scan

Commands used:

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json

trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format table | tee labs/lab7/results/trivy-image.txt

trivy config /tmp/Dockerfile \
  --severity HIGH,CRITICAL \
  --format table | tee labs/lab7/results/trivy-config.txt
```

Tool versions:

```text
Trivy: 0.71.1
Grype: 0.114.0
Syft: 1.45.1
```

Image digest used for the Kubernetes manifest:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|-------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

Trivy also reported 2 HIGH secret findings of type `private-key` in the image. I did not paste the secret material into this submission.

### Config scan result

The sample Dockerfile scan reported 1 HIGH misconfiguration:

```text
DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
```

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2016-1000223 | HIGH | jws | 0.2.6 | >=3.0.0 |
| CVE-2017-18214 | HIGH | moment | 2.0.0 | 2.19.3 |
| CVE-2018-16487 | HIGH | lodash | 2.4.2 | >=4.17.11 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2021-23337 | HIGH | lodash | 2.4.2 | 4.17.21 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |

### Compared to Lab 4's Grype scan

I regenerated a Syft CycloneDX SBOM for `bkimminich/juice-shop:v20.0.0` and scanned it with Grype to compare against the Trivy image scan.

`CVE-2026-45447` was found by both tools on `libssl3t64` version `3.5.5-1~deb13u2`, with fixed version `3.5.6-1~deb13u2`. This is the straightforward overlap case: both scanners matched the Debian package inventory and both databases had a current Debian/OpenSSL advisory for the package.

`CVE-2015-9235` appeared in Trivy for `jsonwebtoken` versions `0.1.0` and `0.4.0`, but Grype reported the same vulnerable package family under GitHub Security Advisory IDs such as `GHSA-c7hr-j4mj-j2w6` instead of that CVE ID. This is a normalization and advisory-source difference, not proof that the vulnerable dependency is absent from Grype. It is exactly why DefectDojo-style deduplication needs more than a raw CVE string: package matching, advisory namespace, and DB freshness can all change the visible ID.

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
serviceAccountName: juice-shop
automountServiceAccountToken: false
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  fsGroupChangePolicy: OnRootMismatch
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: juice-shop
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

- `networkpolicy.yaml` ingress + egress:

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

```text
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-b94bbb7f7-mkvqx   1/1     Running   0          112s
```

### Trivy K8s scan

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 86 |

Trivy k8s also reported 4 HIGH secret findings. The count is higher than the image scan because the same pinned image is used by both the init container and the main application container.

### What broke and how you fixed it

`readOnlyRootFilesystem: true` initially broke Juice Shop because the application mutates files at startup. It needed writable state for `/tmp`, `/juice-shop/logs`, `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/uploads`, `/juice-shop/frontend/dist/frontend`, `/juice-shop/i18n`, and `/juice-shop/.well-known`.

The final Deployment keeps the root filesystem read-only and mounts `emptyDir` volumes only at those write paths. For paths that need seed files (`data`, `ftp`, `frontend/dist/frontend`, `i18n`, and `.well-known`), an initContainer copies the original image contents into the writable volumes before the main container starts.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)

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
  not container.securityContext.allowPrivilegeEscalation == false
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
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop ALL Linux capabilities
FAIL - /tmp/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - deployment must set spec.template.spec.securityContext.runAsNonRoot to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches insecure pod hardening mistakes before `kubectl apply` reaches the cluster: missing non-root execution, writable root filesystems, privilege escalation, and retained Linux capabilities. Admission control is still valuable as the last enforcement point, but CI-time feedback is faster and cheaper because the PR author sees the exact broken manifest before rollout, failed deployments, or production admission rejections.
