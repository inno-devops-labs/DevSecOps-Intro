# Lab 7 - Submission

Scan snapshot: 2026-07-02, using Trivy 0.71.1, kubectl v1.34.1, kind v0.32.0, and Conftest dev / OPA 1.15.2 against `bkimminich/juice-shop:v20.0.0`.

## Task 1: Trivy Image + Config Scan

Commands run:

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json

trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format table --output labs/lab7/results/trivy-image.txt

trivy config /tmp/lab7-config \
  --severity HIGH,CRITICAL \
  --format table --output labs/lab7/results/trivy-config-bad.txt
```

The sample Dockerfile config scan found one High misconfiguration, `DS-0002`, because the final `USER` instruction was `root`.

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|-------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
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

### Compared to Lab 4's Grype scan

`CVE-2019-10744` was found by both Grype and Trivy for `lodash@2.4.2`, and both tools reported it as Critical with fixed version `4.17.12`. This is a straightforward application dependency match where both vulnerability databases agree on the affected version range.

`CVE-2025-57349` was reported by Trivy in Lab 4 for `messageformat@2.3.0`, but Grype did not report it in that snapshot. The most likely cause is advisory ingestion and affected-version matching rather than simple severity scoring; the tools normalize package advisories differently, and Trivy retained this CVE while Grype's DB/matcher did not surface it.

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` PSS labels:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext sections:

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
```

The image is pinned by digest:

```yaml
image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

`networkpolicy.yaml` ingress and egress:

```yaml
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
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-7d9796c649-n44cz   1/1     Running   0          61s
```

### Trivy K8s scan

Command run:

```bash
trivy k8s --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
```

Summary report for `Deployment/juice-shop`:

| Severity | Vulnerabilities | Misconfigurations | Secrets |
|----------|----------------:|------------------:|--------:|
| Critical | 10 | 0 | 0 |
| High | 86 | 0 | 4 |

The remaining High/Critical findings are from the vulnerable Juice Shop image and secret scanner findings in the intentionally vulnerable app, not from Kubernetes hardening misconfigurations.

### What broke and how I fixed it

`readOnlyRootFilesystem: true` initially broke Juice Shop because the app rewrites runtime files during startup. The first failures were under `/tmp`, `/juice-shop/logs`, `/juice-shop/ftp`, and the SQLite/data paths, then additional startup customizers wrote to `.well-known`, `i18n`, and `frontend/dist/frontend`.

I fixed this with an initContainer that copies the original image content into `emptyDir` volumes, then mounts those volumes at `/tmp`, `/juice-shop/logs`, `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/uploads`, `/juice-shop/.well-known`, `/juice-shop/i18n`, and `/juice-shop/frontend/dist/frontend`. This keeps the container root filesystem read-only while allowing the specific runtime paths Juice Shop needs to mutate.

## Bonus: Conftest Policy

### Policy

```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
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
  not drops_all_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

drops_all_capabilities(container) if {
  container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest

```text
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```text
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop ALL Linux capabilities
FAIL - /tmp/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation=false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem=true
FAIL - /tmp/bad-pod.yaml - main - pod securityContext.runAsNonRoot must be true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches insecure pod template drift before `kubectl apply` reaches the cluster: a developer cannot accidentally remove non-root execution, the read-only root filesystem, privilege-escalation blocking, or dropped Linux capabilities. Catching this in CI is better than waiting for admission control because the PR fails close to the author, with clear messages and without relying on a live cluster-side rejection path.
