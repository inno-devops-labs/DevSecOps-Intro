# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

`trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL`

| Severity     | Total | With fix available |
|--------------|------:|------------------:|
| Critical     |     5 |                 5 |
| High         |    43 |                41 |
| **Total**    |**48** |            **46** |

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2015-9235  | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235  | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash       | 2.4.2 | 4.17.12 |
| CVE-2023-46233 | CRITICAL | crypto-js    | 3.3.0 | 4.2.0 |
| CVE-2016-1000223 | HIGH  | jws          | 0.2.6 | >=3.0.0 |
| CVE-2017-18214 | HIGH   | moment       | 2.0.0 | 2.19.3 |
| CVE-2018-16487 | HIGH   | lodash       | 2.4.2 | >=4.17.11 |
| CVE-2020-15084 | HIGH   | express-jwt  | 0.1.3 | 6.0.0 |
| CVE-2021-23337 | HIGH   | lodash       | 2.4.2 | 4.17.21 |
| CVE-2022-23539 | HIGH   | jsonwebtoken | 0.1.0 | 9.0.0 |

### Compared to Lab 4's Grype scan

**CVE found by BOTH — CVE-2026-45447 [HIGH]:**  
Both Trivy and Grype flagged `libssl3t64 3.5.5-1~deb13u2` (OpenSSL, Debian Trixie base layer). The tools agreed here because CVE-2026-45447 is a well-publicized OS-level CVE published in mid-2026 with a clear fix version (`3.5.6-1~deb13u2`) that both vulnerability databases picked up quickly after disclosure.

**CVE found only by Grype — CVE-2026-34180 [HIGH]:**  
Grype (run against the CycloneDX SBOM in Lab 4) found this libssl3t64 CVE; Trivy's scan of the same image did not surface it. The most likely explanation is database freshness: Grype's `grype-db` was pulled at SBOM-scan time and contained this 2026 CVE entry, while Trivy's `trivy-db` snapshot used in the Lab 7 scan either hadn't incorporated the advisory yet or applies a different minimum EPSS threshold before surfacing LOW/HIGH entries from that CVE family. This is the "DB freshness" divergence described in Lecture 7.

**CVE found only by Trivy — CVE-2015-9235 [CRITICAL]:**  
Trivy found an aged `jsonwebtoken 0.1.0` JWT algorithm-confusion CVE that Grype's SBOM scan missed entirely. Grype builds its graph from the CycloneDX SBOM, which lists npm package names and versions; however, Juice Shop bundles multiple old copies of `jsonwebtoken` inside deeply nested `node_modules/` paths. Grype matched the top-level dependency but missed the shadowed older copies, whereas Trivy's layer-by-layer filesystem walk found all installed paths including the transitive copies.

---

## Task 2: Kubernetes Hardening

### Manifests

**`namespace.yaml` PSS labels:**
```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```

**`deployment.yaml` securityContext sections:**
```yaml
# Pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 65532      # actual UID from image (USER 65532)
  runAsGroup: 0
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

# Container-level
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

**`networkpolicy.yaml` ingress + egress:**
```yaml
ingress:
  - ports:
      - port: 3000
        protocol: TCP
egress:
  - ports:           # DNS
      - port: 53
        protocol: UDP
      - port: 53
        protocol: TCP
  - ports:           # HTTPS outbound
      - port: 443
        protocol: TCP
```

### Pod is running

```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-7db86975d8-hwbwp   1/1     Running   0          10s
```

Security context as applied (from `kubectl get pod -o jsonpath`):
```json
Pod:       {"fsGroup":65532,"runAsGroup":0,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}
Container: {"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}
```

### Trivy K8s scan

`trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL`

| Severity | Count |
|----------|------:|
| Critical |     5 |
| High     |    43 |


### What broke and how it was fixed

Setting `readOnlyRootFilesystem: true` caused Juice Shop to fail on startup because it writes its SQLite database, log files and challenge-state files at runtime. Two paths required writable mounts: `/tmp` (Node.js temp files and SQLite scratch) and `/juice-shop/logs` (the app's structured log output). Both were resolved by mounting `emptyDir: {}` volumes at those paths. One additional discovery: the lab template suggested `runAsUser: 1000`, but the actual image sets `USER 65532` in its Dockerfile — using 1000 would have caused a permission error on the `/juice-shop` working directory which is `chown=65532:0`. Matching the UID to 65532 was necessary for the pod to start.

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)

```rego
package main

import rego.v1

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

deny contains msg if {
  pod_spec
  not pod_spec.securityContext.runAsNonRoot == true
  msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  caps := container.securityContext.capabilities.drop
  not "ALL" in caps
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  not container.securityContext.capabilities.drop
  msg := sprintf("Container '%s' must set capabilities.drop: [ALL]", [container.name])
}
```

### Output: PASS on hardened manifest

```
$ conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies/
5 tests, 5 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```
$ conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies/
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set capabilities.drop: [ALL]
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - Deployment must set spec.template.spec.securityContext.runAsNonRoot: true

5 tests, 1 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

Lecture 7 slide 16 shows admission control as the last wall before a pod lands on a node — but by that point the image has already been built, pushed, and a deployment PR has been merged. Catching missing `runAsNonRoot`, `readOnlyRootFilesystem`, and capability drops at **CI time** (when `conftest test` runs on the manifest PR) means the fix costs a one-line YAML edit and a re-push, not a rollback of a running workload or an emergency OPA webhook update. CI-time enforcement also produces a clear developer-facing error message with the exact field that's wrong, whereas admission-time rejection surfaces as a cryptic `kubectl apply` failure that most developers don't know how to read — making CI both earlier and friendlier than admission control.
