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
| CVE-2023-46233 | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | Critical | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | High | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | High | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | High | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | High | jsonwebtoken | 0.1.0 | 9.0.0 |
| GHSA-c7hr-j4mj-j2w6 | High | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Compared to Lab 4's Grype scan

**CVE found by BOTH Grype and Trivy:** `CVE-2019-10744` (Grype: `GHSA-jf85-cpcp-j695`)

Both tools matched the same vulnerable npm package (`lodash@2.4.2`) in the Juice Shop image and linked it to the same prototype-pollution advisory. Grype reports it as a GitHub Security Advisory (GHSA), while Trivy maps it to the canonical CVE ID — but the underlying package, installed version, and fix version (`4.17.12`) agree. This convergence happens when both scanners index the same dependency layer and the advisory is well-catalogued in NVD/GHSA.

**CVE found by ONE tool only:** `GHSA-35jh-r3h4-6jhm` (found by: **Grype**)

Grype flagged this lodash advisory in Lab 4's top-10 (`lodash@2.4.2`, fix `4.17.21`), but Trivy's HIGH/CRITICAL-filtered image scan did not surface it in the same top-10 list. Grype prioritizes GHSA records directly from the SBOM scan path, while Trivy may deduplicate overlapping lodash findings, apply different severity cutoffs, or match via a separate vulnerability DB revision. This illustrates why Lecture 7's triage guidance — *fix available AND severity ≥ HIGH first* — should be applied per-tool, not assumed identical across scanners.

---

## Task 2: Kubernetes Hardening

### Manifests

- `namespace.yaml` PSS labels:

```yaml
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

- `deployment.yaml` securityContext sections (pod + container):

```yaml
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 0
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: juice-shop
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

- `networkpolicy.yaml` ingress + egress:

```yaml
  ingress:
    - ports:
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

### Pod is running

Output of `kubectl get pod -n juice-shop -l app=juice-shop`:

```
NAME                        READY   STATUS    RESTARTS   AGE
juice-shop-d6fcfcd8-hfcmr   1/1     Running   0          36s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 86 |

### What broke and how you fixed it (2-3 sentences)

With `readOnlyRootFilesystem: true`, Juice Shop could not write files at startup — the database in `data/`, UI files in `frontend/dist/`, translations in `i18n/`, and logs. A plain `emptyDir` over `data/` also hid the original files from the image. We fixed it with an init container that copies needed folders from the image into `emptyDir` volumes, plus extra writable mounts for `/tmp`, `i18n/`, and `logs/`.

---

## Bonus: Conftest Policy

### Policy

```rego
package main

capabilities_drop_all(container) if {
	some i
	container.securityContext.capabilities.drop[i] == "ALL"
}

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext must set runAsNonRoot: true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container %q must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not capabilities_drop_all(container)
	msg := sprintf("container %q must drop ALL capabilities", [container.name])
}
```

### Output: PASS on hardened manifest

```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```
FAIL - C:\Users\A0F1~1\AppData\Local\Temp\bad-pod.yaml - main - container "app" must drop ALL capabilities
FAIL - C:\Users\A0F1~1\AppData\Local\Temp\bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation: false
FAIL - C:\Users\A0F1~1\AppData\Local\Temp\bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem: true
FAIL - C:\Users\A0F1~1\AppData\Local\Temp\bad-pod.yaml - main - pod securityContext must set runAsNonRoot: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)

This policy catches insecure pod hardening (missing `runAsNonRoot`, writable root FS, privilege escalation, or dropped capabilities) before manifests reach the cluster. Catching this in CI gives developers fast feedback in the PR pipeline instead of a late rejection at Kubernetes admission time, and it works even without an admission webhook installed on the cluster.