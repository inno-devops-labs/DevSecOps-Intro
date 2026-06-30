# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

*(Trivy 0.71.1, `--severity HIGH,CRITICAL` on `bkimminich/juice-shop:v20.0.0`.)*

### Dockerfile misconfig scan (Task 7.2)
Intentionally bad Dockerfile (`FROM node:latest`, `USER root`, `EXPOSE 22`, `ADD https://...`):

| Check ID | Severity | Finding |
|----------|----------|---------|
| DS-0002 | HIGH | Last `USER` is `root` — container escape risk |

```
Tests: 20 (SUCCESSES: 19, FAILURES: 1)
Failures: 1 (HIGH: 1, CRITICAL: 0)
```

> **Retry note:** first attempt failed (`TLS handshake timeout` downloading Trivy check bundle → `Detected config files: num=0`). After check bundle cached (`sha256:1583562f…`, downloaded via subsequent `trivy k8s`), rescan in a clean directory succeeded.

### Rescan comparison (old vs new)
| Scan | Run 1 (17:18) | Run 2 (17:53) | Delta |
|------|--------------:|--------------:|-------|
| Image HIGH/CRITICAL | 48 (5 Crit + 43 High) | 48 (5 Crit + 43 High) | **identical** |
| With fix available | 46 | 46 | **identical** |
| Dockerfile config | 0 files (bundle timeout) | 1 HIGH (DS-0002) | **now works** |
| Trivy check bundle | not cached | cached | downloaded |

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

### Compared to Lab 4's Grype scan

**1. Both tools found — CVE-2026-45447 (libssl3t64)**
Trivy and Grype both flag the same OpenSSL package in the Debian layer (`libssl3t64@3.5.5-1~deb13u2`, High) with fix `3.5.6-1~deb13u2`. Agreement here is expected: OS packages are matched by name/version against shared NVD/OS advisory feeds, and both scanners scanned the same image digest.

**2. Divergent finding — CVE-2019-10744 (Trivy) vs CVE-2026-34180 (Grype)**
Trivy reports **CVE-2019-10744** on bundled `lodash@2.4.2` (Critical, fix 4.17.12) via node-pkg analysis; Grype missed it in our Lab 4 SBOM scan, while Grype reported **CVE-2026-34180** on the same `libssl3t64` package that Trivy did not list separately (Trivy consolidated to CVE-2026-45447). Divergence comes from different vulnerability DBs/update cadence (Grype DB from June 2026 vs Trivy DB), different transitive dependency matching in SBOM vs image layers, and Grype's broader OS-advisory aliasing for OpenSSL backports.

---

## Task 2: Kubernetes Hardening

### Manifests (relevant snippets)

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
        runAsUser: 1000
        fsGroup: 1000
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
    - from:
        - namespaceSelector: {}
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

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-8786c6ff7-r6t5j   1/1     Running   0          5m27s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |

*(Trivy `k8s --include-namespaces juice-shop --report summary`: no HIGH/CRITICAL misconfigurations or vulnerabilities in the hardened namespace.)*

### What broke and how you fixed it
`readOnlyRootFilesystem: true` caused CrashLoopBackOff: Juice Shop writes to `/tmp`, `/juice-shop/logs`, `/juice-shop/ftp`, seeds SQLite under `/juice-shop/data`, patches `frontend/dist/frontend/index.html`, and updates `.well-known/csaf/`. Mounting a blank `emptyDir` directly on `/juice-shop/data` wiped baked-in static files. Fix: an **initContainer** (Node copy script, distroless image has no shell) seeds `data`, `.well-known`, and `frontend` from the image into `emptyDir` volumes; additional `emptyDir` mounts for `/tmp`, `/logs`, and `/ftp` let the app start under PSS `restricted`.

---

## Bonus: Conftest Policy

### Policy (paste `labs/lab7/policies/pod-hardening.rego`)
```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "pod must set spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.securityContext.runAsNonRoot != true
  msg := "pod must set spec.securityContext.runAsNonRoot to true"
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
  container.securityContext.readOnlyRootFilesystem != true
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
  not "ALL" in container.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}
```

### Output: PASS on hardened manifest
```
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - pod must set spec.securityContext.runAsNonRoot to true

6 tests, 3 passed, 0 warnings, 3 failures, 0 exceptions
```

### What this prevents at CI time
Per Lecture 7 slide 16 (admission control), this policy catches **misconfiguration / excessive privilege** bugs (missing `runAsNonRoot`, writable root FS, privilege escalation) in the **build phase** before manifests reach the API server. CI-time gating gives developers fast feedback in the PR pipeline and blocks merge; admission-time enforcement is still necessary as a safety net, but catching issues in CI avoids deploying non-compliant pods that would be rejected or warn-only under PSS migration modes.
