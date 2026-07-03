# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity  | Total | With fix available |
|-----------|------:|------------------:|
| Critical  |     5 |                 4 |
| High      |    43 |                42 |
| **Total** |**48** |              **46** |

### Top 10 CVEs with fixes

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

### Dockerfile misconfig scan
Trivy `config` scan on a sample bad Dockerfile (`FROM node:latest`, `USER root`, `EXPOSE 22`):

```
Dockerfile (dockerfile)
Tests: 20 (SUCCESSES: 19, FAILURES: 1)
Failures: 1 (HIGH: 1, CRITICAL: 0)

DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
Dockerfile:2 → USER root
```

### Compared to Lab 4's Grype scan

**CVE both tools found — CVE-2019-10744 (lodash, CRITICAL):**
Both Grype and Trivy independently flagged `lodash@2.4.2` for CVE-2019-10744 (prototype pollution via `defaultsDeep`). This is expected — the CVE is years old, assigned in NVD and mirrored in GitHub Advisory DB, so both tools' databases contain it. The fix (`4.17.12`) is identical in both reports.

**CVE Grype found, Trivy missed — GHSA-5mrr-rgp6-x4gr (marsdb, Critical):**
Grype reported `GHSA-5mrr-rgp6-x4gr` for `marsdb@0.6.11` as Critical with no fix version; Trivy did not surface this finding. This GHSA-only advisory has no assigned CVE number — Trivy's primary source is NVD plus OSV, which hadn't picked up this advisory at scan time. Grype's direct GitHub Advisory Database integration means it catches GHSA-only entries faster, while Trivy may lag by days-to-weeks for advisories without a CVE alias. This matches the Lab 4 observation exactly (Lecture 7 + Lecture 4: tool DB freshness and source coverage differ).

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

**`deployment.yaml` securityContext (pod + container):**
```yaml
securityContext:                        # pod-level
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: juice-shop
    securityContext:                    # container-level
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

**`networkpolicy.yaml` ingress + egress:**
```yaml
policyTypes: [Ingress, Egress]
ingress:
  - ports:
      - port: 3000
        protocol: TCP
egress:
  - ports:
      - port: 53   # DNS (UDP + TCP)
        protocol: UDP
      - port: 53
        protocol: TCP
  - ports:
      - port: 443  # HTTPS only
        protocol: TCP
```

### Pod is running

```
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-f7dbc7cc4-x2jng   1/1     Running   0          15s
```

### Trivy K8s scan

```
Workload Assessment
┌────────────┬───────────────────────┬─────────────────┬───────────────────┬─────────┐
│ Namespace  │       Resource        │ Vulnerabilities │ Misconfigurations │ Secrets │
│            │                       ├───────┬─────────┼─────────┬─────────┼────┬────┤
│            │                       │   C   │   H     │    C    │    H    │ C  │ H  │
├────────────┼───────────────────────┼───────┼─────────┼─────────┼─────────┼────┼────┤
│ juice-shop │ Deployment/juice-shop │   5   │   43    │         │         │    │ 2  │
└────────────┴───────────────────────┴───────┴─────────┴─────────┴─────────┴────┴────┘
```

| Category          | Critical | High |
|-------------------|:--------:|:----:|
| Vulnerabilities   |    5     |  43  |
| Misconfigurations |    0     |   0  |
| Secrets           |    0     |   2  |

All CVE findings originate from the `node_modules` layer of the image (same as the image scan). 0 misconfigurations confirms the deployment passed PSS `restricted`. The 2 High secrets are hardcoded tokens embedded in the Juice Shop source code itself (intentional for the DAST challenges), not from the deployment manifest.

### What broke and how I fixed it

`readOnlyRootFilesystem: true` caused Juice Shop to crash immediately on startup because the app writes to three paths at runtime: `/tmp` (Express session temp files and SQLite WAL), `/usr/src/app/logs` (Winston logger output), and `/usr/src/app/data` (SQLite database file on first run). The fix was mounting three `emptyDir: {}` volumes at those exact paths — `emptyDir` provides a writable in-memory (or node-local) filesystem scoped to the pod's lifetime, satisfying `readOnlyRootFilesystem` while giving the app the write access it needs.

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment '%s': pod securityContext must set runAsNonRoot: true", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("Deployment '%s': container '%s' must set readOnlyRootFilesystem: true", [input.metadata.name, container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Deployment '%s': container '%s' must set allowPrivilegeEscalation: false", [input.metadata.name, container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not "ALL" in container.securityContext.capabilities.drop
  msg := sprintf("Deployment '%s': container '%s' must drop ALL capabilities", [input.metadata.name, container.name])
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Deployment 'bad-app': container 'app' must set allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - Deployment 'bad-app': container 'app' must set readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - Deployment 'bad-app': pod securityContext must set runAsNonRoot: true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches missing hardening **before the manifest ever reaches the cluster** — at `git push` or PR CI step, before `kubectl apply` even runs. Lecture 7 slide 16 shows the admission control diagram: even with a Kubernetes Admission Webhook in place, a policy caught at CI time costs seconds to fix (edit the YAML, push again), while the same violation caught at admission time requires a developer to context-switch back to infrastructure mid-deploy. More importantly, some clusters don't have a webhook at all — catching it at CI is the only gate. CI-time policy also runs without cluster credentials, making it safe to enforce in a public PR pipeline where cluster access would be a security risk.
