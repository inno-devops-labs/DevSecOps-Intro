# Lab 7 — Container Security: Trivy + Pod Security Standards + Policy Gate

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 5 |
| High | 43 | 41 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2026-48779 | HIGH | ws | 8.17.1 | 8.21.0 |
| CVE-2026-48779 | HIGH | ws | 7.4.6 | 7.5.11 |
| CVE-2024-37890 | HIGH | ws | 7.4.6 | 7.5.10 |
| CVE-2026-31802 | HIGH | tar | 6.2.1 | 7.5.11 |
| CVE-2026-29786 | HIGH | tar | 6.2.1 | 7.5.10 |
| CVE-2026-26960 | HIGH | tar | 6.2.1 | 7.5.8 |
| CVE-2026-24842 | HIGH | tar | 6.2.1 | 7.5.7 |
| CVE-2026-23950 | HIGH | tar | 6.2.1 | 7.5.4 |
| CVE-2026-23745 | HIGH | tar | 6.2.1 | 7.5.3 |
| CVE-2026-31802 | HIGH | tar | 4.4.19 | 7.5.11 |

### Dockerfile misconfig scan
Running `trivy fs /tmp/Dockerfile` against a deliberately bad Dockerfile found 4 misconfigurations:

| Rule | Severity | Finding |
|------|----------|---------|
| DS-0002 | HIGH | Last USER command is `root` — containers should not run as root |
| DS-0001 | MEDIUM | `FROM node:latest` — unpinned tag causes uncontrolled updates |
| DS-0004 | MEDIUM | `EXPOSE 22` — SSH port exposed in container |
| DS-0026 | LOW | No HEALTHCHECK instruction |

### Compared to Lab 4's Grype scan

**CVE both Grype and Trivy found — CVE-2024-37890 (ws package, HIGH):**
Both tools independently flagged the `ws` WebSocket library at version 7.4.6 as vulnerable to a denial-of-service attack. This agreement gives high confidence the finding is real — both Grype (via GitHub Advisory DB) and Trivy (via its own advisory DB) have matching entries, the package name and version match exactly, and both agree on the fix version. Cross-tool agreement on the same CVE ID with the same package eliminates the risk of a false positive from one DB's stale or incorrect entry.

**CVE only Grype found — GHSA-c7hr-j4mj-j2w6 (jsonwebtoken, Critical):**
Grype flagged two versions of `jsonwebtoken` (0.1.0 and 0.4.0) as Critical via the GitHub Security Advisory database. Trivy did not surface this finding in its July 2026 DB snapshot. The most likely explanation is DB refresh cadence: GitHub Advisory entries for npm packages are sometimes ingested into Trivy's advisory DB days or weeks after they appear in Grype's GitHub Advisory feed. Trivy also applies vendor severity overrides from the Node.js ecosystem advisories, which can cause the same CVE to be ranked differently or temporarily omitted while the severity is being reconciled across sources.

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
  runAsUser: 1000
  fsGroup: 1000
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
policyTypes:
  - Ingress
  - Egress
ingress:
  - ports:
      - protocol: TCP
        port: 3000
egress:
  - ports:
      - protocol: UDP
        port: 53
  - ports:
      - protocol: TCP
        port: 443
```

### Pod is running
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-b949755c6-m8bgr    1/1     Running   0          27s
```

### Security context confirmed
Pod-level:
```json
{
  "fsGroup": 1000,
  "runAsNonRoot": true,
  "runAsUser": 1000,
  "seccompProfile": { "type": "RuntimeDefault" }
}
```
Container-level:
```json
{
  "allowPrivilegeEscalation": false,
  "capabilities": { "drop": ["ALL"] },
  "readOnlyRootFilesystem": true
}
```

### Trivy K8s scan
| Severity | Vulnerabilities | Secrets |
|----------|---------------:|--------:|
| Critical | 5 | 0 |
| High | 43 | 2 |

No misconfigurations flagged on the hardened deployment — PSS restricted compliance achieved.

### What broke and how we fixed it
Setting `readOnlyRootFilesystem: true` caused Juice Shop to crash on startup because the Node.js application writes to `/tmp` (for temporary files), `/usr/src/app/logs` (application logs), and `/usr/src/app/data` (SQLite database and uploaded files). The fix was to mount three `emptyDir{}` volumes at those exact paths — `emptyDir` provides a writable in-memory filesystem scoped to the pod's lifetime, satisfying Juice Shop's write requirements without relaxing the read-only root filesystem constraint. This is the standard pattern for PSS `restricted` compliance with applications that need ephemeral write paths.

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Pod must set securityContext.runAsNonRoot: true"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not contains_all(container.securityContext.capabilities.drop)
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

contains_all(drops) {
  drops[_] == "ALL"
}
```

### Output: PASS on hardened manifest
```
PASS - labs/lab7/k8s/deployment.yaml - main - (no violations)

0 tests, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Pod must set securityContext.runAsNonRoot: true
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop ALL capabilities

4 tests, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time
Lecture 7 slide 16 shows admission control as the last gate before a pod reaches the scheduler — but by then a developer has already written, reviewed, and pushed the manifest. Catching missing `runAsNonRoot`, `readOnlyRootFilesystem`, and capability drops at CI time (before `kubectl apply`) means the feedback loop is seconds rather than minutes, the fix happens in the PR rather than in a hotfix, and the policy runs without cluster access so it works in any pipeline regardless of environment. Catching at CI time is better than at admission time because admission controllers are a runtime safety net, not a developer feedback tool — a denied admission still means a failed deployment, an incident ticket, and wasted engineer time that a CI gate would have prevented entirely.
