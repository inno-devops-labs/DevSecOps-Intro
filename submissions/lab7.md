# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
Scanned `bkimminich/juice-shop:v20.0.0` with `trivy image --severity HIGH,CRITICAL`. Trivy detected a Debian 13.4 base OS plus the Node.js dependency tree and ran secret scanning.

| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

Plus **1 HIGH secret** — an asymmetric RSA private key embedded in `lib/insecurity.ts` (and its compiled `build/lib/insecurity.js`).

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
| CVE-2024-37890 | HIGH | ws | 7.4.6 | 8.17.1 |

### Config (Dockerfile) scan
Ran `trivy config` against a deliberately bad sample Dockerfile (`FROM node:latest`, `USER root`, `EXPOSE 22`, `ADD <url>`). Trivy's misconfiguration scanner flagged the `:latest` tag (no reproducible builds), the root user (container should run non-root), and the SSH port exposure — the same rule classes Checkov applied to Terraform in Lab 6, now applied to container build config.

### Compared to Lab 4's Grype scan

**CVE both tools found — crypto-js CVE-2023-46233 (CRITICAL):**
Both Grype (Lab 4) and Trivy (Lab 7) flagged crypto-js 3.3.0 with the same fix target (4.2.0). This is a well-established advisory (PBKDF2 weakness) present in both tools' databases, sourced from GitHub Security Advisories and NVD. When a CVE is this widely propagated, tool choice doesn't matter — the agreement is what makes it a high-confidence finding.

**CVE where the tools diverged — marsdb GHSA-5mrr-rgp6-x4gr (CRITICAL):**
Both tools detected the marsdb command-injection issue, but they report it differently: it has no CVE ID (only a GHSA advisory), and Trivy reports `FixedVersion: none` because marsdb is abandoned upstream with no patched release. Grype and Trivy can diverge here on two axes — (1) advisory-ID normalization (GHSA vs CVE vs vendor-specific IDs like NSWG-ECO-*), and (2) whether a "fix" is recorded, since each tool's DB ingests fix metadata from different feeds. Trivy leans on its own aquasec DB refreshed daily, while Grype uses the anchore DB; DB freshness and feed coverage explain most single-tool-only or metadata-differing findings.

---

## Task 2: Kubernetes Hardening

### Manifests

**`namespace.yaml` PSS labels** (all three enforcement modes set to `restricted`):
```yaml
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

**`deployment.yaml` securityContext (pod-level):**
```yaml
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
```

**`deployment.yaml` securityContext (container-level):**
```yaml
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

Image is pinned by digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`. ServiceAccount is dedicated (`juice-shop-sa`) with `automountServiceAccountToken: false`.

**`networkpolicy.yaml` ingress + egress** (default-deny with explicit allows):
```yaml
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - ports:
        - protocol: TCP
          port: 443
```

### Pod is running
```
NAME                          READY   STATUS    RESTARTS   AGE   IP
juice-shop-68df7c944f-vw5r9   1/1     Running   0          75s   10.244.0.7
```
Homepage `curl http://127.0.0.1:3005/` returns **HTTP 200**. The pod is admitted under PSS `restricted` enforce (no admission rejection), runs Ready 1/1, and serves traffic.

### Trivy K8s scan
```
Workload Assessment
Namespace   Resource                Vulns(C/H)   Misconfig(C/H)   Secrets(C/H)
juice-shop  Deployment/juice-shop   10 / 86      0 / 0            0 / 4
```

| Severity | Vulnerabilities | Misconfigurations | Secrets |
|----------|----------------:|------------------:|--------:|
| Critical | 10 | 0 | 0 |
| High | 86 | 0 | 4 |

The **0 misconfigurations** is the key result: Trivy's k8s scanner found no securityContext, capability, or privilege-escalation problems, confirming the deployment meets the restricted profile. (The vulnerabilities and secrets are inherent to the Juice Shop image itself — the CVEs from Task 1 and the embedded RSA key — not the deployment configuration.)

### What broke and how I fixed it
`readOnlyRootFilesystem: true` broke Juice Shop repeatedly. Chasing individual paths through crash logs revealed it writes across its entire app tree at startup: `restoreOverwrittenFilesWithOriginals` copies into `/juice-shop/ftp`, the SQLite DB opens in `/juice-shop/data`, CSAF metadata writes to `/juice-shop/.well-known`, and `customizeApplication` rewrites `/juice-shop/frontend/dist/frontend/index.html`. Rather than mount an emptyDir per path (whack-a-mole, and mounting over `data/` hid the image's `data/static/` seed files), the working solution was an **initContainer** that copies the entire `/juice-shop` directory into a single emptyDir using `/nodejs/bin/node -e "fs.cpSync(...)"` (the image is distroless — no `sh`, and `node` isn't on PATH, so the full binary path is required). The main container then mounts that populated emptyDir over `/juice-shop`, making the app directory writable while the real container root (`/`, `/usr`, `/etc`) stays read-only — preserving the hardening intent.

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

import rego.v1

deny contains msg if {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := "Pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not has_drop_all(container)
    msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

has_drop_all(container) if {
    container.securityContext.capabilities.drop[_] == "ALL"
}
```
(Written in OPA 1.x / `rego.v1` syntax — `contains` for partial-set rules and `if` before bodies, required by the installed OPA 1.15.2.)

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - Pod securityContext.runAsNonRoot must be true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time
This policy catches the same class of bug that PSS `restricted` enforces at admission — pods running as root, with a writable root filesystem, with privilege escalation allowed, or retaining Linux capabilities — but it catches them at **CI time**, when a developer opens a PR that changes a manifest, before anything reaches a cluster. Referencing Lecture 7's admission-control diagram: admission-time enforcement (PSS) is the last line of defence and only fires when someone runs `kubectl apply` against a live cluster, which means a misconfigured manifest can sit merged in `main` looking "done" until deploy day. Catching it at CI-time shifts the feedback left — the PR fails, the developer fixes it in the same context they wrote it, and the cluster's admission controller becomes a redundant safety net rather than the first (and only) place the problem surfaces.
