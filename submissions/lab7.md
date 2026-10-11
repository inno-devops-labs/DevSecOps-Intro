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
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.4.0 | 9.0.0 |

### Dockerfile config scan

Trivy detected one HIGH misconfiguration in the sample Dockerfile:

| ID | Severity | Finding |
|----|----------|---------|
| DS-0002 | HIGH | Last USER command in Dockerfile should not be `root` |

Running containers as root increases the impact of a container breakout or privilege escalation. A safer Dockerfile should use a dedicated non-root user.

### Compared to Lab 4's Grype scan

1. **jsonwebtoken vuln (CVE-2015-9235 / GHSA-c7hr-j4mj-j2w6)** — Both tools flagged the same underlying issue in `jsonwebtoken` 0.1.0/0.4.0 (fix: 4.2.2). Trivy reports it under the CVE identifier from NVD, while Grype reports it under the GitHub Security Advisory ID — same package, same installed version, same fix version, just different ID namespaces. This shows both tools converge when a vulnerability has a well-established CVE-to-GHSA cross-reference.

2. **lodash prototype pollution (GHSA-35jh-r3h4-6jhm / GHSA-jf85-cpcp-j695)** — Grype flagged multiple Critical/High `lodash` 2.4.2 findings that don't appear anywhere in Trivy's top-10 HIGH/CRITICAL list. This is likely because Grype leans more heavily on GHSA data for the npm ecosystem, and/or the two tools resolve the effective version of a deeply-nested transitive dependency differently, which changes whether a given advisory's affected-version range matches.

---

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext (pod + container):
```yaml
# pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
# container-level (both init and main container)
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

`networkpolicy.yaml` ingress + egress:
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
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - protocol: TCP
        port: 443
```

### Pod is running
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-58f87f574b-x5b6j   1/1     Running   0          3m49s

Verified live via `kubectl port-forward deployment/juice-shop 3000:3000` — app responded on http://127.0.0.1:3000.

### Trivy K8s scan
| Severity | Vulnerabilities | Secrets |
|----------|------:|------:|
| Critical | 10 | 0 |
| High | 86 | 4 |

### What broke and how you fixed it

`readOnlyRootFilesystem: true` broke Juice Shop in multiple layers. First, the app writes to several paths under `/juice-shop` at startup — not just `/tmp`, but also `data/juiceshop.sqlite` (and its SQLite journal files), `logs/`, `ftp/` (copies static files like `legal.md` and `owasp_promo.vtt` there), `i18n/*.json`, and even `.well-known/csaf/provider-metadata.json`. Piecemeal `subPath` mounts for individual files became unmanageable as new write targets kept surfacing during testing.

Second, the `bkimminich/juice-shop` image has no shell at all (`sh`/`/bin/sh` are absent — confirmed via `docker run --entrypoint sh`, which failed with "executable file not found"). `node` is also not on the image's `PATH`; it lives at the absolute path `/nodejs/bin/node` (found via `docker inspect --format '{{.Config.Entrypoint}}'`). This meant a standard busybox-style init container command (`sh -c "cp ..."`) could never run against this image, and even a plain `node -e ...` init command failed until the absolute binary path was used instead.

The final fix: an init container running the *same* Juice Shop image with `command: [/nodejs/bin/node, -e, "fs.cpSync('/juice-shop', '/work', {recursive:true})"]`, copying the entire `/juice-shop` directory tree into a shared `emptyDir` volume. The main container mounts that same volume at `/juice-shop`, making the whole application directory writable at runtime regardless of which specific file the app decides to write to — while the container's root filesystem itself stays read-only, satisfying PSS `restricted`.

---

## Bonus: Conftest Policy

### Policy
```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  run_as_non_root := object.get(input, ["spec", "template", "spec", "securityContext", "runAsNonRoot"], false)
  run_as_non_root != true
  msg := "Pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  readonly_fs := object.get(container, ["securityContext", "readOnlyRootFilesystem"], false)
  readonly_fs != true
  msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  allow_escalation := object.get(container, ["securityContext", "allowPrivilegeEscalation"], true)
  allow_escalation != false
  msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  dropped := object.get(container, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in dropped
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}
```

### Output: PASS on hardened manifest
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

### Output: FAIL on bad manifest
FAIL - labs\lab7\bad-test\bad-pod.yaml - main - Container 'app' must drop ALL capabilities
FAIL - labs\lab7\bad-test\bad-pod.yaml - main - Container 'app' must set allowPrivilegeEscalation: false
FAIL - labs\lab7\bad-test\bad-pod.yaml - main - Container 'app' must set readOnlyRootFilesystem: true
FAIL - labs\lab7\bad-test\bad-pod.yaml - main - Pod securityContext.runAsNonRoot must be true
4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions

### What this prevents at CI time

This policy catches insecure Pod configuration — root-capable processes, a writable root filesystem, privilege escalation, and excess Linux capabilities — at CI time, before `kubectl apply` ever runs. Catching this at CI time is cheaper and faster than admission-time enforcement: the developer sees the failure directly in the PR within seconds and doesn't need cluster access to diagnose it. An admission controller (PSS or an OPA Gatekeeper webhook) only rejects the manifest at actual deploy time, which means the feedback arrives later and only if someone is actively running `kubectl apply` at that moment. One subtlety worth noting: naive Rego comparisons against a missing field evaluate to `undefined` rather than `false`, silently letting non-compliant manifests pass; using `object.get(...)` with an explicit default was necessary to make the policy actually fire on manifests that omit `securityContext` entirely.