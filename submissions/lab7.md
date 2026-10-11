# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

Дополнительно: OS-уровень (Debian 13.4) — 1 HIGH (`CVE-2026-45447`, libssl3t64, OpenSSL heap use-after-free). Остальные 47 — Node.js-пакеты (42 HIGH, 5 CRITICAL).

### Top 10 CVE with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 (OS) | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Secrets finding (bonus context, not in rubric but worth flagging)

Trivy's secrets scanner detected a hardcoded **asymmetric RSA private key** committed directly into the image at `/juice-shop/build/lib/insecurity.js:46` and `/juice-shop/lib/insecurity.ts:23` (HIGH). This is the JWT signing key baked into the container filesystem — a textbook argument for image-level secrets scanning beyond just CVE matching.

### Compared to Lab 4's Grype scan

Grype (Lab 4) matched **2** overlapping IDs with this Trivy scan: `CVE-2026-45447` and `GHSA-5mrr-rgp6-x4gr`; Trivy additionally surfaced dozens of Node.js CVEs Grype missed (e.g. `CVE-2019-10744`, `CVE-2015-9235`), while Grype uniquely flagged several IDs Trivy did not report (e.g. `CVE-2010-4756`, `CVE-2019-9192`).

**CVE-2026-45447 (both tools agree)** — an OpenSSL heap use-after-free in `libssl3t64`, found identically by both Grype and Trivy. Both tools resolved this via the OS package database (Debian's dpkg status), which is the most reliable source both scanners share — package-manager-tracked OS CVEs rarely diverge between tools since both pull from the same upstream advisory feeds (NVD/Debian Security Tracker).

**CVE-2019-10744 (Trivy only)** — a critical lodash prototype-pollution vulnerability in `defaultsDeep()`. Grype's SBOM-based matching in Lab 4 relied on the CycloneDX SBOM's declared `lodash` version; if that SBOM's package resolution differed even slightly from what Trivy's live filesystem scan found (e.g. a transitive lodash copy bundled inside another package, not surfaced as a top-level SBOM component), Grype's matcher would silently miss it. This is a common divergence pattern (Lecture 7 slide 9): SBOM-based scanning is only as complete as the SBOM generator's dependency resolution, while Trivy's native npm-lockfile parsing tends to catch nested/transitive copies more consistently.

---

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext (pod + container level):
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

`networkpolicy.yaml` ingress + egress:
```yaml
ingress:
  - from: []
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
      - protocol: TCP
        port: 53
  - to: []
    ports:
      - protocol: TCP
        port: 443
```

Image note: deployed by tag `bkimminich/juice-shop:v20.0.0`. Confirmed digest from this environment: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` (matches Lab 4 capture).

### Pod is running

```
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-9f8594ff9-s8zqv   1/1     Running   0          15s
```

### Trivy K8s scan

| Severity | Vulnerabilities | Secrets |
|----------|------:|------:|
| Critical | 5 | 0 |
| High | 43 | 2 |

The 2 HIGH secrets findings are the same hardcoded RSA private key flagged in Task 1's image scan (`insecurity.js` / `insecurity.ts`), now confirmed present in the live running pod's filesystem via `trivy k8s`.

### What broke and how you fixed it

`readOnlyRootFilesystem: true` on its own would crashloop Juice Shop, since the app writes to `/tmp` and to its own log/data directories at runtime. Fixed by mounting three `emptyDir{}` volumes at `/tmp`, `/juice-shop/logs`, and `/juice-shop/data` — giving the app writable scratch space while keeping the container's root filesystem itself immutable.

---

## Bonus: Conftest Policy Gate

### Policy (`labs/lab7/policies/pod-hardening.rego`)

```rego
package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not pod_run_as_nonroot
	msg := "Pod must set securityContext.runAsNonRoot: true"
}

pod_run_as_nonroot if {
	input.spec.template.spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container_readonly_fs(container)
	msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

container_readonly_fs(container) if {
	container.securityContext.readOnlyRootFilesystem == true
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container_no_privesc(container)
	msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

container_no_privesc(container) if {
	container.securityContext.allowPrivilegeEscalation == false
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container_drops_all(container)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

container_drops_all(container) if {
	container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest

```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - Pod must set securityContext.runAsNonRoot: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches missing pod-hardening fields (privilege escalation vectors, writable root filesystems, retained Linux capabilities) *before* `kubectl apply` ever runs — a build-time/CI-time gate. Admission control (e.g. PSS `enforce`, as used in Task 2) catches the same class of bug, but only at the moment of `kubectl apply` against a live cluster, after the manifest is already merged into the deploy pipeline. Catching it in CI is strictly earlier and cheaper: a failed CI check blocks the PR itself, giving the developer immediate feedback in the same review cycle, rather than a runtime rejection that requires someone to notice the failed `apply` and trace it back to the offending YAML.

One early iteration used plain `!=` comparisons (e.g. `securityContext.readOnlyRootFilesystem != true`) instead of `not <helper>` with explicit `== true` checks. That version silently passed the bad manifest, because in Rego an undefined field (missing `securityContext` entirely) makes the whole rule body undefined rather than true — so `!=` comparisons against a field that doesn't exist never fire. Rewriting each check as a helper predicate that must explicitly evaluate to `true`, combined with `not`, correctly treats "field absent" the same as "field set to the wrong value."
