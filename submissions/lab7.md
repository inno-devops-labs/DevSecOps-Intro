# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

> OS layer (Debian 13.4): 1 HIGH. Application layer (node-pkg): 47 (5 CRITICAL, 42 HIGH). The 2 findings without a fix are `lodash.set` (CVE-2020-8203) and `marsdb` (GHSA-5mrr-rgp6-x4gr), both `affected` with no patched release.
> Trivy's secret scanner additionally flagged a hardcoded RSA private key in `lib/insecurity.ts` (and its compiled `build/lib/insecurity.js`) — an intentional Juice Shop vulnerability, but a good demonstration that `trivy image` runs vuln + secret scanning in one pass.

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

### Dockerfile misconfig scan (`trivy config`)
Scanning the sample insecure Dockerfile at `HIGH,CRITICAL` severity, Trivy reports one failure (1 of 20 checks):

| ID | Severity | Meaning |
|----|----------|---------|
| AVD-DS-0002 | HIGH | Last `USER` in the Dockerfile is `root`; containers should run as a non-root user |

Trivy uses its own AVD check IDs, not Checkov's `CKV_DOCKER_*`. The file's other weaknesses — the mutable `:latest` base tag, the `ADD` of a remote URL, and `EXPOSE 22` (SSH) — are rated MEDIUM/LOW and are filtered out by `--severity HIGH,CRITICAL`; dropping the flag surfaces them too.

### Compared to Lab 4's Grype scan
Both scans target the identical image digest `sha256:fd58bdc9…`, so the deltas are tool behaviour, not different inputs.

1. **Found by BOTH Grype and Trivy:** crypto-js 3.3.0 (PBKDF2 weakness, fix 4.2.0). Trivy reports it as `CVE-2023-46233`; Grype reports the same advisory as `GHSA-xwcq-pm8m-c4vf`. It's one vulnerability surfaced under two identifier schemes — Trivy prefers the CVE ID, Grype the GitHub advisory ID — which is itself a reason raw ID lists from the two tools look less similar than they are.
2. **Found by ONE tool only:** `CVE-2026-5450` (libc6, Critical) appears in Grype but not in Trivy. Trivy's Debian target reported just 1 OS vulnerability for this image, whereas Grype matched libc6/libssl version ranges directly and flagged this critical (which Debian itself marks won't-fix). The same happened for `CVE-2026-34182` on libssl3t64: Grype rated it Critical, while Trivy surfaced only `CVE-2026-45447` on that package.

The tools diverge mainly on the **OS layer** because of how they source data: Trivy's Debian scanner follows the Debian Security Tracker and suppresses glibc/openssl issues that Debian triages as no-DSA / not-affected / won't-fix, while Grype matches installed versions against NVD/GHSA ranges through the Anchore feed regardless of distro triage — so Grype skews toward more OS-layer Criticals and Trivy toward more low-severity npm findings. A second, purely cosmetic divergence is identifier choice: Trivy emits vendor pseudo-IDs like `NSWG-ECO-428`/`NSWG-ECO-17` for some npm advisories that Grype either omits or reports under a GHSA/CVE, so identical underlying flaws don't line up by ID.

---

## Task 2: Kubernetes Hardening

### Manifests (relevant snippets)

`namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext (pod + container):
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
```
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL
```

`networkpolicy.yaml` ingress + egress:
```yaml
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
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-54768b9795-cbqvw   1/1     Running   0          36s
```
`kubectl rollout status` reports `deployment "juice-shop" successfully rolled out`; the pod is `1/1 Ready` (the `/` readiness probe on port 3000 returns 200), and `kubectl describe` shows no Pod Security Admission warnings — the pod satisfies the `restricted` profile.

### Trivy K8s scan
`trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL --report summary` — workload assessment for `Deployment/juice-shop`:

| Class | Critical | High |
|-------|---------:|-----:|
| Vulnerabilities | 10 | 86 |
| Secrets | — | 4 |

The vulnerability counts are the image CVEs surfaced again at the cluster level (higher than the standalone `trivy image` HIGH,CRITICAL totals because the K8s scan also counts secondary matches per layer); the 4 HIGH secrets are the hardcoded RSA private key files inside the image. No misconfigurations were reported against the workload — the hardening (non-root, read-only rootfs, dropped caps, seccomp) leaves nothing for Trivy's K8s misconfig checks to flag.

### What broke and how you fixed it
Juice Shop v20.0.0 runs from `/juice-shop` as UID 65532 and rewrites several files under its own tree at every startup, so `readOnlyRootFilesystem: true` made it crash-loop with a chain of `EROFS` errors — first the SQLite DB at `data/juiceshop.sqlite`, then `restoreOverwrittenFilesWithOriginals` copying into `ftp/`, then `datacreator` writing `.well-known/csaf/provider-metadata.json`, then `customizeApplication`/`customizeEasterEgg` rewriting `frontend/dist/frontend/index.html` and the easter-egg assets. Naively mounting empty `emptyDir` volumes over those paths swapped the `EROFS` errors for missing-seed-file crashes, because `data/`, `ftp/`, `.well-known/`, `i18n/`, and `frontend/dist/` all ship required content in the image. The fix keeps the rootfs read-only and mounts empty `emptyDir`s only at the genuinely-empty write paths (`/tmp`, `/juice-shop/logs`), while an `initContainer` (same image, `node -e` with `fs.cpSync`) copies the five populated directories into a shared `emptyDir` that the main container re-mounts read-write via `subPath` — giving each path that is both writable and pre-seeded, after which the pod reaches `1/1 Ready`.

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be set to true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not drops_all_capabilities(container)
	msg := sprintf("container '%s' must drop ALL capabilities", [container.name])
}

drops_all_capabilities(container) if {
	"ALL" in container.securityContext.capabilities.drop
}
```

### Output: PASS on hardened manifest
`conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies`:
```
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
`conftest test labs/lab7/tests/bad-deployment.yaml --policy labs/lab7/policies`:
```
FAIL - labs/lab7/tests/bad-deployment.yaml - main - container 'bad-app' must drop ALL capabilities
FAIL - labs/lab7/tests/bad-deployment.yaml - main - container 'bad-app' must set allowPrivilegeEscalation: false
FAIL - labs/lab7/tests/bad-deployment.yaml - main - container 'bad-app' must set readOnlyRootFilesystem: true
FAIL - labs/lab7/tests/bad-deployment.yaml - main - pod securityContext.runAsNonRoot must be set to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time
This policy catches a whole class of **pod misconfiguration bugs** — containers that can escalate privileges, keep a writable root filesystem, run as root, or retain Linux capabilities — the same defects PSS `restricted` enforces, but *before* the manifest ever reaches the cluster. Catching it at CI time (on the pull request) is cheaper and safer than at admission time: the developer gets the failure in code review with a clear message, the insecure manifest never merges, and you are not depending on every target cluster having the right Pod Security Admission labels configured. Admission control is the last line of defense; CI is the first, and shifting the check left shortens the feedback loop from minutes-in-cluster to seconds-in-pipeline.
