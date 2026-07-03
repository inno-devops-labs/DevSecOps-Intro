# Lab 7 — Submission

> Tooling: Trivy 0.71.1, Conftest 0.68.2, kubectl + kind. Image `bkimminich/juice-shop:v20.0.0`.

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown (`--severity HIGH,CRITICAL`)
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

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

### Dockerfile config scan (`trivy config`)
Scanning a deliberately bad Dockerfile (`FROM node:latest`, `USER root`, `EXPOSE 22`, `ADD <url>`):
| Severity | ID | Finding |
|----------|-----|---------|
| HIGH | DS-0002 | Image user should not be 'root' |
| MEDIUM | DS-0001 | `:latest` tag used |
| MEDIUM | DS-0004 | Port 22 (SSH) exposed |
| LOW | DS-0026 | No HEALTHCHECK defined |

### Compared to Lab 4's Grype scan (same image)
- **Both tools found — CVE-2019-10744 (lodash prototype pollution, Critical).** Trivy reports the
  CVE id directly; Lab 4's Grype reported the *same* finding under the GitHub advisory alias
  `GHSA-jf85-cpcp-j695` (whose related CVE is exactly `CVE-2019-10744`). The divergence is only in
  **identifier namespace** — Grype prefers GHSA for npm, Trivy normalises to CVE — not in coverage.
- **One tool found, the other missed — CVE-2022-4899 (`libzstd`/zstd, High).** Lab 4's Grype flagged
  it (fix state `wont-fix`); Trivy reports nothing for zstd. Trivy follows the **Debian Security
  Tracker**, which marks this not-affected/won't-fix for the distro package and suppresses it; Grype
  matched against broader **NVD** data (and warned the image distro looked EOL, widening its match).
  Same class of difference the lecture calls out: different vulnerability DBs + fix-status awareness.

---

## Task 2: Kubernetes Hardening

Four manifests written (`labs/lab7/k8s/`): `namespace.yaml`, `serviceaccount.yaml`,
`deployment.yaml`, `networkpolicy.yaml` (+ a `service.yaml` for the port-forward proof).

### namespace.yaml — PSS labels (all three modes = restricted)
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

### deployment.yaml — securityContext (pod + container)
```yaml
# pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile: { type: RuntimeDefault }
# container-level (same on initContainer + main container)
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities: { drop: ["ALL"] }
```
Image pinned by digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

### networkpolicy.yaml — ingress + egress
```yaml
policyTypes: [Ingress, Egress]
ingress:                              # default-deny, then allow :3000 from ingress-controller ns
  - from: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: ingress-nginx } } }]
    ports: [{ protocol: TCP, port: 3000 }]
egress:                               # allow only DNS (kube-system) + outbound HTTPS
  - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } } }]
    ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
  - to: [{ ipBlock: { cidr: 0.0.0.0/0 } }]
    ports: [{ protocol: TCP, port: 443 }]
```

### Applied to a kind (v1.33.0) cluster — PSS compliance confirmed
`kubectl apply -f labs/lab7/k8s/` created every object and, critically, produced **no PodSecurity
warnings** — if the spec violated the `restricted` profile, the namespace's `warn: restricted` label
would have printed `Warning: would violate PodSecurity "restricted"`. It didn't:
```
namespace/juice-shop created
serviceaccount/juice-shop created
networkpolicy.networking.k8s.io/juice-shop-restricted created
service/juice-shop created
deployment.apps/juice-shop created          # ← no PSS warning = restricted-compliant
```
Also confirmed the enforcement is *live*, not just declarative: a `kubectl run` of a plain
(non-compliant) pod into the namespace is **rejected at admission**:
```
Error from server (Forbidden): pods "cdtest" is forbidden: violates PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false, unrestricted capabilities, runAsNonRoot != true, seccompProfile ...
```
So the restricted profile is both **satisfied by our Deployment** and **actively blocking** anything
that isn't — the core Task 2 requirement.

> ⚠️ **`Running 1/1` + `trivy k8s` not captured — root cause isolated to the environment, not the
> hardening.** The pod never reached Ready, and I traced why: (1) the local Docker Desktop engine
> repeatedly crashed under kind load (same WSL2 instability as Lab 5); and (2) more fundamentally,
> **a bare `juice-shop` Deployment with _no_ volumes and _no_ hardening also fails** in this kind /
> containerd cluster — the distroless image's first startup gate, `validateDependenciesBasic.ts`
> (`await import('check-dependencies')`), throws and prints *"Please run npm install…"*, even though
> the **identical image runs fine under Docker**. This is an image↔containerd-runtime quirk on this
> machine, independent of the securityContext or the volume design (proven by the minimal repro).
> The manifest itself is validated: it applies clean, is PSS-restricted-compliant, and the
> initContainer completes (`exitCode 0`). On a standard cluster the finish-line commands are:
> ```bash
> kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=300s
> trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL --report=summary
> ```

### What broke and how I fixed it (readOnlyRootFilesystem)
`readOnlyRootFilesystem: true` genuinely breaks Juice Shop v20 — it writes all over its own install
tree at startup, not just `/tmp`. I enumerated the exact paths two ways — `docker run --read-only`
(watching each EROFS in turn) and reading the source (`lib/startup/restoreOverwrittenFilesWithOriginals.ts`,
which copies `data/static/*` into `ftp/`, `i18n/`, and `frontend/dist/.../videos/`). The full writable
set for v20 is: `/tmp`, `/juice-shop/ftp`, `/juice-shop/logs`, `/juice-shop/data` (SQLite DB **and**
read-only seed files it needs), `/juice-shop/.well-known`, `/juice-shop/i18n`, and
`/juice-shop/frontend/dist/frontend/assets/public/videos`. The fix in `deployment.yaml`: a writable
`emptyDir` at each, plus an **initContainer** that copies *only* `/juice-shop/data` (small — no
`node_modules`) into its emptyDir so the seeds survive alongside the writable SQLite path; `node_modules`
and `build/` stay on the read-only image layer. `fsGroup: 1000` gives the pod ownership of the volumes.
The container root stays read-only. (The whole-tree-copy alternative also works but drags ~600 MB of
`node_modules` through an initContainer on every start — the per-path seed is leaner.)

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main
import rego.v1

podspec := input.spec.template.spec

deny contains msg if {
	input.kind == "Deployment"
	not podspec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be true"
}
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container %q: securityContext.readOnlyRootFilesystem must be true", [c.name])
}
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q: securityContext.allowPrivilegeEscalation must be false", [c.name])
}
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not drops_all(c)
	msg := sprintf("container %q: securityContext.capabilities.drop must include \"ALL\"", [c.name])
}
drops_all(c) if { "ALL" in c.securityContext.capabilities.drop }
```
> Note the `not <field> == <value>` form (not `!=`): it also fires when the field is *absent*
> (undefined), so a manifest with no `securityContext` at all is correctly caught.

### PASS on the hardened manifest
```
conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### FAIL on a bad manifest (nginx Deployment, no securityContext)
```
FAIL - bad-pod.yaml - main - container "app": securityContext.allowPrivilegeEscalation must be false
FAIL - bad-pod.yaml - main - container "app": securityContext.capabilities.drop must include "ALL"
FAIL - bad-pod.yaml - main - container "app": securityContext.readOnlyRootFilesystem must be true
FAIL - bad-pod.yaml - main - pod securityContext.runAsNonRoot must be true
4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time
This policy catches **insecure-pod-spec bugs** (a container that could escalate to root, keep a
writable root FS, or retain Linux capabilities) **before `kubectl apply` ever runs** — the
shift-left half of the admission-control diagram (Lecture 7 slide 16). Catching it at CI-time beats
catching it at admission-time because CI **fails the pull request**: the developer gets the feedback
in seconds, in context, and the bad manifest never reaches the cluster's API server. Admission
control (Kyverno/PSA) is the essential *backstop* for anything that bypasses CI, but by then the
change is already merged and being deployed — a slower, noisier failure.
