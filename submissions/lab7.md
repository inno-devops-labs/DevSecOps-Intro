# Lab 7 — Submission

Container security on Juice Shop (`bkimminich/juice-shop:v20.0.0`, digest
`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`). Trivy for the image and
config scans, a hardened Kubernetes deployment on a local `k3d` cluster, and a Conftest policy gate.

Tooling: Trivy 0.69.3 · k3d v5.9.0 (k3s / Kubernetes v1.33.0) · Conftest · jq 1.7.1.

> I used **k3d** for the local cluster (the lab offers kind or k3d). On this macOS/Apple-Silicon
> Docker Desktop, kind's containerd crash-looped on image pulls; k3d's k3s runs a stable cluster here.

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
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
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.4.0 | 9.0.0 |

Almost everything is fixable (46 of 48), so triage here is a patching job: bump the vulnerable npm
packages (`crypto-js`, `lodash`, `jsonwebtoken`, `express-jwt`, `http-cache-semantics`). These are old
transitive deps Juice Shop ships on purpose.

### Config scan (Dockerfile)
The `trivy config` run on the sample bad Dockerfile found 4 misconfigurations. Only one is HIGH, so the
lab's `--severity HIGH,CRITICAL` filter surfaces just that one; dropping the filter shows all 4:

| ID | Severity | Issue |
|----|----------|-------|
| DS-0002 | HIGH | Last `USER` is `root` |
| DS-0001 | MEDIUM | `FROM node:latest` has no pinned tag |
| DS-0004 | MEDIUM | `EXPOSE 22` (SSH) |
| DS-0026 | LOW | No `HEALTHCHECK` instruction |

### Compared to Lab 4's Grype scan
1. **Found by BOTH — `CVE-2019-10744` (lodash 2.4.2, Critical).** Trivy reports it as `CVE-2019-10744`;
   Lab 4's Grype reported the exact same vuln/package/severity but under its GHSA alias
   `GHSA-jf85-cpcp-j695`. The tools agree on the finding — the only difference is the identifier
   namespace (Grype prefers GHSA for npm advisories, Trivy normalizes to the CVE alias). A raw ID diff
   makes them look different when they aren't.
2. **Divergent — `CVE-2026-5450` (libc6).** Lab 4's Grype rated this OS package **Critical** and put it
   in its top-10; my Trivy HIGH/CRITICAL image scan doesn't list it at all. The reason is severity
   source: Grype kept the upstream/NVD CVSS (Critical), while Trivy defers to the Debian vendor severity
   (Medium) for OS packages, so it fell below my `--severity HIGH,CRITICAL` cutoff. Same CVE, different
   score, different bucket.

---

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` — PSS `restricted` on all three modes:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` — pod-level and container-level securityContext:
```yaml
# pod
securityContext:
  runAsNonRoot: true
  runAsUser: 65532        # Juice Shop v20 runs as UID 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
# container
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

`networkpolicy.yaml` — default-deny with explicit allows:
```yaml
ingress:
  - from:
      - namespaceSelector: {}
    ports:
      - { protocol: TCP, port: 3000 }
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
    ports:
      - { protocol: UDP, port: 53 }
      - { protocol: TCP, port: 53 }
  - to: []
    ports:
      - { protocol: TCP, port: 443 }
```

### Pod is running
```
$ kubectl get pod -n juice-shop -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-54487c5f76-cvkbf   1/1     Running   0          63s
```

Effective securityContext on the running pod:
```
POD:       {"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532,
            "seccompProfile":{"type":"RuntimeDefault"}}
CONTAINER: {"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,
            "capabilities":{"drop":["ALL"]}}
```

`enforce: restricted` is actually blocking — a root/privileged test pod is rejected at admission,
while the hardened Juice Shop pod runs:
```
$ kubectl -n juice-shop run bad-pod --image=nginx \
    --overrides='{"spec":{"containers":[{"name":"bad","image":"nginx","securityContext":{"privileged":true}}]}}'
Error from server (Forbidden): pods "bad-pod" is forbidden: violates PodSecurity "restricted:latest":
privileged, allowPrivilegeEscalation != false, unrestricted capabilities, runAsNonRoot != true,
seccompProfile (pod or container "bad" must set securityContext.seccompProfile.type ...)
```

### Trivy K8s scan
Trivy scanned the running workload in the namespace. Per the juice-shop image it reports:

| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

(These match the Task 1 image scan — same image/digest. The raw JSON lists them twice because the pod
references that image in both the initContainer and the app container.)

### What broke and how I fixed it
`readOnlyRootFilesystem: true` stops Juice Shop from booting, because it writes into its own install
dir (`/juice-shop`) at startup. I found the exact paths by running the image read-only locally and by
diffing a running container: it needs to write the SQLite DB (`data/juiceshop.sqlite`), copy `legal.md`
into `ftp/`, write access/audit logs (`logs/`), refresh `.well-known/csaf/`, and re-render the built
frontend (`frontend/dist/frontend`). I mounted `emptyDir` volumes at each of these plus `/tmp`. Three of
those dirs (`data`, `.well-known`, `frontend/dist/frontend`) also contain baked seed files the app reads,
and an empty `emptyDir` would hide them — so an initContainer copies the baked contents into those
volumes before the app container starts (the image is distroless with no shell, so the copy uses the
bundled `node` binary). `fsGroup: 65532` makes the volumes group-writable for the non-root user.

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
	c := podspec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s' must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s' must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not drops_all(c)
	msg := sprintf("container '%s' must drop ALL capabilities", [c.name])
}

drops_all(c) if {
	c.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest
```
$ conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
$ conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies

FAIL - /tmp/bad-pod.yaml - main - container 'app' must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - container 'app' must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - container 'app' must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - pod securityContext.runAsNonRoot must be true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time
This policy catches insecure pod specs — containers that run as root, allow privilege escalation, keep a
writable root filesystem, or hold extra Linux capabilities — the class of misconfig that makes a
container escape easy. Running it in CI (on the YAML, before `kubectl apply`) means a bad manifest fails
the pipeline and never reaches the cluster, so the fix happens in review instead of after a rejected (or
worse, accepted) deploy. It's the same rule set the PSS admission controller enforces, just shifted left
so developers get the feedback on their PR.
