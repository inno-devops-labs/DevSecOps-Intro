## Task 1 (7.4): Trivy vs Grype

### Trivy image scan — severity breakdown
Image: `bkimminich/juice-shop:v20.0.0` · scan date: 2026-06-26 · filter: HIGH,CRITICAL.

| Severity | Count |
|----------|------:|
| CRITICAL | 5 |
| HIGH | 43 |

### Top 10 vulnerabilities with a fix (Trivy)
| CVE | Severity | Package | Installed | Fixed in |
|-----|----------|---------|-----------|----------|
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

### Comparison with Grype (Lab 4)
Grype scan of the same image (2026-06-26), run unfiltered, reported 107 matches. The counts are not
directly comparable (Grype unfiltered vs Trivy HIGH/CRITICAL only), so the comparison is done per-CVE.

| Severity | Grype count |
|----------|------------:|
| Critical | 7 |
| High | 51 |
| Medium | 36 |
| Low | 6 |
| Negligible | 7 |

### Two CVEs — one both tools found, one only one found

**Found by both — crypto-js weakness.** Trivy reports it as `CVE-2023-46233` (Critical); Grype
reports the same flaw as `GHSA-xwcq-pm8m-c4vf` (Critical). Both point to `crypto-js 3.3.0` (weak
PBKDF2 default, fixed in 4.2.0) — the two IDs are the same advisory cross-referenced in the GitHub
Advisory Database. High-confidence finding: two independent databases agree on package, version and fix.

**Found by only one — `NSWG-ECO-17` / `NSWG-ECO-428` (Trivy only).** Trivy carries Node Security
Working Group ecosystem advisories (`NSWG-ECO-*`) for `jsonwebtoken` and `base64url`. Grype does not
track that namespace at all — for the same `jsonwebtoken` it returns only GHSA IDs
(`GHSA-c7hr-j4mj-j2w6`, `GHSA-8cf7-32gw-wr33`, `GHSA-hjrf-2m68-5959`, `GHSA-qwph-4952-7xr6`), so the
NSWG-ECO entries appear exclusively in Trivy.

### Why the tools diverge
Trivy and Grype draw from overlapping but non-identical advisory sources and normalise identifiers
differently: the same crypto-js flaw appears as a CVE in Trivy and a GHSA in Grype, and Trivy also
carries Node-ecosystem `NSWG-ECO-*` advisories that Grype's GHSA/CVE-centric database omits entirely.
Matching logic and daily-updated databases add further drift. This is why correlating two scanners
raises confidence — agreement (crypto-js) is near-certain signal, while divergence (NSWG-ECO) reflects
identifier namespace and source coverage rather than the underlying reality.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
      # pod-level
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: juice-shop
          # container-level
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
        - protocol: TCP
          port: 53
    - to: []
      ports:
        - protocol: TCP
          port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-5b45ccb7d7-vn6rt   1/1     Running   0          8s

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

(These are image-layer vulnerability counts; Trivy reported 0 misconfigurations, confirming the pod hardening passed.)

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` broke Juice Shop on two fronts. First, it writes runtime data to
`/tmp`, `/juice-shop/logs` and `/juice-shop/data`, so those needed writable `emptyDir` mounts.
But `/juice-shop/data` also ships read-only seed files (`data/static/*.md`, `securityQuestions.yml`)
that the app reads at startup — mounting a bare `emptyDir` there hid the seeds (`ENOENT`), while
removing the mount blocked the SQLite DB from being created (`SQLITE_CANTOPEN`). I resolved the
read-and-write conflict with an initContainer that copies the image's `/juice-shop/data` into the
`emptyDir` before the main container starts, so the seeds are present and the DB is writable, all
while the root filesystem stays read-only.

## Bonus: Conftest Policy

### Policy (labs/lab7/policies/pod-hardening.rego)
```rego
package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod spec.securityContext.runAsNonRoot must be true"
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s': readOnlyRootFilesystem must be true", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s': allowPrivilegeEscalation must be false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not drops_all(c)
	msg := sprintf("container '%s': capabilities must drop ALL", [c.name])
}

drops_all(c) if {
	c.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest
$ conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

### Output: FAIL on bad manifest
$ conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
FAIL - /tmp/bad-pod.yaml - main - container 'app': allowPrivilegeEscalation must be false
FAIL - /tmp/bad-pod.yaml - main - container 'app': capabilities must drop ALL
FAIL - /tmp/bad-pod.yaml - main - container 'app': readOnlyRootFilesystem must be true
FAIL - /tmp/bad-pod.yaml - main - pod spec.securityContext.runAsNonRoot must be true
4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions

### What this prevents at CI time (2-3 sentences)
This policy catches insecure pod securityContext misconfigurations — containers running as root,
writable root filesystems, allowed privilege escalation, and undropped Linux capabilities — the
same class of bug that lets a compromised process escalate privileges or break out of its container.
Running it in CI blocks a non-compliant manifest at pull-request time, before `kubectl apply` ever
reaches the cluster's admission controller (Lecture 7 slide 16). Catching it at CI-time is better
than at admission-time because the developer gets immediate feedback in the PR — cheaper to fix and
never merged — whereas an admission-time rejection only surfaces at deploy, after review and merge,
when the bad config is already in the repo and the fix costs more.
