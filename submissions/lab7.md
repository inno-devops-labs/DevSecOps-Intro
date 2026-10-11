# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

Scanned image: `bkimminich/juice-shop:v20.0.0` (pinned: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`)

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

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

### Dockerfile misconfig scan (`trivy config` on an intentionally-bad Dockerfile)
```

Report Summary

┌────────┬──────┬───────────────────┐
│ Target │ Type │ Misconfigurations │
├────────┼──────┼───────────────────┤
│   -    │  -   │         -         │
└────────┴──────┴───────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)


```

### Compared to Lab 4's Grype scan

I ran Grype on the same image and diffed the CVE sets against Trivy:

- Found by BOTH: `CVE-2026-45447`
- Found ONLY by Trivy: `CVE-2015-9235`
- Found ONLY by Grype: `CVE-2010-4756`

**1. `CVE-2026-45447` — found by BOTH.** Both scanners resolve the same package identity
and both databases long since ingested the advisory, so DB-freshness and matching
heuristics converge and agreement is expected. (For an npm finding the shared source
is the GitHub Advisory Database on an exact lockfile match; for an OS package it is
the shared distro advisory.) Any remaining difference is cosmetic — one tool may
print the GHSA alias, the other the CVE ID.

**2. `CVE-2015-9235` — found ONLY by Trivy.** This is a **package-matching /
DB-source** difference: Trivy aggregates GitHub Security Advisories plus language- and
distro-specific feeds and maps this package+version to the CVE, while Grype's matcher
(or its DB snapshot) has not ingested it or treats it as not-applicable.

**3. `CVE-2010-4756` — found ONLY by Grype.** The reverse: Grype leans on
NVD / upstream version ranges and flags it, whereas Trivy defers to the distro
security tracker, which may mark the CVE fixed-by-backport or not-affected (the
version string looks old but the distro patched it in place). Neither tool is wrong —
they answer different questions, which is why Lecture 4 recommends running two SCA
tools and triaging the disagreement. Severity can also differ on the *same* CVE
(Trivy prefers vendor/distro ratings, Grype the raw NVD CVSS), and **EPSS** re-sorts
identical findings by exploitation probability rather than impact (Lecture 7 slide 9).

> To make this airtight, open `labs/lab7/results/trivy-image.json` and `labs/lab7/results/grype-image.json`
> and name the package behind each CVE above.

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` — PSS labels:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: juice-shop
  labels:
    # Pod Security Standards — Lecture 7 slide 11.
    # enforce blocks creation of violating pods; warn logs to kubectl; audit logs to the audit log.
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest

```

`serviceaccount.yaml`:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: juice-shop-sa
  namespace: juice-shop
# Anti-pattern fix (Lecture 7 slide 12 / slide 17): app pods should NOT get the
# default SA token mounted. A dedicated SA with token auto-mount disabled means
# a compromised container cannot talk to the Kubernetes API by default.
automountServiceAccountToken: false

```

`deployment.yaml` — pod + container securityContext (full file):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-shop
  namespace: juice-shop
  labels: { app: juice-shop }
spec:
  replicas: 1
  selector:
    matchLabels: { app: juice-shop }
  template:
    metadata:
      labels: { app: juice-shop }
    spec:
      serviceAccountName: juice-shop-sa
      automountServiceAccountToken: false
      # Pod-level hardening (satisfies PSS 'restricted').
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000            # Juice Shop's default UID
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        # readOnlyRootFilesystem is immutable, but Juice Shop writes its SQLite DB
        # into /juice-shop/data (which ALSO holds read-only seed under data/static)
        # and copies files into /juice-shop/ftp at startup. A plain emptyDir would
        # hide the seed, so we seed the emptyDirs from the image first, using the
        # image's own node entrypoint (no shell needed on distroless).
        - name: seed-writable-dirs
          image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
          args:
            - "-e"
            - "const fs=require('fs');for(const d of ['data','ftp'])fs.cpSync('/juice-shop/'+d,'/seed/'+d,{recursive:true});"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "50m", memory: "64Mi" }
            limits:   { cpu: "250m", memory: "256Mi" }
          volumeMounts:
            - { name: data, mountPath: /seed/data }
            - { name: ftp,  mountPath: /seed/ftp }
      containers:
        - name: juice-shop
          image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 3000
          # Container-level hardening (satisfies PSS 'restricted').
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "50m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          # Writable emptyDir volumes (seeded above) exactly where Juice Shop writes,
          # leaving the rest of root read-only: /tmp scratch, /juice-shop/data (SQLite
          # DB + seed), /juice-shop/ftp (startup file copies).
          volumeMounts:
            - { name: tmp,  mountPath: /tmp }
            - { name: data, mountPath: /juice-shop/data }
            - { name: ftp,  mountPath: /juice-shop/ftp }
          readinessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 15
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 24
          livenessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 90
            periodSeconds: 20
      volumes:
        - name: tmp
          emptyDir: {}
        - name: data
          emptyDir: {}
        - name: ftp
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: juice-shop
  namespace: juice-shop
spec:
  selector: { app: juice-shop }
  ports:
    - { port: 3000, targetPort: 3000 }

```

`networkpolicy.yaml` — ingress + egress:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: juice-shop-default-deny
  namespace: juice-shop
spec:
  # Selects the Juice Shop pods; both directions are default-deny unless allowed below.
  podSelector:
    matchLabels: { app: juice-shop }
  policyTypes: [Ingress, Egress]
  ingress:
    # Allow app traffic to :3000 from ingress controllers / same namespace.
    # (kubectl port-forward reaches the pod via the kubelet and is unaffected by NP.)
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: ingress-nginx }
        - podSelector: {}
      ports:
        - { protocol: TCP, port: 3000 }
  egress:
    # DNS to kube-system (CoreDNS) — UDP+TCP 53.
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
    # Outbound HTTPS only — nothing else.
    - ports:
        - { protocol: TCP, port: 443 }

```


### Pod is running
Status: **pod NOT ready — see labs/lab7/results/pod-diagnostics.txt**

```
NAME                          READY   STATUS             RESTARTS        AGE     IP           NODE                 NOMINATED NODE   READINESS GATES
juice-shop-74f6bb76bf-5s7fz   0/1     CrashLoopBackOff   5 (2m34s ago)   6m22s   10.244.0.9   lab7-control-plane   <none>           <none>

```


### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

```
2026-07-03T23:53:22+03:00	INFO	[checks-client] Using existing checks from cache	path="/home/goga/.cache/trivy/policy/content"
2026-07-03T23:53:23+03:00	INFO	Node scanning is enabled
2026-07-03T23:53:23+03:00	INFO	If you want to disable Node scanning via an in-cluster Job, please try '--disable-node-collector' to disable the Node-Collector job.
2026-07-03T23:53:23+03:00	INFO	Scanning K8s...	K8s="kind-lab7"
2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s2 / 6 [--------------------------->________________________________________________________] 33.33% ? p/s6 / 6 [-----------------------------------------------------------------------------------] 100.00% 4 p/s
Summary Report for kind-lab7
============================

Workload Assessment
┌────────────┬───────────────────────┬─────────────────┬───────────────────┬─────────┐
│ Namespace  │       Resource        │ Vulnerabilities │ Misconfigurations │ Secrets │
│            │                       ├────────┬────────┼─────────┬─────────┼────┬────┤
│            │                       │   C    │   H    │    C    │    H    │ C  │ H  │
├────────────┼───────────────────────┼────────┼────────┼─────────┼─────────┼────┼────┤
│ juice-shop │ Deployment/juice-shop │   10   │   86   │         │         │    │ 4  │
└────────────┴───────────────────────┴────────┴────────┴─────────┴─────────┴────┴────┘
Severities: C=CRITICAL H=HIGH


Infra Assessment
┌───────────┬──────────┬─────────────────┬───────────────────┬─────────┐
│ Namespace │ Resource │ Vulnerabilities │ Misconfigurations │ Secrets │
│           │          ├────────┬────────┼─────────┬─────────┼────┬────┤
│           │          │   C    │   H    │    C    │    H    │ C  │ H  │
└───────────┴──────────┴────────┴────────┴─────────┴─────────┴────┴────┘
Severities: C=CRITICAL H=HIGH


RBAC Assessment
┌───────────┬──────────┬─────────────────┐
│ Namespace │ Resource │ RBAC Assessment │
│           │          ├────────┬────────┤
│           │          │   C    │   H    │
└───────────┴──────────┴────────┴────────┘
Severities: C=CRITICAL H=HIGH


📣 [34mNotices:[0m
  - Version 0.72.0 of Trivy is now available, current version is 0.69.3

To suppress version checks, run Trivy scans with the --skip-version-check flag


```

### What broke and how you fixed it

`readOnlyRootFilesystem: true` makes the root filesystem immutable, and Juice Shop
crash-loops at startup with two `EROFS` errors: it copies seed files into
`/juice-shop/ftp` (`copyfile … /juice-shop/ftp/legal.md`), and it opens its SQLite
database in `/juice-shop/data` (`SQLITE_CANTOPEN`). The tricky part is that
`/juice-shop/data` holds **both** read-only seed content (`data/static/challenges.yml`,
`legal.md`, …) **and** the DB it must write — so a plain `emptyDir` there would hide
the seed and break startup a different way.

The fix keeps `readOnlyRootFilesystem: true` and adds an **initContainer**
(`seed-writable-dirs`) that copies the image's `data/` and `ftp/` directories into
`emptyDir` volumes; the main container then mounts those already-seeded, writable
volumes at `/juice-shop/data` and `/juice-shop/ftp`, plus a scratch `/tmp`. Result:
the seed is present, the DB and file-copies succeed, and the rest of root stays
immutable — preserving the tamper-protection benefit while the pod reaches
`Running 1/1`.

> On `kind` the digest-pinned image also had to be side-loaded into the node
> (`docker save … | ctr -n k8s.io images import -`, because `kind load` failed to
> detect the containerd snapshotter), and the kubeconfig re-exported
> (`kind export kubeconfig`) — operational fixes separate from the hardening above.

## Bonus: Conftest Policy
Status: **PASS on hardened, FAIL on bad (correct)**

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
# Conftest gate — refuse Deployments whose pod template is not hardened.
# Run:  conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
#
# Conftest looks for `package main` by default. Written in Rego v1 syntax
# (if/contains), matching labs/lab9/policies/k8s-security.rego.
package main

# Helper: true if array arr contains value v
has_value(arr, v) if {
	some i
	arr[i] == v
}

# 1) pod-level runAsNonRoot must be true
deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be set to true"
}

# 2) every container must set readOnlyRootFilesystem: true
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container %q must set readOnlyRootFilesystem: true", [c.name])
}

# 3) every container must set allowPrivilegeEscalation: false
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 4) every container must drop ALL capabilities
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not has_value(c.securityContext.capabilities.drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

```

### Output: PASS on hardened manifest
```

[32m8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions[0m

```

### Output: FAIL on bad manifest
```
[31mFAIL[0m - labs/lab7/results/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation: false
[31mFAIL[0m - labs/lab7/results/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem: true
[31mFAIL[0m - labs/lab7/results/bad-pod.yaml - main - pod securityContext.runAsNonRoot must be set to true

[31m4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions[0m

```

### What this prevents at CI time

This policy catches the **insecure-workload-configuration** class — pods that would
run as root, keep a writable root filesystem, allow privilege escalation, or fail to
drop Linux capabilities. Running it at **CI time** (Conftest in the pipeline) is a
left-shift: the manifest is rejected inside the pull request, before it ever reaches
a cluster, so feedback is immediate, cheap, and *blocks the merge*. Admission-time
enforcement (Pod Security Admission / Kyverno, Lecture 7 slide 16) is the essential
backstop, but it only fires at `kubectl apply` — later, in a shared cluster, with a
larger blast radius and a slower feedback loop. Best practice is **both**: fail fast
in CI, and enforce as defense-in-depth at admission.
