# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

### Dockerfile misconfig scan
Ran `trivy config` against a sample hardened-target Dockerfile with four deliberate anti-patterns
(`:latest` tag, `USER root`, `EXPOSE 22`, `ADD <url>`). At `--severity HIGH,CRITICAL` only one
finding cleared the bar:

```
DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
  Dockerfile:4  →  USER root
```

The other three anti-patterns (`:latest` pin, exposed SSH port, remote `ADD`) are real Trivy
checks but rated LOW/MEDIUM, so they're filtered out at this severity threshold — a reminder
that `--severity HIGH,CRITICAL` is a triage filter, not a completeness guarantee.

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

The one Critical without a fix is `GHSA-5mrr-rgp6-x4gr` (marsdb 0.6.11) — an abandoned package
with no upstream patch, so it needs a compensating control or replacement rather than a version bump.

### Compared to Lab 4's Grype scan
Lab 4 Grype breakdown on the same image (`bkimminich/juice-shop:v20.0.0`): Critical 7, High 51,
Medium 4, Low 35, Negligible 7 — Total 104.

1. **Both tools found it — `crypto-js` (installed 3.3.0, fix 4.2.0, Critical).** Grype reported it
   as `GHSA-xwcq-pm8m-c4vf`, Trivy as `CVE-2023-46233` — same underlying flaw (predictable/undefined
   salt in `crypto-js`'s PBKDF), just surfaced under different ID namespaces. Both vendors ingest the
   GitHub Advisory Database as an upstream source for npm packages, so well-established npm advisories
   like this one show up in both tools even though they don't always print the same identifier.

2. **Trivy found it, Grype missed it — `NSWG-ECO-428` (base64url 0.0.6, High, fix >=3.0.0).**
   This is a Node.js Security Working Group advisory. Trivy's `vuln-list` ingests NSWG advisories
   directly as a source; Grype's Anchore feed doesn't map this particular ecosystem-specific advisory
   the same way. It's a DB-coverage gap rather than a scanning-depth gap — both tools scanned the same
   `node_modules` tree, but only one tool's vulnerability database had an entry for this specific advisory ID.

## Task 2: Kubernetes Hardening

### Manifests
- `namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

- `deployment.yaml` securityContext (pod-level):
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
```

- `deployment.yaml` securityContext (container-level, applied identically to the
  `juice-shop` container and the `seed-app-dir` initContainer):
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

- `deployment.yaml` initContainer (seeds the writable volume before the app starts —
  see "What broke" below for why this was necessary):
```yaml
initContainers:
  - name: seed-app-dir
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    command: ["/nodejs/bin/node"]
    args:
      - "-e"
      - "require('fs').cpSync('/juice-shop','/seed',{recursive:true});"
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    volumeMounts:
      - name: appdata
        mountPath: /seed
```

- `networkpolicy.yaml` ingress + egress:
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
  - ports:
      - protocol: TCP
        port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-66585f6cf-nkbhs   1/1     Running   0          2m9s
```
Confirmed from the captured `pod-spec.yaml`: `phase: Running`, `initContainerStatuses`
shows `seed-app-dir` terminated with `reason: Completed, exitCode: 0`, and both containers
carry `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`
— full PSS `restricted` compliance, no admission warnings.

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 86 |

Note: this is exactly **2x** Task 1's per-image count (5 Critical / 43 High) — expected, since
the Deployment now runs the same `bkimminich/juice-shop` image twice per pod (the `juice-shop`
container and the `seed-app-dir` initContainer), and Trivy counts image vulnerabilities once per
container instance, not once per unique image digest. Misconfigurations: 0 Critical/High
(clean — PSS `restricted` compliance holds). Secrets: 4 High (also doubled from Task 1's 2,
same reason — Juice Shop ships embedded RSA keys in its source, flagged once per container).

### What broke and how you fixed it
`readOnlyRootFilesystem: true` broke Juice Shop, but not just at the obvious `/tmp` and
`/logs` paths — this image's `WORKDIR` is `/juice-shop` (not `/usr/src/app` as commonly
documented for older versions), and at startup it writes/copies files scattered all over its
own tree: the SQLite DB and static seed data under `/juice-shop/data`, restored "hacked" files
under `/juice-shop/ftp`, rewritten frontend assets under `/juice-shop/frontend/dist/...`, and
even a relative `.well-known/csaf/...` file. Chasing each individual subpath with a separate
`emptyDir` turned into a whack-a-mole (fixing one `EROFS` just revealed the next). The fix that
actually held: mount a **single `emptyDir` over the entire `/juice-shop` directory** (not the
whole root FS — `/nodejs`, `/etc`, and other system paths stay on the immutable image layer),
and pre-populate it via an `initContainer` that runs `fs.cpSync('/juice-shop', '/seed', {recursive:true})`
using the same image (it has no shell — this is a distroless-style Node image — so the copy has
to be a Node one-liner via `node -e`, not `cp -r`). This satisfies `readOnlyRootFilesystem: true`
for PSS `restricted` while giving the app free rein inside its own working directory.

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

all_containers(spec) = containers {
	containers := array.concat(
		object.get(spec, "containers", []),
		object.get(spec, "initContainers", []),
	)
}

is_non_root(spec) {
	spec.securityContext.runAsNonRoot == true
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	not is_non_root(spec)
	msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot: true"
}

is_readonly_rootfs(container) {
	container.securityContext.readOnlyRootFilesystem == true
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	container := all_containers(spec)[_]
	not is_readonly_rootfs(container)
	msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

no_priv_escalation(container) {
	container.securityContext.allowPrivilegeEscalation == false
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	container := all_containers(spec)[_]
	not no_priv_escalation(container)
	msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

drops_all_caps(container) {
	container.securityContext.capabilities.drop[_] == "ALL"
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	container := all_containers(spec)[_]
	not drops_all_caps(container)
	msg := sprintf("Container '%s' must drop ALL capabilities (securityContext.capabilities.drop: [\"ALL\"])", [container.name])
}
```

Note: the policy checks `spec.containers` **and** `spec.initContainers` together (via
`all_containers`), since our hardened Deployment (Task 2) runs a `seed-app-dir` initContainer
on the same image and it must meet the same bar as the main container.

### Output: PASS on hardened manifest
```
$ conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies

8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```
(8 = 4 rules × 2 containers: `juice-shop` + `seed-app-dir`.)

### Output: FAIL on bad manifest
```
$ conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies

FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop ALL capabilities (securityContext.capabilities.drop: ["ALL"])
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - Deployment must set spec.template.spec.securityContext.runAsNonRoot: true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

One debugging note worth keeping: the first version of this policy wrote the checks as plain
comparisons, e.g. `container.securityContext.readOnlyRootFilesystem != true`. Against the bad
manifest (which has **no** `securityContext` block at all), only the `capabilities.drop` rule
fired — the other three silently passed even though nothing was set. The reason is a Rego
semantics gotcha: dereferencing a field that doesn't exist (`container.securityContext.foo`)
produces `undefined`, not `false`, and `undefined != true` is *itself* undefined — so the rule
body never evaluates to true and `deny` never fires. The `capabilities.drop` rule accidentally
worked because it was written as a separate helper rule (`contains_all_drop(container)`) called
with `not` from outside — a rule with an unsatisfied body evaluates to `false` (not undefined)
when referenced that way, so `not false` correctly becomes `true`. The fix was to rewrite every
check as a small helper rule + `not helper(...)`, so "field missing" is treated the same as
"field present but wrong" everywhere.

### What this prevents at CI time
This Rego policy catches the same class of bug that Pod Security Admission catches (missing
`runAsNonRoot`, writable root FS, retained capabilities) but at CI time, before `kubectl apply`
ever runs — a bad manifest never reaches the cluster, let alone gets a chance to be admitted
with just a `warn` label. Catching it in CI is cheaper and safer: it fails fast on a laptop/PR
check instead of depending on cluster-side admission control being correctly configured (and not
accidentally left at `warn`/`audit` instead of `enforce`) in every environment the manifest might
ever be deployed to.