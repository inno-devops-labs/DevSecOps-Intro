# Lab 7 — Submission

Container and Kubernetes hardening on `bkimminich/juice-shop:v20.0.0`: scan the artifact with
Trivy, then run it under the `restricted` Pod Security Standard.

## Setup

```console
$ trivy --version
Version: 0.74.0
  Vulnerability DB UpdatedAt: 2026-09-20 19:19:55 UTC
$ kubectl version --client
Client Version: v1.37.1
$ k3d version
k3d version v5.9.0 / k3s version v1.35.5-k3s1 (default)
$ docker --version
Docker version 28.0.1
```

Cluster created with `k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1`;
`kubectl cluster-info` confirmed the control plane, CoreDNS and metrics-server were up.

## Task 1 — Scan the artifact

```console
$ trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
    --format json --output labs/lab7/results/trivy-image.json
```

### Vulnerability counts and fix availability

Scan limited to `HIGH,CRITICAL`. Counts from the JSON:

| Severity | Total | Has a fix | No fix |
|---|---:|---:|---:|
| CRITICAL | 11 | 8 | 3 |
| HIGH | 74 | 69 | 5 |
| **Total** | **85** | **77** | **8** |

85 findings across 62 distinct CVE ids (one advisory can hit several packages — e.g. `tar`
`CVE-2026-59873` matches three installed versions). By source: **4** Debian 13.4 OS-package vulns
and **81** Node.js package vulns. Trivy's secret scanner also ran and found **0** secrets in the
image. **77 of the 85 (91%) have a released fix**; only 8 do not.

### Side by side with Lab 4's Grype scan

Lab 4 scanned the same image via its CycloneDX SBOM with Grype (DB schema `v6.1.9`, built
2026-09-20):

| | Grype (Lab 4, SBOM) | Trivy (Lab 7, image) |
|---|---:|---:|
| CRITICAL | 14 | 11 |
| HIGH | 85 | 74 |
| **HIGH+CRITICAL** | **99** | **85** |
| all severities | 183 matches / 157 distinct | not scanned (filtered to HIGH,CRITICAL) |

Comparing like for like (HIGH+CRITICAL), Grype reports 99 and Trivy 85 — the gap is expected, not
an error: the two tools use different vulnerability databases and different matching/dedup logic,
and they looked at the artifact two different ways (Grype matched against syft's SBOM component
list, Trivy unpacked the image's layers directly). Two scanners rarely return the same number on
the same image; that disagreement is exactly why a pipeline normalises both into one tracker
(Lab 10) rather than trusting either count alone.

### The ten fixable HIGH/CRITICAL, ranked (7.2)

```
CRITICAL   CVE-2023-46233   crypto-js    3.3.0            -> 4.2.0
CRITICAL   CVE-2026-71851   crypto-js    3.3.0            -> 4.0.0
CRITICAL   CVE-2015-9235    jsonwebtoken 0.1.0            -> 4.2.2
CRITICAL   CVE-2015-9235    jsonwebtoken 0.4.0            -> 4.2.2
CRITICAL   CVE-2019-10744   lodash       2.4.2            -> 4.17.12
CRITICAL   CVE-2026-59873   tar          4.4.19           -> 7.5.19
CRITICAL   CVE-2026-59873   tar          6.2.1            -> 7.5.19
CRITICAL   CVE-2026-59873   tar          7.5.15           -> 7.5.19
HIGH       CVE-2026-14456   libssl3t64   3.5.5-1~deb13u2  -> 3.5.7-1~deb13u2
HIGH       CVE-2026-45447   libssl3t64   3.5.5-1~deb13u2  -> 3.5.6-1~deb13u2
```

`select(.FixedVersion != null)` filters to vulnerabilities that can actually be closed this
sprint — every row above is a dependency bump. The 8 without a `FixedVersion` are deliberately
excluded, because they are a risk decision, not a ticket (see the last paragraph).

### Dockerfile scan (7.3)

```console
$ trivy config /tmp/df-demo      # Dockerfile: FROM node:latest / USER root / EXPOSE 22 / ADD <url>
```

4 failures — 1 HIGH, 2 MEDIUM, 1 LOW:

| ID | Severity | Finding | What it lets an attacker do |
|---|---|---|---|
| **DS-0002** | HIGH | Last `USER` is `root` | Container runs as root; any process compromise or container escape yields root on the node — direct privilege escalation toward host takeover. |
| **DS-0001** | MEDIUM | `FROM node:latest` (no pinned tag) | The base image can change under you; a later pull can bring in new vulnerable — or malicious — content, and builds aren't reproducible. A supply-chain risk, the same lesson as Lecture 4's pin-by-digest. |
| **DS-0004** | MEDIUM | `EXPOSE 22` | Advertises SSH on the container, an attack surface containers shouldn't have — an extra remote entry point and a lateral-movement foothold. |
| **DS-0026** | LOW | No `HEALTHCHECK` | No liveness signal, so the orchestrator can't distinguish a hung or subverted container from a healthy one; a wedged/compromised container keeps receiving traffic. Resilience gap, not a direct exploit. |

Note: the `ADD https://example.com/app.tar /` line did **not** trigger a finding in this run, so I
am reporting the four checks that actually fired rather than the five I expected. As the lab warns,
a `--severity HIGH,CRITICAL` filter would have hidden three of these four — only DS-0002 would
survive.

### The vulnerabilities with no fix — what I do, and what I tell a manager

Eight of the 85 HIGH/CRITICAL findings have no released patch, so I cannot close them by bumping a
version. Those move from the sprint board to **compensating controls**: lock the workload down
(the `restricted` Pod Security Standard in Task 2 — non-root, dropped capabilities), isolate it
with a NetworkPolicy, block the exploitable path at the edge where one exists, and record each as a
tracked risk acceptance with an owner and a re-scan date so a fix is picked up when upstream ships
one. To a manager asking why the number isn't zero, I'd say zero isn't a meaningful target: the
count is a snapshot of one database's knowledge on one day, and it includes issues the maintainers
themselves haven't patched yet. What matters is that every *fixable* HIGH/CRITICAL (77 of 85 here)
is scheduled, and every *unfixable* one has a documented control and is being watched — managing
the residual eight, not chasing a zero that would be stale by next week's DB update.

## Task 2 — Run it under `restricted`

Manifests under `labs/lab7/k8s/`: `namespace.yaml`, `serviceaccount.yaml`, `deployment.yaml`,
`networkpolicy.yaml`.

### Namespace labels

```yaml
pod-security.kubernetes.io/enforce: restricted      # rejects non-compliant pods
pod-security.kubernetes.io/warn:    restricted      # client-side warning
pod-security.kubernetes.io/audit:   restricted      # audit-log entry
# (each pinned with its *-version: latest)
```

### The two `securityContext` blocks

```yaml
# pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 65532          # the image's own user (docker inspect .Config.User)
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
# container-level
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

The ServiceAccount and the pod spec both set `automountServiceAccountToken: false`, and the image
is pinned by digest (`@sha256:fd58bdc9…418b0`), not by tag.

### Proof the pod runs, and as which user

```console
$ kubectl -n juice-shop get pod -l app=juice-shop -o wide
NAME                          READY   STATUS    RESTARTS   AGE   IP          NODE
juice-shop-5878569755-jtpm8   1/1     Running   0          101s  10.42.0.9   k3d-lab7-server-0
```

The image is so minimal it ships no shell — `exec … id`, `cat`, `ls`, `node` all return
"executable file not found", which is itself a hardening win. I proved the runtime UID from the
node instead, reading the process's `/proc` entry:

```console
$ docker exec k3d-lab7-server-0 sh -c '… grep ^Uid: /proc/<pid>/status'
PID 3253 : /nodejs/bin/node /juice-shop/build/app.js
Uid:    65532   65532   65532   65532
```

Real, effective, saved and filesystem UID are all **65532** — the non-root user the manifest
pins, matching the image's own user.

### Two Trivy summaries side by side (7.6)

`trivy k8s --include-namespaces <ns> --severity HIGH,CRITICAL --report=summary`:

| Namespace | Vulns (C/H) | Misconfigs (HIGH) | Secrets (HIGH) |
|---|---|---|---|
| `juice-plain` (default deploy) | 11 / 74 | **3** — 2× KSV-0118, 1× KSV-0014 | 2× private-key |
| `juice-shop` (hardened) | 11 / 74 | **1** — 1× KSV-0014 | 2× private-key |

**The misconfiguration counts differ; the vulnerability (and secret) counts do not — both halves
are expected.** Misconfig dropped from 3 to 1 because my `securityContext` blocks cleared the two
`KSV-0118` "default security context configured" findings (runAsNonRoot, dropped capabilities,
no-priv-escalation, seccomp). The vulnerability and secret counts are identical because both
namespaces run the *same image by the same digest*: a Pod Security Standard governs how the
container is allowed to run, not which packages or baked-in keys are inside it — hardening the pod
can't patch a CVE in `lodash` or remove the demo RSA key from the image. The one remaining HIGH
misconfig, `KSV-0014` "root file system is not read-only", is deliberate: `restricted` does not
require it, and it's the bonus.

### One thing `restricted` blocked, and one control it doesn't require that I added

**Blocked:** a plain `kubectl create deployment` in this namespace is rejected outright by the
enforce label — proven by trying it:

```
pods "juice-bad-…" is forbidden: violates PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false …, unrestricted capabilities …,
  runAsNonRoot != true …, seccompProfile … must be "RuntimeDefault"
```

So I had to add all four (`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
`runAsNonRoot: true`, `seccompProfile: RuntimeDefault`). I also had to set `runAsUser: 65532`
specifically — the lab's warned trap is that guessing `1000` yields a pod that starts and then
can't write its own files.

**Added beyond the profile:** a default-deny **NetworkPolicy** (`networkpolicy.yaml`) — ingress
only to TCP 3000, egress only DNS to kube-system. Pod Security Standards say nothing about the
network, so a `restricted` pod is still free to talk to anything by default; the NetworkPolicy
closes that. (`automountServiceAccountToken: false` and CPU/memory limits are two more controls
`restricted` doesn't mandate that the manifests set anyway.)

## Artifacts

- `labs/lab7/results/trivy-image.json` — HIGH/CRITICAL image scan (Task 1).
- `labs/lab7/results/pod-spec.yaml` — the admitted pod's full spec.
- `labs/lab7/results/trivy-k8s.json` — hardened-namespace scan (Lab 10 imports this).
- `labs/lab7/k8s/` — the four manifests (committed).

Results files are left uncommitted per the lab; the manifests under `labs/lab7/k8s/` are the
committed deliverable.
