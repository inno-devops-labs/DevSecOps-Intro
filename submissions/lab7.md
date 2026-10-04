# Lab 7 — Container and Kubernetes Hardening

Tooling: `trivy 0.74.0`, `kubectl v1.34.1`, `k3d` with `rancher/k3s:v1.33.0-k3s1`, Docker 29.4.3.
Image: `bkimminich/juice-shop:v20.0.0`, digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

## Task 1

### Vulnerability counts and what is actually fixable

```bash
$ trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
    --format json --output labs/lab7/results/trivy-image.json

$ jq -r '[.Results[].Vulnerabilities[]?|{s:.Severity,f:(.FixedVersion!=null)}]
         | group_by(.s) | map({sev:.[0].s, total:length, fixable:map(select(.f))|length})' \
    labs/lab7/results/trivy-image.json
```

| Severity | Total | Fix available | No fix |
|---|---:|---:|---:|
| CRITICAL | 11 | 8 | 3 |
| HIGH | 74 | 69 | 5 |
| **Total** | **85** | **77 (91 %)** | **8** |

### Side by side with Lab 4's Grype run

| | Grype (Lab 4, SBOM) | Trivy (Lab 7, image) |
|---|---:|---:|
| Critical | 14 | 11 |
| High | 84 | 74 |
| **High + Critical** | **98** | **85** |

Same image, 13 fewer findings from Trivy. Two reasons, both recorded in Lab 4: the tools pick severities from different vendor feeds when the feeds disagree, so a chunk of what Grype calls High lands in Trivy's Medium band and falls outside this `--severity HIGH,CRITICAL` filter; and Grype matched 15 findings against the `node@24.15.0` **binary** via CPE, which Trivy does not catalogue as a package at all. The underlying advisory sets overlap far more than the totals suggest — Lab 4 showed that most of the apparent disagreement was `GHSA-*` versus `CVE-*` names for the same defect.

### Ten fixable findings, ranked

```
CRITICAL	CVE-2023-46233	crypto-js 3.3.0 -> 4.2.0
CRITICAL	CVE-2026-71851	crypto-js 3.3.0 -> 4.0.0
CRITICAL	CVE-2015-9235	jsonwebtoken 0.1.0 -> 4.2.2
CRITICAL	CVE-2015-9235	jsonwebtoken 0.4.0 -> 4.2.2
CRITICAL	CVE-2019-10744	lodash 2.4.2 -> 4.17.12
CRITICAL	CVE-2026-59873	tar 4.4.19 -> 7.5.19
CRITICAL	CVE-2026-59873	tar 6.2.1 -> 7.5.19
CRITICAL	CVE-2026-59873	tar 7.5.15 -> 7.5.19
HIGH	CVE-2026-14456	libssl3t64 3.5.5-1~deb13u2 -> 3.5.7-1~deb13u2
HIGH	CVE-2026-45447	libssl3t64 3.5.5-1~deb13u2 -> 3.5.6-1~deb13u2
```

Eight Criticals across five packages, and three of them are one advisory (`CVE-2026-59873`) against three vendored copies of `tar` — the duplicate-copies problem the Lab 4 SBOM made visible, now showing up as triage work.

### Dockerfile findings

```bash
$ trivy config /tmp/df-demo
Tests: 27 (SUCCESSES: 23, FAILURES: 4)
Failures: 4 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 1, CRITICAL: 0)
```

| ID | Severity | Finding | What it buys an attacker |
|---|---|---|---|
| `DS-0002` | HIGH | Last `USER` is `root` | Every process in the container runs as uid 0. A single RCE in the app is then root *inside* the container, and root inside is one kernel bug, one careless `hostPath` mount or one added capability away from root on the node. It also removes the cheapest defence against writes to anything the image ships. |
| `DS-0001` | MEDIUM | `FROM node:latest` has no tag | `latest` is a moving pointer. The image the build produces is not reproducible, a rebuild can silently pull a different base with different packages, and an attacker who compromises the upstream tag gets code execution in every build that runs after. This is the image-level twin of Lab 8's tag-overwrite demo. |
| `DS-0004` | MEDIUM | `EXPOSE 22` | Advertises an SSH endpoint inside the container. If anything ever listens there, it is a second, unaudited administrative entrance into the workload that bypasses `kubectl exec` logging and whatever authentication the application itself enforces. |
| `DS-0026` | LOW | No `HEALTHCHECK` | Not an attack path on its own. It means the orchestrator cannot tell a wedged container from a healthy one, so a crashed-but-not-exited process keeps receiving traffic — availability, and a longer window in which nobody notices something is wrong. |

Worth noting for the pitfall it illustrates: only `DS-0002` is HIGH, so a pipeline running `trivy config --severity HIGH,CRITICAL` would have reported **one** finding on a four-line Dockerfile that does four things wrong. The filter that keeps noise down on image scans hides most of the configuration findings.

### Eight vulnerabilities have no fix

```
CRITICAL  CVE-2026-101894   decompress@4.2.1
CRITICAL  CVE-2026-53486    decompress@4.2.1
CRITICAL  GHSA-5mrr-rgp6-x4gr  marsdb@0.6.11
HIGH      CVE-2020-8203     lodash.set@4.3.2
HIGH      CVE-2026-93687    braces@3.0.3
HIGH      CVE-2026-93748    http-cache-semantics@3.8.1 and @4.2.0
```

Waiting is not a plan, so the queue splits in three. First, **reachability**: `decompress` and `marsdb` are the two Criticals, and the question is whether the application actually calls them with attacker-controlled input — if `decompress` only ever unpacks a build-time fixture, the finding is real and the exposure is not. Second, **removal or replacement**: `marsdb` is unmaintained, and an unmaintained dependency with a Critical and no fix is a dependency to delete, not to track; that is a sprint of work, not a patch. Third, **compensating controls for what stays**: the `restricted` profile, dropped capabilities, the read-only root filesystem and the default-deny NetworkPolicy in Task 2 all narrow what an exploit of these packages can reach, and they ship today.

To a manager asking why the number is not zero: **zero is not the goal, and a tool that reported zero here would be lying.** 77 of 85 findings have a fix and are ordinary patch work. The remaining eight have no patch in existence — no amount of budget produces one — so the honest status is "triaged": we know which are reachable, we have removed what we can remove, and we have constrained the blast radius of the rest. The number I would actually report is not the count of findings but the count of *reachable, fixable, unfixed* ones, because that is the only number anyone can act on.

## Task 2

### Namespace labels

```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/enforce-version: latest
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/warn-version: latest
  pod-security.kubernetes.io/audit: restricted
  pod-security.kubernetes.io/audit-version: latest
```

`enforce` rejects; `warn` and `audit` make near-misses visible in the client and in the audit log instead of silently passing.

### Both securityContext blocks

```bash
$ kubectl -n juice-shop get pod $POD -o jsonpath='{.spec.securityContext}'
{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,
 "seccompProfile":{"type":"RuntimeDefault"}}

$ kubectl -n juice-shop get pod $POD -o jsonpath='{.spec.containers[0].securityContext}'
{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},
 "readOnlyRootFilesystem":true}
```

### The pod runs, and as whom

```bash
$ kubectl -n juice-shop get pods -o wide
NAME                          READY   STATUS    RESTARTS   AGE   IP
juice-shop-8457b58896-4p2jf   1/1     Running   0          31s   10.42.0.10
```

`runAsUser: 65532`, taken from the image rather than guessed:

```bash
$ docker inspect bkimminich/juice-shop:v20.0.0 --format '{{.Config.User}}'
65532
```

The spec's warning is accurate: `runAsUser: 1000` produces a pod that starts and then cannot write a thing, because every file in the image belongs to 65532.

The Deployment also pins the image by digest (`bkimminich/juice-shop@sha256:fd58bdc9...`), mounts no ServiceAccount token (`automountServiceAccountToken: false` on both the ServiceAccount and the pod spec), and sets requests and limits for cpu and memory.

### Both Trivy summaries

```
juice-plain  Deployment/juice        Vulns C=11  H=74   Misconfig C=0  H=3   Secrets H=2
juice-shop   Deployment/juice-shop   Vulns C=22  H=148  Misconfig C=0  H=0   Secrets H=4
```

**Misconfigurations: 3 → 0.** The plain deployment fails `KSV-0014` (root filesystem is not read-only) and `KSV-0118` twice (default security context, at container and at deployment level). The hardened one fails nothing: `jq '[.Resources[]?.Results[]?.Misconfigurations[]?]'` on its report returns `[]`. This is the half that hardening controls — every one of those findings is about the *pod spec*, which is exactly what the manifests rewrote.

**Vulnerabilities: identical, despite the numbers looking doubled.** Both namespaces run the same image, and hardening does not change the bytes inside it — only a rebuild with updated packages does. The 22/148 is an artefact worth naming: my pod has **two** containers from the same image (the initContainer that seeds the volumes, plus the app), so Trivy scans the same filesystem twice and adds up the results. Per image the numbers are identical, and `jq '[...VulnerabilityID]|unique|length'` confirms it — **62 distinct advisories in each namespace**. The secrets count doubles for the same reason: one `private-key` finding (Juice Shop's hardcoded JWT key, the same one Semgrep flagged in Lab 5 at `lib/insecurity.ts:56`), counted once per container.

### One thing `restricted` blocked, one control it does not require

**Blocked.** Submitting the unhardened deployment into the namespace is rejected with the exact fields named:

```bash
$ kubectl -n juice-shop create deployment juice-plain-attempt \
    --image=bkimminich/juice-shop:v20.0.0 --dry-run=server
Warning: would violate PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false (container "juice-shop" must set
    securityContext.allowPrivilegeEscalation=false),
  unrestricted capabilities (container "juice-shop" must set
    securityContext.capabilities.drop=["ALL"]),
  runAsNonRoot != true (pod or container "juice-shop" must set
    securityContext.runAsNonRoot=true),
  seccompProfile (pod or container "juice-shop" must set
    securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

The one that cost actual work was `runAsNonRoot: true` together with `seccompProfile: RuntimeDefault`: a default `kubectl create deployment` has neither, and satisfying them meant finding the image's real uid instead of assuming one.

**Added anyway.** Three things `restricted` never asks for:

- `readOnlyRootFilesystem: true` — the bonus below; `restricted` permits a writable root filesystem, every CIS-style benchmark objects to it.
- The **NetworkPolicy**, with both `Ingress` and `Egress` and a default deny. Pod Security Admission says nothing about the network; without this, a compromised Juice Shop can reach every pod in the cluster and the whole internet. Egress is limited to DNS in `kube-system`, which also quietly blocks the outbound challenge webhook the Lab 2 threat model flagged.
- `automountServiceAccountToken: false` — `restricted` is happy to mount an API token the app never uses, and that token is the first thing an attacker looks for after an RCE.

I verified the NetworkPolicy is actually enforced rather than merely present — k3s ships a policy controller, but a policy that no CNI implements is a comment. A probe pod carrying the `app: juice-shop` label (so the policy selects it) and satisfying `restricted`:

```bash
$ kubectl -n juice-shop exec netpol-test -- curl -s -m 8 -o /dev/null -w "%{http_code}\n" https://example.com
000                                    # BLOCKED, curl exit 7
$ kubectl -n juice-shop exec netpol-test -- nslookup juice-shop.juice-shop.svc.cluster.local
Address: 10.43.124.87                  # DNS to kube-system: allowed
$ kubectl -n juice-shop exec netpol-test -- curl -s -m 8 -o /dev/null -w "%{http_code}\n" \
    http://juice-shop:3000/rest/admin/application-version
200                                    # in-namespace ingress: allowed
```

Egress to the internet is refused, DNS resolves, and the app is reachable from inside the namespace — which is exactly the three-line contract the policy was written to express.

## Bonus

### `docker diff`, trimmed to what matters

```bash
$ docker run -d --name js-diff bkimminich/juice-shop:v20.0.0 && sleep 28 && docker diff js-diff
```

| Path | Change | Ships files in the image? |
|---|---|---|
| `/juice-shop/i18n` | 43 files added | **No** — empty in the image |
| `/juice-shop/logs` | 2 files added | **No** — empty |
| `/juice-shop/data` | `juiceshop.sqlite` created | **Yes** — 6 files |
| `/juice-shop/ftp` | `legal.md` added | **Yes** — 10 files |
| `/juice-shop/.well-known` | `csaf/provider-metadata.json` rewritten | **Yes** — 2 entries |
| `/juice-shop/frontend/dist/frontend` | `index.html` rewritten; 3 asset files added | **Yes** — the entire built frontend |

The counts come from `docker cp` out of the image, not from guessing — the image is distroless, so there is no shell to `ls` with.

### Volume layout

Seven `emptyDir` volumes, in two groups:

| Volume | Mount | Why |
|---|---|---|
| `logs`, `i18n` | `/juice-shop/logs`, `/juice-shop/i18n` | Written at runtime, empty in the image → a bare `emptyDir` is enough |
| `ftp`, `data`, `well-known`, `frontend` | the matching paths | Written at runtime **and** ship files → seeded by an initContainer |
| `tmp` | `/tmp` | Node and the app expect a writable temp dir; nothing in the image depends on its contents |

### The directory that could not just be replaced

`/juice-shop/frontend/dist/frontend` is the interesting one. An empty volume over it hides the entire built Angular frontend, and the app dies on startup:

```
Error: EROFS: read-only file system, open 'frontend/dist/frontend/index.html'
    at customizeTitle (/juice-shop/build/lib/startup/customizeApplication.js:103:27)
  errno: -30, code: 'EROFS', syscall: 'open'
```

Juice Shop *rewrites* `index.html` at boot to inject the configured application name, so the file has to be both present and writable — mutually exclusive on a read-only root filesystem unless the directory is a pre-populated volume. `ftp`, `data` and `.well-known` have the same shape: `/juice-shop/ftp` ships the ten files Lab 1 found exposed, and an empty volume would have "fixed" that exposure by deleting the lab's own targets.

**The solution** is an initContainer that copies the image's contents into each volume before the app starts, with the volumes mounted at `/seed/...` so the source paths stay visible. The image has no shell and no `cp`, but it does carry a node binary, and `fs.cpSync` copies directories:

```yaml
initContainers:
  - name: seed-writable-dirs
    image: bkimminich/juice-shop@sha256:fd58bdc9...
    command: ["/nodejs/bin/node"]
    args: ["-e", "const fs=require('fs'); for (const [src,dst] of [...]) fs.cpSync(src,dst,{recursive:true})"]
```

```
seeded /juice-shop/ftp -> /seed/ftp 10 entries
seeded /juice-shop/data -> /seed/data 6 entries
seeded /juice-shop/.well-known -> /seed/well-known 2 entries
seeded /juice-shop/frontend/dist/frontend -> /seed/frontend 33 entries
```

The initContainer runs under the same `restricted` constraints, including `readOnlyRootFilesystem: true` on itself.

### Proof

```bash
$ kubectl -n juice-shop get pods
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-8457b58896-4p2jf   1/1     Running   0          31s

$ kubectl -n juice-shop get pod $POD -o jsonpath='{.spec.containers[0].securityContext}'
{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}

$ kubectl -n juice-shop port-forward deploy/juice-shop 3010:3000 &
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3010/
HTTP 200
$ curl -s http://127.0.0.1:3010/rest/admin/application-version
{"version":"20.0.0"}
$ curl -s http://127.0.0.1:3010/api/Products | jq '.data|length'
46
```

Ready, read-only root filesystem, HTTP 200, and the full catalogue — the same 46 products as the Lab 1 container, now with nothing writable outside six explicit volumes.
