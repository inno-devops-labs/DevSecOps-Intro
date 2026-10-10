# Lab 7 — Container and Kubernetes Hardening

Branch: `feature/lab7`. Executed on 2026-10-02 (Europe/Moscow; scan timestamps
are 2026-10-01 UTC). Task 1, the optional Task 2, and the read-only-root bonus
are all done.

Image: `bkimminich/juice-shop:v20.0.0`, pinned as
`bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.
This is the same repository/index digest recorded in Lab 4.

| Tool | Version | How it ran |
| --- | --- | --- |
| Trivy | 0.74.0 (`aquasec/trivy:0.74.0`) | in a container, matching `tools/versions.yaml` |
| Trivy vulnerability DB | schema 2, updated `2026-10-01T19:00:16Z` | shared cache from Lab 4 |
| k3d | v5.9.0 (`k3d-windows-amd64.exe`, SHA-256 `49d0b9c7…680a034`, matches the release `checksums.txt`) | host |
| k3s | `rancher/k3s:v1.33.0-k3s1` (server v1.33.0+k3s1, containerd 2.0.4) | k3d node |
| kubectl | client v1.36.1 (Docker Desktop's) | host; skew warning against the 1.33 server, no effect on these commands |
| jq | 1.8.1 | host |
| Docker | Engine 29.7.2, Docker Desktop on WSL2 | host |

Trivy scanned the Lab 4 `docker save` archive (`--input`, mounted read-only), so
it never needed the Docker socket. For `trivy k8s`, the Trivy container joined
the `k3d-lab7` Docker network, using a kubeconfig whose server was rewritten to
`https://k3d-lab7-server-0:6443`. Raw outputs are in the git-ignored
`labs/lab7/results/`.

## Task 1

### 7.1 Image vulnerabilities (HIGH and CRITICAL only)

`trivy image … --severity HIGH,CRITICAL --format json`, as the lab specifies:

| Severity | Findings | With a released fix | Without a fix | Distinct IDs |
| --- | ---: | ---: | ---: | ---: |
| CRITICAL | 11 | 8 | 3 | 8 |
| HIGH | 70 | 69 | 1 | 52 |
| **Total** | **81** | **77** | **4** | **60** |

77 of 81 (95%) HIGH and CRITICAL findings have a `FixedVersion`. The OS layer
(Debian 13.4) contributes 4 findings, all in `libssl3t64` and all fixable. The
other 77 come from `node_modules`.

The secret scanner also flagged two HIGH `private-key` hits, in
`/juice-shop/build/lib/insecurity.js` and `/juice-shop/lib/insecurity.ts`. This is
Juice Shop's deliberately hard-coded JWT signing key. In a real image it would be
the most urgent finding of the lot: unlike a CVE, it is exploitable today with
no exploit chain at all.

The four findings with no fix:

| Severity | ID | Package | Status |
| --- | --- | --- | --- |
| CRITICAL | CVE-2026-101894 | decompress 4.2.1 | affected |
| CRITICAL | CVE-2026-53486 | decompress 4.2.1 | affected |
| CRITICAL | GHSA-5mrr-rgp6-x4gr | marsdb 0.6.11 | affected |
| HIGH | CVE-2020-8203 | lodash.set 4.3.2 | affected |

### Trivy now vs Grype in Lab 4

| Scan | Date / DB | Critical | High | HIGH+CRITICAL |
| --- | --- | ---: | ---: | ---: |
| Grype 0.118.0 on the Syft CycloneDX SBOM (Lab 4) | DB built 2026-09-18 | 14 | 85 | **99** |
| Trivy 0.74.0 on the image (Lab 4, for reference) | DB 2026-09-18 | 10 | 64 | 74 |
| Trivy 0.74.0 on the image (this lab) | DB 2026-10-01 | 11 | 70 | **81** |

(Grype's all-severity total in Lab 4 was 183.) Grype reports 18 more
HIGH+CRITICAL matches for the same digest. It matches the SBOM using CPEs as
well as package ecosystems: in Lab 4 it flagged the standalone `node` 24.15.0
binary, for example, which Trivy does not. It also reports one GHSA match per
affected package copy, where Trivy prefers CVE ids. Trivy's own count rose from
74 to 81 between the two dates with the image unchanged. Part of any comparison
between scanners is therefore just database age.

### 7.2 Top ten fixable, ranked

Output of the lab's `jq` filter, verbatim:

```
CRITICAL  CVE-2023-46233  crypto-js 3.3.0 -> 4.2.0
CRITICAL  CVE-2026-71851  crypto-js 3.3.0 -> 4.0.0
CRITICAL  CVE-2015-9235   jsonwebtoken 0.1.0 -> 4.2.2
CRITICAL  CVE-2015-9235   jsonwebtoken 0.4.0 -> 4.2.2
CRITICAL  CVE-2019-10744  lodash 2.4.2 -> 4.17.12
CRITICAL  CVE-2026-59873  tar 4.4.19 -> 7.5.19
CRITICAL  CVE-2026-59873  tar 6.2.1 -> 7.5.19
CRITICAL  CVE-2026-59873  tar 7.5.15 -> 7.5.19
HIGH      CVE-2026-14456  libssl3t64 3.5.5-1~deb13u2 -> 3.5.7-1~deb13u2
HIGH      CVE-2026-45447  libssl3t64 3.5.5-1~deb13u2 -> 3.5.6-1~deb13u2
```

These ten rows boil down to five upgrades. One `crypto-js` bump to 4.2.0
clears two rows. Both `jsonwebtoken` copies need 4.2.2 or later. The three `tar`
rows are three copies of one package pulled in at different depths, so the fix
is a single dependency override to `tar@>=7.5.19`, not three tickets. The
`libssl3t64` rows are fixed by rebuilding on a refreshed Debian base.

### 7.3 Dockerfile scan

`trivy config` on a directory holding the four-line file, named exactly
`Dockerfile`: 27 checks, **4 failures (1 HIGH, 2 MEDIUM, 1 LOW)**. A
`--severity HIGH,CRITICAL` filter would have shown only DS-0002.

| ID | Severity | Line | Finding | What it gives an attacker |
| --- | --- | --- | --- | --- |
| DS-0002 | HIGH | 2 `USER root` | Last `USER` is root | Any RCE in the app runs as UID 0. Combined with a runtime or kernel bug, a mounted socket, or a privileged flag, that becomes a container escape. Even without one, the attacker can overwrite anything in the container filesystem, plant persistence, and install tools. |
| DS-0001 | MEDIUM | 1 `FROM node:latest` | No pinned tag | Whoever controls, or compromises, what `latest` points to on the build date controls your base image. It is a supply-chain foothold, and builds are not reproducible, so you cannot say what you shipped. |
| DS-0004 | MEDIUM | 3 `EXPOSE 22` | SSH port exposed | It advertises an SSH service, inviting a password-guessing and credential-reuse target into the container. It also signals that people log in to containers, which bypasses the image pipeline. |
| DS-0026 | LOW | — | No `HEALTHCHECK` | Not exploitable directly. A hung or half-compromised process still counts as healthy, so it keeps getting traffic and nothing restarts it. |

Trivy did **not** flag `ADD https://example.com/app.tar /`. That is arguably
the worst line: the file is fetched over the network at build time with no
checksum, so whoever controls that URL, or the path to it, controls a layer of
your image. (DS-0005 only fires for `ADD` of local files. Remote `ADD` without
`--checksum` passes.) A green scanner run does not mean the Dockerfile is fine.

### Vulnerabilities with no fix

For the four unfixable findings, I would first establish reachability.
`marsdb` and `decompress` are only dangerous if attacker-controlled input
reaches them. If a dependency is not needed at runtime, remove it or replace it:
that is the one remediation that does not wait for upstream. For whatever stays,
I would add compensating controls aimed at the vulnerability class. For
`decompress` path traversal and arbitrary write, that means a read-only root
filesystem, a non-root UID, and no capabilities, all applied in Task 2 and the
bonus. A WAF or input validation in front of upload endpoints, an egress-deny
NetworkPolicy, and a runtime rule on unexpected writes (Lab 9) cover the rest.
Each finding then gets a time-boxed, owner-signed exception, recorded in a
`.trivyignore` with a reason and expiry date, and is revisited whenever the DB
shows a fix. To a manager: "zero" is not the goal, because the count is set by
a database that grows every day (ours went from 74 to 81 with no code change).
The metric that matters is that every fixable critical is closed within the SLA
and every unfixable one has a named owner, a mitigation, and an expiry date.

## Task 2

### Manifests

All in `labs/lab7/k8s/`: `namespace.yaml`, `serviceaccount.yaml`,
`deployment.yaml`, `service.yaml`, and `networkpolicy.yaml`. The namespace is
applied first, then the directory, exactly as in 7.5.

Namespace labels (from `kubectl get ns juice-shop --show-labels`):

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: v1.33
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/warn-version: v1.33
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/audit-version: v1.33
```

The version labels pin the profile to the server's minor version, so a
cluster upgrade cannot silently change what is admitted.

Pod `securityContext`:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532        # the image's own USER (docker inspect … '{{.Config.User}}' -> 65532)
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
```

Container `securityContext`. These are the Task 2 values; the bonus adds
`readOnlyRootFilesystem: true`:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  privileged: false
  capabilities:
    drop: ["ALL"]
```

The Deployment also sets the following:
- `serviceAccountName: juice-shop`, with `automountServiceAccountToken: false` on both the ServiceAccount and the pod spec
- requests `250m` / `384Mi` and limits `1` / `1Gi`
- the image by digest
- readiness and liveness probes on `/rest/admin/application-version`

### Proof it runs, and as whom

```
$ kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=180s
pod/juice-shop-cd8c6c5f8-x2v74 condition met
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-cd8c6c5f8-x2v74   1/1     Running   0          45s
```

The image is distroless, so `kubectl exec … id` fails with `exec: "id":
executable file not found in $PATH`. I asked the image's own node binary
instead:

```
$ kubectl -n juice-shop exec <pod> -- /nodejs/bin/node -e '…process.getuid()…; /proc/1/status…'
uid=65532 gid=65532 groups=65532
Uid:	65532	65532	65532	65532
Gid:	65532	65532	65532	65532
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
NoNewPrivs:	1
Seccomp:	2
sa-token-dir-exists=false
```

PID 1 runs as UID 65532 with an empty capability set and `no_new_privs`, under
seccomp filter mode 2 (RuntimeDefault). No ServiceAccount token is mounted.
`status.containerStatuses[0].imageID` is
`docker.io/bkimminich/juice-shop@sha256:fd58bdc9…18b0`, the pinned digest.

The NetworkPolicy was tested from throwaway pods built from the same image (so
no extra image was pulled). Each pod waited 20 s before connecting, so that
k3s's kube-router had added its IP to the policy's ipsets. The first attempt
without the wait was refused even from the allowed namespace, which is a race,
not the policy.

```
from juice-shop  -> juice-shop:3000      HTTP 200        (allowed: same namespace)
from juice-plain -> juice-shop:3000      ECONNREFUSED    (denied)
app pod: DNS lookup example.com          ok              (UDP/TCP 53 to kube-dns allowed)
app pod: https://example.com             ECONNREFUSED    (all other egress denied)
```

### Trivy k8s: plain vs hardened

`trivy k8s --include-namespaces <ns> --severity HIGH,CRITICAL --report=summary`,
Workload Assessment rows:

| Namespace | Resource | Vuln C | Vuln H | Misconfig C | Misconfig H | Secrets H |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| juice-plain | Deployment/juice | 11 | 70 | – | **3** | 2 |
| juice-shop (Task 2) | Deployment/juice-shop | 11 | 70 | – | **1** | 2 |
| juice-shop (after bonus) | Deployment/juice-shop | 22* | 140* | – | **0** | 4* |

\* After the bonus, the pod has an initContainer running the same image, and
Trivy reports per container. The JSON shows two identical result sets of 4 OS
and 77 Node.js findings, which is the same 81 counted twice.

The three plain HIGHs are KSV-0014 (root filesystem not read-only) and KSV-0118
(default security context) twice. The Task 2 deployment fails only KSV-0014,
and the bonus closes that too. Running with all severities as well widens the
gap: the plain deployment fails **17** checks, including KSV-0001
privilege escalation, KSV-0012 runs as root, KSV-0104 seccomp off, and missing
limits. The final hardened deployment fails **1** check per container: KSV-0125
"restrict images to trusted registries", which needs an admission allowlist,
not a pod field.

Misconfigurations differ because they are properties of the **pod spec**: the
same image becomes safer to run when the spec drops capabilities, forbids
escalation, and pins the UID. Vulnerabilities do not differ, because they are
properties of the **image bytes**, which are the identical digest in both
namespaces. Hardening reduces what an attacker can do after exploiting a CVE.
Only rebuilding the image removes the CVE.

### What `restricted` blocked, and what I added anyway

**Blocked.** The default spec that `kubectl create deployment` generates is
rejected in this namespace. A server-side dry run of the same image shows
exactly which four fields had to change:

```
$ kubectl -n juice-shop run plain --image=bkimminich/juice-shop:v20.0.0 --dry-run=server
Error from server (Forbidden): pods "plain" is forbidden: violates PodSecurity "restricted:v1.33":
allowPrivilegeEscalation != false (container "plain" must set securityContext.allowPrivilegeEscalation=false),
unrestricted capabilities (container "plain" must set securityContext.capabilities.drop=["ALL"]),
runAsNonRoot != true (pod or container "plain" must set securityContext.runAsNonRoot=true),
seccompProfile (pod or container "plain" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

The same Deployment was admitted without complaint in the unlabeled
`juice-plain` namespace. The bonus initContainer needed the same treatment,
because `restricted` checks init containers too.

**Added voluntarily.** The profile requires none of the following:
- the NetworkPolicy (default-deny, re-opening only port 3000 within the namespace and DNS)
- `automountServiceAccountToken: false`
- requests and limits
- the digest pin
- `readOnlyRootFilesystem` (bonus)

The NetworkPolicy is the one I would keep if I could keep only one: it turns
"RCE in Juice Shop" from "pivot anywhere in the cluster or exfiltrate to the
internet" into "talk to CoreDNS".

## Bonus

`docker run --rm --read-only bkimminich/juice-shop:v20.0.0` exits 1:

```
Error: EROFS: read-only file system, copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'
ConnectionError [SequelizeConnectionError]: SQLITE_CANTOPEN: unable to open database file
```

### `docker diff` after 30 s, trimmed

The raw diff has 68 lines. It is reduced here to the paths that matter, and the
43 `A /juice-shop/i18n/*.json` lines are collapsed into one:

```
A /juice-shop/data/juiceshop.sqlite
A /juice-shop/ftp/legal.md
A /juice-shop/i18n/{43 locale files}.json
A /juice-shop/logs/access.log.2026-10-01
A /juice-shop/logs/audit.json
C /juice-shop/frontend/dist/frontend/index.html
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
C /juice-shop/.well-known/csaf/provider-metadata.json
```

Nothing outside `/juice-shop` changed: no `/tmp` and no `$HOME`. So I mounted
no volume that `docker diff` does not justify.

I then compared each written directory with the pristine image
(`docker create` + `docker cp … | tar t`):

| Directory | Entries in image | Entries at runtime | Ships content? |
| --- | ---: | ---: | --- |
| `data` | 219 | 220 | **yes**: `data/static/*` (users, challenges, legal.md…) |
| `ftp` | 15 | 16 | **yes**: the challenge files served at `/ftp` |
| `frontend/dist/frontend` | 766 | 769 | **yes**: the built Angular SPA (38 MB) |
| `.well-known/csaf` | (18 under `.well-known`) | same + modified | **yes**: CSAF advisories |
| `i18n` | 2 (`.gitkeep`) | 45 | no |
| `logs` | 1 (dir only) | 3 | no |

### What fails with plain empty volumes

I applied a variant with an empty `emptyDir` on all six paths and no seeding.
It went into `CrashLoopBackOff` with:

```
warn: Required file index.html is missing (ERROR)
warn: Required file main.js is missing (ERROR)
…
Error: ENOENT: no such file or directory, copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'
error: Exiting due to unsatisfied precondition!
```

So the lab's "interesting" directory is `/juice-shop/data`. The app must create
`juiceshop.sqlite` there, but at boot it also reads `data/static/` from that
same directory. An empty volume hides `data/static`, and the startup copy of
`legal.md` dies with `ENOENT` instead of `EROFS`. The built frontend has the
same problem: the startup precondition check refuses to run without
`index.html` and `main.js`. `ftp` and `.well-known/csaf` would not stop the
process, but hiding them would silently break the `/ftp` and CSAF endpoints.

### Final volume layout

| Volume (`emptyDir`) | Mount | Seeded? | Why |
| --- | --- | --- | --- |
| `data` (64Mi) | `/juice-shop/data` | yes | SQLite DB is created here; `data/static` must survive |
| `ftp` (16Mi) | `/juice-shop/ftp` | yes | `legal.md` copied in; shipped challenge files must stay downloadable |
| `frontend` (128Mi) | `/juice-shop/frontend/dist/frontend` | yes | `index.html` and assets rewritten at startup; SPA must exist |
| `csaf` (4Mi) | `/juice-shop/.well-known/csaf` | yes | `provider-metadata.json` rewritten; other advisories must stay |
| `i18n` (16Mi) | `/juice-shop/i18n` | no | locale files generated at startup into a directory with only `.gitkeep` |
| `logs` (64Mi) | `/juice-shop/logs` | no | access log and audit log; empty in the image |

Seeding uses an initContainer, `seed-writable-dirs`. The image is distroless,
with no `sh` and no `cp`. So the initContainer runs the **same pinned image** and
calls its own node binary:
`fs.cpSync('/juice-shop/data', '/seed/data', {recursive: true})`, and likewise
for `ftp`, the frontend, and CSAF. It reads from its own read-only root and
writes into the emptyDirs before the app container starts. This adds no new
image to trust or scan. The initContainer is itself `restricted`-compliant, with
`readOnlyRootFilesystem: true` and its own requests and limits. Its log:

```
seeded /seed/data from /juice-shop/data: 6 entries
seeded /seed/ftp from /juice-shop/ftp: 10 entries
seeded /seed/frontend from /juice-shop/frontend/dist/frontend: 33 entries
seeded /seed/csaf from /juice-shop/.well-known/csaf: 6 entries
```

The `sizeLimit`s keep a write-path abuse from filling the node's disk. They are
set well above the observed sizes (data ≈ 6 MB, frontend ≈ 38 MB).

### Proof

```
$ kubectl -n juice-shop get pod <pod> -o jsonpath='{.spec.containers[0].securityContext} …ready… restarts'
{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true}
true restarts=0
$ kubectl -n juice-shop get pods
juice-shop-695cd4f584-h4wxk   1/1     Running   0   15s
```

Inside the container, `/` is mounted `overlay ro`, and only the six emptyDirs
are `rw`:

```
WRITE FAIL /juice-shop/test.txt EROFS
WRITE FAIL /tmp/test.txt EROFS
WRITE FAIL /juice-shop/build/x EROFS
WRITE OK   /juice-shop/data/x
WRITE OK   /juice-shop/logs/x
sqlite 258048 bytes; data/static entries 11 ; i18n files 43
```

Through `kubectl -n juice-shop port-forward svc/juice-shop 3000:3000`:

```
/                                             200 9903B
/rest/admin/application-version               200 20B    {"version":"20.0.0"}
/ftp/legal.md                                 200 3047B  (seeded ftp + startup copy)
/assets/i18n/en.json                          200 35472B (generated into the i18n volume)
/.well-known/csaf/provider-metadata.json      200 1023B  (seeded + rewritten)
/rest/products/search?q=apple                 200 921B   (SQLite on the data volume)
```

The final `trivy k8s` scan has **0** HIGH/CRITICAL misconfigurations; KSV-0014
is gone. It was saved as `labs/lab7/results/trivy-k8s.json` for Lab 10.

## Notes

- The k3d binary is in the git-ignored `.venv/lab7/`. The cluster `lab7` is
  still running; remove it with `k3d cluster delete lab7`.
- The bonus `deployment.yaml` replaces the Task 2 one. The Task 2 state is the
  same file without `readOnlyRootFilesystem`, `initContainers`, `volumeMounts`,
  and `volumes`. Its Trivy results are kept in
  `results/trivy-k8s-base.json` and `results/trivy-k8s-hardened-base-summary.txt`.
