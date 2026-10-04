# Lab 7 — Container and Kubernetes Hardening

Tooling: Trivy 0.74.0, kubectl v1.36.1, k3d v5.9.0 (k3s v1.33.0), jq 1.6, Docker on macOS 15.3.1 (arm64).
Target: `bkimminich/juice-shop:v20.0.0` @ `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

## Task 1

### Vulnerability counts and the fix-available split

Scanned at `--severity HIGH,CRITICAL`:

| Severity | Count |
|---|---:|
| CRITICAL | 11 |
| HIGH | 74 |
| **Total (HIGH+CRITICAL)** | **85** |

Of those 85, **77 have a fix** and **8 do not**. `select(.FixedVersion != null)` is the whole point: the
77 fixable ones are this sprint's backlog; the 8 unfixable ones are a compensating-controls decision, not
a ticket.

### Side by side with Lab 4's Grype numbers

| Scan | HIGH+CRITICAL total |
|---|---:|
| Lab 4 — Grype (SBOM) | 99 (14 C + 85 H) |
| Lab 4 — Trivy (image) | 74 (10 C + 64 H) |
| Lab 7 — Trivy (image), today | 85 (11 C + 74 H) |

Two differences, two causes. **Grype > Trivy on the same day** (99 vs 74 in Lab 4) is the finding I
established in Lab 4: Syft catalogues the Node *runtime binary* as a component, so Grype matches Node-runtime
CVEs that Trivy's `node-pkg` analyzer never sees, and Grype expands GHSA↔CVE aliases differently. **Trivy
today > Trivy in Lab 4** (85 vs 74) is pure vulnerability-database drift: the image bytes are identical
(same digest), but two weeks passed (2026-09-21 → 2026-10-04) and the advisory feeds added 11 HIGH/CRITICAL
matches against packages that were already installed. Same artifact, different date, different answer — which
is exactly why a scan is a snapshot, not a property of the image.

### Ten fixable findings, ranked

```console
$ jq -r '["CRITICAL","HIGH"] as $order | [.Results[].Vulnerabilities[]?
   | select(.FixedVersion != null) | {sev:.Severity,id:.VulnerabilityID,pkg:.PkgName,
     now:.InstalledVersion,fix:.FixedVersion}] | sort_by(.sev as $s|$order|index($s))
   | .[:10][] | "\(.sev)\t\(.id)\t\(.pkg) \(.now) -> \(.fix)"' trivy-image.json
```

| Severity | ID | Package: now → fix |
|---|---|---|
| CRITICAL | CVE-2023-46233 | crypto-js 3.3.0 → 4.2.0 |
| CRITICAL | CVE-2026-71851 | crypto-js 3.3.0 → 4.0.0 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken 0.1.0 → 4.2.2 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken 0.4.0 → 4.2.2 |
| CRITICAL | CVE-2019-10744 | lodash 2.4.2 → 4.17.12 |
| CRITICAL | CVE-2026-59873 | tar 4.4.19 → 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar 6.2.1 → 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar 7.5.15 → 7.5.19 |
| HIGH | CVE-2026-14456 | libssl3t64 3.5.5-1~deb13u2 → 3.5.7-1~deb13u2 |
| HIGH | CVE-2026-45447 | libssl3t64 3.5.5-1~deb13u2 → 3.5.6-1~deb13u2 |

### Dockerfile scan (7.3)

`trivy config` on the four-line demo Dockerfile — four findings, one HIGH and three MEDIUM/LOW, so a
`--severity HIGH,CRITICAL` filter would hide three of them and make the file look almost clean:

| Severity | DS id | Finding | What it lets an attacker do |
|---|---|---|---|
| HIGH | **DS-0002** | Last `USER` is `root` | The container runs as root, so any RCE in the app is root *in the container* — one kernel or runtime bug (or a missing `no-new-privileges`) away from a host escape, and root can write anywhere in the image. |
| MEDIUM | **DS-0001** | `FROM node:latest` (`:latest` tag) | The base is non-reproducible: the same `docker build` pulls different bytes over time, so a compromised or simply newer `node:latest` enters the build silently, with no digest to detect the swap. |
| MEDIUM | **DS-0004** | `EXPOSE 22` | Advertises SSH on the container. An SSH daemon inside a container is a second, credential-based entry path that bypasses the orchestrator's access model entirely. |
| LOW | **DS-0026** | No `HEALTHCHECK` | The runtime cannot tell a wedged container from a healthy one, so a crashed or hung process keeps receiving traffic instead of being restarted — availability, and it masks an attacker who has killed the app. |

(The `ADD https://example.com/app.tar /` line is its own bad practice — fetching an unverified remote
archive over the network at build time — though Trivy 0.74 did not raise a separate `DS-*` for it here.)

### The eight with no fix — what I do, and what I tell the manager

The unfixable set is `decompress 4.2.1` (CVE-2026-101894, CVE-2026-53486, both CRITICAL),
`marsdb 0.6.11` (GHSA-5mrr-rgp6-x4gr, CRITICAL), and HIGHs in `lodash.set`, `braces` and
`http-cache-semantics`. "No fix" means no upstream patch exists yet, so waiting is not a plan. What I
actually do: **reduce reachability and blast radius** instead of version-bumping. Confirm whether the
vulnerable code path is even invoked (several of these are transitive deps Juice Shop may never call); if
it is, pin a patched fork or vendor the one function, drop the dependency, or put a control in front of the
exposure (the read-only root filesystem and dropped capabilities from Task 2 and the bonus are exactly this
— they make an unpatched RCE much harder to turn into persistence). Then track each with an owner and a
re-scan cadence so the day a fix lands it becomes a normal ticket. What I tell a manager asking why the
number is not zero: **zero is the wrong target** — it is not achievable while upstream has no patch, and
chasing it hides the real question. The honest metric is "known criticals with an available fix still
unshipped," which *should* trend to zero, versus "known criticals with no fix," which we manage with
compensating controls and accept with eyes open. A dashboard that says 0 is usually a dashboard with the
severity filter turned up, not a secure system.

## Task 2

### Namespace labels

`labs/lab7/k8s/namespace.yaml` enforces `restricted` on all three channels:

```yaml
pod-security.kubernetes.io/enforce: restricted      # reject violating pods at admission
pod-security.kubernetes.io/warn:    restricted      # surface violations to kubectl
pod-security.kubernetes.io/audit:   restricted      # record them in the audit log
```

### The two securityContext blocks

Pod-level:

```yaml
runAsNonRoot: true
runAsUser: 65532           # the image's real user
runAsGroup: 65532
fsGroup: 65532             # group-write on the emptyDir volumes
seccompProfile: { type: RuntimeDefault }
```

Container-level:

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true     # the bonus; not required by restricted
capabilities: { drop: ["ALL"] }
```

### Proof the pod runs, and the user id

```console
$ kubectl -n juice-shop get pods -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-69cd46985d-tt5dw   1/1     Running   0          30s

$ kubectl -n juice-shop exec <pod> -c juice-shop -- /nodejs/bin/node -e 'console.log(process.getuid())'
65532
```

The image is distroless — no `id`, no shell, `node` lives at `/nodejs/bin/node` — so the authoritative
runtime UID comes from the process itself via `process.getuid()`: **65532**, matching `runAsUser`. (Guessing
`1000`, as the lab warns, starts the pod and then fails on the first write.)

### The two Trivy summaries

```console
$ trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL --report=summary
$ trivy k8s --include-namespaces juice-shop  --severity HIGH,CRITICAL --report=summary
```

| | `juice-plain` (unhardened) | `juice-shop` (restricted) |
|---|---|---|
| Vulnerabilities (C/H) | 11 / 74 | 11 / 74 |
| Misconfigurations (C/H) | 0 / **3** | 0 / **1** |
| Secrets (C/H) | 0 / 2 | 0 / 2 |

**The vulnerability counts are identical, and the misconfiguration counts differ** — both halves have the
same root cause: hardening is a property of *how the image is run*, not of *what is in it*. The 11+74 CVEs
live in the image's npm and OS packages and are byte-for-byte the same no matter how the pod is configured;
only a rebuild with upgraded packages changes them. The misconfigurations are read off the pod spec, so they
move: the plain deployment trips `KSV-0014` (root FS not read-only) **plus** `KSV-0118` (default security
context, ×2 — pod and container), while the hardened one has cleared both `KSV-0118` findings and is left
only with `KSV-0014` — which the bonus then closes too. The two secrets (an asymmetric private key baked
into the image) are also image content, so they appear in both.

### One blocked thing, and one voluntary control

**Blocked by `restricted`:** the default container security context. My first instinct was a plain
Deployment with no `securityContext`; `restricted` rejected it at admission, the message naming the exact
fields — `allowPrivilegeEscalation != false`, `unrestricted capabilities`, `runAsNonRoot != true`,
`seccompProfile` unset. Each of those became a line in the spec. That is `KSV-0118` disappearing between the
two scans above.

**Added although `restricted` does not require it:** a **NetworkPolicy** (`networkpolicy.yaml`) that
default-denies both directions for the app pod and re-opens only ingress to :3000 and egress for DNS to
kube-system. The Pod Security Standards say nothing about network reachability — a `restricted` pod can
still talk to anything on the cluster — so default-deny egress is a deliberate addition that limits what a
compromised Juice Shop could reach or exfiltrate to. (The read-only root filesystem in the bonus is a second
such voluntary control.)

## Bonus — read-only root filesystem

`docker run --rm --read-only bkimminich/juice-shop:v20.0.0` crashes:
`Error: EROFS: read-only file system, copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'`,
then `SQLITE_CANTOPEN`. The app writes at several paths under its working directory, so the whole image
cannot be read-only without giving those paths writable volumes.

### `docker diff`, trimmed to what matters

```console
$ docker run -d --name js bkimminich/juice-shop:v20.0.0 && sleep 25 && docker diff js
C /juice-shop/data           A /juice-shop/data/juiceshop.sqlite
C /juice-shop/ftp            A /juice-shop/ftp/legal.md
C /juice-shop/i18n           A /juice-shop/i18n/<44 translation json files>
C /juice-shop/logs
C /juice-shop/frontend/dist  A .../assets/public/videos/owasp_promo.vtt
```

Idle `docker diff` found five write roots. A sixth — `.well-known/csaf/provider-metadata.json` — only
appeared **under enforcement**, as an `EROFS` in the pod log on the first run with
`readOnlyRootFilesystem: true`; the startup write happens later than the 25-second window. Finding it by
reading the crash rather than guessing is the whole exercise.

### Final volume layout and why each entry is there

| Volume (emptyDir) | Mounted at | Seeded? | Why |
|---|---|---|---|
| `data` | `/juice-shop/data` | **yes** | writes `juiceshop.sqlite`, but the dir also ships `data/static/` which `datacreator` reads at startup |
| `dist` | `/juice-shop/frontend/dist` | **yes** | writes `owasp_promo.vtt`, but the dir *is* the served Angular app — empty = blank site |
| `wellknown` | `/juice-shop/.well-known` | **yes** | writes `csaf/provider-metadata.json`, but ships `csaf/` + `security.txt` |
| `ftp` | `/juice-shop/ftp` | no | only receives `legal.md` at startup; an empty dir is fine |
| `logs` | `/juice-shop/logs` | no | runtime logs, ships nothing |
| `i18n` | `/juice-shop/i18n` | no | ships only `.gitkeep`; the 44 translations are generated |
| `tmp` | `/tmp` | no | scratch |

### The directory that could not be an empty volume, and the fix

Three of them, actually — `data`, `frontend/dist` and `.well-known` each ship files that are read or served
at runtime, so mounting an **empty** volume over any of them hides those files and the app either exits
(`data/static/legal.md` not found) or serves a blank page (`frontend/dist`). The lab flagged "one"; read-only
enforcement surfaced three. The fix is an **initContainer** that seeds the volumes before the main container
starts. Because the image is distroless (no `cp`, no shell), the seeding is done with Node:

```yaml
initContainers:
  - name: seed-writable-dirs
    image: <same digest>
    command: ["/nodejs/bin/node", "-e", "
      const fs=require('fs');
      fs.cpSync('/juice-shop/data','/seed/data',{recursive:true});
      fs.cpSync('/juice-shop/frontend/dist','/seed/dist',{recursive:true});
      fs.cpSync('/juice-shop/.well-known','/seed/wellknown',{recursive:true});"]
    volumeMounts:          # mounted at /seed/* so the image originals are still visible to copy FROM
      - { name: data, mountPath: /seed/data }
      - { name: dist, mountPath: /seed/dist }
      - { name: wellknown, mountPath: /seed/wellknown }
```

The initContainer mounts the volumes at `/seed/*`, not at `/juice-shop/*`, precisely so the image's own
files are still visible to copy *from*; the main container then mounts the now-populated volumes at the real
paths.

### Proof

```console
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-69cd46985d-tt5dw   1/1     Running   0          30s

$ kubectl -n juice-shop get pod <pod> -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}'
true

$ kubectl -n juice-shop port-forward deploy/juice-shop 3000:3000 &
$ curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:3000/
HTTP 200
$ curl -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}
$ curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:3000/main.js   # seeded frontend serves
HTTP 200
```

Pod Ready with `readOnlyRootFilesystem: true`, serving 200 on the app root, the version endpoint, and
`main.js` — the last confirming the seeded `frontend/dist` volume actually serves the UI rather than a blank
page.
