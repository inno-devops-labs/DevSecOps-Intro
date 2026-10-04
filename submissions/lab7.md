# Lab 7 — Container and Kubernetes Hardening

**Environment**
- Host: Windows 11, Docker Desktop 29.7.2 (VM memory 4 GiB), Git Bash.
- Tools: `trivy 0.74.0` (vulnerability DB updated 2026-10-04 08:52 UTC), `kubectl` client v1.36.1, `k3d v5.9.0`, cluster `lab7` on `rancher/k3s:v1.33.0-k3s1`.
- Image: `bkimminich/juice-shop:v20.0.0`, digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`. This is the same digest as in Lab 4. `Config.User` is `65532`.

**Deviations from the lab commands.** There are two, and both are caused by Windows rather than by the lab:
1. **`trivy k8s` ran from the Linux image `aquasec/trivy:0.74.0`.** I mounted the kubeconfig and passed `--disable-node-collector`. The native Windows binary returned vulnerability and secret results for the live cluster, but its **misconfiguration report was empty** (`{"ClusterName":"k3d-lab7"}`), even with the checks bundle loaded. I confirmed the checks themselves work on this host: `trivy config` on the same manifests found 17 failures for an unhardened Deployment and 2 for mine. The containerised Trivy produced the same 17 and 2 against the live cluster, so that is the version used below. Lab 4 needed the same kind of workaround for Syft.
2. **`MSYS_NO_PATHCONV=1` for `kubectl exec … -- /nodejs/bin/node`.** Without it, Git Bash rewrites the container path into `C:/Program Files/Git/nodejs/bin/node`.

## Task 1

### 7.1 Image vulnerabilities

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

| Severity | Count | Fix available | No fix |
|---|---|---|---|
| CRITICAL | 11 | 8 | 3 |
| HIGH | 74 | 69 | 5 |
| **HIGH + CRITICAL** | **85** | **77 (91 %)** | **8** |

Of the 85, 4 are in Debian OS packages and 81 in `node-pkg` (npm). A second run without the severity filter adds MEDIUM 95 and LOW 34, for **214** in total.

**Against Lab 4.** Same image digest. Lab 4's scans were on 2026-09-20; this one is on 2026-10-04.

| | CRITICAL | HIGH | Total (all severities) |
|---|---|---|---|
| Grype 0.119.0, Lab 4 (DB 2026-09-20, from the SBOM) | 14 | 85 | 183 |
| Trivy 0.74.0, Lab 4 (DB 2026-09-20) | 10 | 64 | 173 |
| **Trivy 0.74.0, now (DB 2026-10-04)** | **11** | **74** | **214** |

The difference between Grype and Trivy is the one Lab 4 traced:
- Grype also matches the Node.js runtime binary that Syft catalogued (15 extra findings).
- Trivy carries a few NSWG-only npm advisories that Grype has no identifier for.

The difference between Trivy then and Trivy now has nothing to do with the image. The bytes are identical; two weeks of newly published advisories added **+41** findings. A vulnerability count describes the advisory database as much as the artifact.

### 7.2 Top ten fixable findings

```text
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

All eight fixable CRITICALs come before the first HIGH. Several rows share a fix:
- `tar` appears three times, as three copies vendored at different versions. One dependency bump to `tar@7.5.19` clears all three.
- The two `libssl3t64` rows go away with one `apt` upgrade of the base image.

### 7.3 The Dockerfile

```bash
trivy config /tmp/df-demo     # Dockerfile: FROM node:latest / USER root / EXPOSE 22 / ADD https://...
# Tests: 27 (SUCCESSES: 23, FAILURES: 4)  — LOW: 1, MEDIUM: 2, HIGH: 1
```

| ID | Severity | Line | What it lets an attacker do |
|---|---|---|---|
| `DS-0002` | **HIGH** | `USER root` | Any code execution in the app runs as UID 0 in the container. The attacker can overwrite binaries and install tooling. One runtime or kernel bug, or a mounted socket, away from the host. |
| `DS-0001` | MEDIUM | `FROM node:latest` | The build pulls whatever `latest` points to on the day. A compromised or silently changed upstream tag goes straight into the image, and no one can say which base actually shipped. |
| `DS-0004` | MEDIUM | `EXPOSE 22` | Advertises SSH, which implies an `sshd` inside the container. That is another authentication surface to brute-force, and a persistent way in that bypasses `kubectl exec` and its audit log. |
| `DS-0026` | LOW | (no `HEALTHCHECK`) | Not an entry point by itself. A hung or tampered process keeps receiving traffic, and nothing restarts it. |

Note what was **not** flagged: `ADD https://example.com/app.tar /`. That line fetches remote content at build time with no checksum, which is a supply-chain risk. Trivy's ADD check passes it because a `.tar` source looks like the legitimate "ADD to extract an archive" case, but `ADD` never extracts remote URLs. As the lab warns, `--severity HIGH,CRITICAL` would have left only `DS-0002` visible.

### Vulnerabilities with no fix

Eight HIGH/CRITICAL findings have no fixed version. They include CRITICAL `GHSA-5mrr-rgp6-x4gr` (command injection in `marsdb 0.6.11`) and two CRITICALs in `decompress 4.2.1` (path traversal and arbitrary file write).

For each one I would:
1. Check whether the vulnerable code is actually reachable at runtime. If it is not, record that in a VEX statement.
2. Replace the dependency where it is abandoned. `marsdb` has had no release in years.
3. Otherwise accept the risk for a fixed period, with an owner and an expiry date, behind compensating controls.

Task 2 and the bonus are those compensating controls: non-root, no capabilities, seccomp, a read-only root filesystem and a default-deny NetworkPolicy. A `decompress` path traversal can then write only into six small emptyDirs. A `marsdb` command injection runs as UID 65532 with no outbound network.

What I would tell a manager: the count measures advisories published against the code we ship. It grew by 41 in two weeks without us changing a byte, so "zero" is not a state we can reach or hold. The number to track is how many **fixable** criticals are past their deadline (8 today, all with patches available), plus whether every unfixable one has an owner and a mitigation.

## Task 2

Manifests are in `labs/lab7/k8s/`:
- `namespace.yaml`, `serviceaccount.yaml`, `deployment.yaml`, `networkpolicy.yaml`
- `service.yaml`, which the NetworkPolicy's ingress rule and the port-forward use.

### 7.4 Namespace labels and security contexts

```yaml
# namespace.yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/enforce-version: v1.33
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/warn-version: v1.33
  pod-security.kubernetes.io/audit: restricted
  pod-security.kubernetes.io/audit-version: v1.33
```

The `-version` labels pin what "restricted" means. Otherwise a cluster upgrade could silently change the profile.

```yaml
# deployment.yaml: pod securityContext
securityContext:
  runAsNonRoot: true
  runAsUser: 65532        # docker inspect ... --format '{{.Config.User}}' -> 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

# deployment.yaml: container securityContext
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true   # added in the Bonus; not required by restricted
  capabilities:
    drop: ["ALL"]
```

The Deployment also has the following:
- **Service account:** a dedicated `ServiceAccount`, with `automountServiceAccountToken: false` on both the ServiceAccount and the pod spec.
- **Resources:** requests of `250m` CPU and `256Mi` memory, limits of `1` CPU and `768Mi`.
- **Probes:** readiness and liveness on `/rest/admin/application-version`.
- **Image:** pinned by digest, `bkimminich/juice-shop@sha256:fd58bdc9…418b0`.

### 7.5 Running, and as whom

```text
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-674df97d49-46rbq   1/1     Running   0          14s
```

The image is distroless, so there is no `id` binary (`exec: "id": executable file not found`). I asked the container's own Node runtime instead:

```text
$ kubectl -n juice-shop exec <pod> -- /nodejs/bin/node -e 'console.log("uid="+process.getuid()+" gid="+process.getgid())'
uid=65532 gid=65532 groups=65532

$ kubectl -n juice-shop exec <pod> -- /nodejs/bin/node -e '...read /proc/1/status...'
Uid:        65532 65532 65532 65532
CapPrm:     0000000000000000
CapEff:     0000000000000000
NoNewPrivs: 1
Seccomp:    2              # filter mode = RuntimeDefault
```

From the same pod I also checked:
- **Token:** the service-account token is not mounted (`/var/run/secrets/kubernetes.io/serviceaccount/token` does not exist).
- **NetworkPolicy, egress:** DNS resolves (`example.com -> 104.20.23.154`), but `https://example.com` fails with `ECONNREFUSED`.
- **NetworkPolicy, ingress:** a request from the `juice-plain` pod to `juice-shop.juice-shop.svc:3000` also fails with `ECONNREFUSED`, while the plain app answers itself with 200. k3s enforces NetworkPolicy with its embedded kube-router.
- **Port-forward still works.** It enters the pod through the kubelet, not over the pod network, so NetworkPolicy does not apply to it. It is an operator path, not a user path.

### 7.6 Trivy on the running workload: plain vs restricted

```bash
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL --report=summary
trivy k8s --include-namespaces juice-shop  --severity HIGH,CRITICAL --report=summary
```

| Namespace / resource | Vuln C | Vuln H | Misconfig C | Misconfig H | Secrets H |
|---|---|---|---|---|---|
| `juice-plain` / `Deployment/juice` | 11 | 74 | – | **3** | 2 |
| `juice-shop` / `Deployment/juice-shop` (Task 2) | 11 | 74 | – | **1** | 2 |
| `juice-shop` after the Bonus | 22 | 148 | – | **0** | 4 |

Across all severities, the plain Deployment fails **17** checks:
- HIGH `KSV-0014` (root filesystem not read-only), plus `KSV-0118` (default security context) twice.
- MEDIUM `KSV-0001` (can escalate privileges), `KSV-0012` (runs as root), `KSV-0104` (seccomp disabled) and `KSV-0125` (untrusted registry).
- 10 LOW checks for capabilities, limits and requests, UID/GID ≤ 10000, and seccomp.

The hardened Deployment fails 2: `KSV-0014`, which the Bonus fixes, and `KSV-0125`. After the Bonus, only `KSV-0125` remains, once per container. It needs a trusted-registry list configured; Docker Hub is not on Trivy's default list.

**Why one half differs and the other does not.** Misconfigurations are read from the workload's pod spec. Hardening is a pod-spec change, so that column moved from 3 HIGH (17 failures in total) to 1 and then 0. Vulnerabilities and secrets are read from the image layers. Both Deployments run the identical image, so that column cannot move: only a rebuild changes it. Hardening limits what an exploit can do, not whether the vulnerable package is present.

One detail makes the same point from the other side. After the Bonus, the vulnerability count *doubled* to 22/148 and the secrets count to 4. The initContainer runs the same image, and Trivy counts per container reference. No new vulnerability appeared; the number moved for a reason unrelated to risk. Trivy's "Runs as root" (`KSV-0012`) on the plain Deployment is also a manifest finding: that pod actually runs as 65532, because the image says so, but the manifest does not declare it.

### What restricted blocked, and what I added anyway

**Blocked.** A plain pod, which is what `kubectl create deployment` generates, is rejected at admission:

```text
$ kubectl -n juice-shop run plain --image=bkimminich/juice-shop:v20.0.0 --dry-run=server
Error from server (Forbidden): pods "plain" is forbidden: violates PodSecurity "restricted:v1.33":
allowPrivilegeEscalation != false (...), unrestricted capabilities (... must set securityContext.capabilities.drop=["ALL"]),
runAsNonRoot != true (pod or container "plain" must set securityContext.runAsNonRoot=true),
seccompProfile (... must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

The change that surprised me was `runAsNonRoot`. The image already runs as 65532, but admission cannot look inside an image, so the pod spec must say it explicitly. I also set `runAsUser: 65532` to match the image rather than guessing 1000.

**Added though not required:**
- The **NetworkPolicy** (default deny, DNS-only egress, ingress only from Traefik on 3000), proven above with `ECONNREFUSED` in both directions.
- **No service-account token.** The restricted profile allows both, but this app needs neither the network nor the Kubernetes API.
- The read-only root filesystem below.

## Bonus — A read-only root filesystem

```text
$ docker run --rm --read-only bkimminich/juice-shop:v20.0.0
... original: [Error: SQLITE_CANTOPEN: unable to open database file] { errno: 14, code: 'SQLITE_CANTOPEN' }
```

### Where it writes: `docker diff` (68 lines, trimmed)

```text
C /juice-shop/data
A /juice-shop/data/juiceshop.sqlite                         <- database created at startup
C /juice-shop/ftp
A /juice-shop/ftp/legal.md                                   <- copied from data/static/legal.md
C /juice-shop/logs
A /juice-shop/logs/access.log.2026-10-04
A /juice-shop/logs/audit.json
C /juice-shop/i18n
A /juice-shop/i18n/*.json                                    <- 43 translation files generated
C /juice-shop/.well-known/csaf/provider-metadata.json        <- rewritten
C /juice-shop/frontend/dist/frontend/index.html              <- rewritten (title, theme)
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
```

What the image already ships in each of those directories:

| Directory | Files shipped in the image |
|---|---|
| `data/` | 214 files (5.7 MB), including `data/static/` |
| `ftp/` | 13 files |
| `.well-known/` | 13 files |
| `frontend/dist/frontend/` | 752 files (35.7 MB) |
| `logs/` | none |
| `i18n/` | only `.gitkeep` |

### Volume layout

| Volume (`emptyDir`) | Mounted at | How it starts | Why |
|---|---|---|---|
| `data` | `/juice-shop/data` | seeded | The SQLite DB is created here, next to `data/static/`, which the app reads at startup. |
| `ftp` | `/juice-shop/ftp` | seeded | The app copies `legal.md` in at startup. The 13 shipped files are what `/ftp` serves. |
| `well-known` | `/juice-shop/.well-known` | seeded | `csaf/provider-metadata.json` is rewritten. `security.txt` and the CSAF files must stay. |
| `frontend` | `/juice-shop/frontend/dist/frontend` | seeded | `index.html` is rewritten and images are copied in. The 752 build files *are* the UI. |
| `logs` | `/juice-shop/logs` | empty | Access and audit logs. Nothing is shipped there. |
| `i18n` | `/juice-shop/i18n` | empty | Translations are generated at startup. Only a `.gitkeep` is shipped. |

Every volume has a `sizeLimit`, so a write-heavy attack fills a small volume rather than the node's disk. Nothing else is writable: `/tmp` is not in the diff, so it stays read-only.

### The directory an empty volume cannot replace: `data/`

I tested this with docker `--read-only` and empty tmpfs mounts before writing any YAML:

```text
logs+i18n writable only    -> EROFS copyfile data/static/legal.md -> ftp/legal.md ; SQLITE_CANTOPEN
+ data/ as an EMPTY volume -> ENOENT copyfile '/juice-shop/data/static/legal.md' ...
                              error: Could not open file: "/juice-shop/data/static/securityQuestions.yml"
                              TypeError: questions.map is not a function   -> exits
```

The SQLite file must be created inside `data/`. But `data/` also holds `data/static/`, the seed users, challenges and security questions, and an empty volume over it hides all of that. `ftp/`, `.well-known/` and the frontend build have the same shape: shipped content plus runtime writes.

**The fix.** An initContainer runs the same digest-pinned image and copies the image's own content into the emptyDirs before the app starts. The image is distroless, with no shell and no `cp`, so the copy uses its Node runtime:

```yaml
initContainers:
  - name: seed-writable-dirs
    image: bkimminich/juice-shop@sha256:fd58bdc9...418b0
    command: ["/nodejs/bin/node", "-e", "<fs.cpSync for data, ftp, .well-known, frontend/dist/frontend -> /seed/*>"]
    securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
```

```text
$ kubectl -n juice-shop logs <pod> -c seed-writable-dirs
seeded /seed/data from /juice-shop/data
seeded /seed/ftp from /juice-shop/ftp
seeded /seed/well-known from /juice-shop/.well-known
seeded /seed/frontend from /juice-shop/frontend/dist/frontend
```

The init container is itself read-only and admitted under `restricted`; `fsGroup: 65532` makes the emptyDirs writable for it. The cost is about 43 MB copied on every pod start, and the database lives only as long as the pod, as it did in the container layer before. The durable fix belongs in the image: write state to one dedicated directory and keep shipped assets elsewhere.

### Proof

```text
seed-writable-dirs: readOnlyRootFilesystem=true
juice-shop:         readOnlyRootFilesystem=true
Ready=True restarts=0

$ kubectl -n juice-shop port-forward svc/juice-shop 3017:3000
GET /                      -> HTTP 200
GET /rest/admin/application-version -> {"version":"20.0.0"}
GET /ftp/legal.md          -> HTTP 200     (seeded ftp/ + the runtime copy)
GET /api/Products          -> HTTP 200     (SQLite DB in the data/ volume)

# inside the pod
WRITE FAIL  /juice-shop/test.txt EROFS
WRITE FAIL  /tmp/test.txt        EROFS
WRITE OK    /juice-shop/logs/test.txt
WRITE OK    /juice-shop/data/test.txt
/ overlay ro,...            # root filesystem mounted read-only
/juice-shop/data ext4 rw    # ...and the six emptyDirs read-write
```

After the Bonus, Trivy's HIGH misconfiguration `KSV-0014` is gone (table in 7.6). `labs/lab7/results/trivy-k8s.json`, the file Lab 10 imports, was generated from this final state.
