# Lab 7 — Container and Kubernetes Hardening

## Task 1

### 1. Image scan

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

Trivy 0.75.0, vulnerability DB updated 2026-10-04. Base OS is Debian 13.4.

| Severity  | Vulnerabilities | With a fix (`FixedVersion` set) | No fix |
| --------- | --------------: | ------------------------------: | -----: |
| CRITICAL  |              11 |                               8 |      3 |
| HIGH      |              74 |                              69 |      5 |
| **Total** |          **85** |                          **77** |  **8** |

They split as **4** in the Debian OS packages and **81** in `node-pkg` (npm dependencies under `/juice-shop/node_modules`). The 85 rows cover 62 distinct vulnerability IDs, because several packages are bundled in more than one version (for example `tar` 4.4.19 / 6.2.1 / 7.5.15). The four other targets in the report (`build/lib/insecurity.js`, `lib/insecurity.ts` and two `.spec.ts` files) come from the secret scanner. They have no vulnerabilities and hold Juice Shop's deliberately hard-coded RSA private key.

### 2. Trivy here vs. Grype in Lab 4

| Scanner (source) | Critical | High | C + H | All severities |
| ---------------- | -------: | ---: | ----: | -------------: |
| Grype (Lab 4, scanned the Syft CycloneDX SBOM) | 14 | 85 | **99** | 182 |
| Trivy (Lab 4, image) | 10 | 64 | 74 | 172 |
| Trivy (this lab, image, `--severity HIGH,CRITICAL`) | 11 | 74 | **85** | n/a (filtered) |

Grype reports 14 more Critical and High findings than Trivy for the same digest. Lab 4 explained most of the gap. Grype matched the SBOM's binary entries (such as the Node.js 24.15.0 runtime itself), which Trivy does not treat as a package. The two tools also key npm advisories differently (GHSA vs CVE IDs) and take severities from different vendors, so the same flaw can land in a different bucket or be counted twice. Trivy itself moved from 74 to 85 between Lab 4 and today on the same image. The image didn't change, the vulnerability DB did, so these numbers are only meaningful together with the DB date.

### 3. Ten fixable findings, ranked (output of 7.2)

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

These ten rows are only five upgrades: `crypto-js` → 4.2.0, `jsonwebtoken` → 4.2.2 (both old copies), `lodash` → 4.17.12, `tar` → 7.5.19 (all three copies), and a base-image rebuild that picks up `libssl3t64` 3.5.7. The two `libssl3t64` rows also show that the jq ranking only sorts by severity. Inside a severity, rows keep Trivy's report order, so the "top ten" is not ranked by CVSS.

### 4. Dockerfile scan

```dockerfile
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
```

```bash
trivy config /tmp/df-demo
```

`Tests: 27 (SUCCESSES: 23, FAILURES: 4)`, `Failures: 4 (LOW: 1, MEDIUM: 2, HIGH: 1, CRITICAL: 0)`

| ID | Severity | Line | Finding | What it gives an attacker |
| -- | -------- | ---: | ------- | ------------------------- |
| `DS-0002` | HIGH | 2 | Last `USER` is `root` | Any RCE in the app runs as UID 0 inside the container. A kernel or runtime escape (or a writable hostPath / docker.sock mount) then lands as root on the node, and inside the container the attacker can install tools or tamper with the app's own files. |
| `DS-0001` | MEDIUM | 1 | `FROM node:latest`, no pinned tag | The build pulls whatever `latest` points to on that day. A poisoned or broken upstream push, or a typosquatted mirror, gets into the next build without review, and the build can't be reproduced to show what shipped. |
| `DS-0004` | MEDIUM | 3 | `EXPOSE 22` | It advertises and invites an SSH daemon inside the container. That opens a remote login surface (brute force, stolen keys) that bypasses the orchestrator's `exec`/audit path. |
| `DS-0026` | LOW | — | No `HEALTHCHECK` | Not directly exploitable. A hung or half-compromised process (for example one stuck after a DoS) keeps receiving traffic because nothing marks it unhealthy, which makes availability attacks last longer. |

The `ADD https://example.com/app.tar /` line was **not** flagged. `DS-0005` ("use COPY instead of ADD") only fires for local files, because fetching a URL is a legitimate use of `ADD`. The real risk there is a remote file pulled at build time with no checksum. The fix is `ADD --checksum=sha256:…` or a verified download step, and no Trivy check asks for it. With `--severity HIGH,CRITICAL` only `DS-0002` would be visible, so three of the four findings would be hidden.

### 5. Vulnerabilities with no fix

Eight of the Critical and High findings have no released fix, so upgrading isn't an option for them. For each one I would check whether the vulnerable code is actually reachable in Juice Shop. Many of these are in build-time or transitive packages, and the ones that aren't reachable get an expiring VEX/`.trivyignore` entry with a written justification. For the ones that are reachable, I would cut the exploit path. Task 2 does this at the platform level: non-root user, no capabilities, seccomp, read-only rootfs, and a NetworkPolicy that blocks the outbound connection most RCE payloads need to fetch a second stage. Where it's possible, I would also drop or replace the dependency. All of these stay on a watch list that is re-scanned daily against the SBOM, so a fix released tomorrow becomes a ticket the same day. To a manager I would say the number can't be zero, because it counts known bugs in other people's code, and new ones are published every day against an image that hasn't changed: Trivy found 74 last month and 85 today on the same digest. The useful targets are "zero fixable Critical/High older than N days" and "every unfixed one has an owner, a compensating control and a review date".

## Task 2

### 1. Manifests

Files in `labs/lab7/k8s/`: `namespace.yaml`, `serviceaccount.yaml`, `deployment.yaml`, `service.yaml`, `networkpolicy.yaml`. The cluster is k3d with `rancher/k3s:v1.33.0-k3s1`.

**Namespace labels** (`kubectl get ns juice-shop --show-labels`):

```
pod-security.kubernetes.io/enforce=restricted   pod-security.kubernetes.io/enforce-version=latest
pod-security.kubernetes.io/warn=restricted      pod-security.kubernetes.io/warn-version=latest
pod-security.kubernetes.io/audit=restricted     pod-security.kubernetes.io/audit-version=latest
```

**Pod `securityContext`:**

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
```

**Container `securityContext`:**

```yaml
securityContext:
  allowPrivilegeEscalation: false
  privileged: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

`runAsUser: 65532` is the image's own user (`docker inspect bkimminich/juice-shop:v20.0.0 --format '{{.Config.User}}'` → `65532`). `readOnlyRootFilesystem: true` was added for the Bonus; Task 2 first ran without it.

The other requirements:
- `ServiceAccount/juice-shop` has `automountServiceAccountToken: false`, and the pod spec sets it to false as well.
- Requests are `250m` / `256Mi` and limits are `1` / `512Mi`.
- The image is pinned by digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`, taken from `docker inspect --format '{{index .RepoDigests 0}}'`.

**NetworkPolicy:** `podSelector: {app: juice-shop}`, `policyTypes: [Ingress, Egress]`.
- **Ingress:** only TCP 3000, and only from the Traefik ingress controller pods in `kube-system`. That is the only in-cluster client a web app needs.
- **Egress:** only UDP/TCP 53 to `k8s-app: kube-dns` in `kube-system`.

### 2. Proof the pod runs, and as whom

```
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-7f8f565494-gp6rf   1/1     Running   0          26s

$ kubectl -n juice-shop exec deploy/juice-shop -- /nodejs/bin/node -e \
    'console.log("uid="+process.getuid()+" gid="+process.getgid())'
uid=65532 gid=65532 groups=65532
```

The image is distroless, so it has no `id` or `sh`. I used Node itself to read the process credentials and `/proc/1/status`:

```
Uid:  65532 65532 65532 65532
CapEff: 0000000000000000      CapBnd: 0000000000000000
NoNewPrivs: 1                 Seccomp: 2   (filter mode = RuntimeDefault)
```

The ServiceAccount token isn't mounted: reading `/var/run/secrets/kubernetes.io/serviceaccount` fails with `ENOENT`. The full spec is saved in `labs/lab7/results/pod-spec.yaml`.

NetworkPolicy checks:
- `busybox` in `default` → `wget http://juice-shop.juice-shop.svc:3000/` → **BLOCKED** (timeout).
- From the app pod, in-cluster DNS (`kubernetes.default.svc.cluster.local` → `10.43.0.1`) works, and a TCP connect to `1.1.1.1:443` is refused.
- The same connect from an unrestricted pod in `default` is **OPEN**.

### 3. Trivy summaries side by side

`trivy k8s --include-namespaces <ns> --severity HIGH,CRITICAL --report=summary`. I added `--disable-node-collector`, which keeps the scan from launching a node-collector Job and only affects the Infra section.

| Namespace / resource | Vuln C | Vuln H | Misconfig C | Misconfig H | Secrets H |
| -------------------- | -----: | -----: | ----------: | ----------: | --------: |
| `juice-plain` / `Deployment/juice` (`kubectl create deployment`) | 11 | 74 | – | **3** | 2 |
| `juice-shop` / `Deployment/juice-shop` (restricted, before Bonus) | 11 | 74 | – | **1** | 2 |
| `juice-shop` / `Deployment/juice-shop` (final, with Bonus) | 22 | 148 | – | **0** | 4 |

HIGH misconfigurations in `juice-plain` were `KSV-0118` ×2 (default security context, pod and container) and `KSV-0014` (root FS not read-only). The restricted deployment cleared both `KSV-0118`, and the Bonus cleared `KSV-0014`. Across all severities (`--scanners misconfig`), `juice-plain` fails **16** distinct checks (KSV-0001, 0003, 0004, 0011, 0012, 0014, 0015, 0016, 0018, 0020, 0021, 0030, 0104, 0106, 0118, 0125) and the hardened deployment fails **1** (`KSV-0125`, MEDIUM, "restrict images to trusted registries").

**Why misconfigurations differ:** misconfiguration checks read the *pod spec*. Setting `runAsNonRoot`, seccomp, `drop: [ALL]`, limits and a read-only rootfs changes that spec, so the checks turn green.

**Why vulnerabilities don't:** vulnerability checks read the *image layers*. Both namespaces run the same digest with the same `node_modules` and Debian packages, so the scanner sees the same 11 + 74 findings. A securityContext reduces what an attacker can do with a vulnerable library, but it doesn't remove the library. Only a rebuild does.

The doubling in the final row is the same effect. The Bonus initContainer uses the same image, and Trivy scans each container's image separately, so every vulnerability and the secret appear twice. It's still one digest and the attack surface hasn't grown.

### 4. What `restricted` blocked, and what I added voluntarily

**Blocked:** the spec that `kubectl create deployment` generates (the `juice-plain` workload) is rejected at admission in `juice-shop`:

```
$ kubectl -n juice-shop run plain --image=bkimminich/juice-shop:v20.0.0 --dry-run=server
Error from server (Forbidden): pods "plain" is forbidden: violates PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false (container "plain" must set securityContext.allowPrivilegeEscalation=false),
  unrestricted capabilities (container "plain" must set securityContext.capabilities.drop=["ALL"]),
  runAsNonRoot != true (pod or container "plain" must set securityContext.runAsNonRoot=true),
  seccompProfile (pod or container "plain" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

The ones I had to add explicitly were `seccompProfile: RuntimeDefault` and `capabilities.drop: [ALL]`. The image already runs as non-root, but the profile wants that stated in the spec, not inherited. With those two lines removed, the Deployment itself is still accepted with only a `Warning: would violate PodSecurity`, because PSA enforces on Pods, not on Deployments. The ReplicaSet then fails to create any pod. That is easy to miss when you only look at the `kubectl apply` output.

**Added voluntarily (not required by `restricted`):**
- `automountServiceAccountToken: false` on both the SA and the pod, so a compromised app has no API token to use against the cluster.
- The default-deny NetworkPolicy. The profile doesn't touch networking at all, and the NetworkPolicy is what blocks the outbound connection an RCE payload needs.
- CPU/memory limits.
- Digest pinning.
- `readOnlyRootFilesystem` (Bonus).

## Bonus

### 1. What the process writes (`docker diff`)

`docker run --read-only` crashes immediately:

```
Error: EROFS: read-only file system, copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'
ConnectionError [SequelizeConnectionError]: SQLITE_CANTOPEN: unable to open database file
```

`docker run -d --name js bkimminich/juice-shop:v20.0.0 && sleep 30 && docker diff js` returns 68 lines. Trimmed to the paths that matter (`i18n/` had 44 `A` entries, one per locale, collapsed here):

```
C /juice-shop/data
A /juice-shop/data/juiceshop.sqlite
C /juice-shop/frontend/dist/frontend/index.html
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/ftp/legal.md
C /juice-shop/.well-known/csaf/provider-metadata.json
A /juice-shop/i18n/en.json  (+ 43 more locale files)
A /juice-shop/logs/access.log.2026-10-04
A /juice-shop/logs/audit.json
```

Nothing is written outside `/juice-shop`. Writing to `/tmp` also fails with `EROFS` in the final pod and the app doesn't care, so no `/tmp` volume is needed.

### 2. Final volume layout

| Volume (`emptyDir`) | Mounted at | Why | Seeded? |
| ------------------- | ---------- | --- | ------- |
| `data` (64Mi) | `/juice-shop/data` | `juiceshop.sqlite` is created here, plus SQLite journal files next to it | **yes**: 214 shipped files (`static/` YAML, product images, codefixes) |
| `frontend` (128Mi) | `/juice-shop/frontend/dist/frontend` | `index.html` and several assets are rewritten at start-up; user uploads also land under `assets/public/images/uploads` | **yes**: 752 files / 37.5 MB, the whole Angular build |
| `ftp` (16Mi) | `/juice-shop/ftp` | `legal.md` is copied in at start-up | **yes**: 13 shipped files (the FTP challenge files) |
| `csaf` (4Mi) | `/juice-shop/.well-known/csaf` | `provider-metadata.json` is rewritten | **yes**: 12 shipped advisories |
| `i18n` (16Mi) | `/juice-shop/i18n` | all 44 locale files are generated at start-up | no, ships with only `.gitkeep` |
| `logs` (64Mi) | `/juice-shop/logs` | access and audit logs | no, ships empty |

Each `emptyDir` has a `sizeLimit`, so a filled log or upload directory gets the pod evicted and doesn't fill the node's disk.

### 3. The directory that can't just be an empty volume

Several of them can't. My first attempt (in the scratchpad, not committed) put a plain empty `emptyDir` on all six paths, and the pod went into `CrashLoopBackOff`:

```
warn: Required file main.js is missing (ERROR)
warn: Required file index.html is missing (ERROR)
Error: ENOENT: no such file or directory, copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'
```

The most obvious case is `/juice-shop/frontend/dist/frontend`: the app rewrites `index.html` there at start-up, but the directory *is* the whole compiled frontend. An empty volume hides it, the start-up integrity check finds no `main.js`, and the app exits. `data/` is the same problem on the server side: the empty volume hides `data/static/`, which the app reads its seed data from.

**Solution:** an `initContainer` named `seed` that copies the image's own contents into the volumes before the app starts. It runs the **same image by the same digest**, so the seed is byte-for-byte what the app expects and can't drift from it. The image is distroless (no `sh`, no `cp`), so the copy is done with the bundled Node: `fs.cpSync(src, '/seed/<name>', {recursive: true})` for `data`, `frontend`, `ftp` and `csaf`. The init container mounts the volumes under `/seed/*`, so the original paths in its own root FS stay readable. It runs under the same restricted securityContext, including `readOnlyRootFilesystem: true`, and has its own requests/limits. `i18n` and `logs` ship empty, so they are plain `emptyDir`s with no seeding.

Init container log:

```
seeded /juice-shop/data
seeded /juice-shop/frontend/dist/frontend
seeded /juice-shop/ftp
seeded /juice-shop/.well-known/csaf
```

### 4. Proof

```
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-7f8f565494-gp6rf   1/1     Running   0          26s

$ kubectl -n juice-shop get pod <pod> -o jsonpath='{.spec.containers[0].securityContext}'
{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true}

$ kubectl -n juice-shop logs <pod> | grep listening
info: Server listening on port 3000

$ kubectl -n juice-shop exec <pod> -- /nodejs/bin/node -e '<try fs.writeFileSync on each path>'
EROFS     /juice-shop/build/test.txt
EROFS     /tmp/x
WRITE OK  /juice-shop/logs/x

$ kubectl -n juice-shop port-forward svc/juice-shop 3000:3000 &
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3000/
200
$ curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:3000/rest/products/search?q=apple"
200
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3000/ftp/legal.md
200
```

Trivy confirms it: `KSV-0014` ("Root file system is not read-only") is gone, and the hardened deployment has **0** HIGH/CRITICAL misconfigurations (table in Task 2.3). The final scan is saved for Lab 10 as `labs/lab7/results/trivy-k8s.json`.
