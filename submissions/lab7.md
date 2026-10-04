# Lab 7 — Container and Kubernetes Hardening

## Task 1

### 7.1 Image vulnerabilities

`trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL` (Trivy 0.74.0, DB refreshed 2026-10-04), image digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

| Severity | Findings | With a fix | Without a fix |
| --- | ---: | ---: | ---: |
| CRITICAL | 11 | 8 | 3 |
| HIGH | 74 | 69 | 5 |
| **Total** | **85** | **77** | **8** |

85 findings (62 unique IDs, the rest are the same CVE in several copies of a package): 4 in Debian 13.4 OS packages, 81 in Node.js packages. **77 of 85 (91%) have a fixed version.**

### Comparison with Lab 4 (Grype)

| | CRITICAL | HIGH | CRITICAL + HIGH | All severities |
| --- | ---: | ---: | ---: | ---: |
| Grype, Lab 4 (from the SBOM) | 14 | 85 | **99** | 183 |
| Trivy, Lab 4 (DB of 2026-09-21) | 10 | 64 | 74 | 173 |
| Trivy, Lab 7 (DB of 2026-10-04) | 11 | 74 | **85** | — (filtered) |

Grype reports 14 more CRITICAL+HIGH matches than Trivy on the same image: the tools use different advisory feeds (Grype leans on GHSA, Trivy on NVD/vendor data with its own severity selection) and different matching rules, so the same package can be rated differently or matched by only one tool. The Trivy-to-Trivy jump from 74 to 85 with an identical image digest shows that the count also depends on the date of the database, not only on the image.

### 7.2 Ten fixable findings, ranked

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

### 7.3 Dockerfile scan

`trivy config /tmp/df-demo` → `Tests: 27 (SUCCESSES: 23, FAILURES: 4)`, `LOW: 1, MEDIUM: 2, HIGH: 1`.

| ID | Severity | Line | What it would let an attacker do |
| --- | --- | --- | --- |
| DS-0002 | HIGH | `USER root` | The app runs as UID 0. Any RCE in the app is root inside the container, and one kernel/runtime bug or a mounted socket away from root on the node. |
| DS-0001 | MEDIUM | `FROM node:latest` | The base is whatever `latest` points to at build time. A poisoned or simply broken upstream push lands in the next build unnoticed, and builds are not reproducible, so you cannot prove what you shipped. |
| DS-0004 | MEDIUM | `EXPOSE 22` | Advertises (and usually means running) an SSH daemon in the container: an extra remote login surface for brute force or stolen keys, and a way to get an interactive shell that bypasses `kubectl exec` auditing. |
| DS-0026 | LOW | no `HEALTHCHECK` | A hung or hijacked process keeps "running", so the orchestrator never restarts it; it reduces availability and hides compromise rather than enabling it directly. |

`ADD https://example.com/app.tar /` is not flagged by any `DS-*` check here, but it pulls unpinned, unverified remote content into the image; `curl` + checksum (or `COPY` of a verified artifact) is the safer pattern. With `--severity HIGH,CRITICAL` only DS-0002 would be shown.

### Vulnerabilities with no fix

Eight findings have no fixed version (e.g. `marsdb 0.6.11` GHSA-5mrr-rgp6-x4gr and `decompress 4.2.1`, both CRITICAL; `lodash.set`, `braces`, `http-cache-semantics`, HIGH). For each one I would check whether the vulnerable code is actually reachable, and if it is, replace or remove the dependency (most are abandoned packages; `lodash.set` → `lodash`, `marsdb` → a maintained store). Whatever stays gets compensating controls: the runtime hardening from Task 2 (non-root, no capabilities, read-only root filesystem, default-deny NetworkPolicy) so that a working exploit has very little to do, plus an expiring, documented risk acceptance in the scanner (`.trivyignore` with an owner and review date) so it is reviewed, not forgotten. To a manager: the number is not zero because some of these flaws have no patch anywhere yet; zero is not the goal, *no known fixable critical issue and no unexplained open issue* is, and every remaining one has an owner, a mitigation and a re-check date.

## Task 2

All manifests are in `labs/lab7/k8s/`. Cluster: k3d 5.8.3, `rancher/k3s:v1.33.0-k3s1`. The namespace is applied first, then the directory.

### Namespace labels

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: latest
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/warn-version: latest
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/audit-version: latest
```

### Both `securityContext` blocks

These are read back from the running pod with `kubectl -n juice-shop get pod -l app=juice-shop -o jsonpath=...`:

```
pod:       {"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}
container: {"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true}
automount=false sa=juice-shop
```

Other settings in the Deployment:

- **ServiceAccount:** its own `juice-shop` ServiceAccount, with `automountServiceAccountToken: false` on both the ServiceAccount and the pod spec.
- **Resources:** requests `250m` CPU / `256Mi` memory, limits `1` CPU / `768Mi` memory.
- **Image:** pinned by digest, `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`, the value from `docker inspect ... --format '{{index .RepoDigests 0}}'`.
- **User:** `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{.Config.User}}'` returns `65532`, so `runAsUser` is 65532, not 1000.

### Proof: the pod is running, and as which user

```
$ kubectl -n juice-shop get pods -o wide
NAME                         READY   STATUS    RESTARTS   AGE     IP          NODE
juice-shop-76f59b5d8-zlw2b   1/1     Running   0          5m17s   10.42.0.9   k3d-lab7-server-0

$ kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop
pod/juice-shop-76f59b5d8-zlw2b condition met

$ kubectl -n juice-shop exec deploy/juice-shop -c juice-shop -- /nodejs/bin/node -e "console.log('uid', process.getuid(), 'gid', process.getgid())"
uid 65532 gid 65532

# /proc/1/status of the app process
Uid:        65532   65532   65532   65532
Gid:        65532   65532   65532   65532
CapEff:     0000000000000000
NoNewPrivs: 1
Seccomp:    2
```

The image is distroless and has no `id` or `sh`, so the user ID is read through the image's own Node binary. `CapEff` is all zeros because every capability is dropped. `NoNewPrivs: 1` comes from `allowPrivilegeEscalation: false`. `Seccomp: 2` means a filter is active, the `RuntimeDefault` profile. The pod spec is also saved in `labs/lab7/results/pod-spec.yaml`.

### Trivy: plain vs hardened

`trivy k8s --include-namespaces <ns> --severity HIGH,CRITICAL --report=summary`:

| Namespace | Resource | Vuln C | Vuln H | Misconf C | Misconf H | Secrets H |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| juice-plain | Deployment/juice | 11 | 74 | – | – | 2 |
| juice-shop | Deployment/juice-shop | 22 | 148 | – | – | 4 |

On this Windows/k3d setup, `trivy k8s` returned no misconfiguration results for either namespace. It stayed empty even with `--scanners misconfig` and no severity filter, and neither JSON file has a `config` result. To compare misconfigurations, I ran the same Trivy Kubernetes checks on the live Deployment objects exported from the API server (`kubectl get deploy -o yaml | trivy config`):

| Namespace | Checks | Failures | CRITICAL | HIGH | MEDIUM | LOW |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| juice-plain | 99 | **17** | 0 | **3** (KSV-0014, KSV-0118 ×2) | 4 (KSV-0001, 0012, 0104, 0125) | 10 |
| juice-shop | 99 | **2** | 0 | **0** | 2 (KSV-0125 ×2) | 0 |

**Why the counts differ the way they do.**

- **Misconfigurations differ.** They are properties of the pod spec, and that is what I changed: non-root, no privilege escalation, all capabilities dropped, seccomp, resources and a read-only root filesystem. That takes the result from 17 failures (3 HIGH) to 2. The 2 left are KSV-0125 ("untrusted registry", Docker Hub not on an allow-list), which only a private registry would fix.
- **Vulnerabilities do not differ.** They are properties of the image contents, and both Deployments run the same digest. Per image it is 11 CRITICAL / 74 HIGH in both namespaces, matching the Task 1 scan. `juice-shop` shows 22 / 148 only because the initContainer uses the same image and Trivy counts each container. Only rebuilding the image with updated packages changes these numbers.

### One thing `restricted` blocked

A pod with the default spec is rejected at admission. `kubectl -n juice-shop run plain --image=bkimminich/juice-shop:v20.0.0 --dry-run=server` returns:

```
Error from server (Forbidden): pods "plain" is forbidden: violates PodSecurity "restricted:latest":
allowPrivilegeEscalation != false, unrestricted capabilities (must set securityContext.capabilities.drop=["ALL"]),
runAsNonRoot != true, seccompProfile (must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

The image already runs as 65532, but that does not satisfy the profile. `runAsNonRoot: true`, `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false` and `capabilities.drop: [ALL]` all had to be set explicitly. The initContainer needed the same treatment, because the profile checks every container in the pod.

### Controls the profile does not require that I added anyway

- **`readOnlyRootFilesystem: true`:** see the Bonus. Writing to the image filesystem now fails: `write /juice-shop/x -> EROFS`.
- **No service account token:** `automountServiceAccountToken: false` on the ServiceAccount and the pod. The check prints `no service account token mounted`, so code running in the pod cannot call the Kubernetes API.
- **Default-deny NetworkPolicy** (`labs/lab7/k8s/networkpolicy.yaml`): both `Ingress` and `Egress`. Ingress is allowed only on TCP 3000 from `kube-system`, where Traefik runs. Egress is allowed only for DNS (UDP/TCP 53) to the `kube-dns` pods. A compromised app cannot reach other pods or the internet.
- **Resource requests and limits**, plus `sizeLimit` on each emptyDir, so the pod cannot exhaust the node's CPU, memory or disk.

## Bonus

### Where the process writes (`docker diff`)

`docker run -d --name js bkimminich/juice-shop:v20.0.0 && sleep 30 && docker diff js`, trimmed (43 `A /juice-shop/i18n/*.json` lines collapsed):

```
C /juice-shop/data
A /juice-shop/data/juiceshop.sqlite
C /juice-shop/ftp
A /juice-shop/ftp/legal.md
C /juice-shop/i18n
A /juice-shop/i18n/*.json                 (43 files)
C /juice-shop/.well-known/csaf/provider-metadata.json
C /juice-shop/frontend/dist/frontend/index.html
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
A /juice-shop/logs/access.log.2026-10-04
A /juice-shop/logs/audit.json
```

Nothing outside `/juice-shop` (no `/tmp`), so `/tmp` is not mounted. Without any volume, `docker run --read-only` dies on the first write: `SQLITE_CANTOPEN: unable to open database file`.

### Volume layout

| Volume (emptyDir) | Mounted at | Why | Seeded? |
| --- | --- | --- | --- |
| `data` | `/juice-shop/data` | creates `juiceshop.sqlite`; also holds `data/static/*` (challenges, products, legal.md) shipped in the image | yes |
| `ftp` | `/juice-shop/ftp` | rewrites `legal.md`; directory ships 14 files served by the FTP challenge | yes |
| `i18n` | `/juice-shop/i18n` | writes the 43 translation files at startup | yes (1 shipped file) |
| `well-known` | `/juice-shop/.well-known` | edits `csaf/provider-metadata.json` in place | yes |
| `frontend-dist` | `/juice-shop/frontend/dist` | edits `index.html` and others in place, adds images; ships the whole Angular build (768 files) | yes |
| `logs` | `/juice-shop/logs` | access and audit logs; empty in the image | no |

### The directory that cannot be an empty volume

Every directory except `logs` both receives runtime writes **and** contains files shipped in the image. An empty emptyDir hides those files; tested with empty tmpfs mounts, the app reports `Required file index.html is missing` and exits with `ENOENT: ... copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'`. `data/` is the clearest case: the app needs `data/static/` to build the database and writes the database next to it.

Fix: an initContainer from the **same pinned image** (it is distroless, no shell, so it uses the bundled Node: `/nodejs/bin/node -e 'fs.cpSync(...)'`) copies the five directories into their emptyDirs, then the main container mounts the emptyDirs over the original paths. The initContainer is itself restricted-compliant (non-root, no privilege escalation, `drop: ALL`, read-only root, requests/limits). The same layout was verified first with Docker: `--read-only --user 65532 --cap-drop ALL` plus the seeded bind mounts → `running=true ro=true`, HTTP 200.

### Proof in Kubernetes

```
$ kubectl -n juice-shop get pods
juice-shop-76f59b5d8-zlw2b   1/1   Running   0   5m17s

$ kubectl -n juice-shop logs deploy/juice-shop -c seed-writable-dirs
seeded /seed/data
seeded /seed/ftp
seeded /seed/i18n
seeded /seed/well-known
seeded /seed/frontend-dist

$ kubectl -n juice-shop get pod -l app=juice-shop -o jsonpath='{.items[0].spec.containers[0].securityContext}'
{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true}

# writing to the root filesystem inside the running container
write /juice-shop/x -> EROFS

$ kubectl -n juice-shop port-forward deploy/juice-shop 18080:3000 &
$ Invoke-WebRequest http://127.0.0.1:18080/
HTTP 200 text/html; charset=UTF-8
```

The pod is Ready with zero restarts and serves HTTP 200 through `kubectl port-forward`. The image's own filesystem is read-only, as the `EROFS` result shows, and the app writes only into the six emptyDirs. Local port 18080 was used because 3000 was already in use on the host.
