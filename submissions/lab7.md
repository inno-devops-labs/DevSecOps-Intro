# Lab 7 — Container and Kubernetes Hardening

Image `bkimminich/juice-shop:v20.0.0` (digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`). Tools: Trivy `0.74.0`, `kubectl` 1.36, `k3d` 5.8.3 (k3s v1.33.0). Cluster: `k3d-lab7`. All numbers from the JSON reports.

## Task 1

### Vulnerability counts and the fix-available split

`trivy image --severity HIGH,CRITICAL`:

| Severity | Count | Of those, fix available |
|---|---|---|
| CRITICAL | 11 | 8 |
| HIGH | 74 | 69 |
| **Total** | **85** | **77** |

So **8 of the 85 HIGH/CRITICAL findings have no released fix** (3 CRITICAL, 5 HIGH). (For context, the full scan also reports 95 MEDIUM and 34 LOW.)

### Side by side with Lab 4's Grype

Lab 4's Grype run (full-severity, from `grype-from-sbom.json`): **Critical 14, High 85**. Trivy here (HIGH,CRITICAL): **Critical 11, High 74**.

| Severity | Grype (Lab 4) | Trivy (Lab 7) |
|---|---|---|
| Critical | 14 | 11 |
| High | 85 | 74 |

Grype reports more in both buckets. The two scanners use different vulnerability databases and matching logic (Grype pulls from the Anchore feed, Trivy from its own aggregated DB with vendor severity re-ranking), and the scans are weeks apart, so the backing data itself has shifted — the same image legitimately produces different totals depending on which tool and which DB snapshot you ask.

### Ten fixable findings, ranked

```
CRITICAL  CVE-2023-46233   crypto-js 3.3.0 -> 4.2.0
CRITICAL  CVE-2026-71851   crypto-js 3.3.0 -> 4.0.0
CRITICAL  CVE-2015-9235    jsonwebtoken 0.1.0 -> 4.2.2
CRITICAL  CVE-2015-9235    jsonwebtoken 0.4.0 -> 4.2.2
CRITICAL  CVE-2019-10744   lodash 2.4.2 -> 4.17.12
CRITICAL  CVE-2026-59873   tar 4.4.19 -> 7.5.19
CRITICAL  CVE-2026-59873   tar 6.2.1 -> 7.5.19
CRITICAL  CVE-2026-59873   tar 7.5.15 -> 7.5.19
HIGH      CVE-2026-14456   libssl3t64 3.5.5-1~deb13u2 -> 3.5.7-1~deb13u2
HIGH      CVE-2026-45447   libssl3t64 3.5.5-1~deb13u2 -> 3.5.6-1~deb13u2
```

### Dockerfile findings (`trivy config` on the 7.3 demo file)

| ID | Severity | Issue | What it lets an attacker do |
|---|---|---|---|
| DS-0002 | HIGH | Last `USER` is `root` | If the process is compromised, the attacker is root inside the container, which turns any container-escape bug (kernel, misconfigured mount, writable host path) into root on the node. |
| DS-0001 | MEDIUM | `:latest` tag in `FROM` | The base image is not reproducible; a re-pull can silently swap in a different (possibly backdoored or regressed) image, so the build you tested is not the build you ship. |
| DS-0004 | MEDIUM | `EXPOSE 22` | Advertises SSH on the container; if an sshd is ever present, it is an extra remote-login surface that belongs on the host, not in an app container. |
| DS-0026 | LOW | No `HEALTHCHECK` | The orchestrator can't tell a hung container from a healthy one, so a wedged or exploited process keeps receiving traffic instead of being restarted. |

Only DS-0002 is HIGH, so `trivy config --severity HIGH,CRITICAL` would hide the other three and the file would look almost clean — the reason the lab warns against that filter here. These are `DS-*` (Trivy) ids, not Checkov's `CKV_DOCKER_*`.

### Vulnerabilities with no fix — what to do, and what to tell a manager

Eight HIGH/CRITICAL findings have no upstream fix, so "upgrade" is not an available ticket for them this sprint. For those I would (1) confirm whether the vulnerable code path is actually reachable in Juice Shop's usage of the package — many are not — and (2) apply compensating controls where it is: pin and monitor the package for a future patch, drop capabilities and run read-only/non-root (done in Task 2) to shrink what a successful exploit can do, and put the app behind network policy so the blast radius is contained. To a manager asking why the number isn't zero: zero-known-vulnerabilities is not a reachable or even meaningful target for a real image — new CVEs are published daily and some have no patch yet. The number that matters is *fixable HIGH/CRITICAL findings still open past SLA* (here, 77 are fixable and should be driven down), with the no-fix remainder tracked as accepted risk with named compensating controls, not pretended away.

## Task 2

### Namespace labels

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: latest
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/warn-version: latest
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/audit-version: latest
```

### Both securityContext blocks

Pod-level:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
```
Container-level:
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true   # bonus; restricted does not require it
  capabilities:
    drop:
      - ALL
```

The Deployment also uses its own ServiceAccount with `automountServiceAccountToken: false` on both the ServiceAccount and the pod spec, sets cpu/memory requests and limits, and pins the image **by digest**. A `NetworkPolicy` (`juice-shop-default-deny`) selects `app=juice-shop` with both `Ingress` and `Egress` policy types: ingress only TCP/3000, egress only DNS (UDP/TCP 53) to `kube-system`.

### Proof the pod runs and the user id

```
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-5f5ff7f8fc-8h2nt   1/1     Running   0          ...

$ kubectl -n juice-shop exec <pod> -- /nodejs/bin/node -e "console.log(process.getuid())"
65532
```

`spec.securityContext.runAsUser` is `65532` and the running process confirms `uid=65532` — matching the image's own `.Config.User` (not 1000).

### The two Trivy summaries

`trivy k8s --include-namespaces <ns> --severity HIGH,CRITICAL --report=summary`, Deployment row:

| Namespace | Vuln C | Vuln H | Secrets H |
|---|---|---|---|
| juice-plain (unhardened) | 11 | 74 | 2 |
| juice-shop (hardened)    | 11 | 74 | 2 |

At HIGH/CRITICAL the k8s-workload scanner shows no misconfiguration rows for either, so the *vulnerability and secret* numbers are identical. To see the hardening difference I scanned the two workload specs with `trivy config` (the same AVD/KSV misconfiguration checks `trivy k8s` wraps):

| Workload | Misconfigs (H / M / L) | Total |
|---|---|---|
| juice-plain (`kubectl create deployment`) | 3 / 4 / 10 | 17 |
| juice-shop (hardened manifest) | 1 / 1 / 0 | 2 |

**Both halves explained:** the **vulnerability counts are identical** because both namespaces run the *same image bytes* — hardening the pod spec changes how the container is allowed to behave, not what packages are inside it; only rebuilding the image moves that number. The **misconfiguration counts differ** (17 → 2) because that is exactly what the pod spec controls: dropping capabilities, non-root, seccomp, no privilege escalation, limits and a pinned digest clear KSV checks like KSV-0118 (default security context), KSV-0014/0003 (root fs / runAsNonRoot), KSV-0012, etc. The two that remain on the hardened pod are **KSV-0014** (read-only root fs — the bonus) and **KSV-0125** (image not from a trusted registry).

### One thing `restricted` blocked, and one control added voluntarily

**Blocked:** a plain pod is rejected at admission. `kubectl -n juice-shop create deployment ... --dry-run=server` returns:
> must set `securityContext.allowPrivilegeEscalation=false`, `capabilities.drop=["ALL"]`, `runAsNonRoot=true`, and `seccompProfile.type` to `RuntimeDefault`.

So I had to add all four of those fields before the Deployment was admitted.

**Added voluntarily:** the `restricted` profile says nothing about network reachability, but I added a **default-deny `NetworkPolicy`** (ingress limited to 3000, egress limited to DNS). I also added `readOnlyRootFilesystem: true` (the bonus), which `restricted` likewise does not require.

## Bonus — read-only root filesystem

`docker run --rm --read-only bkimminich/juice-shop:v20.0.0` crashes with `SQLITE_CANTOPEN`. The fix is to give Kubernetes `readOnlyRootFilesystem: true` plus writable volumes exactly where the process writes.

### `docker diff`, trimmed to the paths that matter

```
C /juice-shop/frontend/dist/frontend/index.html
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/i18n/en.json
A /juice-shop/logs/access.log.2026-10-04
A /juice-shop/logs/audit.json
A /juice-shop/data/juiceshop.sqlite
A /juice-shop/ftp/legal.md
C /juice-shop/.well-known/csaf/provider-metadata.json
```

### Final volume layout and why each entry is there

All are `emptyDir`, mounted writable over the paths the process writes at runtime:

| Mount | Why |
|---|---|
| `/juice-shop/data` | the SQLite DB `juiceshop.sqlite` is created here at boot — **seeded** (see below) |
| `/juice-shop/ftp` | the app copies `legal.md` in here at startup — **seeded** |
| `/juice-shop/.well-known` | `csaf/provider-metadata.json` is rewritten at startup — **seeded** |
| `/juice-shop/frontend/dist/frontend` | theme customisation rewrites `index.html` and asset files — **seeded** |
| `/juice-shop/logs` | access/audit logs; ships empty, so a plain empty volume is enough |
| `/juice-shop/i18n` | merged locale files written at startup; ships empty, plain empty volume |
| `/tmp` | scratch |

### The directory that could not just be an empty volume

Not one but **four** directories both ship files in the image *and* are written at runtime: `data`, `ftp`, `.well-known`, and `frontend/dist/frontend`. Mounting an empty volume over any of them hides the shipped files, and the app then fails — `data` with `SQLITE_CANTOPEN`, the others with `EROFS … open 'frontend/dist/frontend/index.html'` and friends. I solved it with an **initContainer** (`seed-writable-dirs`, the same image, itself read-only) that `fs.cpSync`s each of those four directories from the image into its emptyDir *before* the app container starts; the app then finds the shipped files present and still writes to a read-write volume. `logs`, `i18n` and `tmp` ship empty, so they need no seeding.

### Proof

```
$ kubectl -n juice-shop get pod -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-5f5ff7f8fc-8h2nt   1/1     Running   0          ...

$ kubectl -n juice-shop get pod <pod> -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}'
true

$ kubectl -n juice-shop port-forward <pod> 3000:3000 &
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/rest/admin/application-version
200
$ curl -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}
```

Pod `1/1 Ready` with `readOnlyRootFilesystem: true` and serving HTTP 200.
