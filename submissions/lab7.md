# Lab 7 — Container and Kubernetes Hardening

Tools: Trivy 0.74.0, k3d v5.9.0 (k3s v1.33.0), kubectl, conftest 0.71.0.
Image: `bkimminich/juice-shop:v20.0.0` @ `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

## Task 1

### Image vulnerabilities (HIGH/CRITICAL)
| Severity | Count | With fix |
|----------|------:|---------:|
| CRITICAL | 11 | — |
| HIGH | 74 | — |
| **Total** | **85** | **77 fixable** (8 have no fix) |

### Trivy vs Grype (Lab 4), same image
| Tool (HIGH+CRITICAL) | Critical | High | Total |
|----------------------|---------:|-----:|------:|
| Grype (Lab 4) | 14 | 85 | **99** |
| Trivy (this lab) | 11 | 74 | **85** |

The two disagree because they use different advisory databases and matching rules, and Grype reports both `CVE-` and `GHSA-` identifiers for the same package (so one real flaw can appear under two IDs), inflating its count. Neither is "right" — they are two opinions over the same packages; the overlap is what matters.

### Ten fixable findings (7.2)
| Sev | ID | Package now → fix |
|-----|----|-------------------|
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

### Dockerfile findings (`trivy config`)
| ID | Severity | Issue | What it lets an attacker do |
|----|----------|-------|------------------------------|
| DS-0002 | HIGH | Last `USER` is `root` | Container process runs as root; a code-exec bug becomes a root-in-container foothold and a stepping stone to container escape. |
| DS-0001 | MEDIUM | `:latest` tag used | Non-reproducible builds: the base can change under you, silently pulling in new vulns or a poisoned image. |
| DS-0004 | MEDIUM | Port 22 exposed | Advertises/opens SSH into the container — an extra remote-login surface that shouldn't exist in an app image. |
| DS-0026 | LOW | No `HEALTHCHECK` | The orchestrator can't tell a wedged container from a healthy one, so a compromised/hung process keeps serving. |

(All four are MEDIUM/LOW except DS-0002, so a `--severity HIGH,CRITICAL` filter would hide three of them and the file would look clean.)

### Vulnerabilities with no fix
Eight HIGH/CRITICAL findings have no released fix. You can't patch them this sprint, so you (1) record them as accepted-with-justification against the specific CVEs, (2) add compensating controls — the NetworkPolicy, non-root + dropped caps, read-only root FS below all shrink what an exploit of an unpatched lib can do — and (3) watch for a fix and re-scan (the Lab 4 SBOM makes that a seconds-long re-query). To a manager asking why it isn't zero: zero is not the goal and not achievable on a third-party image we don't build — the goal is that every finding is *known, triaged, and contained*; an honest 85-with-a-plan beats a fake zero from a `HIGH,CRITICAL`-only filter that just hides the rest.

## Task 2

### Namespace labels (`restricted`)
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted   # (+ *-version: latest on each)
```

### securityContext blocks
Pod:
```yaml
runAsNonRoot: true
runAsUser: 65532        # the image's real distroless-nonroot user, not 1000
runAsGroup: 65532
fsGroup: 65532
seccompProfile: { type: RuntimeDefault }
```
Container:
```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true     # bonus
capabilities: { drop: ["ALL"] }
```
Plus: dedicated ServiceAccount with `automountServiceAccountToken: false` on both SA and pod, cpu/memory requests+limits, image pinned by digest, and a default-deny NetworkPolicy (Ingress+Egress; ingress only TCP/3000, egress only DNS to kube-system).

### Proof the pod runs, and as which user
```
$ kubectl -n juice-shop get pods -l app=juice-shop
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-7b7bdd9dcf-v9hfm   1/1     Running   0          3m

$ kubectl -n juice-shop get <pod> -o jsonpath='{.spec.securityContext.runAsUser}'
65532
```

### Two Trivy k8s summaries side by side
| Namespace | HIGH/CRIT misconfigurations | HIGH/CRIT image vulns |
|-----------|----------------------------:|----------------------:|
| `juice-plain` (default deployment) | **3** (KSV-0014 root FS not read-only, KSV-0118 default security context) | 85 (same image) |
| `juice-shop` (restricted + hardened) | **0** | 85 (same image) |

**Both halves explained:** the *misconfiguration* counts differ (3 → 0) because that is exactly what hardening changes — the plain deployment ships a default security context and a writable root FS, which my manifest fixes (non-root, dropped caps, read-only root, seccomp). The *vulnerability* counts are identical because both namespaces run the **same image digest**: CVEs live in the image's packages, and no Kubernetes securityContext edit rewrites the image — only rebuilding/patching the image changes those.
> Note: `trivy k8s`'s vulnerability sub-scan errored on this Docker 29 host (a layer-tar extraction bug, same one seen in Lab 4), so the vuln columns came back empty in the live run; the 85 figure is the image-level count from 7.1, which applies equally to both namespaces by construction. The misconfiguration scan (the point of the comparison) ran cleanly.

### One blocked, one voluntary
- **Blocked by `restricted`:** a pod with the default container security context is rejected at admission — `restricted` demands `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `runAsNonRoot`, and a `seccompProfile`, so I had to add all of them (the first apply of the plain-style spec is refused with the exact field named).
- **Added voluntarily (not required by `restricted`):** a default-deny **NetworkPolicy** (Ingress+Egress) and `automountServiceAccountToken: false` — `restricted` says nothing about network egress or token mounting, but both shrink blast radius, so I added them. (`readOnlyRootFilesystem` is the bonus, also not required by `restricted`.)

## Bonus — read-only root filesystem

`docker run --rm --read-only bkimminich/juice-shop:v20.0.0` crashes because the app writes at runtime. `docker diff` (trimmed to what matters):
```
C /juice-shop/data        A /juice-shop/data/juiceshop.sqlite   # SQLite DB created at boot
C /juice-shop/logs        A /juice-shop/logs/access.log...      # access + audit logs
C /juice-shop/ftp         A /juice-shop/ftp/legal.md            # ftp dir (ships challenge files)
C /juice-shop/.well-known/csaf/provider-metadata.json          # regenerated at boot
C /juice-shop/i18n        A /juice-shop/i18n/en.json            # merged locale files
C /juice-shop/frontend/dist/frontend/index.html                # config injected into index.html at boot
```

### Final volume layout and why
The image is **distroless** (no `sh`/`cp`; its node binary is at `/nodejs/bin/node`, and its user is UID **65532**), and the write paths are spread across *several* directories that also ship files (`data/static`, `ftp`, `.well-known/csaf`, `frontend/dist`). Rather than seed each one, I seed the **whole `/juice-shop` (216 MB) into a single writable `emptyDir`** and mount it at `/juice-shop`:
- `app` (`emptyDir`, mounted `/juice-shop`) — the app's own tree, now writable, seeded from the image.
- `tmp` (`emptyDir`, mounted `/tmp`) — scratch writes.
Everything else (`/`, `/usr`, `/nodejs`, `/etc`) stays read-only, which is the point of `readOnlyRootFilesystem: true`.

### The directory that couldn't be an empty volume
`/juice-shop/data` (and `frontend/dist`, `ftp`, `.well-known/csaf`) ship files the app **reads** *and* writes: an empty volume mounted over `/juice-shop/data` hides `data/static/*` and the app exits at boot. Because the image has no shell, I seed with an **initContainer running the image's own node binary**:
```yaml
initContainers:
  - name: seed-app
    command: ["/nodejs/bin/node","-e","require('fs').cpSync('/juice-shop','/seed',{recursive:true})"]
    volumeMounts: [{ name: app, mountPath: /seed }]
```
The init copies the shipped tree into the `app` volume; the main container then mounts that seeded, writable volume at `/juice-shop`.

### Proof
```
$ kubectl -n juice-shop get pods -l app=juice-shop
juice-shop-7b7bdd9dcf-v9hfm   1/1   Running

$ kubectl -n juice-shop get <pod> -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}'
true

$ kubectl -n juice-shop port-forward <pod> 3005:3000 &
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3005/rest/admin/application-version
HTTP 200
$ curl -s http://127.0.0.1:3005/rest/admin/application-version
{"version":"20.0.0"}
```
