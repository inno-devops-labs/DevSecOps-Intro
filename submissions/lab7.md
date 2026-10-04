# Lab 7 — Container and Kubernetes Hardening

Run date: **2026-10-04**. Trivy **0.74.0**, k3d **5.9.0**, Kubernetes
**v1.33.0+k3s1**, kubectl **v1.36.3**, Docker **29.7.2**, arm64.
Both tasks and the read-only filesystem bonus were executed locally. Bulk evidence
is retained in gitignored `labs/lab7/results/`, including `trivy-k8s.json` for Lab 10.
The intentionally vulnerable application and the Lab 6 samples were not modified.

Image inspected and deployed:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
Config.User: 65532
Entrypoint: /nodejs/bin/node
```

## Task 1

### Image scan and fix availability

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

Counts are vulnerability records across `.Results[].Vulnerabilities[]`, not unique
CVE IDs; one advisory can affect multiple installed package versions.

| Severity | Findings | Released fix | No released fix |
|---|---:|---:|---:|
| CRITICAL | 11 | 8 | 3 |
| HIGH | 74 | 69 | 5 |
| Total scanned | 85 | 77 | 8 |

Lower severities were excluded from this scan. Fix availability uses a **nonempty**
`FixedVersion`: `select((.FixedVersion // "") != "")`, so an empty string does not
mistakenly become a fix ticket.

### Comparison with Lab 4

Lab 4's saved `labs/lab4/grype-from-sbom.json` is available (Grype **0.118.0**,
vulnerability DB built **2026-09-21**); its source labels identify Juice Shop 20.0.0,
but its source metadata does not preserve a usable image digest.

| Severity | Lab 4 Grype | Lab 7 Trivy |
|---|---:|---:|
| CRITICAL | 14 | 11 |
| HIGH | 85 | 74 |
| HIGH + CRITICAL | 99 | 85 |
| All severities | 183 | Not scanned |

These are different scanner/database snapshots and package matching/severity
choices, so the difference is not evidence that the application was fixed.
The older Grype report also lacks a verifiable digest, limiting an exact immutable
artifact comparison; comparing its all-severity 183 to Trivy's filtered 85 would
mix scopes.

### Ten fixable findings, critical first

```bash
jq -r '["CRITICAL","HIGH"] as $order
  | [.Results[].Vulnerabilities[]?
     | select((.FixedVersion // "") != "")
     | {sev: .Severity, id: .VulnerabilityID, pkg: .PkgName,
        now: .InstalledVersion, fix: .FixedVersion}]
  | sort_by(.sev as $s | $order | index($s))
  | .[:10][] | "\(.sev)\t\(.id)\t\(.pkg) \(.now) -> \(.fix)"' \
  labs/lab7/results/trivy-image.json
```

| Severity | ID | Package | Installed | Fixed version |
|---|---|---|---|---|
| CRITICAL | CVE-2023-46233 | crypto-js | 3.3.0 | 4.2.0 |
| CRITICAL | CVE-2026-71851 | crypto-js | 3.3.0 | 4.0.0 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.1.0 | 4.2.2 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.4.0 | 4.2.2 |
| CRITICAL | CVE-2019-10744 | lodash | 2.4.2 | 4.17.12 |
| CRITICAL | CVE-2026-59873 | tar | 4.4.19 | 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar | 6.2.1 | 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar | 7.5.15 | 7.5.19 |
| HIGH | CVE-2026-14456 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| HIGH | CVE-2026-45447 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

Versions above are per-advisory fixes, not a complete upgrade plan. For example,
crypto-js must satisfy both advisories, and the old jsonwebtoken versions require
compatibility testing when moving to a supported version.

### Dockerfile scan

```dockerfile
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
```

The file was saved as `/tmp/df-demo/Dockerfile` and scanned without a severity filter:

```bash
trivy config /tmp/df-demo --format json \
  --output labs/lab7/results/trivy-dockerfile.json
```

| Rule | Severity | Finding and attacker impact |
|---|---|---|
| DS-0001 | MEDIUM | `node:latest` is mutable: replacement upstream content can enter later builds without a source change; pin a reviewed digest. |
| DS-0002 | HIGH | The final user is root: an application exploit gains root inside the container, increasing the reach of filesystem writes and potential escape chains. |
| DS-0004 | MEDIUM | Port 22 is exposed: an SSH service, if installed, listening and published, would add a remote login/brute-force surface. `EXPOSE` alone does not start SSH or publish the port. |
| DS-0026 | LOW | No health check: an attacker-induced outage or unhealthy process can go unnoticed by tooling that relies on image health status. |

Actual result: **4 failures: 1 HIGH, 2 MEDIUM, 1 LOW**. This rule selection did not
flag the remote `ADD`; absence of an alert does not verify downloaded content.
Kubernetes probes in the final deployment provide application health checks.

### Findings with no released fix

Validate whether each affected dependency and code path is reachable, then apply
isolation, least privilege, restricted egress and monitoring to reduce the impact.
Where practical, disable the vulnerable feature or replace the dependency, with a
named owner and an expiring risk exception rather than an indefinite suppression.
Tell the manager which of the eight no-fix findings are exploitable in our context,
what controls reduce the risk, and when we will reassess them. Zero is not a useful
promise for an intentionally vulnerable teaching image; keep it confined to the lab
and track risk and remediation separately from scanner totals.

## Task 2

### Manifests

Files are under `labs/lab7/k8s/`:
`namespace.yaml`, `serviceaccount.yaml`, `deployment.yaml`, `networkpolicy.yaml`.
The namespace labels are:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/enforce-version: v1.33
pod-security.kubernetes.io/warn-version: v1.33
pod-security.kubernetes.io/audit-version: v1.33
```

Pod security context:

```yaml
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
```

Both the application and init container use:

```yaml
allowPrivilegeEscalation: false
capabilities:
  drop: [ALL]
readOnlyRootFilesystem: true
```

The dedicated `juice-shop` ServiceAccount and pod both disable
`automountServiceAccountToken`. Each container requests 250m CPU and 512Mi memory,
with limits of 1 CPU and 1Gi memory. Both images are pinned to the inspected digest.
Startup, readiness and liveness probes check HTTP `/` on port 3000.

The NetworkPolicy selects `app: juice-shop`, has both Ingress and Egress policy
types, and denies all pod ingress because lab access is through `kubectl port-forward`.
It permits only TCP/UDP 53 to `kube-dns` pods in `kube-system` for egress; other
outbound traffic is denied. This intentionally disables optional external AI/web3
integrations, which the application logs as warnings while still serving HTTP.
The API-mediated port-forward is an authorised administrative access path, not a
pod-to-pod ingress exception.

### Apply, readiness and real UID

```bash
k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1 \
  --kubeconfig-update-default=false --kubeconfig-switch-context=false
k3d kubeconfig get lab7 > labs/lab7/results/kubeconfig
# On this Docker host, replace host.docker.internal in this private kubeconfig
# with 127.0.0.1; the published API port then connects successfully.
export KUBECONFIG="$PWD/labs/lab7/results/kubeconfig"
kubectl apply -f labs/lab7/k8s/namespace.yaml
kubectl apply -f labs/lab7/k8s/
kubectl -n juice-shop rollout status deployment/juice-shop --timeout=180s
kubectl -n juice-shop get pod -l app=juice-shop -o yaml \
  > labs/lab7/results/pod-spec.yaml
kubectl -n juice-shop exec deployment/juice-shop -- /nodejs/bin/node \
  -e 'console.log("uid=" + process.getuid() + " gid=" + process.getgid())'
```

```text
deployment "juice-shop" successfully rolled out
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-678bc4d8d7-ftdpd    1/1     Running   0          30s
uid=65532 gid=65532
```

`docker inspect ... --format '{{.Config.User}}'` gave 65532 first; the Node command
above confirms the actual running process identity without needing a shell or `id`
in this distroless image. The initial init command `node` failed because it is not
in `$PATH`; using the inspected `/nodejs/bin/node` path fixed startup.
The installed kubectl is newer than the normal supported skew for this server;
these commands succeeded, but a repeatable toolchain should pin kubectl 1.33.x.

### Trivy comparison

```bash
kubectl create ns juice-plain
kubectl -n juice-plain create deployment juice --image=bkimminich/juice-shop:v20.0.0
kubectl -n juice-plain rollout status deployment/juice --timeout=180s
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL \
  --disable-node-collector --report summary
trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL \
  --disable-node-collector --report summary
trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL \
  --disable-node-collector --report summary --format json \
  --output labs/lab7/results/trivy-k8s.json
```

The commands used the explicit private `--kubeconfig` path. Node collection was
disabled in both scans to compare the namespaced application resources without
adding host inspection jobs. JSON and terminal summaries for both namespaces are
retained under `results/`.

| Deployment summary metric | juice-plain / juice | juice-shop / juice-shop |
|---|---:|---:|
| HIGH misconfiguration records | 3 | 0 |
| CRITICAL misconfiguration records | 0 | 0 |
| Raw HIGH vulnerability records | 74 | 148 |
| Raw CRITICAL vulnerability records | 11 | 22 |
| HIGH vulnerabilities per image/container | 74 | 74 |
| CRITICAL vulnerabilities per image/container | 11 | 11 |

Baseline misconfigurations: `KSV-0014` (writable root filesystem) and two
`KSV-0118` records (default container and deployment security contexts).
Hardening changes the pod configuration, eliminating these high findings, but
cannot remove vulnerabilities inside an unchanged image. The bonus adds an init
container with that same image, so Trivy reports 170 raw vulnerability records;
normalising by image digest and package location leaves the same 85 as the baseline.
Secrets are a separate scanner category and are not included in these vulnerability
or misconfiguration totals.

### A blocked setting and an extra control

To prove admission enforcement, a temporary Pod copy with `runAsUser: 0` was sent
with `kubectl create --dry-run=server`; it was never created:

```text
Error from server (Forbidden): pods "rejected-root" is forbidden:
violates PodSecurity "restricted:v1.33": runAsUser=0
(pod must not set runAsUser=0)
```

The admitted deployment sets the image's actual non-root UID 65532.
`restricted` does not require a read-only root filesystem; I added that control
and its supporting volumes for the bonus. Token mounting prevention, resource
limits and NetworkPolicy are additional controls beyond admission's requirements.
The [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
define the restricted admission requirements.

## Bonus

### Discovering writes

```bash
docker run --rm --read-only bkimminich/juice-shop:v20.0.0
docker run -d --name lab7-js-diff bkimminich/juice-shop:v20.0.0
# After startup and the "Server listening on port 3000" log:
docker diff lab7-js-diff
```

The read-only run exited 1 with `EROFS` copying `data/static/legal.md` to
`ftp/legal.md`, followed by `SQLITE_CANTOPEN`. Relevant observed changes:

```text
C /juice-shop/frontend/dist/frontend/index.html
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
A /juice-shop/ftp/legal.md
A /juice-shop/logs/access.log.2026-10-04
A /juice-shop/logs/audit.json
A /juice-shop/data/juiceshop.sqlite
C /juice-shop/.well-known/csaf/provider-metadata.json
A /juice-shop/i18n/en.json
A /juice-shop/i18n/ru_RU.json
# Additional language files under /juice-shop/i18n omitted here.
```

The full diff remains in `results/docker-diff.txt`.

### Final volume layout

| Volume / mount | Reason |
|---|---|
| data → `/juice-shop/data` | SQLite database and runtime data; seed bundled static data before startup. |
| ftp → `/juice-shop/ftp` | Restored legal document and other application files; seed existing downloadable files. |
| logs → `/juice-shop/logs` | Access/audit logs; seed any shipped contents. |
| i18n → `/juice-shop/i18n` | Generated language JSON; retain the image's initial directory contents. |
| frontend → `/juice-shop/frontend/dist/frontend` | Rewritten HTML and generated assets; preserve the shipped frontend bundle. |
| well-known → `/juice-shop/.well-known` | Updated CSAF metadata; preserve initial metadata. |
| tmp → `/tmp` | Bounded scratch space for runtime temporary files; defensive provision beyond observed startup writes. |

All are `emptyDir`, capped at 256Mi per application directory and 64Mi for `/tmp`.
`fsGroup: 65532` grants the non-root init process access to the volume roots.
The init container uses the **same digest**, runs Node's `fs.cpSync` recursively to
copy all six image directories into `/seed/<volume>` mounts, and exits before the
application starts. It has the same restricted context and read-only root setting.

An empty volume over the **frontend bundle** would hide `index.html`, JavaScript
and other required application assets; the **data directory** also contains
`static/legal.md` and other startup inputs. Seeding both, and the other observed
write directories, preserves those inputs while allowing writes only in explicit
mounts. The rest of the image filesystem remains read-only. These volumes are
intentionally ephemeral: pod replacement resets lab state, and a production service
would need a separate persistence and backup design.

### Ready and HTTP 200 proof

The saved live `pod-spec.yaml` shows `readOnlyRootFilesystem: true` for both
containers, the init container terminated successfully (exit 0), and the application
Ready without restarts. Runtime and HTTP evidence:

```bash
kubectl -n juice-shop get pods
kubectl -n juice-shop port-forward deployment/juice-shop 13007:3000
# In another terminal:
curl --fail --silent --output /dev/null --write-out 'HTTP %{http_code}\n' \
  http://127.0.0.1:13007/
```

```text
juice-shop-678bc4d8d7-ftdpd   1/1   Running   0
Forwarding from 127.0.0.1:13007 -> 3000
HTTP 200
```

Evidence files: `pod-spec.yaml`, `pod-ready.txt`, `runtime-user.txt`,
`http-proof.txt`, `pss-rejection.txt`, and `read-only-failure.log`.

### Cleanup

After collecting the evidence, stop port-forward, remove only `lab7-js-diff`, and
run `k3d cluster delete lab7`. Scan reports remain available locally for later labs;
no raw results or private kubeconfig belong in the submission commit.
