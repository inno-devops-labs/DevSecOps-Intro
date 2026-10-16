# Lab 7 Submission — Container and Kubernetes Hardening

## Task 1

### Image vulnerability scan

I scanned `bkimminich/juice-shop:v20.0.0` with Trivy 0.74.0 and limited the report to HIGH and CRITICAL findings.

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

| Severity | Findings | With a fixed version | Without a fixed version |
|---|---:|---:|---:|
| CRITICAL | 11 | 8 | 3 |
| HIGH | 74 | 69 | 5 |
| **Total** | **85** | **77** | **8** |

### Trivy vs Lab 4 Grype totals

| Tool | Scope reported here | Critical | High | High + Critical |
|---|---|---:|---:|---:|
| Grype from Lab 4 | SBOM scan | 14 | 85 | 99 |
| Trivy from Lab 7 | Image scan with `--severity HIGH,CRITICAL` | 11 | 74 | 85 |

Lab 4's Grype report also had 183 findings across all severities. The HIGH and CRITICAL totals differ because the tools use different advisory feeds, matching logic, package evidence, and identifier mapping. For example, Lab 4 showed cases where Grype reported a GitHub advisory while Trivy reported the related CVE.

### Ten fixable findings to rank first

```bash
jq -r '["CRITICAL","HIGH"] as $order
  | [.Results[].Vulnerabilities[]? | select((.FixedVersion // "") != "")
     | {sev: .Severity, id: .VulnerabilityID, pkg: .PkgName,
        now: .InstalledVersion, fix: .FixedVersion}]
  | sort_by(.sev as $s | $order | index($s))
  | .[:10][] | "\(.sev)\t\(.id)\t\(.pkg) \(.now) -> \(.fix)"' \
  labs/lab7/results/trivy-image.json
```

| Severity | ID | Package and version | Fixed version |
|---|---|---|---|
| CRITICAL | `CVE-2023-46233` | `crypto-js` 3.3.0 | 4.2.0 |
| CRITICAL | `CVE-2026-71851` | `crypto-js` 3.3.0 | 4.0.0 |
| CRITICAL | `CVE-2015-9235` | `jsonwebtoken` 0.1.0 | 4.2.2 |
| CRITICAL | `CVE-2015-9235` | `jsonwebtoken` 0.4.0 | 4.2.2 |
| CRITICAL | `CVE-2019-10744` | `lodash` 2.4.2 | 4.17.12 |
| CRITICAL | `CVE-2026-59873` | `tar` 4.4.19 | 7.5.19 |
| CRITICAL | `CVE-2026-59873` | `tar` 6.2.1 | 7.5.19 |
| CRITICAL | `CVE-2026-59873` | `tar` 7.5.15 | 7.5.19 |
| HIGH | `CVE-2026-14456` | `libssl3t64` 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| HIGH | `CVE-2026-45447` | `libssl3t64` 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

### Dockerfile scan

The demo Dockerfile was named exactly `Dockerfile` under `/tmp/df-demo`, then scanned with `trivy config /tmp/df-demo`.

| ID | Severity | Finding | Attacker impact |
|---|---|---|---|
| `DS-0001` | MEDIUM | `FROM node:latest` uses a mutable tag. | A later rebuild can silently pick up a different base image, including malicious or vulnerable content, which makes builds hard to reproduce and audit. |
| `DS-0002` | HIGH | The final `USER` is `root`. | A successful remote code execution inside the app gets root inside the container, increasing the impact of mounted files, kernel bugs, or container escape paths. |
| `DS-0004` | MEDIUM | Port 22 is exposed. | Exposing SSH invites direct login attempts and credential attacks against a container that should only expose the application port. |
| `DS-0026` | LOW | No `HEALTHCHECK` is defined. | The platform has less signal to restart or route away from a broken container, so an attacker-triggered hang or crash can last longer. |

### Findings with no fix available

Eight HIGH or CRITICAL findings had no fixed version in the Trivy report. I would first check whether each vulnerable package is reachable in this image, then remove or replace unused dependencies, add runtime controls such as non-root execution, read-only root filesystem, NetworkPolicy, and admission policies, and track the remaining risk with a time-bound exception. To a manager, I would say that the number cannot be zero until upstream releases fixes or the application removes the affected dependencies. The useful target is reducing exploitable risk quickly: patch what has a fix, isolate what has no fix, and keep evidence so the remaining risk is visible.

## Task 2

### Manifests

Files created under `labs/lab7/k8s/`:

- `namespace.yaml`
- `serviceaccount.yaml`
- `deployment.yaml`
- `service.yaml`
- `networkpolicy.yaml`
- `configmap.yaml`

The namespace enforces the restricted Pod Security Standard:

```yaml
metadata:
  name: juice-shop
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

The pod security context is:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  fsGroupChangePolicy: OnRootMismatch
  seccompProfile:
    type: RuntimeDefault
```

The app container security context is:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

The ServiceAccount disables token automounting in the ServiceAccount and the pod spec:

```yaml
automountServiceAccountToken: false
```

The image is pinned by digest:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Running proof and UID

Commands:

```bash
kubectl -n juice-shop get pods -o wide
kubectl -n juice-shop exec "$POD" -c juice-shop -- /nodejs/bin/node -e 'console.log(process.getuid())'
```

Output:

```text
NAME                          READY   STATUS    RESTARTS   AGE   IP            NODE
juice-shop-bc878478b-kd9b5   1/1     Running   0          11s   10.42.0.130   k3d-quickticket-server-0
65532
```

The image itself reports `User=65532` from:

```bash
docker inspect bkimminich/juice-shop:v20.0.0 --format '{{.Config.User}}'
```

### Trivy Kubernetes summaries

Commands:

```bash
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL --report=summary
trivy k8s --include-namespaces juice-shop  --severity HIGH,CRITICAL --report=summary
trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
```

| Namespace | Resource | Critical vulns | High vulns | Critical misconfigs | High misconfigs | High secrets |
|---|---|---:|---:|---:|---:|---:|
| `juice-plain` | `Deployment/juice` | 11 | 74 | 0 | 3 | 2 |
| `juice-shop` | `Deployment/juice-shop` | 11 | 74 | 0 | 0 | 2 |

The vulnerability counts are the same because both deployments run the same Juice Shop image digest; Kubernetes hardening changes workload configuration, not the packages inside the image. The misconfiguration counts differ because the hardened deployment adds a dedicated ServiceAccount, disables token automounting, sets the restricted security context, drops Linux capabilities, sets resource requests and limits, and uses a read-only root filesystem. The secret counts stay the same because Trivy still scans the same application image contents.

One control the restricted profile forced was the container security context: the default pod would violate restricted policy until `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `runAsNonRoot: true`, and `seccompProfile: RuntimeDefault` were set. One voluntary control I added was the default-deny `NetworkPolicy` with only app ingress on TCP 3000 from the same namespace and DNS egress to CoreDNS in `kube-system`.

## Bonus

### Read-only crash and docker diff

The plain read-only Docker run crashed as expected:

```bash
docker run --rm --read-only bkimminich/juice-shop:v20.0.0
```

Relevant error:

```text
Error: EROFS: read-only file system, copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'
ConnectionError [SequelizeConnectionError]: SQLITE_CANTOPEN: unable to open database file
```

I then captured runtime writes with:

```bash
docker run -d --name js-lab7-diff bkimminich/juice-shop:v20.0.0
sleep 25
docker diff js-lab7-diff
```

Trimmed write paths that mattered:

```text
C /juice-shop/data
A /juice-shop/data/juiceshop.sqlite
C /juice-shop/.well-known/csaf
C /juice-shop/.well-known/csaf/provider-metadata.json
C /juice-shop/i18n
A /juice-shop/i18n/*.json
C /juice-shop/frontend/dist/frontend/index.html
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
C /juice-shop/logs
A /juice-shop/logs/access.log.2026-10-04
A /juice-shop/logs/audit.json
C /juice-shop/ftp
A /juice-shop/ftp/legal.md
```

### Final volume layout

The final `deployment.yaml` runs the same Juice Shop image with `readOnlyRootFilesystem: true`. For SQLite, the app starts with an in-memory Sequelize instance, so the read-only root filesystem does not need a writable `/juice-shop/data` directory for `juiceshop.sqlite`.

| Volume | Mount | Why it exists |
|---|---|---|
| `ftp-files` | `/juice-shop/ftp/legal.md` via `subPath` | Startup restores `legal.md` into the FTP area. |
| `i18n` | `/juice-shop/i18n` | Startup copies backend locale JSON files at runtime. |
| `csaf-files` | `/juice-shop/.well-known/csaf/provider-metadata.json` via `subPath` | Startup rewrites the CSAF provider metadata URL. |
| `asset-files` | `hackingInstructor.png`, `ChatbotAvatar.png`, `owasp_promo.vtt` via `subPath` | Startup customization writes generated/static asset files. |
| `frontend-files` | `index.html` and `assets/private/threejs-demo.html` via `subPath` | Startup customization rewrites shipped frontend files. |
| `seed-files` | `/seed`, read-only ConfigMap | Seeds original `index.html` and CSAF metadata into writable `emptyDir` files before startup rewrites them. |
| `logs` | `/juice-shop/logs` | The app writes access and audit logs. |

The directory that could not simply be replaced with an empty volume was `frontend/dist/frontend`. It contains the shipped Angular application. Mounting an empty volume over the whole directory hides `index.html`, JavaScript bundles, CSS, and assets, and the app fails its startup preconditions. I solved it with `subPath` mounts only for the files that the startup code rewrites, leaving the rest of the shipped frontend visible from the image.

### Bonus proof

The final pod is Ready and has `readOnlyRootFilesystem: true`:

```bash
kubectl -n juice-shop get pods -o wide
kubectl -n juice-shop get deploy juice-shop -o json \
  | jq '.spec.template.spec.containers[0].securityContext'
```

Output:

```text
NAME                          READY   STATUS    RESTARTS   AGE   IP            NODE
juice-shop-bc878478b-kd9b5   1/1     Running   0          11s   10.42.0.130   k3d-quickticket-server-0
```

```json
{
  "allowPrivilegeEscalation": false,
  "capabilities": {
    "drop": [
      "ALL"
    ]
  },
  "readOnlyRootFilesystem": true
}
```

HTTP proof through `kubectl port-forward`:

```bash
kubectl -n juice-shop port-forward svc/juice-shop 3000:3000
curl -fsS -o /tmp/lab7-http-body.html -w '%{http_code}' http://127.0.0.1:3000/
```

Output:

```text
200
```
