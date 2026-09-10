# Lab 7 — Container / Kubernetes Hardening

## Task 1

### Image vulns (HIGH+CRITICAL)
| Severity | Count |
|----------|------:|
| CRITICAL | 10 |
| HIGH | 64 |
| **total** | **74** |
| with FixedVersion | **71** |

Lab 4 Grype total was **181** (all severities). Trivy here is HIGH+CRITICAL only (**74**) — different floor + DB explains most of the gap.

### Dockerfile (`trivy config`)
| ID | Sev | Impact |
|----|-----|--------|
| DS-0001 | — | floating `FROM node:latest` |
| DS-0002 | HIGH | `USER root` → escape blast radius |
| DS-0004 | MEDIUM | `EXPOSE 22` |
| DS-0026 | LOW | missing HEALTHCHECK |

### No-fix CVEs
Compensate with PSS restricted, NetworkPolicy, read-only rootfs, drop ALL caps, runtime detection — document residual risk; “zero vulns” is not realistic on this fat Node image without upstream rebuild.

## Task 2

### Namespace labels
`pod-security.kubernetes.io/{enforce,warn,audit}=restricted` on `juice-shop`.

### securityContext
- Pod: `runAsNonRoot`, `runAsUser/Group: 65532`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`
- Container: `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`
- Image pinned by digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Dedicated ServiceAccount; requests/limits set; NetworkPolicy Ingress+Egress (DNS only egress)

### Proof
k3d cluster `lab7`. Pod Ready with `runAsUser=65532` and `readOnlyRootFilesystem=true` after seeding writable dirs (see Bonus).

```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-788dd7564f-sm4ft   1/1     Running   0          23s
readOnlyRootFilesystem=true runAsUser=65532 READY=true
curl http://127.0.0.1:18080/rest/admin/application-version -> HTTP 200 {"version":"20.0.0"}
curl http://127.0.0.1:18080/ -> HTTP 200
```

### Trivy k8s
Misconfiguration counts differ between `juice-plain` and `juice-shop`; vulnerability counts stay similar because hardening does not rebuild the image.

**Blocked by restricted / fixed:** e.g. must drop ALL caps, runAsNonRoot, no privileged. **Voluntary:** NetworkPolicy + digest pin + readOnlyRootFilesystem (bonus).

## Bonus — readOnlyRootFilesystem

### `docker diff` (paths that matter)
Writes under `/juice-shop/ftp`, `/juice-shop/i18n`, `/juice-shop/data` (sqlite + static), `/juice-shop/logs`, plus frontend asset touches.

### Volume layout
emptyDir mounts for `tmp`, `ftp`, `i18n`, `data`, `logs`, `frontend/dist/frontend`, `.well-known`. Init uses `/nodejs/bin/node` (no `sh`) to seed those trees so shipped files are not hidden by blank mounts.

### Hard directories
- `/juice-shop/data` ships `static/` needed at boot — seed, do not mount empty.
- `/juice-shop/frontend/dist/frontend` is rewritten at startup (`customizeApplication` / easter egg) — seed the whole dist tree.
- `/.well-known` is rewritten for CSAF metadata — seed similarly.
