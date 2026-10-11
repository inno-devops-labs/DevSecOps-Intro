# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Compared to Lab 4's Grype scan

**CVE-2026-45447 — found by BOTH tools.** Both Trivy and Grype flagged this OpenSSL
issue (`libssl3t64 3.5.5-1~deb13u2`, HIGH, fix `3.5.6-1~deb13u2`) with identical package,
version and fix. Agreement is expected for OS-package CVEs: both tools consume the same
Debian security feed, so their package-to-advisory matching converges on the same result.

**CVE-2026-34180 — found by Grype, missed by Trivy.** Grype reported this OpenSSL
(`libssl3t64`) HIGH advisory, but it is absent from Trivy's result set. The most likely
cause is **DB freshness**: Trivy's vulnerability DB banner showed `UpdatedAt 2026-06-19`,
while the scan ran on 2026-07-03, so OpenSSL advisories added to the feeds in that two-week
window are present in Grype's freshly-pulled DB but not yet in Trivy's cached one. A secondary
factor that inflates the raw 38-vs-94 CVE gap is **ID namespace / package matching**: many npm
findings Trivy labels with CVE IDs while Grype labels them with GHSA IDs — e.g. `lodash 2.4.2`
is `CVE-2019-10744` in Trivy but `GHSA-jf85-cpcp-j695` in Grype (same vuln, same fix `4.17.12`),
counted as a divergence even though both tools caught it.

---

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
# pod-level
securityContext:
  runAsNonRoot: true
  runAsUser: 65532        # image ships as USER 65532 (distroless nonroot)
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
# container-level
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```
- `networkpolicy.yaml` ingress + egress:
```yaml
ingress:
  - from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
    ports:
      - protocol: TCP
        port: 3000
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
    ports:
      - protocol: UDP
        port: 53
      - protocol: TCP
        port: 53
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - protocol: TCP
        port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-5db856f847-sgr7l   1/1     Running   0          2m39s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 86 |

(Vulnerabilities only; Misconfigurations = 0 — the hardened Deployment produced no
PSS/misconfig findings. Secrets: 4 High.)

### What broke and how you fixed it
`readOnlyRootFilesystem: true` makes the container's root filesystem immutable, but Juice
Shop writes to several paths under its working directory at startup. Debugging via the pod
logs and `docker diff` surfaced them one by one: it creates the SQLite DB in
`/juice-shop/data` (which also holds seed files it reads), restores promo assets into
`/juice-shop/frontend/dist/frontend`, rewrites `/juice-shop/.well-known/csaf/provider-metadata.json`,
and writes to `/juice-shop/logs` and `/juice-shop/ftp`. The fix mounts an `emptyDir{}` at
each of these paths; because three of them ship seed files that an empty mount would hide
(causing `ENOENT`/`EROFS` crashes), a small init container first copies those directories
from the image into the volumes (using the image's own `/nodejs/bin/node`, since the
distroless image has no shell) before the app container starts.
