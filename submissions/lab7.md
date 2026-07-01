# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 5 |
| High | 43 | 41 |
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
Looking back at Lab 4 results:
1. **CVE-2019-10744 (lodash)** - Both Grype and Trivy found this vulnerability. Both tools detected lodash with the same installed version (2.4.2) and recommended the same fix (4.17.12). This shows good agreement on application-level dependencies.

2. **CVE-2026-45447 (libssl3t64)** - This was found by Trivy but not by Grype. This is because Grype focuses primarily on application-level dependencies (Node.js packages), while Trivy scans both application and OS-level packages. The OS-level vulnerabilities (libssl, glibc) are only detected by Trivy because it scans the full container filesystem including system libraries.

## Task 2: Kubernetes Hardening

### Manifests
- `namespace.yaml` PSS labels: enforce: restricted, warn: restricted, audit: restricted
- `serviceaccount.yaml`: dedicated SA with `automountServiceAccountToken: false`
- `deployment.yaml`: securityContext with runAsNonRoot: true, runAsUser: 1000, fsGroup: 1000, seccompProfile: RuntimeDefault, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities.drop: ["ALL"]
- `networkpolicy.yaml`: default-deny with ingress (port 3000 from any namespace) and egress (UDP 53 to kube-system, TCP 443 to any)

### Pod is running
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-8849bb897-n7b82   1/1     Running   0          7m


### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

### What broke and how you fixed it
`readOnlyRootFilesystem: true` broke Juice Shop because it tries to write to several directories: `/tmp`, `/usr/src/app/logs`, `/usr/src/app/data`, `/juice-shop/ftp`, `/juice-shop/data`, and `/juice-shop/data/db`. I fixed it by adding `emptyDir{}` volume mounts for all these paths, which allows writes while keeping the root filesystem read-only. The SQLite database also required a writable location, so I mounted `/juice-shop/data/db` separately.
