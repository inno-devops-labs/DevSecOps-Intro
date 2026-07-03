# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 4 | 4 |
| High | 6 | 6 |
| **Total** | 10 | 10 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Fix |
|-----|----------|---------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | >=4.2.2 |

### Compared to Lab 4's Grype scan
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:
1. One that BOTH Grype and Trivy found

``CVE-2026-45447`` - detected by both tools, as it is a vulnerability in the OpenSSL system package. Both scanners use up-to-date OS-level databases.

2. One that ONE tool found and the OTHER missed
For each: explain why the tools differ (DB freshness? Different package matching?
EPSS scoring? Lecture 7 + Lecture 4 give context.) (2-3 sentences per CVE.)

``NSWG-ECO-428`` - Found by Trivy but missing from Grype. Trivy can inspect the contents of **package-lock.json** and understands all npm dependencies. Grype operates via an SBOM and sees the general list of libraries, but if a vulnerability is recorded in the database as **NSWG-ECO-428**, Grype might not recognize it; it is geared toward system packages and CVE identifiers. If Trivy flagged CVE-2026-45447 with a high EPSS score, while Grype found the same vulnerability without a probability score, then Trivy provides more context for prioritization.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
```
- `networkpolicy.yaml` ingress + egress:
```yaml
ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - port: 3000
          protocol: TCP
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
    - ports:
        - port: 443
          protocol: TCP
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-68bc966c84-sqnjt   1/1     Running   0          4s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` likely broke Juice Shop. What paths did it need to write?
How did you fix it (which emptyDir mounts)?

Setting `readOnlyRootFilesystem: true` broke Juice Shop because the application writes to several directories: `/juice-shop/data/`, `/juice-shop/ftp/`, `/tmp/`, and `/usr/src/app/logs/`. The issue was resolved by mounting `emptyDir` volumes at each of these paths; this provided Juice Shop with writable temporary storage while keeping the root filesystem read-only. However, even with `emptyDir` volumes, SQLite database initialization failed because the original database file inside the image was obscured by the mounted empty volume. Ultimately, it was decided to forgo the `readOnlyRootFilesystem: true` setting.

