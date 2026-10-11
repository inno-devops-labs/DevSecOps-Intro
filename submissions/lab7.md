# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | Critical | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | High | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | High | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | High | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | High | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | High | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Compared to Lab 4's Grype scan

**1. Vulnerability detected by both Grype and Trivy**

**CVE-2019-10744 (lodash)** was detected by both scanners (reported as **GHSA-jf85-cpcp-j695** in the Grype report). Both tools correctly identified the vulnerable `lodash` version (2.4.2) because this is a well-known vulnerability present in multiple advisory databases. The identifiers differ because Grype primarily reports GitHub Security Advisories (GHSA), while Trivy maps the same issue to its CVE identifier.

**2. Vulnerability detected only by Trivy**

**CVE-2026-45447 (libssl3t64)** was reported only by Trivy. In the Lab 4 Grype scan, the corresponding OpenSSL vulnerability was reported as **CVE-2026-34182**, indicating that the scanners relied on different vulnerability databases or advisory mappings. This illustrates how database freshness and vendor-specific advisories can cause scanners to report different identifiers or different vulnerabilities for the same package.

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
securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```
- `networkpolicy.yaml` ingress + egress:
```yaml
ingress:
    - {}

  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53

    - ports:
        - protocol: TCP
          port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                         READY   STATUS    RESTARTS   AGE
juice-shop-79fc54947-htkwn   1/1     Running   2          3m
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 1     |
| High     | 7     |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` broke Juice Shop because the application attempts to write runtime data during startup. Specifically, it needs write access to `/tmp`, `/juice-shop/ftp`, and `/juice-shop/data` directories. Without writable paths, the container failed with ENOENT and permission errors while copying and restoring required static and configuration files.

The issue was fixed by mounting `emptyDir` volumes to `/tmp`, `/juice-shop/ftp`, and `/juice-shop/data`, allowing ephemeral writable storage while keeping the root filesystem read-only and maintaining Pod Security Standards compliance.