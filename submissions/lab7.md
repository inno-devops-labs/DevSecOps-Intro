# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5     | 4                 |
| High     | 43    | 42                |
| **Total**| 48    | 46                |

### Top 10 CVEs with fixes

| CVE               | Severity | Package            | Fix                   |
|-------------------|----------|--------------------|-----------------------|
| CVE-2023-46233    | CRITICAL | crypto-js          | 4.2.0                 |
| CVE-2015-9235     | CRITICAL | jsonwebtoken       | 4.2.2                 |
| CVE-2015-9235     | CRITICAL | jsonwebtoken       | 4.2.2                 |
| CVE-2019-10744    | CRITICAL | lodash             | 4.17.12               |
| CVE-2026-45447    | HIGH     | libssl3t64         | 3.5.6-1~deb13u2       |
| NSWG-ECO-428      | HIGH     | base64url          | >=3.0.0               |
| CVE-2020-15084    | HIGH     | express-jwt        | 6.0.0                 |
| CVE-2022-25881    | HIGH     | http-cache-semantics| 4.1.1                 |
| CVE-2022-23539    | HIGH     | jsonwebtoken       | 9.0.0                 |
| NSWG-ECO-17       | HIGH     | jsonwebtoken       | >=4.2.2               |

### Compared to Lab 4's Grype scan

**CVE found by BOTH tools:** `CVE-2022-25881` (http-cache-semantics)  
Both Trivy and Grype correctly reported this high‑severity ReDoS vulnerability because it is a well‑known issue in a widely used npm package. Both tools pull from the NVD and GitHub Advisory Database, and the CVE was mature enough to be included in both databases at the time of scanning.

**CVE divergence – Trivy found but Grype missed:** `CVE-2026-45447` (libssl3t64)  
This CVE was published very recently (June 2026) and likely was not yet in Grype's vulnerability database when you ran Lab 4. Trivy, having just downloaded its DB (`trivy-db:2`) during this scan, included the latest entries. This shows the importance of keeping scanner databases up‑to‑date; newer CVEs may only appear in one tool until the others sync.

---

## Task 2: Kubernetes Hardening

### Manifests (relevant snippets)

- `namespace.yaml` PSS labels:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: juice-shop
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
