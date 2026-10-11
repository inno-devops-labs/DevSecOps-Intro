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
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |
| CVE-2016-1000223 | HIGH | jws | ? | >=3.0.0 |

### Compared to Lab 4's Grype scan

1. **CVE-2023-46233** (crypto-js, CRITICAL) — Both Grype and Trivy found this CVE because it's a well-known prototype pollution vulnerability in a widely-used npm package. Both tools pull from the NVD and GHSA databases, and this CVE has a CVSS 9.8 score, so it appears regardless of DB freshness differences.

2. **GHSA-5mrr-rgp6-x4gr** (marsdb, CRITICAL, no fix) — Trivy found this but Grype may have missed it. marsdb is a niche npm package (MongoDB-like embedded DB for Juice Shop). Trivy uses a broader vulnerability database that includes GHSA entries directly, while Grype's matching strategy may filter out vulnerabilities with no known fix (`FixedVersion: null`), treating them as informational rather than actionable.

### Trivy Config scan on sample Dockerfile
```
Dockerfile (dockerfile)
Tests: 20 (SUCCESSES: 19, FAILURES: 1)
Failures: 1 (HIGH: 1, CRITICAL: 0)

DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
```
The sample Dockerfile failed the DS-0002 check because the last USER command was `root`, which allows container escape.

---

## Task 2: Kubernetes Hardening

### Manifests

`namespace.yaml` PSS labels:
```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```

`deployment.yaml` securityContext sections (pod + container):
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
```

`networkpolicy.yaml` ingress + egress:
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
        podSelector:
          matchLabels:
            k8s-app: kube-dns
    ports:
      - port: 53
        protocol: UDP
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
          except:
            - 10.0.0.0/8
            - 172.16.0.0/12
            - 192.168.0.0/16
    ports:
      - port: 443
        protocol: TCP
```

### Pod is running
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-57bbdb5559-52ll4   1/1     Running   0          25s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 15 |
| High | 129 |

(Includes vulnerabilities from both the main container and init containers used to copy application data to writable volumes.)

### What broke and how you fixed it (2-3 sentences)

`readOnlyRootFilesystem: true` broke Juice Shop because the application writes to multiple paths at startup: it copies files to `/juice-shop/ftp/`, creates a SQLite database in `/juice-shop/data/`, and writes the CSAF provider metadata to `/juice-shop/.well-known/`. I fixed it by adding two initContainers that copy the application files (including node_modules) to emptyDir volumes before the main container starts, and then mounting those volumes at the appropriate paths via `subPath`. This preserves the original static files while allowing writes to the writable copy.

---

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

deny contains msg if {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := "Pod must set runAsNonRoot: true in pod-level securityContext"
}

deny contains msg if {
    input.kind == "Deployment"
    some container
    c := input.spec.template.spec.containers[container]
    not c.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container %v must set readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    some container
    c := input.spec.template.spec.containers[container]
    not c.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %v must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    some container
    c := input.spec.template.spec.containers[container]
    not c.securityContext.capabilities
    msg := sprintf("Container %v must define capabilities.drop (missing entirely)", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    some container
    c := input.spec.template.spec.containers[container]
    c.securityContext.capabilities
    every cap in c.securityContext.capabilities.drop {
        cap != "ALL"
    }
    msg := sprintf("Container %v must drop ALL capabilities", [c.name])
}
```

### Output: PASS on hardened manifest
```
5 tests, 5 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - Container app must define capabilities.drop (missing entirely)
FAIL - /tmp/bad-pod.yaml - Container app must set allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - Container app must set readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - Pod must set runAsNonRoot: true in pod-level securityContext
5 tests, 1 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)

This policy catches non-compliant pod configurations (missing `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, or wildcard capabilities) BEFORE `kubectl apply` ever touches the cluster. Catching at CI-time is better than at admission-time because it provides immediate developer feedback in the pull request, reduces cluster control-plane load from rejected requests, and prevents misconfigured manifests from being merged into the repository in the first place — shifting security as far left as possible (Lecture 7 slide 16).