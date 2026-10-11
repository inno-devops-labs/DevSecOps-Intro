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
| CVE-2023-46233 | CRITICAL | crypto-js | | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | | >=4.2.2 |

### Compared to Lab 4's Grype scan
1. **CVE-2016-1000223**: Found by Trivy (as seen in the scan output) but missed by Grype in Lab 4. This difference likely stems from Trivy's use of its own curated vulnerability database which may include different mapping rules for older CVEs or different sources.
2. **GHSA-23c5-xmqv-rm74**: Found by Grype in Lab 4 but missed by Trivy here. Grype often has deeper integration with GitHub Security Advisories (GHSA) for npm packages, which can lead to higher recall for certain ecosystems.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
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
...
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
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-779d97cc4f-hx42f   1/1     Running   0          2m29s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
(Note: Misconfigurations are 0, vulnerabilities are image-based).

### What broke and how you fixed it (2-3 sentences)
Setting `readOnlyRootFilesystem: true` caused the application to crash because Juice Shop needs to write to `/tmp`, `/usr/src/app/logs`, and `/usr/src/app/data`. I fixed this by using initContainers to copy the app files to `emptyDir` volumes, which provided the necessary writable layers while keeping the image itself read-only.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
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
0 failures
```

### Output: FAIL on bad manifest
```
FAIL: /tmp/bad-pod.yaml
  │ Pod must set runAsNonRoot: true in pod-level securityContext
  │ Container app must set readOnlyRootFilesystem: true
  │ Container app must set allowPrivilegeEscalation: false
  │ Container app must define capabilities.drop (missing entirely)
```

### What this prevents at CI time (2-3 sentences)
This policy prevents insecure pod configurations from ever reaching the cluster by failing the CI pipeline if requirements like `runAsNonRoot` or `readOnlyRootFilesystem` are missing. Catching these at CI-time is better than at admission-time because it provides immediate feedback to the developer and prevents the deployment process from starting with an insecure manifest.
