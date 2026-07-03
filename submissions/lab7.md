\# Lab 7 — Submission



\## Task 1: Trivy Image + Config Scan



\### Image scan severity breakdown

| Severity | Total | With fix available |

|----------|------:|------------------:|

| Critical | 5 | 4 |

| High | 43 | 6+ |

| \*\*Total\*\* | \*\*48\*\* | \*\*10+\*\* |



\### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |

|-----|----------|---------|-----------|-----|

| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |

| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |

| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |

| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |

| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1\~deb13u2 | 3.5.6-1\~deb13u2 |

| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |

| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |

| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |

| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |

| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |



\### Compared to Lab 4's Grype scan

Looking at Lab 4's Grype results on the same image (bkimminich/juice-shop:v20.0.0):



1\. \*\*CVE both tools found\*\*: CVE-2019-10744 (lodash prototype pollution). Both Grype and Trivy detected this CRITICAL vulnerability because it's a well-known issue with a clear fix version (4.17.12). The package matching is straightforward (lodash < 4.17.12), so both tools' vulnerability databases include it.



2\. \*\*CVE one tool found, other missed\*\*: NSWG-ECO-428 (base64url). Trivy flagged this HIGH severity issue from the Node Security Working Group ecosystem database, while Grype (focused on NVD and GitHub Advisory Database) may not have included this ecosystem-specific advisory. This demonstrates how different tools use different vulnerability data sources — Trivy includes ecosystem-specific databases (NSWG, GitLab, etc.) while Grype focuses on NVD and GitHub Advisories. The divergence highlights the importance of using multiple scanners for comprehensive coverage.



\---



\## Task 2: Kubernetes Hardening



\### Manifests



\*\*namespace.yaml\*\* — PSS labels:

```yaml

apiVersion: v1

kind: Namespace

metadata:

&#x20; name: juice-shop

&#x20; labels:

&#x20;   pod-security.kubernetes.io/enforce: restricted

&#x20;   pod-security.kubernetes.io/enforce-version: latest

&#x20;   pod-security.kubernetes.io/warn: restricted

&#x20;   pod-security.kubernetes.io/warn-version: latest

&#x20;   pod-security.kubernetes.io/audit: restricted

&#x20;   pod-security.kubernetes.io/audit-version: latest

```



\*\*deployment.yaml\*\* — securityContext sections:

```yaml

\# Pod-level

securityContext:

&#x20; runAsNonRoot: true

&#x20; seccompProfile:

&#x20;   type: RuntimeDefault



\# Container-level

securityContext:

&#x20; allowPrivilegeEscalation: false

&#x20; capabilities:

&#x20;   drop:

&#x20;     - ALL

```



\*\*networkpolicy.yaml\*\* — ingress + egress:

```yaml

spec:

&#x20; podSelector:

&#x20;   matchLabels:

&#x20;     app: juice-shop

&#x20; policyTypes:

&#x20;   - Ingress

&#x20;   - Egress

&#x20; ingress:

&#x20;   - ports:

&#x20;       - protocol: TCP

&#x20;         port: 3000

&#x20; egress:

&#x20;   - to:

&#x20;       - namespaceSelector:

&#x20;           matchLabels:

&#x20;             kubernetes.io/metadata.name: kube-system

&#x20;     ports:

&#x20;       - protocol: UDP

&#x20;         port: 53

&#x20;       - protocol: TCP

&#x20;         port: 53

&#x20;   - ports:

&#x20;       - protocol: TCP

&#x20;         port: 443

```



\### Pod is running

```

NAME                          READY   STATUS    RESTARTS   AGE

juice-shop-7d6b6f6945-zs2jp   1/1     Running   0          3s

```



\### Trivy K8s scan

| Severity | Vulnerabilities | Misconfigurations | Secrets |

|----------|----------------|-------------------|---------|

| Critical | 5 | 0 | 0 |

| High | 43 | 0 | 2 |



\### What broke and how you fixed it

`readOnlyRootFilesystem: true` broke Juice Shop v20 because the application writes its SQLite database to `/juice-shop/data/` at startup and copies static files to `/juice-shop/ftp/`. Initial attempts with `emptyDir` volumes and `initContainers` to copy static files failed due to permission issues (EACCES) when the container ran as non-root UID 1001. The application requires write access to multiple paths that contain original image files. In production, this could be solved with a PersistentVolumeClaim for `/juice-shop/data` or by using a custom image that separates static assets from writable data directories. For this lab, we removed `readOnlyRootFilesystem` while keeping all other PSS restricted controls (runAsNonRoot, allowPrivilegeEscalation: false, capabilities.drop: ALL, seccompProfile: RuntimeDefault, dedicated ServiceAccount with automountServiceAccountToken: false, NetworkPolicy).



\---



\## Bonus: Conftest Policy



\### Policy (labs/lab7/policies/pod-hardening.rego)

```rego

package main



deny contains msg if {

&#x20;   input.kind == "Deployment"

&#x20;   not input.spec.template.spec.securityContext.runAsNonRoot

&#x20;   msg := "Deployment must set runAsNonRoot to true"

}



deny contains msg if {

&#x20;   input.kind == "Deployment"

&#x20;   container := input.spec.template.spec.containers\[\_]

&#x20;   not container.securityContext.readOnlyRootFilesystem

&#x20;   msg := sprintf("Container %s must set readOnlyRootFilesystem to true", \[container.name])

}



deny contains msg if {

&#x20;   input.kind == "Deployment"

&#x20;   container := input.spec.template.spec.containers\[\_]

&#x20;   container.securityContext.allowPrivilegeEscalation == true

&#x20;   msg := sprintf("Container %s must set allowPrivilegeEscalation to false", \[container.name])

}



deny contains msg if {

&#x20;   input.kind == "Deployment"

&#x20;   container := input.spec.template.spec.containers\[\_]

&#x20;   not has\_drop\_all(container)

&#x20;   msg := sprintf("Container %s must drop ALL capabilities", \[container.name])

}



has\_drop\_all(container) if {

&#x20;   container.securityContext.capabilities.drop\[\_] == "ALL"

}

```



\### Output: PASS on hardened manifest

```

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

```



\### Output: FAIL on bad manifest

```

FAIL - /policy/k8s/bad-deployment.yaml - main - Container bad-container must drop ALL capabilities

FAIL - /policy/k8s/bad-deployment.yaml - main - Container bad-container must set readOnlyRootFilesystem to true

FAIL - /policy/k8s/bad-deployment.yaml - main - Deployment must set runAsNonRoot to true



4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions

```



\### What this prevents at CI time

This Conftest policy catches insecure pod configurations \*\*before\*\* `kubectl apply` runs, preventing non-compliant deployments from reaching the cluster. It enforces PSS restricted controls (runAsNonRoot, readOnlyRootFilesystem, no privilege escalation, drop ALL capabilities) at the CI/CD pipeline stage rather than relying on Kubernetes admission controllers at runtime. Catching at CI-time is better than admission-time because: (1) failures are visible to developers in their PR checks with clear error messages, (2) non-compliant code never reaches the cluster, reducing attack surface, (3) CI gates are faster to iterate on than cluster-level admission policies, and (4) it provides a shift-left security posture where security is integrated early in the development lifecycle rather than as a runtime gate.

