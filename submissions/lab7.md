\# Lab 7 — Submission



\## Task 1: Trivy Image + Config Scan



\### Image scan severity breakdown

| Severity | Total | With fix available |

|----------|------:|------------------:|

| Critical | 5 | 5 |

| High | 43 | 43 |

| \*\*Total\*\* | 48 | 48 |



\### Top 10 CVEs with fixes

| CVE | Severity | Package | Fix |

|-----|----------|---------|-----|

| CVE-2023-46233 | CRITICAL | crypto-js | 4.2.0 |

| CVE-2015-9235 | CRITICAL | jsonwebtoken | 4.2.2 |

| CVE-2019-10744 | CRITICAL | lodash | 4.17.12 |

| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.6-1\~deb13u2 |

| NSWG-ECO-428 | HIGH | base64url | >=3.0.0 |

| CVE-2020-15084 | HIGH | express-jwt | 6.0.0 |

| CVE-2022-25881 | HIGH | http-cache-semantics | 4.1.1 |

| CVE-2022-23539 | HIGH | jsonwebtoken | 9.0.0 |

| NSWG-ECO-17 | HIGH | jsonwebtoken | >=4.2.2 |



\### Compared to Lab 4's Grype scan

1\. One that BOTH Grype and Trivy found: CVE-2023-46233 (crypto-js). Both tools use similar upstream vulnerability databases (NVD/OSV) and matched the package version correctly.

2\. One that ONE tool found and the OTHER missed: CVE-2015-9235 (jsonwebtoken). Trivy found this, but Grype missed it. This is likely due to differences in database refresh cadence and how each tool handles dependency tree resolution for Node.js packages.



\---



\## Task 2: Kubernetes Hardening



\### Manifests (paste relevant snippets)

\- `namespace.yaml` PSS labels:

```yaml

pod-security.kubernetes.io/enforce: restricted

pod-security.kubernetes.io/warn: restricted

pod-security.kubernetes.io/audit: restricted

```

\### deployment.yaml securityContext sections (pod + container):

```

securityContext:

&#x20; runAsNonRoot: true

&#x20; runAsUser: 1000

&#x20; fsGroup: 1000

&#x20; seccompProfile:

&#x20;   type: RuntimeDefault

```

\# ... container level ...

```

securityContext:

&#x20; allowPrivilegeEscalation: false

&#x20; readOnlyRootFilesystem: true

&#x20; capabilities:

&#x20;   drop: \["ALL"]

```

\### networkpolicy.yaml ingress + egress:

```

policyTypes: \[Ingress, Egress]

ingress:

&#x20; - ports: \[{protocol: TCP, port: 3000}]

egress:

&#x20; - to: \[{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}}]

&#x20;   ports: \[{protocol: UDP, port: 53}]

&#x20; - to: \[{ipBlock: {cidr: 0.0.0.0/0}}]

&#x20;   ports: \[{protocol: TCP, port: 443}]

Pod is running

```

\### Output of kubectl get pod -n juice-shop -l app=juice-shop:

```

NAME                          READY   STATUS    RESTARTS   AGE

juice-shop-567478d44f-ggkhv   1/1     Running   0          2m

```

\### Trivy K8s scan

| Severity | Count |

|----------|------:|

| Critical | 5 |

| High | 43 |

\### What broke and I fixed it:

readOnlyRootFilesystem: true broke Juice Shop because the application attempts to write to /tmp, /usr/src/app/logs, /juice-shop/data (SQLite database), and /juice-shop/ftp during startup. I fixed this by mounting emptyDir volumes to /tmp and /usr/src/app/logs to handle temporary files and logs, allowing the application to start while maintaining a read-only root filesystem where possible.

\# Bonus: Conftest Policy

\## Policy (paste labs/lab7/policies/pod-hardening.rego)

```

package main



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; not input.spec.template.spec.securityContext.runAsNonRoot

&#x20; msg := "Pod must set spec.securityContext.runAsNonRoot to true"

}



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; c := input.spec.template.spec.containers\[\_]

&#x20; not c.securityContext.readOnlyRootFilesystem

&#x20; msg := sprintf("Container %s must set readOnlyRootFilesystem to true", \[c.name])

}



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; c := input.spec.template.spec.containers\[\_]

&#x20; not c.securityContext.allowPrivilegeEscalation == false

&#x20; msg := sprintf("Container %s must set allowPrivilegeEscalation to false", \[c.name])

}



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; c := input.spec.template.spec.containers\[\_]

&#x20; not "ALL" in c.securityContext.capabilities.drop

&#x20; msg := sprintf("Container %s must drop ALL capabilities", \[c.name])

}

```

\### Output: PASS on hardened manifest

```

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

```



\### Output: FAIL on bad manifest

```

FAIL - /project/k8s/bad-pod.yaml - main - Container app must set allowPrivilegeEscalation to false

FAIL - /project/k8s/bad-pod.yaml - main - Container app must set readOnlyRootFilesystem to true

FAIL - /project/k8s/bad-pod.yaml - main - Pod must set spec.securityContext.runAsNonRoot to true



4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions

```

\### What this prevents at CI time:

This policy catches configuration drift and missing security contexts (e.g., a developer forgetting to drop capabilities) before the manifest ever reaches the cluster API server. Catching this at CI-time is better because it provides immediate feedback to the developer in their pull request, preventing the deployment from being created at all, whereas admission-time rejection requires a round-trip to the cluster and can block a deployment pipeline at a later, more costly stage.



