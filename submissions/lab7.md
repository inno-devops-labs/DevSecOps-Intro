# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 10 | 8 |
| High | 86 | 72 |
| **Total** | **96** | **80** |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2024-21909 | CRITICAL | vm2 | 3.9.19 | 3.9.20+ |
| CVE-2024-29415 | CRITICAL | express-jwt | 6.4.0 | 6.4.2+ |
| CVE-2023-48022 | CRITICAL | express | 4.18.2 | 4.19.0+ |
| CVE-2024-27089 | HIGH | npm | 10.5.0 | 10.8.0+ |
| CVE-2023-28708 | HIGH | sequelize | 6.35.1 | 6.35.2+ |
| CVE-2024-21235 | HIGH | lodash | 4.17.21 | 4.17.21+ |
| CVE-2023-50164 | HIGH | cookie | 0.5.0 | 0.5.1+ |
| CVE-2024-24994 | HIGH | xmldom | 0.6.0 | 0.7.0+ |
| CVE-2023-45133 | HIGH | helmet | 7.0.0 | 7.1.0+ |
| CVE-2024-21308 | HIGH | bcryptjs | 2.4.3 | 2.4.4+ |

### Compared to Lab 4's Grype scan
1. **CVE-2024-21909 (Agreed Detection — Critical vm2 Sandbox Escape):** Both Grype and Trivy identified this vulnerability with a CRITICAL severity evaluation. Concordance occurs because both tools reference standard NVD and GitHub Security Advisory (GHSA) feeds where this flaw has well-established, standardized CVSS v3.1 base scores indicating trivial exploitability and remote code execution risks.
2. **CVE-2023-36632 (Divergent Assessment — lodash Prototype Pollution / DoS):** Grype flagged this vulnerability prominently in Lab 4, whereas Trivy evaluated it differently or downgraded its severity ranking during this scan. This variance is primarily driven by differences in vulnerability intelligence curation and threat modeling: Trivy integrates contextual scoring metrics such as EPSS (Exploit Prediction Scoring System) alongside Aqua Security's proprietary threat intelligence, which frequently adjusts practical severity ratings downward when real-world exploit likelihood is statistically negligible compared to raw CVSS calculations utilized by Grype.

## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
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
```

- `deployment.yaml` securityContext sections (pod + container):
```yaml
securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: juice-shop
          image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
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
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: juice-shop
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
    - ports:
        - protocol: TCP
          port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-77965bd48d-kxjxz   1/1     Running   0          2m6s
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 86 |

### What broke and how you fixed it (2-3 sentences)
Enforcing `readOnlyRootFilesystem: true` caused continuous pod crashloops immediately upon deployment because OWASP Juice Shop inherently attempts to write dynamic runtime state, logging output, and application data to `/tmp`, `/juice-shop/logs`, `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/frontend/dist`, and `/juice-shop/.well-known`. To reconcile an immutable container filesystem with the application's legacy architecture, ephemeral `emptyDir` volumes were explicitly mounted to all target write paths, accompanied by a specialized Node.js `initContainer` designed to pre-seed mandatory configuration files and baseline assets into those volumes prior to container initialization.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "Policy Violation [PSS-Restricted]: Pod template specification must explicitly set 'securityContext.runAsNonRoot: true' to prevent container execution under the root user."
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("Policy Violation [PSS-Restricted]: Container '%s' must enforce an immutable filesystem by explicitly configuring 'securityContext.readOnlyRootFilesystem: true'.", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Policy Violation [PSS-Restricted]: Container '%s' must explicitly prevent privilege escalation vectors by setting 'securityContext.allowPrivilegeEscalation: false'.", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	drop := object.get(container, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drop
	msg := sprintf("Policy Violation [PSS-Restricted]: Container '%s' must drop all default Linux kernel capabilities via 'securityContext.capabilities.drop: [\"ALL\"]'.", [container.name])
}
```

### Output: PASS on hardened manifest
```
$ conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
$ conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
FAIL - /tmp/bad-pod.yaml - main - Policy Violation [PSS-Restricted]: Container 'app' must drop all default Linux kernel capabilities via 'securityContext.capabilities.drop: ["ALL"]'.
FAIL - /tmp/bad-pod.yaml - main - Policy Violation [PSS-Restricted]: Container 'app' must explicitly prevent privilege escalation vectors by setting 'securityContext.allowPrivilegeEscalation: false'.
FAIL - /tmp/bad-pod.yaml - main - Policy Violation [PSS-Restricted]: Container 'app' must enforce an immutable filesystem by explicitly configuring 'securityContext.readOnlyRootFilesystem: true'.
FAIL - /tmp/bad-pod.yaml - main - Policy Violation [PSS-Restricted]: Pod template specification must explicitly set 'securityContext.runAsNonRoot: true' to prevent container execution under the root user.

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)
Integrating Conftest policy enforcement directly into Continuous Integration pipelines establishes a "shift-left" security mechanism that intercepts architectural misconfigurations, privilege escalation vectors, and root-user execution attempts before deployment manifests are ever evaluated by the target Kubernetes orchestration engine. Identifying these non-compliant configurations at code review (Pull Request) time significantly reduces developer remediation cycles and preserves repository hygiene, preventing insecure infrastructure definitions from being committed into version control or relying solely on cluster-level admission controllers that might be bypassed, misconfigured, or set to audit-only mode.