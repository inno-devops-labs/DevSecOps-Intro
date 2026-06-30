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

> **Note regarding lab instructions error:** 
> The `jq` command provided in step 7.3 of the lab instructions (`{cve: .VulnerabilityID, severity: .Severity, pkg: .PkgName, fix: .FixedVersion}`) omits the `InstalledVersion` field, making it impossible to fill out the 'Installed' column in the table above using only the provided command. The command had to be manually modified to include `installed: .InstalledVersion` to complete the assignment properly.


### Compared to Lab 4's Grype scan
1. **Found by both tools (CVE-2015-9235 / GHSA-c7hr-j4mj-j2w6 in `jsonwebtoken`)**: Both tools identified the vulnerability, but they represent it differently. Trivy outputs the standard `CVE-2015-9235`, whereas Grype prefers ecosystem-specific identifiers and outputs `GHSA-c7hr-j4mj-j2w6`. This illustrates that the tools use different identifier preferences and package matching rules (Grype favors GitHub Security Advisories for npm).
2. **Found by Trivy, missed by Grype (CVE-2025-57349 in `messageformat`)**: This recent vulnerability was flagged by Trivy but missed by Grype. This difference is primarily due to DB freshness and update cadence. Trivy's vulnerability database is likely updated more frequently, allowing it to ingest newer CVEs faster than the default Anchore snapshot used by Grype.




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
  - {} # Allows incoming connections (e.g. for kubectl port-forward)
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
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-654c7d67fb-2hzs4   1/1     Running   0          42s
```
> **Note:** The pod successfully passes the `kubectl wait` condition because it initially starts without crashing, but shortly after goes into a `CrashLoopBackOff` state.

### Trivy K8s scan
> **Note regarding lab instructions error:** The command `trivy k8s --namespace juice-shop` is deprecated. I used `trivy k8s --include-namespaces juice-shop`.

| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` breaks Juice Shop because it needs to write to `/tmp` and `/juice-shop/logs`, as well as its SQLite database and FTP directory. I fixed the initial crash by mounting `emptyDir` volumes at `/tmp` and `/juice-shop/logs` (although v20.0.0 also requires writable access to `/juice-shop/data`, but simply mounting an `emptyDir` there hides the required `static` directory unless advanced K8s patterns like initContainers are used).



## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
package main
import rego.v1

# 1. spec.securityContext.runAsNonRoot != true
deny contains msg if {
    input.kind == "Deployment"
    pod_spec := input.spec.template.spec
    not pod_spec.securityContext.runAsNonRoot == true
    msg := "Pod securityContext must have runAsNonRoot set to true"
}

# 2. (any container) spec.containers[_].securityContext.readOnlyRootFilesystem != true
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%v' must have readOnlyRootFilesystem set to true", [container.name])
}

# 3. (any container) spec.containers[_].securityContext.allowPrivilegeEscalation != false
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%v' must have allowPrivilegeEscalation set to false", [container.name])
}

# 4. (any container) spec.containers[_].securityContext.capabilities.drop missing "ALL"
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not has_drop_all(container)
    msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

has_drop_all(container) if {
    "ALL" in container.securityContext.capabilities.drop
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must have allowPrivilegeEscalation set to false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must have readOnlyRootFilesystem set to true
FAIL - /tmp/bad-pod.yaml - main - Pod securityContext must have runAsNonRoot set to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time (2-3 sentences)
This policy catches insecure configuration bugs (like running as root or allowing privilege escalation) natively in the CI pipeline BEFORE `kubectl apply` is ever executed. By failing the pipeline early, developers get immediate feedback in their Pull Requests without waiting for the cluster's admission controller (like PSS) to reject the deployment. This represents true "shift-left" security, reducing friction and keeping the cluster entirely unaware of bad manifests.