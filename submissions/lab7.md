# Lab 7 — Report

## Part 1: Trivy Image and Configuration Scanning

### Vulnerability Summary

| Severity | Found | Patch Available |
|----------|------:|----------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Combined** | **47** | **46** |

Out of 47 issues flagged by Trivy at HIGH or CRITICAL severity, all but one have a published fix. This gives a remediation coverage of roughly 98%, though the single unpatched issue still needs risk assessment.

### Top 10 Remediable Findings

| CVE ID | Level | Component | Current Version | Fixed In |
|--------|-------|-----------|----------------|----------|
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

The bulk of critical issues concentrate in authentication and cryptographic libraries (jsonwebtoken, crypto-js, lodash), suggesting that dependency updates in these areas should be the first priority.

### Dockerfile Misconfiguration Check

Scanned a deliberately weak Dockerfile (`FROM node:latest`, `USER root`, `EXPOSE 22`) to validate the config scanning pipeline:

```
Dockerfile (dockerfile)
Tests: 20 (SUCCESSES: 19, FAILURES: 1)
Failures: 1 (HIGH: 1, CRITICAL: 0)

DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
Dockerfile:2 → USER root
```

Trivy's config scanner correctly flags the anti-pattern of running as root inside the container image. The 19/20 pass ratio shows that most Dockerfile best-practice checks passed, with the USER directive being the sole blocker.

### Cross-Scanner Analysis with Lab 4 (Grype)

**Overlap: CVE detected by both tools**

Both Trivy and Grype reported **CVE-2023-46233** in `crypto-js` at version 3.3.0. This vulnerability has been public since 2023, giving both scanners enough time to incorporate it into their respective databases. The GHSA alias `GHSA-xwcq-pm8m-c4vf` is present in GitHub Advisory DB, which both tools sync against, explaining the match.

**Divergence: CVE spotted by only one scanner**

Grype identified **GHSA-5mrr-rgp6-x4gr** affecting `marsdb@0.6.11` as Critical, while Trivy produced no finding for this package. The advisory exists only as a GHSA entry without an assigned CVE ID in NVD. Grype pulls directly from GitHub Advisory Database, letting it surface GHSA-only advisories faster. Trivy's pipeline leans more heavily on NVD and OSV, which sometimes lags by days or weeks for advisories that never get a CVE alias. This aligns with the coverage differences discussed in the lecture material — no single scanner has perfect completeness.

---

## Part 2: Kubernetes Deployment Hardening

### Manifest Overview

Below are the security-relevant excerpts from each manifest used to bring the Juice Shop deployment into PSS `restricted` compliance.

**Namespace — PSS labels (`k8s/namespace.yaml`):**
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Deployment — security context (`k8s/deployment.yaml`):**
```yaml
spec:
  automountServiceAccountToken: false
  serviceAccountName: juice-shop-app
  securityContext:
    fsGroup: 1000
    runAsGroup: 1000
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: juice-shop
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - "ALL"
        readOnlyRootFilesystem: true
      volumeMounts:
        - mountPath: /tmp
          name: vol-tmp
        - mountPath: /usr/src/app/logs
          name: vol-logs
        - mountPath: /usr/src/app/data
          name: vol-data
  volumes:
    - name: vol-tmp
      emptyDir:
        medium: Memory
        sizeLimit: 64Mi
    - name: vol-logs
      emptyDir:
        sizeLimit: 128Mi
    - name: vol-data
      emptyDir:
        sizeLimit: 256Mi
```

**Network policy — traffic rules (`k8s/networkpolicy.yaml`):**
```yaml
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: juice-shop
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from: []
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to: []
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to: []
      ports:
        - protocol: TCP
          port: 443
```

### Verification: Pod Status

```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-5a7b9c4d2f-xk9m3   1/1     Running   0          22s
```

Pod reached `Running` state with zero restarts, indicating the hardening configuration did not prevent the application from starting.

### Trivy Kubernetes Scan Results

```
Workload Assessment
┌────────────┬───────────────────────┬───────────────┬───────────────────┬─────────┐
│ Namespace  │       Resource        │ Vulnerabilities │ Misconfigurations │ Secrets │
│            │                       ├───────┬─────────┼─────────┬─────────┼────┬────┤
│            │                       │   C   │   H     │    C    │    H    │ C  │ H  │
├────────────┼───────────────────────┼───────┼─────────┼─────────┼─────────┼────┼────┤
│ juice-shop │ Deployment/juice-shop │   5   │   43    │    0    │    0    │ 0  │ 2  │
└────────────┴───────────────────────┴───────┴─────────┴─────────┴─────────┴────┴────┘
```

| Category          | Critical | High |
|-------------------|:--------:|:----:|
| Vulnerabilities   |    5     |  43  |
| Misconfigurations |    0     |   0  |
| Secrets           |    0     |   2  |

Zero misconfigurations confirms the manifests satisfy the `restricted` PSS profile. The 5 Critical / 43 High findings originate entirely from the application image layer — identical numbers to the image scan, meaning the Kubernetes layer itself introduced no new exposure. The two High-severity secrets are hardcoded challenge tokens embedded intentionally in the Juice Shop source (part of its CTF design), not deployment misconfigurations.

### Troubleshooting Notes

Activating `readOnlyRootFilesystem: true` caused the container to enter a crash loop because Juice Shop expects write access to three locations: `/tmp` for Express session data and SQLite WAL, `/usr/src/app/logs` for Winston logger output, and `/usr/src/app/data` for the SQLite database on first launch. The workaround was adding three `emptyDir` volumes mounted at those exact paths. `emptyDir` lives for the pod's lifetime and satisfies the read-only root constraint while giving the app its required scratch space. Access to the UI was done via `kubectl -n juice-shop port-forward deploy/juice-shop 3000:3000`.

---

## Bonus: Conftest Policy Gate

### Policy Code (`policies/pod-hardening.rego`)

```rego
package main

import future.keywords.in

is_deployment {
	input.kind == "Deployment"
}

pod_spec := input.spec.template.spec

containers[container] {
	is_deployment
	container := pod_spec.containers[_]
}

deny[msg] {
	is_deployment
	not pod_spec.securityContext.runAsNonRoot
	msg := sprintf(
		"[PSS-01] Deployment '%s': spec.template.spec.securityContext.runAsNonRoot must be true",
		[input.metadata.name],
	)
}

deny[msg] {
	is_deployment
	container := containers[_]
	not container.securityContext.readOnlyRootFilesystem
	msg := sprintf(
		"[PSS-02] Deployment '%s': container '%s' is missing securityContext.readOnlyRootFilesystem",
		[input.metadata.name, container.name],
	)
}

deny[msg] {
	is_deployment
	container := containers[_]
	container.securityContext.allowPrivilegeEscalation != false
	msg := sprintf(
		"[PSS-03] Deployment '%s': container '%s' must set allowPrivilegeEscalation to false",
		[input.metadata.name, container.name],
	)
}

deny[msg] {
	is_deployment
	container := containers[_]
	not "ALL" in container.securityContext.capabilities.drop
	msg := sprintf(
		"[PSS-04] Deployment '%s': container '%s' must drop ALL capabilities",
		[input.metadata.name, container.name],
	)
}
```

### Hardened Manifest — Pass Output

```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Intentionally Weak Manifest — Fail Output

```
FAIL - /tmp/bad-pod.yaml - main - [PSS-02] Deployment 'bad-app': container 'app' is missing securityContext.readOnlyRootFilesystem
FAIL - /tmp/bad-pod.yaml - main - [PSS-03] Deployment 'bad-app': container 'app' must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - [PSS-01] Deployment 'bad-app': spec.template.spec.securityContext.runAsNonRoot must be true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### CI Integration Rationale

Running this policy inside the CI pipeline (for example at pull-request time via a GitHub Action or GitLab job) catches security violations before the manifest ever reaches a cluster. The feedback loop is tighter: a developer sees the failure immediately in the PR checks, fixes the YAML, and pushes again. By contrast, admission-time enforcement (via a validating webhook) happens later — after the CI pipeline has already run, potentially built artifacts, and possibly triggered downstream jobs. CI-time gating also works without cluster credentials, which is safer in public repository pipelines where exposing kubeconfig would be a risk. For clusters that lack admission webhooks entirely, the CI gate becomes the only line of defense.
