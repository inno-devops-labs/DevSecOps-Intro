# Lab 7 — Submission

---

## Task 1: Trivy Image + Config Scan

**Image:** `bkimminich/juice-shop:v20.0.0`  
**Trivy:** v0.69.3 (Vuln DB updated 2026-06-29)  
**Filter:** `--severity HIGH,CRITICAL`

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|-------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

96% of HIGH/CRITICAL findings have a published fix: patch fix-available distro + npm packages first, then accept risk on the remainder.

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

### Dockerfile misconfig scan

Target: `/tmp/docker-bad/Dockerfile` (Trivy `config` mode requires a **directory**, not a single file path).

| Target | Type | Misconfigurations |
|--------|------|------------------:|
| Dockerfile | dockerfile | 1 |

**Tests:** 20 (19 passed, 1 failed) — **1 HIGH**, 0 CRITICAL (filter `--severity HIGH,CRITICAL`).

| Rule | Severity | Issue | Line |
|------|----------|-------|-----:|
| DS-0002 | HIGH | Last `USER` is `root` — containers should run as non-root | 2 |

```
USER root                             # DS-0002: run as non-root user instead
FROM node:latest                      # not flagged at HIGH/CRITICAL in this Trivy bundle
EXPOSE 22                             # not flagged at HIGH/CRITICAL
ADD https://example.com/app.tar /     # not flagged at HIGH/CRITICAL
```

Trivy 0.69.3 reported only **DS-0002** at HIGH+; other anti-patterns from the sample Dockerfile may appear at lower severity or under different check IDs (Checkov CKV_DOCKER_* in Lab 6 context).

### Compared to Lab 4's Grype scan

Same image (`bkimminich/juice-shop:v20.0.0`). Lab 7 Trivy filter is HIGH+CRITICAL only (48 findings); Lab 4 Grype counted all severities (97 total).

**CVE both tools found — `CVE-2026-45447` (libssl3t64, High):**  
Both Grype and Trivy flag the Debian OpenSSL package in the image layer. This is a distro-scoped match on `libssl3t64` with a concrete fix version (`3.5.6-1~deb13u2`). Agreement here shows both DBs track the same OS-level advisory when the package name/version aligns cleanly.

**CVE only Trivy reported (by ID) — `CVE-2015-9235` (jsonwebtoken, Critical):**  
Trivy lists the legacy CVE ID on nested `jsonwebtoken@0.1.0` / `0.4.0`. Grype reports the same underlying flaw as **`GHSA-c7hr-j4mj-j2w6`** (GitHub Advisory ID) in Lab 4's top-10 — not the CVE string — so `comm` shows it as Trivy-only. Same vulnerability, different identifier and advisory source (NVD/CVE vs GitHub Advisory DB). Grype-only examples from the diff include ancient glibc issues like **`CVE-2019-1010022`** that Grype keeps in its full scan but Trivy often suppresses or rates below the HIGH threshold.

```text
Both:     CVE-2026-45447, GHSA-5mrr-rgp6-x4gr
Grype-only: CVE-2010-4756, CVE-2018-20796, CVE-2019-1010022
Trivy-only: CVE-2015-9235, CVE-2016-1000223, CVE-2017-18214
```

---

## Task 2: Kubernetes Hardening

**Cluster:** `kind-lab7`  
**Manifests:** `labs/lab7/k8s/` (namespace, serviceaccount, deployment, networkpolicy)

Apply on Kali:

```bash
kubectl apply -f labs/lab7/k8s/
kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=300s
kubectl get pod -n juice-shop -l app=juice-shop
```

### Manifests

**`namespace.yaml` — PSS labels:**

```yaml
labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted
```

**`deployment.yaml` — securityContext (pod + container):**

```yaml
spec:
  template:
    spec:
      serviceAccountName: juice-shop-sa
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532          # distroless v20 image USER (Dockerfile)
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: juice-shop
          image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { memory: 512Mi, cpu: 100m }
            limits:   { memory: 1Gi, cpu: 500m }
```


**`networkpolicy.yaml` — ingress + egress:**

```yaml
ingress:
  - ports:
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
  - ports:
      - protocol: TCP
        port: 443
```

### Pod is running

```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-68bd9dcfd6-rxmmn   1/1     Running   0          37s
```

### Trivy K8s scan

```bash
trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL --report=summary
```

**Workload Assessment — `juice-shop/Deployment/juice-shop`:**

| Category | Critical | High |
|----------|:--------:|:----:|
| **Vulnerabilities** (image CVEs) | 5 | 43 |
| **Misconfigurations** | 0 | **1** |
| Secrets | 0 | 2 |

Same **5 Critical / 43 High** image CVEs as Task 1 — expected (same pinned digest). **1 HIGH misconfiguration** = missing `readOnlyRootFilesystem: true` (see below). **2 HIGH secrets** = Trivy secret patterns in workload/image metadata.

### What broke and how you fixed it

**Strict lab hardening** (`readOnlyRootFilesystem: true` + many `emptyDir` mounts) repeatedly crashlooped on Juice Shop **v20 distroless** (`USER 65532`, no `/bin/sh`, writes to `data/`, `ftp/`, `.well-known/csaf/`, etc.). **Working config:** keep PSS `restricted` namespace labels, dedicated SA (`automountServiceAccountToken: false`), non-root UID **65532**, `seccompProfile: RuntimeDefault`, drop ALL caps, `allowPrivilegeEscalation: false`, resource limits, NetworkPolicy — but **omit `readOnlyRootFilesystem`** so the distroless app can start. Pod reaches **Running 1/1**; Trivy k8s flags the missing read-only root FS as 1 HIGH misconfig (acceptable trade-off for this lab image).

---

## Bonus: Conftest Policy

**File:** `labs/lab7/policies/pod-hardening.rego`

### Policy

```rego
package main

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot
	msg := "Pod must set spec.template.spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem
	msg := sprintf("Container '%s' must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Container '%s' must set allowPrivilegeEscalation to false", [container.name])
}

drop_includes_all(drop) if {
	drop[_] == "ALL"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	capabilities := object.get(container.securityContext, "capabilities", {})
	drop := object.get(capabilities, "drop", [])
	not drop_includes_all(drop)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}
```

### Output: hardened deployment

```bash
conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
```

```
FAIL - labs/lab7/k8s/deployment.yaml - main - Container 'juice-shop' must set readOnlyRootFilesystem to true

4 tests, 3 passed, 0 warnings, 1 failure, 0 exceptions
```

**3/4 passed** — `runAsNonRoot`, `allowPrivilegeEscalation: false`, `capabilities.drop: ALL`. **1 expected failure:** `readOnlyRootFilesystem` omitted so distroless Juice Shop v20 can start (matches Trivy k8s **1 HIGH** misconfig).

### Output: FAIL on bad manifest

```bash
conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
```

```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - Pod must set spec.template.spec.securityContext.runAsNonRoot to true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

Policy **blocks** the intentionally weak nginx Deployment (no pod/container hardening).

### What this prevents at CI time

This policy catches **insecure pod specs** — missing non-root, writable root FS, privilege escalation, or full capability sets — **before** `kubectl apply` or merge to main. CI-time gating is cheaper than admission-time rejection: developers get immediate feedback in the PR pipeline without needing cluster access or waiting for the API server / webhook to reject a bad manifest during deploy.
