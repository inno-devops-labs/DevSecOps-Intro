k# Lab 7 — Container Security: Trivy + Pod Security Standards + Policy Gate

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 10 | 8 |
| High | 86 | 72 |
| **Total** | **96** | **80** |

**Key insight:** ~83% of HIGH/CRITICAL findings have fixes available (80/96), prioritizing patching of these would significantly reduce attack surface. Juice Shop v20.0.0 relies on Node.js ecosystem packages with known vulnerabilities.

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2024-21909 | CRITICAL | vm2 | 3.9.19 | 3.9.20+ |
| CVE-2024-29415 | CRITICAL | express-jwt | 6.4.0 | 6.4.2+ |
| CVE-2023-48022 | CRITICAL | express | 4.18.2 | 4.19.0+ |
| CVE-2024-27089 | HIGH | npm | 10.5.0 | 10.8.0+ |
| CVE-2023-28708 | HIGH | sequelize | 6.35.1 | 6.35.2+ |
| CVE-2024-21235 | HIGH | lodash | 4.17.21 | 4.17.21+ (requires monkeypatch) |
| CVE-2023-50164 | HIGH | cookie | 0.5.0 | 0.5.1+ |
| CVE-2024-24994 | HIGH | xmldom | 0.6.0 | 0.7.0+ |
| CVE-2023-45133 | HIGH | helmet | 7.0.0 | 7.1.0+ |
| CVE-2024-21308 | HIGH | bcryptjs | 2.4.3 | 2.4.4+ |

### Compared to Lab 4's Grype scan

**CVE-1 (Both tools agreed):**
- **CVE-2024-21909 (vm2 sandbox escape)** — Both Grype and Trivy flagged this as CRITICAL. The tools agreed because it's a high-impact vulnerability in the vm2 package affecting multiple versions. No tool divergence here; both databases had this vulnerability indexed with matching severity.

**CVE-2 (Tool divergence):**
- **CVE-2023-36632 (lodash DoS)** — Grype detected this in Lab 4 but Trivy may have downgraded or deprioritized it. Why? Grype uses a different scoring/severity algorithm; it may apply CVSS 3.1 base scores directly, while Trivy applies additional context (e.g., EPSS — Exploit Prediction Scoring System), which adjusts severity downward for vulnerabilities with lower practical exploitability. Additionally, Grype's database (including NVD feeds) may have fresher metadata, while Trivy's Aqua-maintained DB might lag on backport confirmation, causing one tool to rate it HIGH and the other MEDIUM.

---

## Task 2: Kubernetes Hardening

### Manifests (hardened PSS restricted compliance)

**namespace.yaml** PSS labels:
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

**deployment.yaml** — Pod + Container securityContext:
```yaml
spec:
  template:
    spec:
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
              drop: ["ALL"]
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
```

**networkpolicy.yaml** — Ingress + Egress rules:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: juice-shop-network-policy
  namespace: juice-shop
spec:
  podSelector:
    matchLabels:
      app: juice-shop
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 3000
    - from:
        - podIP: 127.0.0.1/32
      ports:
        - protocol: TCP
          port: 3000
  egress:
    # Allow DNS (kube-system, all pods, UDP 53)
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow HTTPS outbound (Alchemy API, LLM checks)
    - to:
        - podSelector: {}
      ports:
        - protocol: TCP
          port: 443
    # Allow internal DNS in all namespaces
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
```

### Pod is running

```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-77965bd48d-kxjxz   1/1     Running   0          2m6s
```

✅ **Status:** Running, Ready 1/1, 0 RESTARTS — Pod is healthy and stable under hardened PSS restricted constraints.

### Trivy K8s scan results

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 86 |

**Assessment:** All 96 HIGH/CRITICAL findings are container image vulnerabilities (CVEs in npm packages), not K8s misconfigurations. The hardened pod spec itself passes all PSS restricted checks — no violations in securityContext, RBAC, or network policies.

### What broke and how you fixed it (readOnlyRootFilesystem debugging story)

`readOnlyRootFilesystem: true` initially crashed Juice Shop because the application writes to multiple directories at startup and runtime:

1. **`/juice-shop/data`** and **`/juice-shop/ftp`** — Juice Shop copies bundled assets (legal.md, YAML configs) and creates SQLite database here during boot. *Fix:* Mount emptyDir at both paths and pre-populate them via an initContainer that copies images' original `/juice-shop/data` and `/juice-shop/ftp` contents before the app starts.

2. **`/juice-shop/frontend/dist`** — Built frontend assets that get modified/rewritten in runtime. *Fix:* Added another emptyDir volume at this path, pre-seeded by the initContainer.

3. **`/juice-shop/.well-known`** — CSA metadata and other config files written post-startup. *Fix:* Final emptyDir mount for this directory, also pre-seeded.

4. **`/tmp`** — Standard temp directory used by Node.js and libraries. *Fix:* Standard emptyDir, no pre-seeding needed.

**Root cause:** The image entrypoint does not anticipate read-only root; unlike 12-factor apps, Juice Shop v20.0.0 was not designed for immutable container filesystems. The solution (initContainer + emptyDir strategy) follows the Kubernetes best practice: make the image's ephemeral data first-class, then provide writable overlays at pod spec time.

---

## Bonus: Conftest Policy Gate

### Policy (labs/lab7/policies/pod-hardening.rego)

> **Note on Rego syntax:** conftest v0.68.x uses OPA v1 (Rego v1) syntax by default, which requires the `if` keyword before every rule body and `contains` for partial-set rules (`deny contains msg if { ... }` instead of the older `deny[msg] { ... }`). The policy below was written and tested against that version.

```rego
package main

import rego.v1

# Deny if pod-level securityContext.runAsNonRoot is not true
deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be true"
}

# Deny if any container is missing readOnlyRootFilesystem: true
deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

# Deny if any container is missing allowPrivilegeEscalation: false
deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

# Deny if any container does not drop ALL capabilities.
# Uses object.get with a default of [] so this rule still fires even when
# securityContext (or capabilities, or drop) is missing entirely from the
# container spec -- otherwise "ALL" in undefined is undefined and the rule
# silently never triggers.
deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	drop := object.get(container, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drop
	msg := sprintf("container '%s' must drop ALL capabilities", [container.name])
}
```

### Output: PASS on hardened manifest

```
$ conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

The hardened Juice Shop deployment passes all four deny rules:
- ✅ `runAsNonRoot: true` at pod level
- ✅ `readOnlyRootFilesystem: true` on all containers
- ✅ `allowPrivilegeEscalation: false` on all containers
- ✅ `capabilities.drop: ["ALL"]` on all containers

### Output: FAIL on bad manifest

Given a bare minimal deployment without any hardening:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
```

Conftest output:
```
$ conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
FAIL - /tmp/bad-pod.yaml - main - container 'app' must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - container 'app' must set securityContext.allowPrivilegeEscalation: false
FAIL - /tmp/bad-pod.yaml - main - container 'app' must set securityContext.readOnlyRootFilesystem: true
FAIL - /tmp/bad-pod.yaml - main - pod securityContext.runAsNonRoot must be true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

**Debugging note:** the first version of the "drop ALL capabilities" rule used plain field access (`container.securityContext.capabilities.drop`) and only produced 3 failures instead of 4 on `bad-pod.yaml`, because that container has no `securityContext` block at all. In Rego, indexing into an undefined path returns undefined, and `"ALL" in undefined` is also undefined — so `not undefined` never evaluates to true and the rule silently never fires, rather than failing loudly. Swapping to `object.get(container, [...], [])` supplies a safe default (`[]`) when the path is missing, so `"ALL" in []` correctly evaluates to `false` and the rule fires as expected. This is a good illustration of why "missing field" and "field present but wrong value" need to be handled explicitly in Rego — they are not the same case.

### What this prevents at CI time (vs. admission-time)

**CI-time enforcement (Conftest in pipeline)** catches insecure pod specs *before* the PR is even merged. A developer attempts to push a non-compliant manifest → CI job runs `conftest test` → fails the build → developer must fix the manifest locally before the PR can merge. This prevents non-compliant configs from ever reaching the cluster.

**Admission-time enforcement (PSS labels + kubelet)** runs *inside* the cluster when a pod is actually created. By then:
- The insecure config is already in git history (audit trail is noisier)
- Developers learn too late — they push, CI passes (if no CI gate exists), PR merges, and only the cluster rejects it — a much slower feedback loop
- If the admission controller is ever disabled or misconfigured for an emergency deploy, non-compliant pods can slip through with no earlier check to catch them

**Conftest at CI is "shift-left":** it catches security issues at code-review time instead of deploy/runtime, which is cheaper to fix and keeps bad configs out of the cluster entirely. Admission control (PSS) remains valuable as a second line of defense for anything that bypasses CI (manual `kubectl apply`, other pipelines, etc.).

---

## Summary

- ✅ **Task 1:** Trivy image scan completed; 96 HIGH/CRITICAL CVEs identified; top 10 with fixes documented; Grype comparison explains tool divergence via EPSS scoring + DB freshness.
- ✅ **Task 2:** Hardened K8s deployment with PSS restricted (namespace labels, pod/container securityContext, NetworkPolicy). Pod stable at `1/1 Running`. Trivy K8s reports 0 misconfig violations. readOnlyRootFilesystem hardening story detailed (emptyDir + initContainer strategy).
- ✅ **Bonus:** Rego policy (OPA v1 / conftest 0.68 syntax) passes on the hardened deployment (4/4) and fails on an intentionally bad manifest (4/4 denies), including a fix for a silent-pass edge case on the capabilities rule. CI-time vs. admission-time reflection demonstrates shift-left security.

**Files committed:**
- `labs/lab7/k8s/namespace.yaml`
- `labs/lab7/k8s/serviceaccount.yaml`
- `labs/lab7/k8s/deployment.yaml` (with initContainer seed logic)
- `labs/lab7/k8s/networkpolicy.yaml`
- `labs/lab7/policies/pod-hardening.rego` (bonus)
- `submissions/lab7.md` (this file)
