# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 35 | 34 |
| **Total** | **40** | **38** |

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

### Compared to Lab 4's Grype scan

**1. CVE both Grype and Trivy found: CVE-2026-45447 (HIGH, `libssl3t64` 3.5.5-1~deb13u2)**
Both tools flagged the same OpenSSL/debian package vulnerability with a fix version available. Agreement is expected here because both scanners index OS packages from the image's Debian layer using the same underlying distro security advisories; the SBOM-decoupled Grype scan and Trivy's direct image scan converge on well-catalogued system-library CVEs.

**2. CVE only one tool found: CVE-2015-9235 (Trivy only; CRITICAL, `jsonwebtoken` 0.1.0)**
Trivy reported this legacy npm advisory on a deeply nested JavaScript dependency, but Grype did not list it among Critical/High matches. Trivy ships a broader npm/GitHub-advisory feed and matches transitive Node packages aggressively; Grype's SBOM-based matching can miss older npm CVEs when package metadata in the CycloneDX SBOM does not align with Grype's npm namespace mapping, or when severity thresholds differ. This illustrates why decoupled SBOM+SCA and all-in-one image scanning are complementary rather than redundant.

### Config scan (sample bad Dockerfile)
Trivy config on `labs/lab7/results/dockerfile-bad/` found **1 HIGH** failure: `USER root` (AVD-DS-0002). Other intentional misconfigs (`node:latest`, `EXPOSE 22`, remote `ADD`) were below the HIGH/CRITICAL filter on Trivy 0.52.2.

### Commands run (Task 1)
```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json

trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format table | tee labs/lab7/results/trivy-image.txt

trivy config labs/lab7/results/dockerfile-bad \
  --severity HIGH,CRITICAL --format table

jq '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab7/results/trivy-image.json

jq '[.Results[].Vulnerabilities[]? | select(.FixedVersion != null) |
    {cve: .VulnerabilityID, severity: .Severity, pkg: .PkgName, installed: .InstalledVersion, fix: .FixedVersion}] |
    sort_by(.severity) | .[:10]' \
  labs/lab7/results/trivy-image.json
```

## Task 2: Kubernetes Hardening

### Manifests (relevant snippets)

**`namespace.yaml` PSS labels:**
```yaml
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

**`deployment.yaml` securityContext (pod + container):**
```yaml
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      # ...
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

**`networkpolicy.yaml` ingress + egress:**
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
        - protocol: TCP
          port: 53
    - ports:
        - protocol: TCP
          port: 443
```

### Pod is running
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-768595789f-nl8nf   1/1     Running   0          40m
```

### Trivy K8s scan (Workload Assessment — `juice-shop/Deployment/juice-shop`)
| Category | Critical | High |
|----------|----------|------|
| Vulnerabilities (container image) | 10 | 70 |
| Misconfigurations | 0 | 1 |
| Secrets | 0 | 4 |

> Image CVEs are expected (same Juice Shop v20.0.0 from Task 1). The deployment passes PSS `restricted`; remaining findings are mostly image-layer vulnerabilities, not missing `securityContext` hardening.

### What broke and how you fixed it
`readOnlyRootFilesystem: true` broke Juice Shop v20 on startup. First, mounting `emptyDir` directly on `/juice-shop/data` hid bundled static files (`ENOENT` on `data/static/legal.md`). SQLite then failed with `SQLITE_CANTOPEN`. v20 also writes to `/juice-shop/frontend/dist/...` (video assets), `/juice-shop/ftp/`, `/juice-shop/logs/`, `/juice-shop/.well-known/csaf/`, and `/tmp`. Fix: an **initContainer** (using `/nodejs/bin/node`, not `node` — not on PATH in the image) copies `data/` and `frontend/dist/` from the image into `emptyDir` volumes, seeds a CSAF metadata placeholder, and the main container mounts writable `emptyDir` at `/juice-shop/data`, `/juice-shop/frontend/dist`, `/juice-shop/.well-known`, `/juice-shop/ftp`, `/juice-shop/logs`, and `/tmp`.

### Commands run (Task 2)
```bash
kubectl apply -f labs/lab7/k8s/namespace.yaml
kubectl apply -f labs/lab7/k8s/serviceaccount.yaml
kubectl apply -f labs/lab7/k8s/networkpolicy.yaml
kubectl apply -f labs/lab7/k8s/deployment.yaml

kubectl -n juice-shop rollout status deployment/juice-shop --timeout=300s
kubectl -n juice-shop get pod -l app=juice-shop

cp ~/.kube/config labs/lab7/results/kubeconfig-lab7
trivy k8s --kubeconfig labs/lab7/results/kubeconfig-lab7 \
  --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
trivy k8s --kubeconfig labs/lab7/results/kubeconfig-lab7 \
  --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --report=summary
```

## Bonus: Conftest Policy

### Policy (`labs/lab7/policies/pod-hardening.rego`)
```rego
package main

import rego.v1

# Pod-level: runAsNonRoot must be true (PSS restricted)
deny contains msg if {
	input.kind == "Deployment"
	pod_spec := input.spec.template.spec
	not pod_spec.securityContext.runAsNonRoot
	msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot to true"
}

# Container-level hardening checks
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem
	msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not capabilities_drop_all(container)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

capabilities_drop_all(container) if {
	container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest
```
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must drop ALL capabilities
FAIL - /tmp/bad-pod.yaml - main - Container 'app' must set securityContext.readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - Deployment must set spec.template.spec.securityContext.runAsNonRoot to true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### What this prevents at CI time
This policy catches **security misconfiguration** (CWE-16 / Kubernetes Pod Security Standards violations) before manifests reach the cluster — missing `runAsNonRoot`, writable root filesystems, privilege escalation, or undropped capabilities. Per Lecture 7 slide 16, admission control is the last line of defense; CI-time Conftest gates shift the same checks left so developers get immediate feedback in a PR instead of a rejected `kubectl apply` or a non-compliant pod scheduled with only a PSS audit warning.

### Commands run (Bonus)
```bash
conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies

cat > /tmp/bad-pod.yaml <<'EOF'
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
EOF

conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
```
