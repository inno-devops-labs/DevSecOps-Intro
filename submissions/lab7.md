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
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.4.0 | 9.0.0 |

### Dockerfile misconfiguration scan

I scanned a deliberately insecure sample Dockerfile with Trivy config mode.

```text
DS-0002 (HIGH): Last USER command in Dockerfile should not be 'root'
```

This finding means the container would run as the root user. Running containers as root is dangerous because if the application is compromised, the attacker gets stronger permissions inside the container. A safer approach is to create or use a non-root user and set it with the `USER` instruction.

### Compared to Lab 4's Grype scan

#### CVE found by both Grype and Trivy

`CVE-2022-23539` was reported by Trivy for the `jsonwebtoken` package. This type of finding is also expected in Grype because both scanners analyze application dependencies from the same Juice Shop image and map vulnerable package versions to known advisories. Small differences in severity, duplicate entries, or fixed versions can still happen because Trivy and Grype use different vulnerability databases and package matching logic.

#### Finding reported by one tool but not the other

`CVE-2015-9235` was reported by Trivy for the `jsonwebtoken` package, while my Lab 4 comparison showed it as Trivy-only. A likely reason is a difference in vulnerability database freshness or advisory mapping: Trivy mapped the old `jsonwebtoken` versions directly to this CVE, while Grype did not report the same identifier in my previous scan. This shows why comparing scanners is useful: different tools may normalize advisories and package evidence differently.

Another example from Lab 4 was `GHSA-35jh-r3h4-6jhm`, which was Grype-only for an old `lodash` dependency. This can happen when one scanner reports a GitHub Security Advisory identifier while another scanner either maps it differently, ignores it because of package matching, or reports a different CVE/GHSA for the same underlying issue.

---

## Task 2: Kubernetes Hardening

### Manifests

#### `namespace.yaml` PSS labels

```yaml
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
```

#### `deployment.yaml` securityContext sections

Pod-level security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
```

Container-level security context:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

The deployment uses a dedicated ServiceAccount and disables service account token automounting:

```yaml
serviceAccountName: juice-shop-sa
automountServiceAccountToken: false
```

The image is pinned by digest:

```yaml
image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

Writable paths are provided through `emptyDir` volumes while keeping the root filesystem read-only:

```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: logs
    mountPath: /juice-shop/logs
  - name: data
    mountPath: /juice-shop/data
  - name: ftp
    mountPath: /juice-shop/ftp
  - name: frontend-dist
    mountPath: /juice-shop/frontend/dist
  - name: well-known
    mountPath: /juice-shop/.well-known
```

The initContainer copies original application files from the image into writable `emptyDir` volumes before the main container starts:

```yaml
initContainers:
  - name: init-juice-shop-data
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    imagePullPolicy: IfNotPresent
    command:
      - /nodejs/bin/node
      - -e
      - |
        const fs = require('fs');
        const path = require('path');

        function copyContents(src, dst) {
          fs.mkdirSync(dst, { recursive: true });

          if (!fs.existsSync(src)) {
            return;
          }

          for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
            const srcPath = path.join(src, entry.name);
            const dstPath = path.join(dst, entry.name);

            if (entry.isDirectory()) {
              copyContents(srcPath, dstPath);
            } else if (entry.isFile()) {
              fs.copyFileSync(srcPath, dstPath);
            }
          }
        }

        copyContents('/juice-shop/data', '/work-data');
        copyContents('/juice-shop/ftp', '/work-ftp');
        copyContents('/juice-shop/frontend/dist', '/work-frontend-dist');
        copyContents('/juice-shop/.well-known', '/work-well-known');
```

#### `networkpolicy.yaml` ingress + egress

```yaml
policyTypes:
  - Ingress
  - Egress
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
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - protocol: TCP
        port: 443
```

### Pod is running

Output of `kubectl get pod -n juice-shop -l app=juice-shop`:

```text
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-685498bdcb-fl85t   1/1     Running   0          115s
```

### PSS namespace labels verification

Output of `kubectl get ns juice-shop -o yaml | grep pod-security`:

```text
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
```

### Trivy K8s scan

| Severity | Count |
|----------|------:|
| Critical | 10 |
| High | 90 |

Trivy summary reported 10 critical vulnerabilities and 86 high vulnerabilities for the Juice Shop Deployment. It also reported 4 high-severity secret findings, so the JSON severity count is 90 high findings in total.

### What broke and how I fixed it

`readOnlyRootFilesystem: true` broke Juice Shop because the application writes files during startup. It needed writable paths for `/tmp`, logs, SQLite data, FTP files, frontend static assets, and `.well-known` metadata. I fixed this by mounting `emptyDir` volumes at `/tmp`, `/juice-shop/logs`, `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/frontend/dist`, and `/juice-shop/.well-known`.

A simple `emptyDir` mount over `/juice-shop/data` was not enough because it hid original application files such as `securityQuestions.yml` and static files. To solve this, I added an initContainer that runs `/nodejs/bin/node` and copies the original `/juice-shop/data`, `/juice-shop/ftp`, `/juice-shop/frontend/dist`, and `/juice-shop/.well-known` contents into writable `emptyDir` volumes before the main container starts.

---

## Bonus: Conftest Policy

### Policy

```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "pod must set spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("container %s must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %s must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("container %s must drop ALL Linux capabilities", [container.name])
}

drops_all_capabilities(container) if {
  container.securityContext.capabilities.drop[_] == "ALL"
}
```

### Output: PASS on hardened manifest

Command:

```bash
conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
```

Output:

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Output: FAIL on bad manifest

Command:

```bash
conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
```

Output:

```text
FAIL - /tmp/bad-pod.yaml - main - container app must drop ALL Linux capabilities
FAIL - /tmp/bad-pod.yaml - main - container app must set allowPrivilegeEscalation to false
FAIL - /tmp/bad-pod.yaml - main - container app must set readOnlyRootFilesystem to true
FAIL - /tmp/bad-pod.yaml - main - pod must set spec.securityContext.runAsNonRoot to true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

This policy prevents insecure Kubernetes deployments from reaching the cluster when they miss important hardening settings such as non-root execution, read-only root filesystem, disabled privilege escalation, and dropped Linux capabilities. Catching this in CI is better than catching it only at admission time because developers get feedback before merge or deployment. It also keeps the main branch and deployment manifests compliant by default, instead of relying only on the cluster to reject bad resources later.
