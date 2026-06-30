# Lab 7 — Submission

## Environment

- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Local Kubernetes cluster: `kind-lab7`
- Trivy version used locally: `0.71.2`

Note: The lab asks for Trivy `v0.69.x`, but this local environment used Trivy `0.71.2`. Vulnerability results may differ from `v0.69.x` because Trivy scanner versions and vulnerability databases change over time.

---

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

Trivy also detected two high-severity secret findings in the Juice Shop image:

- `/juice-shop/build/lib/insecurity.js` — `AsymmetricPrivateKey`
- `/juice-shop/lib/insecurity.ts` — `AsymmetricPrivateKey`

These findings are expected in a deliberately vulnerable training application, but they still demonstrate why secret scanning is useful for container images.

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

### Trivy config scan

A deliberately insecure Dockerfile was scanned with `trivy config`.

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |

Finding:

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| DS-0002 | HIGH | Last USER command in Dockerfile should not be `root` | `Dockerfile:2` |

This confirms that Trivy config scanning can catch container build-time hardening issues such as running the final image as root.

### Compared to Lab 4's Grype scan

For comparison, I used the Lab 4 Grype result from:

```text
labs/lab4/grype-from-sbom.json
```

CVEs found by both tools:

```text
CVE-2026-45447
GHSA-5mrr-rgp6-x4gr
```

Example found by both tools:

1. `CVE-2026-45447`

Both Trivy and Grype reported `CVE-2026-45447`, which affected `libssl3t64` in the Debian layer of the image. This is expected because OS package vulnerabilities are usually easier for both tools to match consistently: the package name, installed version, distro family, and fixed version are clearly available from the image metadata.

Example found by one tool only:

2. `CVE-2023-46233`

Trivy reported `CVE-2023-46233` for `crypto-js`, while it did not appear in the Grype comparison output from Lab 4. The likely reason is a combination of database freshness and package matching differences. Trivy 0.71.2 used a freshly downloaded vulnerability database during this scan, while the Lab 4 Grype output was generated earlier. The tools also use different vulnerability sources and matching logic for Node.js packages, so transitive dependency findings may not line up exactly. EPSS can further affect prioritization and triage order even when the raw detection sets differ.

Other Trivy-only examples included:

```text
CVE-2015-9235
CVE-2016-1000223
CVE-2017-18214
CVE-2018-16487
CVE-2019-10744
CVE-2020-15084
CVE-2020-8203
CVE-2021-23337
CVE-2022-23539
CVE-2022-24785
CVE-2022-25881
CVE-2022-25887
CVE-2023-46233
CVE-2024-37890
CVE-2025-47935
CVE-2025-47944
CVE-2025-48997
CVE-2025-65945
CVE-2025-7338
CVE-2026-2359
```

Other Grype-only examples included:

```text
CVE-2010-4756
CVE-2018-20796
CVE-2019-1010022
CVE-2019-1010023
CVE-2019-1010024
CVE-2019-1010025
CVE-2019-9192
CVE-2026-27171
CVE-2026-34180
CVE-2026-34181
CVE-2026-34182
CVE-2026-34183
CVE-2026-4046
CVE-2026-42764
CVE-2026-42766
CVE-2026-42767
CVE-2026-42768
CVE-2026-42769
CVE-2026-42770
CVE-2026-4437
```

The difference shows why vulnerability scanners should not be treated as identical sources of truth. For prioritization, I would focus first on findings with severity HIGH or CRITICAL and an available fix, then check whether multiple scanners agree.

---

## Task 2: Kubernetes Hardening

### Manifests

The lab includes four Kubernetes manifests:

```text
labs/lab7/k8s/namespace.yaml
labs/lab7/k8s/serviceaccount.yaml
labs/lab7/k8s/deployment.yaml
labs/lab7/k8s/networkpolicy.yaml
```

### `namespace.yaml` PSS labels

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

These labels enable Pod Security Admission for the namespace and apply the `restricted` profile in enforce, warn, and audit modes.

### `serviceaccount.yaml`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: juice-shop-sa
  namespace: juice-shop
automountServiceAccountToken: false
```

The workload uses a dedicated non-default ServiceAccount, and automatic ServiceAccount token mounting is disabled.

### `deployment.yaml` securityContext sections

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

Resource requests and limits:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

Writable paths were provided with `emptyDir` volumes:

```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: logs
    mountPath: /usr/src/app/logs
  - name: data
    mountPath: /juice-shop/data
  - name: frontend-dist
    mountPath: /juice-shop/frontend/dist
```

The image is pinned by digest:

```yaml
image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### `networkpolicy.yaml` ingress + egress

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
        podSelector:
          matchLabels:
            k8s-app: kube-dns
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

The policy restricts normal pod traffic to explicit ingress on port 3000 from the namespace and limits egress to DNS and HTTPS. Local testing with `kubectl port-forward` remains possible because port-forwarding is API-server mediated and is not the same as unrestricted pod-to-pod ingress.

### Pod is running

Output of `kubectl get pod -n juice-shop -l app=juice-shop -o wide`:

```text
NAME                          READY   STATUS    RESTARTS   AGE   IP           NODE                 NOMINATED NODE   READINESS GATES
juice-shop-7f58f577f4-fj74k   1/1     Running   0          16s   10.244.0.5   lab7-control-plane   <none>           <none>
```

### Live security context proof

```json
{
  "serviceAccountName": "juice-shop-sa",
  "automountServiceAccountToken": false,
  "podSecurityContext": {
    "fsGroup": 1000,
    "runAsGroup": 1000,
    "runAsNonRoot": true,
    "runAsUser": 1000,
    "seccompProfile": {
      "type": "RuntimeDefault"
    }
  },
  "containerSecurityContext": {
    "allowPrivilegeEscalation": false,
    "capabilities": {
      "drop": [
        "ALL"
      ]
    },
    "readOnlyRootFilesystem": true
  },
  "resources": {
    "limits": {
      "cpu": "500m",
      "memory": "512Mi"
    },
    "requests": {
      "cpu": "100m",
      "memory": "256Mi"
    }
  },
  "volumeMounts": [
    {
      "mountPath": "/tmp",
      "name": "tmp"
    },
    {
      "mountPath": "/usr/src/app/logs",
      "name": "logs"
    },
    {
      "mountPath": "/juice-shop/data",
      "name": "data"
    },
    {
      "mountPath": "/juice-shop/frontend/dist",
      "name": "frontend-dist"
    }
  ],
  "volumes": [
    {
      "emptyDir": {},
      "name": "tmp"
    },
    {
      "emptyDir": {},
      "name": "logs"
    },
    {
      "emptyDir": {},
      "name": "data"
    },
    {
      "emptyDir": {},
      "name": "frontend-dist"
    }
  ]
}
```

### Trivy K8s scan

| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |

The Trivy K8s scan reported the same HIGH and CRITICAL vulnerabilities as the image scan because the Kubernetes Deployment uses the same Juice Shop image. The summary did not report HIGH or CRITICAL Kubernetes misconfigurations for the hardened workload.

The summary report showed:

```text
Deployment/juice-shop
Vulnerabilities: CRITICAL 5, HIGH 43
Misconfigurations: CRITICAL 0, HIGH 0
Secrets: CRITICAL 0, HIGH 2
```

### What broke and how it was fixed

`readOnlyRootFilesystem: true` can break Juice Shop because the application expects to write runtime files. To keep the container filesystem read-only while still allowing required runtime writes, I mounted `emptyDir` volumes at `/tmp`, `/usr/src/app/logs`, `/juice-shop/data`, and `/juice-shop/frontend/dist`. This preserves the hardening benefit of a read-only root filesystem while giving the application isolated writable scratch locations.

---

## Bonus: Conftest Policy

### Policy

File:

```text
labs/lab7/policies/pod-hardening.rego
```

Policy content:

```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not allow_privilege_escalation_false(container)
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not has_drop_all(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

allow_privilege_escalation_false(container) if {
  container.securityContext.allowPrivilegeEscalation == false
}

has_drop_all(container) if {
  some i
  container.securityContext.capabilities.drop[i] == "ALL"
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

The bad manifest intentionally omitted pod and container security contexts.

Command:

```bash
conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
```

Output:

```text
FAIL - /tmp/bad-pod.yaml - main - container "app" must drop ALL Linux capabilities
FAIL - /tmp/bad-pod.yaml - main - container "app" must set allowPrivilegeEscalation=false
FAIL - /tmp/bad-pod.yaml - main - container "app" must set readOnlyRootFilesystem=true
FAIL - /tmp/bad-pod.yaml - main - pod securityContext.runAsNonRoot must be true

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### What this prevents at CI time

This policy catches missing container hardening before `kubectl apply` runs. It prevents insecure pod specs from reaching the cluster when they omit `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, or `capabilities.drop: ["ALL"]`. Catching this in CI is better than relying only on admission control because developers get fast feedback before deployment, and insecure manifests are blocked earlier in the delivery pipeline.
