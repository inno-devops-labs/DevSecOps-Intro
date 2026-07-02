# Lab 7 — Submission

## Environment

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
kubectl: gitVersion: v1.36.2
kind: kind v0.32.0 go1.26.3 linux/amd64
Trivy image: aquasec/trivy:0.69.3
Conftest image: openpolicyagent/conftest:v0.68.0
Target: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|------:|-------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | **48** | **46** |

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| `CVE-2015-9235` | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| `CVE-2015-9235` | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| `CVE-2019-10744` | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| `CVE-2023-46233` | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| `CVE-2016-1000223` | HIGH | jws | 0.2.6 | >=3.0.0 |
| `CVE-2017-18214` | HIGH | moment | 2.0.0 | 2.19.3 |
| `CVE-2018-16487` | HIGH | lodash | 2.4.2 | >=4.17.11 |
| `CVE-2020-15084` | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| `CVE-2021-23337` | HIGH | lodash | 2.4.2 | 4.17.21 |
| `CVE-2022-23539` | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |

### Dockerfile misconfiguration scan

| Rule | Severity | Finding |
|------|----------|---------|
| `DS-0002` | HIGH | Image user should not be 'root' |

### Compared with Grype

**Finding reported by both tools:** `CVE-2026-45447`.

This agreement indicates that both scanners mapped the affected package and advisory to
the image inventory. Matching results are strongest when both databases contain the same
advisory and both scanners identify the package using compatible distro/package metadata.

**Tool-divergent finding:** `CVE-2015-9235 (Trivy only)`.

A one-tool-only result is not automatically a false positive. Trivy and Grype can differ
because their vulnerability databases update at different times, their package and CPE
matching logic differs, and they may make different decisions about distro backports,
vendor status, or whether a fix is applicable. The comparison used reports captured in
the same run to reduce database-freshness skew.

## Task 2: Kubernetes Hardening

### Namespace with PSS enforcement

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: juice-shop
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
```

### Hardened Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-shop
  namespace: juice-shop
  labels:
    app: juice-shop
spec:
  replicas: 1
  selector:
    matchLabels:
      app: juice-shop
  template:
    metadata:
      labels:
        app: juice-shop
    spec:
      serviceAccountName: juice-shop
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 0
        fsGroup: 0
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: initialize-writable-directories
          image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
          imagePullPolicy: IfNotPresent
          command: ["/nodejs/bin/node", "-e"]
          args:
            - |
              const fs = require("node:fs");
              const path = require("node:path");

              function copyTree(source, destination) {
                fs.mkdirSync(destination, { recursive: true });

                if (!fs.existsSync(source)) {
                  return;
                }

                for (const entry of fs.readdirSync(source, {
                  withFileTypes: true
                })) {
                  const src = path.join(source, entry.name);
                  const dst = path.join(destination, entry.name);

                  if (entry.isDirectory()) {
                    copyTree(src, dst);
                  } else if (entry.isFile()) {
                    fs.copyFileSync(src, dst);
                  }
                }
              }

              for (const directory of [
                "logs",
                "data",
                "ftp",
                "uploads",
                "frontend/dist",
                "i18n",
                ".well-known"
              ]) {
                copyTree(
                  `/juice-shop/${directory}`,
                  `/work/${directory}`
                );
              }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 25m
              memory: 32Mi
            limits:
              cpu: 100m
              memory: 128Mi
          volumeMounts:
            - name: logs
              mountPath: /work/logs
            - name: data
              mountPath: /work/data
            - name: ftp
              mountPath: /work/ftp
            - name: uploads
              mountPath: /work/uploads
            - name: frontend-dist
              mountPath: /work/frontend/dist
            - name: i18n
              mountPath: /work/i18n
            - name: well-known
              mountPath: /work/.well-known
      containers:
        - name: juice-shop
          image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
          imagePullPolicy: IfNotPresent
          ports:
            - name: http
              containerPort: 3000
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 750m
              memory: 768Mi
          readinessProbe:
            httpGet:
              path: /
              port: http
            initialDelaySeconds: 15
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 24
          livenessProbe:
            httpGet:
              path: /
              port: http
            initialDelaySeconds: 45
            periodSeconds: 15
            timeoutSeconds: 3
            failureThreshold: 5
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: logs
              mountPath: /juice-shop/logs
            - name: data
              mountPath: /juice-shop/data
            - name: ftp
              mountPath: /juice-shop/ftp
            - name: uploads
              mountPath: /juice-shop/uploads
            - name: frontend-dist
              mountPath: /juice-shop/frontend/dist
            - name: i18n
              mountPath: /juice-shop/i18n
            - name: well-known
              mountPath: /juice-shop/.well-known
            - name: legacy-logs
              mountPath: /usr/src/app/logs
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 128Mi
        - name: logs
          emptyDir:
            sizeLimit: 128Mi
        - name: data
          emptyDir:
            sizeLimit: 512Mi
        - name: ftp
          emptyDir:
            sizeLimit: 256Mi
        - name: uploads
          emptyDir:
            sizeLimit: 256Mi
        - name: frontend-dist
          emptyDir:
            sizeLimit: 256Mi
        - name: i18n
          emptyDir:
            sizeLimit: 64Mi
        - name: well-known
          emptyDir:
            sizeLimit: 16Mi
        - name: legacy-logs
          emptyDir:
            sizeLimit: 128Mi
```

### NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: juice-shop-restricted-network
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

### Pod is running

```text
NAME                          READY   STATUS    RESTARTS   AGE    IP            NODE                 NOMINATED NODE   READINESS GATES
juice-shop-8647457794-ldp9c   1/1     Running   0          3m9s   10.244.0.10   lab7-control-plane   <none>           <none>
```

### Trivy Kubernetes scan

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |

### What broke and how it was fixed

A read-only root filesystem prevents Juice Shop from writing runtime state to locations
such as `/tmp`, logs, the SQLite-backed data directory, uploads, and FTP content. The
deployment mounts bounded `emptyDir` volumes at those paths; an equally hardened init
container copies packaged seed content into the writable volumes before the application
starts. This preserves `readOnlyRootFilesystem: true` without making the application
unusable.

## Bonus: Conftest Policy

### Policy

```rego
package main

import rego.v1

is_deployment if {
  input.kind == "Deployment"
}

pod_spec := input.spec.template.spec if {
  is_deployment
}

all_containers := array.concat(
  object.get(pod_spec, "initContainers", []),
  object.get(pod_spec, "containers", [])
) if {
  is_deployment
}

deny contains msg if {
  is_deployment
  object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
  msg := "pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  is_deployment
  container := all_containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
  is_deployment
  container := all_containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  is_deployment
  container := all_containers[_]
  context := object.get(container, "securityContext", {})
  capabilities := object.get(context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])
  not "ALL" in dropped
  msg := sprintf("container %q must drop the ALL capability set", [container.name])
}
```

### PASS on the hardened manifest

```text
[32m4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions[0m
```

### FAIL on the intentionally bad manifest

```text
[31mFAIL[0m - labs/lab7/results/bad-deployment.yaml - main - container "app" must drop the ALL capability set
[31mFAIL[0m - labs/lab7/results/bad-deployment.yaml - main - container "app" must set allowPrivilegeEscalation=false
[31mFAIL[0m - labs/lab7/results/bad-deployment.yaml - main - container "app" must set readOnlyRootFilesystem=true
[31mFAIL[0m - labs/lab7/results/bad-deployment.yaml - main - pod securityContext.runAsNonRoot must be true

[31m4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions[0m
```

### What this prevents at CI time

The policy catches missing non-root execution, writable root filesystems, privilege
escalation, and retained Linux capabilities before a manifest reaches `kubectl apply`.
CI-time rejection gives developers immediate, reproducible feedback and prevents an
invalid artifact from ever reaching admission control, while cluster admission remains
the final defense against bypasses and out-of-band deployments.

## Completion checklist

- [x] Trivy image vulnerability scan completed.
- [x] Trivy Dockerfile configuration scan completed.
- [x] Fixed HIGH/CRITICAL CVEs were prioritized.
- [x] PSS `restricted` labels, ServiceAccount, security contexts, resources, and NetworkPolicy were added.
- [x] The Juice Shop pod reached Ready state.
- [x] Trivy Kubernetes scan completed.
- [x] Conftest passed the hardened Deployment and rejected a bad Deployment.
