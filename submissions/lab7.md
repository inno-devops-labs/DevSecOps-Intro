# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 4 | 4 |
| High | 6 | 6 |
| **Total** | 10 | 10 |

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

**CVE found by BOTH tools:**
CVE-2023-46233 / GHSA-xwcq-pm8m-c4vf (crypto-js, CRITICAL) - Both Trivy and Grype detected this vulnerability because it's a well-documented CVE with clear version ranges (affected < 4.2.0), and both tools maintain up-to-date vulnerability databases that include this entry. The consistent detection demonstrates that established CVEs are reliably identified across different scanners when their databases are current.

**CVE found by Trivy but missed by Grype:**
CVE-2015-9235 / GHSA-c7hr-j4mj-j2w6 (jsonwebtoken, CRITICAL) - Trivy detected this vulnerability while Grype missed it because Trivy uses a broader vulnerability database that includes older CVEs with proper version mapping, whereas Grype may have filtered out this CVE due to its age (2015) or different matching criteria for legacy version ranges.

**CVE found by Grype but missed by Trivy:**
GHSA-35jh-r3h4-6jhm (lodash, HIGH) - Grype detected this vulnerability in lodash 2.4.2 while Trivy missed it due to differences in vulnerability database sources. Grype uses GitHub Advisory Database which includes this GHSA entry for lodash prototype pollution, while Trivy's database may not have this specific advisory mapped to such an old version (2.4.2).


## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)

**namespace.yaml PSS labels:**
```yml
apiVersion: v1
kind: Namespace
metadata:
    name: juice-shop
    labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

**deployment.yaml securityContext sections (pod + container):**
```yml
spec:
    serviceAccountName: juice-shop-sa
    automountServiceAccountToken: false
    securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
        type: RuntimeDefault
    containers:
    - name: juice-shop
    image: bkimminich/juice-shop:latest
    securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
        drop: ["ALL"]
    resources:
        requests:
        memory: "256Mi"
        cpu: "250m"
        limits:
        memory: "512Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
        mountPath: /tmp
    - name: logs
        mountPath: /usr/src/app/logs
    - name: data
        mountPath: /juice-shop/data
    - name: ftp
        mountPath: /juice-shop/ftp
    - name: uploads
        mountPath: /usr/src/app/uploads
    volumes:
    - name: tmp
    emptyDir: {}
    - name: logs
    emptyDir: {}
    - name: data
    emptyDir: {}
    - name: ftp
    emptyDir: {}
    - name: uploads
    emptyDir: {}
```

**networkpolicy.yaml ingress + egress:**
```yml
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
    - ipBlock:
        cidr: 0.0.0.0/0
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
    - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
        port: 443
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-58d8fb9bd7-9lg5h   1/1     Running   0          2m
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 6 |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` broke Juice Shop because it needed to write to `/tmp`, `/juice-shop/data`, `/juice-shop/ftp`, and `/usr/src/app/logs` for SQLite database operations, file copying, and logging. I fixed it by adding emptyDir volumes mounted at these writable paths while maintaining the read-only root filesystem for security. The key was identifying all write paths from the error logs and creating appropriate emptyDir mounts for each location.