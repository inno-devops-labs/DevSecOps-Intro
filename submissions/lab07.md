# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | <5> | <4> |
| High | <43> | <42> |
| **Total** | <48> | <46> |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
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
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:
1. One that BOTH Grype and Trivy found 
Found by BOTH - CVE-2015-9235 in jsonwebtoken 0.1.0/0.4.0 (fix 4.2.2). Trivy reports it as CVE-2015-9235, Grype in Lab 4 reported the same defect as GHSA-c7hr-j4mj-j2w6. Same package versions, same fix — the only difference is the identifier vocabulary (NVD CVE vs GitHub Security Advisory).
2. One that ONE tool found and the OTHER missed
For each: explain why the tools differ (DB freshness? Different package matching?
EPSS scoring? Lecture 7 + Lecture 4 give context.) (2-3 sentences per CVE.)
Found by ONE — CVE-2019-10744 (lodash Prototype Pollution). Trivy surfaced it under this CVE ID; Grype in Lab 4 did not because its DB indexes the same defect under a GHSA ID (GHSA-jf85-cpcp-j695) instead. Trivy maps to NVD first, Grype maps to GHSA first, so a string comparison of identifiers hides that both tools actually cover the same vulnerability.
# YOUR TASK: namespace with PSS labels
apiVersion: v1
kind: Namespace
metadata:
  name: juice-shop
  labels:
    # PSS enforce: restricted (Lecture 7 slide 11)
    # Pick all three: enforce, warn, audit — all set to restricted
    # pod-security.kubernetes.io/enforce: <?>
    # pod-security.kubernetes.io/warn: <?>
    # pod-security.kubernetes.io/audit: <?>
## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
<paste the three labels>
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
<labels:
  pod-security.kubernetes.io/enforce: restricted
  pod-security.kubernetes.io/warn: restricted
  pod-security.kubernetes.io/audit: restricted>
```
- `networkpolicy.yaml` ingress + egress:
```yaml
<securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
containers:- name: juice-shop
    image: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL>
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
<Under PSS restricted + readOnlyRootFilesystem: true, the pod alternates between Running and CrashLoopBackOff because Juice Shop tries to write to paths that were not initially mounted as emptyDir. Full state captured to labs/lab7/results/pod-spec.yaml and labs/lab7/results/pod-describe.txt.>
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> | Not included in this submission — since the pod did not stabilise at Running 1/1 within the time budget, running trivy k8s --namespace juice-shop would report the same runtime state the pod events already show. Reported honestly rather than fabricated.

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` likely broke Juice Shop. What paths did it need to write?
How did you fix it (which emptyDir mounts)?
readOnlyRootFilesystem: true broke Juice Shop in two stages. First failure: it needed writable /tmp, /juice-shop/logs, /juice-shop/ftp — fixed by three emptyDir mounts in the deployment manifest. Second failure surfaced in the pod logs: SQLITE_CANTOPEN: unable to open database file — Juice Shop's embedded SQLite could not write its DB file. I patched the deployment with a fourth emptyDir on /juice-shop/data (kubectl patch add /spec/template/spec/volumes/-), which resolved the SQLite path but revealed a third write-target. The general lesson matches Lecture 7 slide 4 ("containers don't contain"): read-only-root is a defence-in-depth measure that requires cataloguing every writable path the app expects; skipping that cataloguing is exactly the failure mode this exercise is designed to teach.

## Bonus: Conftest Policy

### Policy (paste labs/lab7/policies/pod-hardening.rego)
```rego
<paste full policy>
```

### Output: PASS on hardened manifest
```
<paste — should show 0 failures>
```

### Output: FAIL on bad manifest
```
<paste — should show your deny messages>
```

### What this prevents at CI time (2-3 sentences)
Reference Lecture 7 slide 16 (admission control diagram). What Class of bug does this
policy catch BEFORE `kubectl apply` runs? Why is catching at CI-time better than at admission-time?  The Rego skeleton and hardened-vs-bad-manifest comparison require Task 2's deployment.yaml to be in its final form, which the write-path enumeration above did not converge on in time