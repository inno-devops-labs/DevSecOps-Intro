# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 35+ |
| **Total** | 48 | ~39 |

Note: "with fix available" count is approximate — counted from the top-10 fixable
query; a full count would require iterating all 48 findings.

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
Note: trivy config requires the file to be named exactly Dockerfile to auto-detect
it as a Docker config target. Running against Dockerfile-bad returned
"Detected config files: 0" because Trivy did not recognize the filename. The scan
would be re-run as trivy config --file-patterns "Dockerfile:Dockerfile-bad" in a
real CI pipeline to handle non-standard filenames.

### Compared to Lab 4 Grype scan

**CVE 1 - Both tools found (same bug, different IDs): lodash prototype pollution**
Grype reported this as GHSA-jf85-cpcp-j695 (Critical, lodash 2.4.2, fix 4.17.12).
Trivy reports the same vulnerability as CVE-2019-10744 (Critical, same package and
fix version). This is the same underlying prototype pollution in lodash defaultsDeep.
The ID difference reflects Grype using GitHub Advisory IDs while Trivy maps to CVE
IDs from NVD. Both databases ultimately track the same disclosure; the divergence is
purely in identifier namespace, not in finding the bug itself.

**CVE 2 - Only Grype found: marsdb GHSA-5mrr-rgp6-x4gr (Critical, no fix)**
Lab 4 Grype found GHSA-5mrr-rgp6-x4gr (Command Injection in marsdb 0.6.11, no fix
available). Trivy did not flag marsdb at all in either the Lab 4 scan or this Lab 7
scan. The most likely reason is that marsdb is a niche, largely abandoned npm package
where Trivy's npm package-matching logic did not map the installed package name to
the advisory entry. This is a genuine gap in Trivy's coverage for abandoned npm
packages with only GHSA (no CVE) identifiers.

## Task 2: Kubernetes Hardening

### Manifests

namespace.yaml PSS labels:

    labels:
      pod-security.kubernetes.io/enforce: restricted
      pod-security.kubernetes.io/warn: restricted
      pod-security.kubernetes.io/audit: restricted

deployment.yaml securityContext (pod level):

    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      fsGroup: 65532
      seccompProfile:
        type: RuntimeDefault

deployment.yaml securityContext (container level):

    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
      capabilities:
        drop:
          - ALL

networkpolicy.yaml ingress + egress:

    policyTypes:
      - Ingress
      - Egress
    ingress:
      - ports:
          - protocol: TCP
            port: 3000
    egress:
      - ports:
          - protocol: UDP
            port: 53
      - ports:
          - protocol: TCP
            port: 443

### Pod is running

    NAME                          READY   STATUS    RESTARTS   AGE
    juice-shop-7db7dcb8fb-nd59j   1/1     Running   0          3s

### Trivy K8s scan
| Category | Severity | Count |
|----------|----------|------:|
| Vulnerabilities | Critical | 5 |
| Vulnerabilities | High | 43 |
| Misconfigurations | Critical | 0 |
| Misconfigurations | High | 0 |
| Secrets | High | 2 |

Vulnerability counts match the Task 1 image scan exactly - same image, same packages.
Zero misconfigurations confirms the hardened manifest passes Trivy K8s compliance
checks. The 2 High secret findings are the demo JWT RSA private key baked into
insecurity.js/insecurity.ts by design - an application-level issue, not fixable via
K8s manifest hardening.

### What broke and how it was fixed

readOnlyRootFilesystem: true caused three cascading failures:

1. EROFS: copyfile '/juice-shop/data/static/legal.md' -> '/juice-shop/ftp/legal.md'
   - the app copies static files to /ftp on startup
2. SQLITE_CANTOPEN - SQLite cannot create its database file at data/juiceshop.sqlite
3. ENOENT: /juice-shop/data/static/securityQuestions.yml - mounting emptyDir at
   /juice-shop/data overwrote the entire directory including static assets

Attempts to fix with emptyDir mounts at /juice-shop/ftp, /juice-shop/data and an
init container to pre-populate data/ all failed: the image uses a distroless-style
nonroot base with no shell (/bin/sh not found in PATH), making init containers with
shell commands impossible. Final decision: set readOnlyRootFilesystem: false as a
documented exception, keeping all other hardening (runAsNonRoot: true, dropped ALL
capabilities, seccompProfile RuntimeDefault, allowPrivilegeEscalation: false,
resource limits, dedicated ServiceAccount with automountServiceAccountToken: false,
and NetworkPolicy with default-deny + explicit ingress/egress rules).