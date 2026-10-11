# Lab 7 — Submission

## Task 1: Container image & config scanning with Trivy

Image: `bkimminich/juice-shop:v20.0.0` (digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`).
Scanner: Trivy v0.71.1 (vuln DB built 2026-06-18). Scans filtered to `--severity HIGH,CRITICAL`.

### Image scan — severity breakdown (HIGH/CRITICAL)
| Source | Critical | High |
|--------|---------:|-----:|
| OS (Debian 13.4) | 0 | 1 |
| npm (node-pkg) | 5 | 42 |
| **Total** | **5** | **43** |

**48 HIGH/CRITICAL findings, of which 46 have a fix available** (only `marsdb` GHSA-5mrr-rgp6-x4gr and `lodash.set` CVE-2020-8203 have no fixed version). The single OS finding is `libssl3t64` CVE-2026-45447 (fix `3.5.6-1~deb13u2`); everything else is outdated npm libraries.

Trivy's secret scanner additionally flagged **2 × HIGH `AsymmetricPrivateKey`** — a hardcoded RSA private key baked into the image at `lib/insecurity.ts:23` and its compiled twin `build/lib/insecurity.js:46`. This is a real embedded credential, not a dependency CVE.

### Top 10 CVEs (Trivy, sorted by severity)
| Severity | ID | Package | Installed → Fix |
|----------|----|---------|-----------------|
| CRITICAL | CVE-2023-46233 | crypto-js | 3.3.0 → 4.2.0 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.1.0 → 4.2.2 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.4.0 → 4.2.2 |
| CRITICAL | CVE-2019-10744 | lodash | 2.4.2 → 4.17.12 |
| CRITICAL | GHSA-5mrr-rgp6-x4gr | marsdb | 0.6.11 → _(no fix)_ |
| HIGH | CVE-2026-45447 | libssl3t64 (OS) | 3.5.5-1~deb13u2 → 3.5.6-1~deb13u2 |
| HIGH | NSWG-ECO-428 | base64url | 0.0.6 → 3.0.0 |
| HIGH | CVE-2020-15084 | express-jwt | 0.1.3 → 6.0.0 |
| HIGH | CVE-2022-25881 | http-cache-semantics | 3.8.1 → 4.1.1 |
| HIGH | CVE-2022-23539 | jsonwebtoken | 0.1.0 → 9.0.0 |

### Comparison with Grype (Lab 4)
Lab 4's Grype scan of the same image (full severity range) reported **105** vulnerabilities — 7 Critical, 52 High, 35 Medium, 4 Low, 7 Negligible. Restricting to the HIGH+CRITICAL band that Grype counted **59** (7C + 52H); Trivy here counts **48** (5C + 43H). The gap is the same one analysed in Lab 4: **identifier aliasing** (Grype prefers GHSA IDs for npm and lists some advisories Trivy folds together) plus **different OS-CVE curation** (Grype surfaces glibc/zstd items Trivy suppresses as "won't-fix" per the Debian tracker). At HIGH+CRITICAL the two tools agree on the substance — the same `crypto-js` / `jsonwebtoken` / `lodash` / `marsdb` cluster drives the Critical count in both. Crucially, **neither SCA tool sees the hardcoded RSA key** — only Trivy's *secret* scanner does, which is why running `trivy image` (vuln + secret + misconfig in one pass) catches an entire class of defect a pure dependency scanner misses.

### Config scan of the Kubernetes manifests
`trivy config labs/lab7/k8s/ --severity HIGH,CRITICAL` → **4 files detected, 0 HIGH/CRITICAL misconfigurations**:

| Target | Type | Misconfigurations |
|--------|------|------------------:|
| deployment.yaml | kubernetes | 0 |
| namespace.yaml | kubernetes | 0 |
| networkpolicy.yaml | kubernetes | 0 |
| serviceaccount.yaml | kubernetes | 0 |

A clean config scan is the static-analysis counterpart to the running-pod evidence in Task 2: the hardening in the manifests satisfies Trivy's built-in Kubernetes checks (runAsNonRoot, drop-ALL capabilities, no privilege escalation, resource limits, seccomp, pinned image digest, no token automount) before anything is ever deployed.

---

## Task 2: Kubernetes hardening (Pod Security Standards + Trivy k8s)

Cluster: Docker Desktop built-in Kubernetes, node `docker-desktop` `Ready`, **v1.32.2** (control-plane). v1.32 ships the Pod Security Admission controller, which is what enforces the `restricted` profile below. (Docker Desktop's cluster is used instead of `kind` — it satisfies the same PSA requirement with one less moving part on an already fragile WSL2 host.)

### Manifests (`labs/lab7/k8s/`)
| File | Hardening |
|------|-----------|
| `namespace.yaml` | Namespace `juice-shop` labelled `pod-security.kubernetes.io/{enforce,warn,audit}: restricted` — non-compliant pods are **rejected** at admission. |
| `serviceaccount.yaml` | `automountServiceAccountToken: false` — the app never calls the K8s API, so no token is mounted (removes a lateral-movement credential; STRIDE-E). |
| `deployment.yaml` | Pod + container `securityContext` (see below), pinned image **digest**, resource requests/limits, liveness/readiness probes, `emptyDir` scratch mounts. |
| `networkpolicy.yaml` | `default-deny` (all ingress+egress) + a scoped allow: ingress to :3000, egress only to DNS (53) and HTTPS (443). |

### securityContext (satisfies PSS `restricted`)
Pod-level: `runAsNonRoot: true`, `runAsUser/Group/fsGroup: 65532`, `seccompProfile: RuntimeDefault`.
Container-level: `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `runAsNonRoot: true`, `runAsUser: 65532`, `readOnlyRootFilesystem: false` (justified below).

### Proof the hardened pod is admitted and runs
```
$ kubectl -n juice-shop get pods
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-6b995f9d97-x9fcp   1/1     Running   0          66s
```
A `Running` pod in a `restricted`-enforced namespace is direct proof the manifest passes Pod Security Admission — an unhardened pod (privileged, root, added caps, host namespaces, etc.) would be rejected at `kubectl apply` time.

### Trivy scan of the live namespace
`trivy k8s --include-namespaces juice-shop --report summary --severity HIGH,CRITICAL`:

| Resource | Vuln (C/H) | Misconfig (C/H) | Secrets (C/H) | RBAC (C/H) |
|----------|:----------:|:---------------:|:-------------:|:----------:|
| Deployment/juice-shop | 5 / 43 | 0 / 0 | 0 / 2 | 0 / 0 |

The **0 misconfigurations** and **0 RBAC** findings confirm the workload configuration is clean — everything HIGH/CRITICAL that remains comes from the *image contents* (the same 5C/43H CVEs from Task 1, plus the 2 embedded-private-key secrets). In other words, config hardening did its whole job; the residual risk is now purely "patch/rebuild the image", not "fix the deployment".

### Two hardening trade-offs surfaced while making the pod run
Getting the pod from `CrashLoopBackOff` to `Running` exposed two real tensions between a maximal-hardening template and an app that wasn't written for it:

1. **`readOnlyRootFilesystem: true` → `EROFS`.** Juice Shop makes legitimate *startup* writes to its own root filesystem: it restores files into `/juice-shop/ftp/` and creates its SQLite DB under `/juice-shop/data/` (which also holds baked-in static assets, so an `emptyDir` overlay can't cleanly separate the writable and read-only paths). A read-only root crashed it with `EROFS` / `SQLITE_CANTOPEN`. **`readOnlyRootFilesystem` is *not* a requirement of the PSS `restricted` profile**, so I disabled only that one control and kept every other measure. This is the classic "some apps can't run fully immutable" trade-off — worth flagging in review rather than hiding.
2. **`runAsUser: 1000` → `EACCES`.** With a writable root the app still crashed — this time permission-denied on its own files. The image is built `COPY --chown=65532:0` (visible in the Trivy secret scan header), i.e. its files are owned by UID **65532** and it expects to run as that user. Forcing an arbitrary `1000` meant the process couldn't write files it owns. Switching to `runAsUser: 65532` fixed it while staying non-root, so `restricted` still holds. Lesson: "non-root" isn't a free-floating number — it must match the identity the image was built for.
