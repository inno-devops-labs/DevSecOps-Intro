**# Lab 7 — Submission**

I scanned Juice Shop together with an intentionally insecure Dockerfile, and then deployed the same image to a local Kubernetes cluster configured with restricted Pod Security, network isolation, and a read-only root filesystem. The final Kubernetes manifests are stored in [labs/lab7/k8s](../labs/lab7/k8s/); the raw scanner results and runtime evidence are kept locally in the ignored `labs/lab7/results/` directory.

**## Environment and reproducibility**

| Item             | Version or reference                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| Scan date        | 29 September 2026                                                                                        |
| Application      | `bkimminich/juice-shop:v20.0.0`, Linux/amd64                                                             |
| Pinned image     | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`          |
| Trivy            | 0.74.0 on Windows; Linux container used to cross-check Kubernetes misconfigurations                      |
| Trivy container  | `aquasec/trivy:0.74.0`, digest `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| Vulnerability DB | Schema 2, updated `2026-09-29T07:15:39.724391795Z`                                                       |
| k3d / kubectl    | 5.9.0 / 1.34.1                                                                                           |
| Kubernetes       | `rancher/k3s:v1.33.0-k3s1`                                                                               |

The image digest and configured user were obtained with `docker inspect`, rather than being inferred from the image tag. I created a separate k3d kubeconfig and configured the Kubernetes API to be accessible only through loopback:

```powershell
k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1 `
  --api-port 127.0.0.1:6550 `
  --kubeconfig-update-default=false --kubeconfig-switch-context=false
$env:KUBECONFIG = (k3d kubeconfig write lab7)
```

**## Task 1**

**### Image vulnerabilities and available fixes**

```powershell
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL `
  --format json --output labs/lab7/results/trivy-image.json
```

The scan finished successfully in 10.08 seconds. The following numbers were calculated from the JSON `Vulnerabilities` arrays. They count vulnerability/package matches rather than unique advisory IDs, and secret findings are not included.

| Severity  | Matches | With a listed fix | Without a listed fix |
| --------- | ------: | ----------------: | -------------------: |
| Critical  |      10 |                 8 |                    2 |
| High      |      64 |                63 |                    1 |
| **Total** |  **74** |            **71** |                **3** |

Since only High and Critical severities were selected, these figures do not represent the total number of vulnerabilities across all severities.

For fix availability, I considered a finding fixable when `FixedVersion` was nonempty. The assignment's `FixedVersion != null` filter therefore produces the same 71 findings in this report.

An earlier Grype SBOM scan of the same image digest is also available for comparison:

| Comparable severity | Grype, 20 September | Trivy, 23 September |
| ------------------- | ------------------: | ------------------: |
| Critical            |                  14 |                  10 |
| High                |                  85 |                  64 |
| **High + Critical** |              **99** |              **74** |

Grype reported 183 findings across all severities in the original scan, so that number should not be compared directly with the High/Critical-only Trivy results. The difference between 99 and 74 may be caused by differences in package inventory and matching coverage, severity sources, advisory aliases, and the three-day difference between database snapshots. It therefore does not indicate that the unchanged image itself became safer.

**### First ten fixable findings**

The following are the first ten fixable entries after sorting by Critical and then High severity, while preserving Trivy's original ordering within each severity:

| Severity | Advisory       | Package      | Installed       | Listed fix      |
| -------- | -------------- | ------------ | --------------- | --------------- |
| Critical | CVE-2023-46233 | crypto-js    | 3.3.0           | 4.2.0           |
| Critical | CVE-2026-71851 | crypto-js    | 3.3.0           | 4.0.0           |
| Critical | CVE-2015-9235  | jsonwebtoken | 0.1.0           | 4.2.2           |
| Critical | CVE-2015-9235  | jsonwebtoken | 0.4.0           | 4.2.2           |
| Critical | CVE-2019-10744 | lodash       | 2.4.2           | 4.17.12         |
| Critical | CVE-2026-59873 | tar          | 4.4.19          | 7.5.19          |
| Critical | CVE-2026-59873 | tar          | 6.2.1           | 7.5.19          |
| Critical | CVE-2026-59873 | tar          | 7.5.15          | 7.5.19          |
| High     | CVE-2026-14456 | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| High     | CVE-2026-45447 | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

The listed fix version applies to the specific advisory and should not be interpreted as a recommendation to stop at the oldest available version. For instance, `crypto-js` has to meet both applicable version requirements, while every affected `tar` installation needs to be addressed.

**### Dockerfile findings**

I stored the exact demonstration Dockerfile in `labs/lab7/results/df-demo/Dockerfile` and scanned the directory without excluding Medium or Low severity findings:

```dockerfile
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
```

```powershell
trivy config labs/lab7/results/df-demo --format json `
  --output labs/lab7/results/trivy-dockerfile.json
```

| Check     | Severity | Finding and practical impact                                                                                                                                                                                                                |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DS-0001` | Medium   | Using the mutable `latest` base tag makes future rebuild contents unpredictable. An unwanted or compromised upstream change could therefore be included in a later build. The base image should be pinned to a reviewed digest.             |
| `DS-0002` | High     | The final container user is root. As a result, code execution inside the application receives root privileges within the container and has broader permission to modify files. This does not automatically provide root access to the host. |
| `DS-0004` | Medium   | Exposing port 22 advertises an SSH attack surface that would require separate authentication and patching if an SSH service were installed and made available. `EXPOSE` itself does not start SSH or publish the port on the host.          |
| `DS-0026` | Low      | No health check is defined, meaning a failed or attacker-disrupted process may not produce a container health signal, which can delay automated detection or recovery. This is an operational weakness rather than an exploit by itself.    |

The scan produced four failures: one High, two Medium, and one Low. It did not report a finding for the remote `ADD` instruction, so I have not added an unsupported `DS-*` finding. In an actual build, however, the downloaded artifact would still require integrity verification.

**### Handling findings without a fix**

Three findings had no listed fix: `decompress@4.2.1` (`CVE-2026-53486`, Critical), `marsdb@0.6.11` (`GHSA-5mrr-rgp6-x4gr`, Critical), and `lodash.set@4.3.2` (`CVE-2020-8203`, High).

My first step would be to determine whether the vulnerable behavior is reachable by the application. Depending on that analysis, possible actions include removing or replacing the dependency, disabling the affected feature, or restricting the inputs that can reach it. While a replacement is being prepared, least privilege, network isolation, read-only filesystems, and monitoring can reduce the potential impact, but these controls do not eliminate the vulnerable code itself.

Every accepted exception should have an assigned owner, documented justification, expiration date, and scheduled rescan. I would explain to a manager that having zero scanner findings is not a dependable release criterion. More useful evidence is which remaining risks are reachable, which controls reduce their impact, and when remediation will be reviewed.

**## Task 2**

**### Restricted workload**

The [namespace](../labs/lab7/k8s/namespace.yaml) configures all three Pod Security admission modes as `restricted` and explicitly pins the policy version to `v1.33`:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

The pod-level security context in the [Deployment](../labs/lab7/k8s/deployment.yaml) is:

```yaml
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
```

The application container and the initContainer share the following container-level restrictions:

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
```

A dedicated [ServiceAccount](../labs/lab7/k8s/serviceaccount.yaml) is used, and both the ServiceAccount and pod explicitly disable `automountServiceAccountToken`. The application has requests of 100m CPU and 256 MiB memory, with limits of one CPU and 512 MiB. The initContainer requests 100m CPU and 128 MiB memory and is limited to 500m CPU and 256 MiB. Both images use the same pinned digest. Storage requests, limits, and a bounded `emptyDir` make the temporary writable storage explicit.

I applied the namespace first. I then created the ServiceAccount before applying the Deployment to avoid a temporary missing-ServiceAccount event:

```powershell
kubectl apply -f labs/lab7/k8s/namespace.yaml
kubectl apply -f labs/lab7/k8s/serviceaccount.yaml
kubectl apply -f labs/lab7/k8s/
kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=180s
kubectl -n juice-shop get pod -l app=juice-shop -o yaml
```

The saved pod evidence reports:

```text
NAME                          READY   STATUS    RESTARTS
juice-shop-5785cd548d-lb784  1/1     Running   0
```

I verified the runtime UID using the Node executable available in this image, which does not provide a shell:

```powershell
kubectl -n juice-shop exec deployment/juice-shop -c juice-shop -- `
  /nodejs/bin/node -e 'console.log(process.getuid())'

# 65532
```

This matches the configured Docker image user obtained with:

```text
docker inspect --format '{{.Config.User}}' bkimminich/juice-shop:v20.0.0
```

which returned `65532`. Additional runtime checks confirmed GID 65532 and the absence of a mounted ServiceAccount token.

**### Network isolation**

The [NetworkPolicy](../labs/lab7/k8s/networkpolicy.yaml) selects pods with `app=juice-shop` and isolates both ingress and egress traffic. Incoming TCP port 3000 is allowed only from pods in the same namespace that have `access=juice-shop-client`. Outgoing traffic is restricted to TCP/UDP port 53 on CoreDNS pods in `kube-system`, using both namespace and pod selectors.

Temporary probe pods were used to verify the behavior:

| Probe                                                  | Observed result          |
| ------------------------------------------------------ | ------------------------ |
| Same-namespace client with the allowed label           | HTTP 200                 |
| Same-namespace client without the allowed label        | Connection refused       |
| App resolving `kubernetes.default.svc.cluster.local`   | DNS returned `10.43.0.1` |
| App connecting to the plain Juice Shop pod on TCP 3000 | Connection refused       |
| Health check inside that destination pod               | HTTP 200                 |

The destination that was blocked was healthy, so the failed connection was not caused by a stopped server. The local k3s network policy implementation rejected the connection instead of silently timing it out.

Port-forwarding works through the Kubernetes API/kubelet path and therefore cannot by itself demonstrate NetworkPolicy enforcement. The pod-to-pod probes provide the relevant evidence.

**### Scanner comparison**

I created the comparison workload using the assignment's commands:

```powershell
kubectl create namespace juice-plain
kubectl -n juice-plain create deployment juice --image=bkimminich/juice-shop:v20.0.0
kubectl -n juice-plain rollout status deployment/juice --timeout=180s
```

The first Windows Kubernetes scan did not show configuration findings, even though scanning the exported Deployment separately revealed three High failures. In Trivy 0.74.0, the temporary-file generator's [implementation](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/k8s/scanner/io.go) replaces the `*` placeholder during Windows sanitization before creating the file, causing the random suffix to be placed after `.yaml`. Supplying an explicit file pattern restored the configuration findings.

A separate Linux scan returned the same three failures. Therefore, the comparison below uses the corrected Windows invocation:

```powershell
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL `
  --report summary --disable-node-collector --skip-db-update --skip-check-update `
  --file-patterns 'kubernetes:.*\.yaml[0-9]+$'

trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL `
  --report summary --disable-node-collector --skip-db-update --skip-check-update `
  --file-patterns 'kubernetes:.*\.yaml[0-9]+$'

trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL `
  --disable-node-collector --skip-db-update --skip-check-update `
  --file-patterns 'kubernetes:.*\.yaml[0-9]+$' `
  --format json --output labs/lab7/results/trivy-k8s.json
```

All of these commands use the dedicated `$env:KUBECONFIG` configured above. I disabled the node collector because the comparison is focused on application workloads rather than host configuration. I also kept the vulnerability database and check bundle unchanged across the scans using `--skip-db-update` and `--skip-check-update`.

The Windows file-pattern workaround is specific to this version and is not required on Linux. Both summary scans and the JSON scan completed with exit code 0.

The actual **raw summary rows** for the final manifests were:

| Workload                             | Critical vulnerabilities | High vulnerabilities | Critical misconfigurations | High misconfigurations | High secrets |
| ------------------------------------ | -----------------------: | -------------------: | -------------------------: | ---------------------: | -----------: |
| `juice-plain / Deployment/juice`     |                       10 |                   64 |                          0 |                      3 |            2 |
| `juice-shop / Deployment/juice-shop` |                       20 |                  128 |                          0 |                      0 |            4 |

The final Deployment contains the bonus initContainer, which uses the same image as the main application container. Trivy consequently scans that image twice and reports its vulnerability and secret findings twice. I kept the raw totals rather than incorrectly representing them as 74.

For comparing the image itself, each identical image's package/advisory matches can be counted once:

| Same image, counted once                 |  Plain | Hardened |
| ---------------------------------------- | -----: | -------: |
| Critical vulnerabilities                 |     10 |       10 |
| High vulnerabilities                     |     64 |       64 |
| **High + Critical**                      | **74** |   **74** |
| High/Critical workload misconfigurations |      3 |        0 |

The plain Deployment fails `KSV-0014` once because its root filesystem is writable and `KSV-0118` twice because explicit security contexts are missing. The hardened Deployment eliminates all three configuration findings. The image's 74 High/Critical vulnerability matches remain unchanged because the image itself was neither rebuilt nor upgraded.

The image already specifies UID 65532 by default in both namespaces. Therefore, the security-context findings on the plain Deployment should not be interpreted as evidence that the plain pod actually executed as root.

**### Enforced control and additional hardening**

I performed a server-side dry-run using a Pod that had the correct non-root UID, seccomp profile, and dropped capabilities, but deliberately set `allowPrivilegeEscalation: true`. Kubernetes admission rejected it with:

```text
violates PodSecurity "restricted:v1.33": allowPrivilegeEscalation != false (container "juice-shop" must set securityContext.allowPrivilegeEscalation=false)
```

The final manifest therefore sets this field to `false`.

I additionally enabled `readOnlyRootFilesystem: true`. This is not required by the restricted Pod Security Standard, but making the application compatible with a read-only root filesystem provides the extra hardening demonstrated in the bonus section.

**## Bonus**

**### Identifying the required writable paths**

Running:

```text
docker run --rm --read-only bkimminich/juice-shop:v20.0.0
```

caused the container to exit with:

```text
SQLITE_CANTOPEN: unable to open database file
```

I then launched a normal disposable container and inspected its filesystem changes using `docker diff lab7-writepaths`. The relevant modifications included:

```text
A /juice-shop/data/juiceshop.sqlite
A /juice-shop/logs/access.log.2026-09-23
A /juice-shop/logs/audit.json
A /juice-shop/ftp/legal.md
C /juice-shop/.well-known/csaf/provider-metadata.json
C /juice-shop/frontend/dist/frontend/index.html
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/i18n/en.json
A /juice-shop/i18n/ru_RU.json
```

The complete diff contains additional generated locale files. I grouped the observed writes into six application directories instead of assuming that only the database directory needed to be writable.

**### Final volume configuration**

The final configuration uses one disk-backed `emptyDir` named `writable-paths`, with a 512 MiB limit. Its individual subdirectories are mounted separately so that everything else in the image remains read-only:

| Mount path                           | Subpath     | Why it is writable                                                                                                 |
| ------------------------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------ |
| `/juice-shop/data`                   | `data`      | Contains the SQLite database and runtime data; packaged seed files also need to remain available.                  |
| `/juice-shop/logs`                   | `logs`      | Used for access logs and audit output.                                                                             |
| `/juice-shop/ftp`                    | `ftp`       | Stores the generated legal document together with files already included in the image.                             |
| `/juice-shop/.well-known`            | `wellknown` | Used for updated CSAF provider metadata.                                                                           |
| `/juice-shop/frontend/dist/frontend` | `frontend`  | Startup modifies the page and creates/copies generated assets here.                                                |
| `/juice-shop/i18n`                   | `i18n`      | Runtime locale files are generated here.                                                                           |
| `/tmp`                               | `tmp`       | Bounded temporary scratch space; added as a defensive measure rather than because it appeared in the startup diff. |

The initContainer uses the same pinned image and Node's `fs.cpSync` to copy the contents of all six application directories into the empty volume. It runs as UID 65532 with the same security restrictions as the main container. `fsGroup: 65532` allows the non-root process to write to the volume without requiring a privileged or root initContainer.

The application then mounts the populated subdirectories over their corresponding locations in the image. The server code under `/juice-shop/build` and `node_modules` remains read-only. Frontend assets are writable only within their dedicated mount because startup modifies them.

Simply mounting an empty volume at `/juice-shop/data` is not sufficient. I confirmed this using a separate read-only Docker run with a writable but empty tmpfs mounted at that path. Startup then failed to open:

```text
/juice-shop/data/static/securityQuestions.yml
```

and exited with:

```text
TypeError: questions.map is not a function
```

Seeding the directory preserves the required packaged file, and the final pod verified that the file exists. The other seeded directories similarly retain the files shipped in the original image.

These volumes are ephemeral. Replacing the pod removes the database and generated files. That is acceptable for this disposable lab, but persistent application data would require a separate persistence solution.

**### Runtime verification**

The saved pod specification confirms `readOnlyRootFilesystem: true` for both containers, and the application reached Ready state with zero restarts.

A Node-based runtime check produced:

```json
{
  "uid": 65532,
  "gid": 65532,
  "rootWrite": "EROFS",
  "tokenMounted": false,
  "seedFile": true
}
```

Here, `rootWrite` represents the result of trying to create `/juice-shop/readonly-proof`; `seedFile` verifies the presence of `/juice-shop/data/static/securityQuestions.yml`.

Finally, I verified application availability through a local-only port-forward:

```powershell
kubectl -n juice-shop port-forward deployment/juice-shop 3008:3000 --address 127.0.0.1
```

In a second terminal:

```powershell
(Invoke-WebRequest http://127.0.0.1:3008/ -UseBasicParsing).StatusCode

# 200
```

The returned response contained the Juice Shop page.

The Kubernetes JSON report is retained locally as `labs/lab7/results/trivy-k8s.json` for later import.

After all evidence had been collected, I removed the `lab7` Kubernetes cluster and deleted the disposable Docker container used for inspecting filesystem writes.
