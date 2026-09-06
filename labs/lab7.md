# Lab 7 — Container and Kubernetes Hardening

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Container%20%2B%20K8s-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Trivy%20%2B%20k3d-informational)

> **Goal:** Scan the image and its Dockerfile, then run Juice Shop in Kubernetes under the `restricted` Pod Security Standard and prove the difference a scanner can see.
> **Deliverable:** A PR from `feature/lab7` with `submissions/lab7.md` and your manifests under `labs/lab7/k8s/`. Submit the PR link via Moodle.
> **Builds on:** the image digest from Lab 4. **Used by:** Lab 9 runs runtime detection against a cluster like this one.

## Setup

- Docker, `jq`, Trivy 0.74.x, `kubectl` 1.31+, and `k3d` 5.8+.
- `conftest` 0.69.x for the bonus.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab7
```

```bash
trivy --version && kubectl version --client && docker --version
mkdir -p labs/lab7/results labs/lab7/k8s labs/lab7/policies
```

<!-- verify:skip creates a cluster; run it once by hand -->
```bash
k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1
kubectl cluster-info
```

## Task 1 — Scan the artifact (6 pts)

### 7.1 Image vulnerabilities

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

### 7.2 Rank what you can actually fix

```bash
jq -r '["CRITICAL","HIGH"] as $order
  | [.Results[].Vulnerabilities[]? | select(.FixedVersion != null)
     | {sev: .Severity, id: .VulnerabilityID, pkg: .PkgName,
        now: .InstalledVersion, fix: .FixedVersion}]
  | sort_by(.sev as $s | $order | index($s))
  | .[:10][] | "\(.sev)\t\(.id)\t\(.pkg) \(.now) -> \(.fix)"' \
  labs/lab7/results/trivy-image.json
```

`select(.FixedVersion != null)` is the whole trick: a vulnerability with no released fix is a decision about compensating controls, not a ticket for this sprint.

### 7.3 Scan a Dockerfile

```bash
mkdir -p /tmp/df-demo
cat > /tmp/df-demo/Dockerfile <<'EOF'
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
EOF

trivy config /tmp/df-demo
```

The file must be named `Dockerfile`, in a directory you point Trivy at. Named `Dockerfile-bad` or `Dockerfile.bad`, Trivy does not recognise it and cheerfully reports zero findings. Expect four failures: one HIGH and the rest MEDIUM or LOW, so a `--severity HIGH,CRITICAL` filter hides most of them.

**Submit** in `submissions/lab7.md`, section `## Task 1`:

- Vulnerability counts by severity, and how many of the HIGH and CRITICAL ones have a fix.
- The same image was scanned by Grype in Lab 4. Put the two totals side by side and explain the difference in one or two sentences; if you no longer have Lab 4's numbers, say so rather than inventing them.
- The ten rows from 7.2.
- The Dockerfile findings with their `DS-*` ids, and what each one would let an attacker do.
- Three or four sentences: your image has vulnerabilities with no fix available. What do you do about those, and what would you tell a manager who asks why the number is not zero?

## Task 2 — Run it under `restricted` (4 pts)

Optional. Skipping it does not affect later labs.

The `restricted` Pod Security Standard is the strictest of the three profiles Kubernetes ships. Write the manifests yourself; the requirements below are the contract.

### 7.4 The manifests

`labs/lab7/k8s/namespace.yaml`

```yaml
# YOUR TASK: a namespace that enforces the restricted profile
# Requirements:
#   - name: juice-shop
#   - the three pod-security.kubernetes.io labels (enforce, warn, audit), all restricted
# Hint: https://kubernetes.io/docs/concepts/security/pod-security-admission/
```

`labs/lab7/k8s/serviceaccount.yaml` and `labs/lab7/k8s/deployment.yaml`

```yaml
# YOUR TASK: a dedicated ServiceAccount and a Deployment that the restricted
# profile admits. Requirements:
#   - its own ServiceAccount, with automountServiceAccountToken: false on both
#     the ServiceAccount and the pod spec
#   - pod securityContext: runAsNonRoot, a runAsUser matching the image's own
#     user, seccompProfile RuntimeDefault
#   - container securityContext: allowPrivilegeEscalation false, capabilities
#     drop ALL
#   - requests and limits for cpu and memory
#   - the image pinned by digest, not by tag. Get it with:
#       docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
# Hints:
#   - the image already runs as a non-root user. Find which one:
#     docker inspect bkimminich/juice-shop:v20.0.0 --format '{{.Config.User}}'
#     Guessing 1000 gives you a pod that starts and then cannot write anything
#   - restricted does NOT require readOnlyRootFilesystem. That is the bonus
```

`labs/lab7/k8s/networkpolicy.yaml`

```yaml
# YOUR TASK: default-deny for the app pod, with the minimum re-opened
# Requirements:
#   - podSelector on your app label; policyTypes Ingress and Egress
#   - ingress: only what you actually need to reach the app
#   - egress: DNS to kube-system, nothing else it does not need
```

### 7.5 Apply and prove it

<!-- verify:skip needs the manifests the student writes in 7.4 -->
```bash
kubectl apply -f labs/lab7/k8s/namespace.yaml
kubectl apply -f labs/lab7/k8s/
kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=180s
kubectl -n juice-shop get pod -l app=juice-shop -o yaml > labs/lab7/results/pod-spec.yaml
```

The namespace goes first on purpose. `kubectl apply -f <dir>` processes files in alphabetical order, so `deployment.yaml` reaches the API server before `namespace.yaml` and fails with `namespaces "juice-shop" not found`.

### 7.6 Scan the running workload

<!-- produces: labs/lab7/results/trivy-image.json for lab 10 -->
<!-- produces: labs/lab7/results/trivy-k8s.json for lab 10 -->
<!-- verify:skip needs the cluster and the deployment from 7.5 -->
```bash
kubectl create ns juice-plain
kubectl -n juice-plain create deployment juice --image=bkimminich/juice-shop:v20.0.0
sleep 20
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL --report=summary
trivy k8s --include-namespaces juice-shop  --severity HIGH,CRITICAL --report=summary

# Lab 10 imports this file, so keep it
trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
```

**Submit**, section `## Task 2`:

- The namespace labels and both `securityContext` blocks.
- Proof the pod is running, and the user id it runs as, with the command that told you.
- The two Trivy summaries side by side. The misconfiguration counts should differ; the vulnerability counts should not. Explain both halves of that in two or three sentences.
- One thing the `restricted` profile blocked that you had to change, and one control the profile does not require that you added anyway.

## Bonus — A read-only root filesystem (2 pts)

`restricted` does not demand it, every hardening benchmark does, and Juice Shop fights back.

<!-- verify:nonzero-ok the container is expected to crash -->
```bash
docker run --rm --read-only bkimminich/juice-shop:v20.0.0
```

That crashes. Your task is to make the same container run with `readOnlyRootFilesystem: true` in Kubernetes.

```yaml
# YOUR TASK: extend deployment.yaml
# Requirements:
#   - container securityContext: readOnlyRootFilesystem: true
#   - the pod becomes Ready and serves HTTP 200
# Hints:
#   - find every path the process writes at runtime, do not guess:
#     docker run -d --name js bkimminich/juice-shop:v20.0.0 && sleep 25 && docker diff js
#   - one of those directories also contains files shipped in the image, so an
#     empty volume over it hides them and the app exits. That is the interesting part
#   - emptyDir volumes, and an initContainer if you need to seed one of them
```

**Submit**, section `## Bonus`:

- The `docker diff` output, trimmed to the paths that matter.
- Your final volume layout and why each entry is there.
- The directory that could not simply be replaced with an empty volume, and how you solved it.
- Proof: the pod Ready with `readOnlyRootFilesystem: true`, and an HTTP 200 through `kubectl port-forward`.

## Submit

<!-- verify:skip student fork files -->
```bash
git add labs/lab7/k8s/ submissions/lab7.md
git commit -m "feat(lab7): trivy scans + PSS restricted deployment"
git push -u origin feature/lab7
```

Clean up: `k3d cluster delete lab7`.

## Acceptance criteria

- Task 1 (6): image scan completed; severity counts and the fix-available split; the comparison against Lab 4's Grype totals, or an explicit statement that the numbers were not kept; ten fixable findings ranked; Dockerfile findings with `DS-*` ids and impact; the no-fix answer proposes something other than waiting.
- Task 2 (4): namespace enforces `restricted`; the Deployment uses its own ServiceAccount with token mounting disabled, sets requests and limits, and pins the image by digest; a NetworkPolicy exists with both policy types; the pod runs and is Ready; `runAsUser` matches the image's real user; both Trivy summaries present with the misconfiguration difference explained; one blocked thing and one voluntary control named.
- Bonus (2): pod Ready with `readOnlyRootFilesystem: true` and serving 200; the write paths come from `docker diff`, not from guessing; the seeded directory problem is described and solved.

## Common pitfalls

- `kubectl apply -f <dir>` is alphabetical, so `deployment.yaml` goes before `namespace.yaml` and the first apply fails. Apply the namespace first.
- The image runs as UID **65532**, not 1000. `runAsUser: 1000` starts, then fails on the first write.
- `trivy config` only recognises a file literally named `Dockerfile` (or `*.Dockerfile`). Any other name silently scans nothing.
- Trivy's Dockerfile checks are `DS-*` ids. `CKV_DOCKER_*` ids belong to Checkov, which is Lab 6's tool.
- Most Dockerfile findings are MEDIUM. `--severity HIGH,CRITICAL` hides them, which looks like a clean file.
- `trivy k8s` reports the same image vulnerabilities in both namespaces. Hardening changes misconfigurations, not the contents of the image; only a rebuild changes those.
- Under `restricted`, a pod that violates the profile is rejected at admission with a clear message. Read it: it names the exact field.

## Resources

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) and [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Trivy Kubernetes scanning](https://trivy.dev/latest/docs/target/kubernetes/) and [misconfiguration checks](https://avd.aquasec.com/misconfig/)
- [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [k3d](https://k3d.io/) — the local cluster this lab uses
