# Lab 7 — Container Security: Trivy + Pod Security Standards + Policy Gate

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Container%20Security-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Trivy%20%2B%20PSS%20%2B%20Conftest-informational)

> **Goal:** Scan Juice Shop image with Trivy (CVE + misconfig + secrets), harden a Kubernetes deployment of it with Pod Security Standards + NetworkPolicy + securityContext, and write a Conftest policy that gates non-compliant pods.
> **Deliverable:** A PR from `feature/lab7` with `submissions/lab7.md` + hardened K8s manifests + (bonus) a Conftest policy. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- **Trivy v0.69.x** in three modes: `image`, `config`, `k8s` (Lecture 7 slide 8)
- Hardening a K8s Deployment with **Pod Security Standards** (`restricted` profile) + **`securityContext`** + **NetworkPolicy** (Lectures 7 slides 11-15)
- (Bonus) Writing a **Conftest/Rego** policy to gate non-compliant pods at CI time

> Recall Lecture 7 slide 4 — "containers don't contain". The hardening here is the difference between a contained workload and a kernel-CVE-away-from-pwned one.

---

## Project State

**You should have from Labs 1-6:**
- Juice Shop v20.0.0 image pulled (Lab 1)
- Sign-ready CycloneDX SBOM at `labs/lab4/juice-shop.cdx.json` (Lab 4 bonus)
- Familiarity with Checkov-style scanner output (Lab 6)
- Signed commits + pre-commit gitleaks (Lab 3)

**This lab adds:**
- A Trivy image scan + manifest scan of Juice Shop
- A hardened Kubernetes deployment of Juice Shop (PSS restricted + NetworkPolicy)
- (Bonus) A Conftest policy that fails CI on non-compliant pods

---

## Setup

You need:
- **Docker**
- **Trivy v0.69.x** — `brew install trivy` or [GitHub releases](https://github.com/aquasecurity/trivy/releases)
- **`kubectl`** + **`kind`** or **`k3d`** — for a local Kubernetes cluster
- **`conftest`** v0.68.x — `brew install conftest` (only needed for bonus)
- **`jq`**

```bash
git switch main && git pull
git switch -c feature/lab7

# Verify
trivy --version && kubectl version --client && docker --version

# Start a local K8s cluster
kind create cluster --name lab7 --image kindest/node:v1.33.0
# OR: k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1

kubectl cluster-info

mkdir -p labs/lab7/{results,k8s,policies}
```

---

## Task 1 — Trivy Image + Misconfig Scan (6 pts)

**Objective:** Run Trivy in two modes against Juice Shop and analyze the findings.

### 7.1: Image vulnerability scan

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json

trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format table | tee labs/lab7/results/trivy-image.txt
```

### 7.2: Dockerfile misconfig scan

```bash
# We don't have Juice Shop's Dockerfile, but we WILL write our own K8s manifest
# in Task 2. For now, scan a sample Dockerfile to learn the workflow.
cat > /tmp/Dockerfile-bad <<'EOF'
FROM node:latest                      # CKV_DOCKER_3: avoid :latest
USER root                             # CKV_DOCKER_8: USER non-root
EXPOSE 22                             # CKV_DOCKER_1: don't expose SSH
ADD https://example.com/app.tar /     # CKV_DOCKER_4: ADD URL is risky
EOF

trivy config /tmp/Dockerfile-bad --severity HIGH,CRITICAL --format table
```

### 7.3: Triage by fix availability

```bash
# Top 10 CVEs with fixes (Lecture 7 slide 9 — "fix available AND severity ≥ HIGH first")
jq '[.Results[].Vulnerabilities[]? | select(.FixedVersion != null) |
    {cve: .VulnerabilityID, severity: .Severity, pkg: .PkgName, installed: .InstalledVersion, fix: .FixedVersion}] |
    sort_by(.severity) | .[:10]' \
  labs/lab7/results/trivy-image.json
```

### 7.4: Document in `submissions/lab7.md`

```markdown
# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | <n> | <m> |
| High | <n> | <m> |
| **Total** | <n> | <m> |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| ... |

### Compared to Lab 4's Grype scan
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:
1. One that BOTH Grype and Trivy found
2. One that ONE tool found and the OTHER missed
For each: explain why the tools differ (DB freshness? Different package matching?
EPSS scoring? Lecture 7 + Lecture 4 give context.) (2-3 sentences per CVE.)
```

---

## Task 2 — Kubernetes Hardening (4 pts)

> ⏭️ Optional. Skipping won't affect future labs, but you miss the most concrete shift-right experience of the course.

**Objective:** Deploy Juice Shop to your local K8s cluster with full PSS `restricted` profile compliance, including securityContext, NetworkPolicy, and a non-default ServiceAccount.

### 7.5: Write the hardened manifests

Create the following files. **The lab does NOT ship them as plumbing** — writing them is the skill.

#### `labs/lab7/k8s/namespace.yaml`

```yaml
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
```

#### `labs/lab7/k8s/serviceaccount.yaml`

A dedicated SA with `automountServiceAccountToken: false` (Lecture 7 slide 12 anti-pattern).

#### `labs/lab7/k8s/deployment.yaml`

```yaml
# YOUR TASK: Juice Shop Deployment with FULL hardening
# Requirements (all required for PSS restricted compliance):
#   - serviceAccountName: <your dedicated SA>
#   - automountServiceAccountToken: false
#   - pod-level securityContext:
#       runAsNonRoot: true
#       runAsUser: 1000      # Juice Shop runs as UID 1000 by default
#       fsGroup: 1000
#       seccompProfile: { type: RuntimeDefault }
#   - container-level securityContext:
#       allowPrivilegeEscalation: false
#       readOnlyRootFilesystem: true       # See pitfalls — Juice Shop writes /tmp
#       capabilities: { drop: ["ALL"] }
#   - resources.limits.{memory,cpu} + resources.requests.{memory,cpu}
#   - image pinned by digest: bkimminich/juice-shop@sha256:<from your Lab 4 capture>
#
# Hint: readOnlyRootFilesystem=true breaks Juice Shop. Mount emptyDir
#       at /tmp, /usr/src/app/logs, and any other path Juice Shop writes to.
```

#### `labs/lab7/k8s/networkpolicy.yaml`

```yaml
# YOUR TASK: default-deny + allow-ingress-from-localhost
# Requirements (Lecture 7 slide 15):
#   - podSelector matching app=juice-shop
#   - policyTypes: [Ingress, Egress]
#   - ingress: explicitly allow from-namespace-ingress-controller-or-localhost-port-forward
#   - egress: explicitly allow DNS (UDP 53 to kube-system) and HTTPS (TCP 443) — nothing else
```

### 7.6: Apply + verify

```bash
kubectl apply -f labs/lab7/k8s/

# Wait for the pod
kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=120s

# Capture full pod spec for proof
kubectl -n juice-shop get pod -l app=juice-shop -o yaml > labs/lab7/results/pod-spec.yaml

# Quick PSS compliance check
kubectl -n juice-shop describe pod -l app=juice-shop | grep -A 3 -i "security context"
```

### 7.7: Trivy K8s scan

```bash
trivy k8s --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json

trivy k8s --include-namespaces juice-shop \
  --severity HIGH,CRITICAL \
  --report=summary
```

### 7.8: Document in `submissions/lab7.md`

````markdown
## Task 2: Kubernetes Hardening

### Manifests (paste relevant snippets)
- `namespace.yaml` PSS labels:
```yaml
<paste the three labels>
```
- `deployment.yaml` securityContext sections (pod + container):
```yaml
<paste>
```
- `networkpolicy.yaml` ingress + egress:
```yaml
<paste>
```

### Pod is running
Output of `kubectl get pod -n juice-shop -l app=juice-shop`:
```
<paste — must show Running, Ready 1/1>
```

### Trivy K8s scan
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |

### What broke and how you fixed it (2-3 sentences)
`readOnlyRootFilesystem: true` likely broke Juice Shop. What paths did it need to write?
How did you fix it (which emptyDir mounts)?
````

---

## Bonus Task — Conftest Policy Gate (2 pts)

> 🌟 **Genuinely valuable.** Conftest in CI catches insecure pods *before* `kubectl apply`. Lecture 9 covers Conftest in depth; this bonus is your preview.

**Objective:** Write a Rego policy that refuses pods missing key hardening (runAsNonRoot, readOnlyRootFilesystem, no wildcard caps).

### B.1: Write the policy

```rego
# labs/lab7/policies/pod-hardening.rego
# YOUR TASK: Rego policy refusing non-compliant pods
# Requirements:
#   - Run via: conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
#   - Must produce deny[msg] for pods missing:
#       1. spec.securityContext.runAsNonRoot != true
#       2. (any container) spec.containers[_].securityContext.readOnlyRootFilesystem != true
#       3. (any container) spec.containers[_].securityContext.allowPrivilegeEscalation != false
#       4. (any container) spec.containers[_].securityContext.capabilities.drop missing "ALL"
#
# Hints:
#   - Rego primer at https://www.openpolicyagent.org/docs/latest/policy-language/
#   - `input.kind == "Deployment"` to filter; the pod spec is `input.spec.template.spec`
#   - `[_]` iterates; `msg := sprintf("...", [...])` formats
#   - Sample structure:
#     package main
#     deny[msg] { input.kind == "Deployment"; <condition>; msg := "..." }
```

### B.2: Run Conftest against your manifests

```bash
# Should PASS on your hardened deployment (Task 2 work)
conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies

# Create an intentionally bad manifest to verify the policy fires
cat > /tmp/bad-pod.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad-app }
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          # No securityContext at all — should fail your policy
EOF

conftest test /tmp/bad-pod.yaml --policy labs/lab7/policies
# Should FAIL with deny messages
```

### B.3: Document in `submissions/lab7.md`

````markdown
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
policy catch BEFORE `kubectl apply` runs? Why is catching at CI-time better than at admission-time?
````

---

## How to Submit

```bash
git add labs/lab7/k8s/
git add labs/lab7/policies/                # Bonus only
git add submissions/lab7.md
git commit -m "feat(lab7): trivy + PSS restricted + conftest gate"
git push -u origin feature/lab7

# Cleanup the cluster after submitting
kind delete cluster --name lab7    # or k3d cluster delete lab7
```

> **Do NOT commit** `labs/lab7/results/` — regeneratable.

PR checklist body:

```text
- [x] Task 1 — Trivy image + config scans + Grype comparison
- [ ] Task 2 — Hardened K8s deployment with PSS restricted + NetworkPolicy
- [ ] Bonus — Conftest policy passing on hardened + failing on bad manifest
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Trivy image scan completes; severity table populated
- ✅ Top-10 fixed CVE table with real CVE IDs + fix versions
- ✅ Two CVEs compared to Lab 4's Grype results (one tool-agreed, one tool-divergent)
- ✅ Tool-divergence explanation references DB freshness / package matching / EPSS

### Task 2 (4 pts)
- ✅ All four manifests written (namespace, sa, deployment, networkpolicy)
- ✅ Namespace has all three PSS labels (enforce + warn + audit) set to `restricted`
- ✅ Deployment passes PSS restricted (pod is Running 1/1; no PSS warnings in describe)
- ✅ Trivy `k8s` scan completes; result documented
- ✅ "What broke and how you fixed it" addresses readOnlyRootFilesystem specifically

### Bonus Task (2 pts)
- ✅ Rego policy file exists at `labs/lab7/policies/pod-hardening.rego`
- ✅ Policy PASSES on Task 2 hardened deployment
- ✅ Policy FAILS on intentionally bad manifest with clear deny messages
- ✅ CI-time vs admission-time explanation demonstrates understanding (2-3 sentences)

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Trivy scans | **6** | Image + config scans + top-10 CVEs + Grype comparison |
| **Task 2** — K8s hardening | **4** | 4 manifests + pod runs + Trivy K8s scan + read-only-root debug story |
| **Bonus Task** — Conftest | **2** | Rego policy PASSES + FAILS correctly + CI-vs-admission reflection |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Trivy documentation](https://trivy.dev/) — All six targets including image, config, k8s
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — Official K8s reference
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) — How the labels work
- [Conftest documentation](https://www.conftest.dev/) — Tool homepage
- [OPA Rego playground](https://play.openpolicyagent.org/) — Interactive 30-min tutorial (do this before B.1)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — The source of most K8s rules

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`k3d cluster create` fails with "Failed to watch ... too many open files"** — WSL2 + crowded Docker Desktop environments hit the default `fs.inotify.max_user_instances = 128` limit. Fix: as root, `sysctl -w fs.inotify.max_user_instances=1024 fs.inotify.max_user_watches=1048576` (or add to `/etc/sysctl.d/*.conf`). On WSL2 specifically, persist via `wsl.conf` or restart WSL after editing `/etc/sysctl.conf`.
- 🚨 **`kind create cluster` fails on Docker Desktop with "no space left"** — `docker system prune -a` (warning: nukes ALL unused images) or use a Linux VM.
- 🚨 **Juice Shop pod crashloops with `readOnlyRootFilesystem: true`** — Juice Shop writes to `/tmp` and `/usr/src/app/logs` (and possibly the SQLite DB path). Mount `emptyDir{}` volumes at those paths.
- 🚨 **PSS doesn't block your bad pod** — verify the namespace labels: `kubectl get ns juice-shop -o yaml | grep pod-security`. If labels show only `warn:` and not `enforce:`, the bad pod will get created with a warning, not blocked.
- 🚨 **`trivy k8s` requires cluster access** — your `~/.kube/config` must point to the lab cluster. `kubectl config current-context` should show `kind-lab7` or `k3d-lab7`.
- 🚨 **Conftest `package main` is mandatory** — your Rego file must declare a package. Conftest defaults to looking for `package main` unless you pass `--namespace`.
- 🚨 **`kubectl wait` times out** — the image pull on first run can take 60+ seconds. Bump `--timeout=300s` if your network is slow.
- 💡 **PSS `enforce` blocks at create**; `warn` just shows a kubectl message; `audit` writes to audit log only. For production: `enforce`. For migration: start with `warn` and escalate. The lab uses all three set to `restricted`.

</details>

<details>
<summary>🪜 Looking ahead</summary>

- **Lab 8** (Supply Chain) signs the EXACT image you scanned here with Cosign
- **Lab 9** (Falco + Conftest) extends the Conftest bonus to **runtime admission** + Falco runtime detection — same Rego skills
- **Lab 10** (DefectDojo) imports Trivy + your scan results; the hardened manifest becomes the deployable artifact in your portfolio walkthrough

</details>
