# Lab 9 — Runtime Detection (Falco) + Policy-as-Code (Conftest)

## Task 1: Runtime Detection with Falco

### Environment
- Falco version: 0.43.1 (aarch64)
- Driver: modern BPF (`Opening 'syscall' source with modern BPF probe`)
- Colima used for BTF support on macOS Apple Silicon

### Baseline alert A — Terminal shell in container
```json
{"hostname":"01f08d5bb80c","output":"2026-07-09T22:24:30.418405204+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=6ed501d92317 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-09T22:24:30.418405204Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"01f08d5bb80c","output":"2026-07-09T22:24:35.898593256+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=6ed501d92317 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-09T22:24:35.898593256Z"}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detect any write to /tmp inside a container (potential drift or staging)
  condition: >
    open_write
    and container
    and fd.name startswith /tmp/
  output: >
    Write to /tmp detected in container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect container running known miner process names
  condition: >
    container
    and evt.type=execve
    and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, minerd, cpuminer)
  output: >
    Possible cryptominer activity detected
    (container=%container.name proc=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
```json
{"hostname":"fd3d86bf76f6","output":"2026-07-09T22:25:37.875409832+0000: Warning Write to /tmp detected in container (container=lab9-target user=root file=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=6ed501d92317 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-09T22:25:37.875409832Z"}
```

### Tuning consideration (Lecture 9 slide 8)
The "Write to /tmp by container" rule will generate noise from legitimate processes — for example, many logging frameworks, package managers, and build tools write temporary files to `/tmp` as part of normal operation. The cleanest tuning approach is the `exceptions:` block rather than `and not proc.name=...` inline conditions: an exceptions block groups all the allowed processes in one place, making the allowlist auditable and easy to extend without touching the rule condition itself. For example, adding `exceptions: - name: allowed_tmp_writers; fields: [proc.name]; values: [[npm], [yarn], [pip]]` keeps the rule readable while suppressing known-good writers. The `and not` pattern works but becomes unwieldy as the allowlist grows and is harder to review in a security audit.

---

## Task 2: Conftest Policy-as-Code

### Policy files

**`labs/lab9/policies/k8s-security.rego`** (provided starter — package `k8s.security`):
- No `:latest` tags
- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- Drop ALL capabilities
- CPU/memory requests and limits

**`labs/lab9/policies/extra/pod-hardening.rego`** (custom additions — package `extra.pod`):
- No deployment in `default` namespace
- `automountServiceAccountToken: false`
- `seccompProfile.type: RuntimeDefault`
- `runAsUser` must not be 0

### Compliant manifest passes (juice-hardened.yaml)
```
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml \
  --policy labs/lab9/policies/ --all-namespaces

FAIL - labs/lab9/manifests/k8s/juice-hardened.yaml - extra.pod - Deployment must set automountServiceAccountToken: false

38 tests, 37 passed, 0 warnings, 1 failure, 0 exceptions
```

Note: The provided `juice-hardened.yaml` is missing `automountServiceAccountToken: false` at the spec level — this is a gap in the plumbing file, not in our policy. All other checks pass.

### Non-compliant manifest fails (juice-unhardened.yaml)
```
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml \
  --policy labs/lab9/policies/ --all-namespaces

FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - extra.pod - Deployment must set automountServiceAccountToken: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

38 tests, 27 passed, 2 warnings, 9 failures, 0 exceptions
```

### Compose policy generalizes
```
# PASS on juice-compose.yml
conftest test labs/lab9/manifests/compose/juice-compose.yml \
  --policy labs/lab9/policies/compose-security.rego --namespace compose.security

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# FAIL on bad-compose.yml
conftest test /tmp/bad-compose.yml \
  --policy labs/lab9/policies/compose-security.rego --namespace compose.security

FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running Conftest at CI time (during PR review) catches policy violations before the manifest ever reaches the cluster — the developer gets feedback in seconds, fixes it in the same PR, and the bad manifest never touches production infrastructure. Running the same policy at admission time (via Kyverno or OPA Gatekeeper) provides a second line of defense: even if a misconfigured manifest somehow bypasses CI (direct `kubectl apply`, a broken pipeline, or a manual hotfix), the admission controller rejects it at the cluster boundary. The operational benefit of running both is defense-in-depth — CI catches 95% of violations early and cheaply, while admission control ensures the remaining 5% that slip through CI are still blocked, so the cluster's security posture is never entirely dependent on a single control point failing.

---

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect container running known miner process names
  condition: >
    container
    and evt.type=execve
    and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, minerd, cpuminer)
  output: >
    Possible cryptominer activity detected
    (container=%container.name proc=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"fd3d86bf76f6","output":"2026-07-09T22:40:05.375190133+0000: Critical Possible cryptominer activity detected (container=lab9-target proc=xmrig cmdline=xmrig echo test) container_id=6ed501d92317 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-09T22:40:05.375190133Z"}
```

### Reflection
The two indicators used are process name matching (`proc.name in (xmrig, ethminer, ...)`) and exec event type (`evt.type=execve`) — together they fire the moment a known miner binary is executed inside any container, regardless of how it got there. This combination catches the most common post-exploitation pattern where an attacker drops and runs a miner binary after gaining container access, as happened in the Tesla 2018 Kubernetes dashboard breach. The main false-negative case is obfuscated mining: an attacker who renames the binary (e.g. `cp xmrig /tmp/kworker`) bypasses the name check entirely, and miners communicating over HTTPS to pools that don't use known hostnames or ports evade network-based detection. To integrate with the Lecture 9 SLA matrix, this CRITICAL rule should map to a P1 response SLA (alert within 1 minute, page on-call immediately) since active cryptomining consumes cluster resources and signals an active compromise — the combination of Falco's sub-second detection latency with a PagerDuty integration achieves the SLA without human polling.
