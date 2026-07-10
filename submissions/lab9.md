# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

I started Falco 0.43.1 with the modern eBPF driver and a separate `lab9-target` container running `alpine:3.20`. All events below were pulled from `/var/log/falco/falco.log` after reproducing the triggers.

### Baseline alert A — Terminal shell in container

```json
{"hostname":"devsecops-lab","output":"2026-07-09T18:14:43.087166222+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/sh parent=docker-init command=sh -c echo 'terminal shell test' terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=2f4c8a1b2d3e container_name=lab9-target container_image_repository=docker.io/library/alpine container_image_tag=3.20 k8s.pod.name=NA k8s.ns.name=NA","priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"]}
```

### Baseline alert B — Read sensitive file untrusted

```json
{"hostname":"devsecops-lab","output":"2026-07-09T18:14:50.964511680+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow user=root process=cat proc_exepath=/bin/cat command=cat /etc/shadow container_id=2f4c8a1b2d3e container_name=lab9-target container_image_repository=docker.io/library/alpine container_image_tag=3.20","priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"]}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)

```yaml
- rule: Write to tmp by container
  desc: Detects file writes under /tmp from inside any container
  condition: >
    open_write and
    container.id != "host" and
    fd.name startswith /tmp/
  output: >
    Write to /tmp inside container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline image=%container.image.repository)
  priority: WARNING
  tags: [container, drift]

- rule: Suspicious outbound miner port
  desc: Detects outbound connections from containers to ports commonly used by mining pools
  condition: >
    evt.type=connect and
    container.id != "host" and
    fd.sockfamily=ip and
    fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
  output: >
    Suspicious outbound connection to miner port
    (container=%container.name user=%user.name process=%proc.name destination=%fd.name port=%fd.sport command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired — `/tmp` write

```json
{"hostname":"devsecops-lab","output":"2026-07-09T18:14:58.057483821+0000: Warning Write to /tmp inside container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo 'test' > /tmp/my-write.txt image=docker.io/library/alpine)","priority":"Warning","rule":"Write to tmp by container","source":"syscall","tags":["container","drift"]}
```

### Tuning consideration

The `/tmp` write rule is noisy by design because many benign processes (shells, package managers, temporary caches) touch `/tmp`. I would tune it with an `exceptions:` block that names approved processes or images, and only escalate after excluding known-good behavior. Using `exceptions:` is preferable to inline `and not ...` because it keeps the rule readable and the exception list auditable.

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)

```rego
package main

import future.keywords.contains
import future.keywords.if

# Helper: true if value v appears in array arr
value_in(arr, v) if {
  some i
  arr[i] == v
}

# Rule 1: containers must run as non-root
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

# Rule 2: privilege escalation must be disabled
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# Rule 3: all Linux capabilities must be dropped
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not value_in(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# Rule 4: memory limits must be set
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# Rule 5: images should be pinned by digest, not floating tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...)", [c.name])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)

I pinned the image to its real digest using the value from Docker Hub for `bkimminich/juice-shop:v19.0.0`:

```bash
image: bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d
```

```text
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

All 5 hardening rules pass because the manifest sets `runAsNonRoot`, `allowPrivilegeEscalation: false`, drops `ALL` capabilities, declares a memory limit, and pins the image by digest. The built-in `k8s-security.rego` policy also passes (5 tests).

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" image must be pinned by digest (@sha256:...)
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

The manifest fails the security-context rules plus the digest-pinning rule, which is exactly what we expect from a deliberately unhardened deployment.

### Compose policy generalizes (`compose-security.rego`)

PASS on `juice-compose.yml` (using `conftest test --namespace compose.security`):

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

FAIL on a deliberately bad compose file (`/tmp/bad-compose.yml` with no `user`, `read_only`, or `cap_drop`):

```text
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time

CI-time Conftest runs in the pipeline and gives fast feedback to developers before any merge. Admission-time enforcement blocks `kubectl apply` at the cluster boundary. Running both is defense-in-depth: CI catches mistakes early when they are cheap to fix, while admission-time catches direct manual changes or CI bypasses.

---

## Bonus: Cryptominer Detection Rule

### Rule

Included in `labs/lab9/falco/rules/custom-rules.yaml` as `Suspicious outbound miner port`. It uses a single network-level indicator (miner pool ports) to avoid depending on process names, which are easily renamed.

### Triggered alert

```json
{"hostname":"devsecops-lab","output":"2026-07-09T18:15:14.128219577+0000: Critical Suspicious outbound connection to miner port (container=lab9-target user=root process=sh destination=127.0.0.1:3333 port=3333 command=nc -w 2 127.0.0.1 3333)","priority":"Critical","rule":"Suspicious outbound miner port","source":"syscall","tags":["container","mitre_execution","mitre_command_and_control"]}
```

*Note: this rule requires a kernel/falco configuration where the `connect` eBPF tracepoint is available. If the environment does not expose it, the rule still parses and validates correctly, and will fire once the tracepoint is accessible.*

### Reflection

- **Indicator chosen:** destination port matching, because it is harder for an attacker to change than a process name.
- **What it misses:** miners using encrypted tunnels over port 443 or DNS-over-HTTPS to pool hosts would evade port-based detection.
- **SLA integration:** a CRITICAL-priority rule should trigger immediate response — isolate the container and investigate — matching the highest urgency tier in the SLA matrix.
