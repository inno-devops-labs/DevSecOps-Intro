# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Environment
- Falco: `falcosecurity/falco:0.43.1` with modern eBPF (`falco -U`)
- Target container: `lab9-target` (`alpine:3.20`)
- BTF check: `test -f /sys/kernel/btf/vmlinux` → OK (native Linux)
- Custom rules: `labs/lab9/falco/rules/custom-rules.yaml`

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs:
```json
{
  "hostname": "bc96ef36cb01",
  "output": "2026-07-10T20:03:28.473830616+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=722b8f65bbbf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "722b8f65bbbf",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.type": "execve",
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
    "proc.name": "sh",
    "user.name": "root"
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
  "time": "2026-07-10T20:03:28.473830616Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
  "hostname": "bc96ef36cb01",
  "output": "2026-07-10T20:03:28.873664979+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=722b8f65bbbf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "722b8f65bbbf",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.type": "open",
    "fd.name": "/etc/shadow",
    "proc.cmdline": "cat /etc/shadow",
    "proc.name": "cat",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
  "time": "2026-07-10T20:03:28.873664979Z"
}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detect file writes under /tmp inside a container (not on the host)
  condition: >
    open_write
    and container
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (user=%user.name container=%container.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing the custom rule:
```json
{
  "hostname": "bc96ef36cb01",
  "output": "2026-07-10T20:06:26.081264645+0000: Warning Write to /tmp by container (user=root container=lab9-target file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=722b8f65bbbf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "722b8f65bbbf",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-07-10T20:06:26.081264645Z"
}
```

Trigger command:
```bash
docker exec --user 0 lab9-target /bin/sh -lc 'echo "test" > /tmp/my-write.txt'
```

### Tuning consideration (Lecture 9 slide 8)
A blanket "write to /tmp" rule will fire on legitimate workloads too (logging frameworks, package managers, and temp-file helpers often write under `/tmp`). My tuning approach is to add an `exceptions:` block scoped to known-safe processes or container images — for example, excluding `proc.name in (npm, node, java)` or a specific `container.image.repository` used in dev — rather than disabling the rule entirely. Alternatively, `and not proc.name in (trusted_tmp_writers)` using a Falco list keeps the rule readable and lets operators extend the allowlist without rewriting the condition. This follows the Lecture 9 pattern: keep the detection broad, then narrow noise with explicit exceptions instead of `and not` scattered ad hoc across many rules.

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

run_as_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

run_as_non_root if {
  c := input.spec.template.spec.containers[_]
  c.securityContext.runAsNonRoot == true
}

deny contains msg if {
  input.kind == "Deployment"
  not run_as_non_root
  msg := "pod or containers must set runAsNonRoot: true"
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...)", [c.name])
}
```

**Rules enforced (5 denies):**
1. `runAsNonRoot` must be true (pod or container level)
2. `allowPrivilegeEscalation` must be false
3. `capabilities.drop` must include `ALL`
4. `resources.limits.memory` must be set
5. Image must use `@sha256:` digest pin (not tag-only)

### Compliant manifest passes (`juice-hardened.yaml`)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" image must be pinned by digest (@sha256:...)
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - pod or containers must set runAsNonRoot: true

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`)

**PASS on `juice-compose.yml`:**
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

**FAIL on `/tmp/bad-compose.yml`:**
```
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest runs during PR review, so policy violations are caught before code merges — developers get fast feedback in the pipeline and can fix manifests without touching a live cluster. Admission-time enforcement (e.g. Kyverno or OPA Gatekeeper at `kubectl apply`) is the last line of defense: even if someone bypasses CI or applies manifests manually, non-compliant workloads are rejected at the API server. Running both provides defense in depth — CI keeps the main branch clean and educates authors early; admission-time blocks drift, emergency hotfixes, and compromised pipelines from starting non-compliant pods in production.
