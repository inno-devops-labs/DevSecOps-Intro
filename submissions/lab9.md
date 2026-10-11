# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{"hostname":"0233df356b87","output":"2026-07-07T08:29:32.957192026+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo shell-in-container test terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=2d1385179a7b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-07T08:29:32.957192026Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"0233df356b87","output":"2026-07-07T08:29:37.665986949+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=2d1385179a7b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-07T08:29:37.665986949Z"}
```

### Custom rule
```yaml
- rule: Write to /tmp by container
  desc: Detects a process inside a container writing to /tmp
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp inside container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{"hostname":"0233df356b87","output":"2026-07-07T08:34:58.048173250+0000: Warning Write to /tmp inside container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=2d1385179a7b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-07T08:34:58.048173250Z"}
```

### Tuning consideration
This rule will fire heavily on legitimate workloads — many logging frameworks, package managers, and health-check scripts write to `/tmp` as a normal part of operation. Two tuning approaches: (1) an `exceptions:` block listing known-safe `proc.name` values (e.g. `npm`, `pip`, specific logging daemons) that Falco skips at the engine level without touching the base condition, which is auditable and easy to diff in PRs; or (2) inlining `and not proc.name in (npm, pip, ...)` directly into the condition, which is simpler for a one-off rule but gets unreadable as the exception list grows. For a rule meant to stay in production, the `exceptions:` block is the better long-term choice since it keeps the detection logic and the noise-suppression list visibly separate.

---

## Task 2: Conftest Policy-as-Code

### My policy file
```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  run_as_non_root := object.get(c, ["securityContext", "runAsNonRoot"], false)
  run_as_non_root != true
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  allow_escalation := object.get(c, ["securityContext", "allowPrivilegeEscalation"], true)
  allow_escalation != false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  dropped := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in dropped
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  mem_limit := object.get(c, ["resources", "limits", "memory"], "")
  mem_limit == ""
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not startswith(c.image, "bkimminich/juice-shop@sha256:")
  contains(c.image, "@sha256:") == false
  msg := sprintf("container %q should pin image by digest (sha256:...), not a tag", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" should pin image by digest (sha256:...), not a tag
10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
PASS on `juice-compose.yml`:
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

FAIL on a deliberately unhardened compose (`nginx:latest`, no user/read_only/cap_drop):
```
FAIL - C:\temp\bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - C:\temp\bad-compose.yml - compose.security - services must set read_only: true
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

The same `deny[msg]` pattern (input inspection → missing/incorrect field → sprintf message) worked unchanged against a completely different input shape (`input.services` for compose vs `input.spec.template.spec.containers` for K8s Deployments) — only the field paths changed, not the underlying Rego logic.

### Why CI-time vs admission-time
CI-time Conftest runs during PR review, giving the developer feedback in seconds without needing cluster access — a non-compliant manifest never even gets merged. Admission-time enforcement (PSS, Kyverno, OPA Gatekeeper) runs at `kubectl apply` and is the last line of defense: it catches manifests that bypassed CI (a manual `kubectl apply` from a laptop, a manifest generated by a script that skipped the pipeline, or a CI policy that was accidentally disabled). Running both gives defense in depth — CI-time is the fast, cheap filter that catches almost everything early, and admission-time is the backstop that guarantees nothing non-compliant reaches the cluster regardless of how it got there.

---

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects a container connecting to a known mining-pool port
  condition: >
    evt.type=connect and
    container.id != host and
    fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
  output: >
    Possible cryptominer network activity
    (container=%container.name process=%proc.name port=%fd.sport command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"0233df356b87","output":"2026-07-07T09:01:39.120272414+0000: Critical Possible cryptominer network activity (container=lab9-target process=nc port=3333 command=nc -w 2 127.0.0.1 3333) container_id=2d1385179a7b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"2d1385179a7b","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783414899120272414,"fd.sport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-07T09:01:39.120272414Z"}
```

### Reflection
- **Indicators used**: connection port (`fd.sport in (3333, 4444, ...)`) as the primary signal, combined implicitly with the container scope check (`container.id != host`) to keep this container-specific rather than host-wide. A true multi-indicator version would also check `proc.name in (xmrig, ethminer, ...)`, but a single well-chosen port range already catches the most common Stratum-protocol mining pools without needing to know the specific binary name.
- **What this misses**: obfuscated mining that tunnels over HTTPS (port 443) to a pool proxy, or a miner recompiled/renamed to avoid matching `proc.name` — port-based detection alone won't catch a miner that connects out on 443 disguised as normal web traffic. This is a real false-negative gap; catching it would need behavioral signals (sustained high CPU + steady small outbound packets) rather than a static port list.
- **SLA matrix integration**: a CRITICAL-priority runtime alert like this should map to the tightest response SLA — page on-call within minutes, since active cryptomining on a compromised container both burns compute budget and signals the attacker already has code execution. It sits at the "detect and respond immediately" end of the matrix, unlike a WARNING-tier tuning-noise rule (like the `/tmp` write rule) that can sit in a daily-review queue instead.
