# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Runtime setup

Falco `0.43.1` was started in a privileged Docker container with the modern eBPF driver. The target was the `lab9-target` Alpine container.

### Modern eBPF confirmation


Modern eBPF evidence: Opening 'syscall' source with modern BPF probe.
### Baseline alert A — Terminal shell in container

```json
{"hostname":"9b61785f48d6","output":"2026-06-26T10:16:29.981909328+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=686e94dbf7ee container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"686e94dbf7ee","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1782468989981909328,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"systemd","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-06-26T10:16:29.981909328Z"}
```

### Baseline alert B — Container drift: write below binary directory

A write was made to `/usr/bin/lab9-drift.txt` inside the target container.

```json
{"hostname":"9b61785f48d6","output":"2026-06-26T15:11:28.958678476+0000: Error File below a known binary directory opened for writing | file=/usr/bin/lab9-drift.txt pcmdline=systemd --switched-root --system --deserialize=52 gparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"drift\" > /usr/bin/lab9-drift.txt terminal=0 container_id=686e94dbf7ee container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"686e94dbf7ee","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1782486688958678476,"evt.type":"open","fd.name":"/usr/bin/lab9-drift.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.cmdline":"sh -lc echo \"drift\" > /usr/bin/lab9-drift.txt","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pcmdline":"systemd --switched-root --system --deserialize=52","proc.pname":"systemd","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Error","rule":"Write below binary dir","source":"syscall","tags":["T1543","container","filesystem","host","maturity_sandbox","mitre_persistence"],"time":"2026-06-26T15:11:28.958678476Z"}
```

### Custom rule

```yaml
- rule: Write to /tmp by container
  desc: Detect a process in a container writing to /tmp
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (user=%user.name container=%container.name file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

```

### Custom rule fired

```json
{"hostname":"9b61785f48d6","output":"2026-06-26T15:30:08.587685733+0000: Warning Write to /tmp by container (user=root container=lab9-target file=/tmp/final-custom-rule-check.txt proc=sh -lc echo \"final-custom-rule-check\" > /tmp/final-custom-rule-check.txt) container_id=686e94dbf7ee container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"686e94dbf7ee","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1782487808587685733,"fd.name":"/tmp/final-custom-rule-check.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"final-custom-rule-check\" > /tmp/final-custom-rule-check.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-06-26T15:30:08.587685733Z"}
```

### Tuning consideration

A rule covering every write to `/tmp` can be noisy because legitimate applications, package tools, and logging components often use this directory. I would first use narrowly scoped structured `exceptions:` entries for known-safe combinations of image, process, and path because they are easier to audit than long conditions. A short `and not proc.name=...` exclusion is suitable only for a stable, well-understood process; broad exclusions could hide malicious activity.

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

# Supports both standalone Pods and Deployments.
pod_spec := input.spec if {
  input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

has_value(arr, value) if {
  some i
  arr[i] == value
}

# 1. runAsNonRoot may be set either at Pod level or container level.
deny contains msg if {
  c := pod_spec.containers[_]
  not pod_spec.securityContext.runAsNonRoot == true
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [c.name])
}

# 2. Every container must block privilege escalation.
deny contains msg if {
  c := pod_spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. Every container must drop all Linux capabilities.
deny contains msg if {
  c := pod_spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. Every container must have a memory limit.
deny contains msg if {
  c := pod_spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}
```

The policy enforces four requirements:

1. `runAsNonRoot: true` at Pod or container level.
2. `allowPrivilegeEscalation: false` for every container.
3. `capabilities.drop` includes `ALL` for every container.
4. `resources.limits.memory` is configured for every container.

### Good manifest passes

```text

[32m4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions[0m
```

### Bad manifest 1 fails — runs as root

```text
[31mFAIL[0m - labs/lab9/manifests/bad-pod-runasroot.yaml - main - container "root-app" must set runAsNonRoot: true at pod or container level

[31m4 tests, 3 passed, 0 warnings, 1 failure, 0 exceptions[0m
```

### Bad manifest 2 fails — missing memory limit

```text
[31mFAIL[0m - labs/lab9/manifests/bad-pod-no-resources.yaml - main - container "unbounded-app" must set resources.limits.memory

[31m4 tests, 3 passed, 0 warnings, 1 failure, 0 exceptions[0m
```

### Why CI-time and admission-time checks should both be used

CI-time Conftest gives developers immediate feedback during pull-request review, before an unsafe manifest reaches a cluster. Admission-time policy enforcement provides a final non-bypassable cluster boundary for manual `kubectl apply` actions and deployment paths outside the usual CI pipeline. Running both provides defense in depth: CI improves feedback speed, while admission control prevents unsafe configuration from being applied.

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- rule: Possible Cryptominer Activity
  desc: Detect a known mining process connecting from a container to a common mining-pool port
  condition: >
    evt.type=connect and
    container.id != host and
    fd.l4proto=tcp and
    fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) and
    proc.name in (xmrig, ethminer, cgminer, "t-rex", claymore)
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name target=%fd.rip:%fd.rport
    command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

A local listener was started on `127.0.0.1:3333`, then `xmrig` was run against that local address with a five-second timeout. No real mining pool was contacted.

```json
{"hostname":"9b61785f48d6","output":"2026-06-26T15:26:56.449900420+0000: Critical Possible Cryptominer Activity (container=lab9-target process=xmrig target=127.0.0.1:3333 command=xmrig -o 127.0.0.1:3333 --donate-level=0 --no-color) container_id=686e94dbf7ee container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"686e94dbf7ee","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1782487616449900420,"fd.rip":"127.0.0.1","fd.rport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"xmrig -o 127.0.0.1:3333 --donate-level=0 --no-color","proc.name":"xmrig"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-06-26T15:26:56.449900420Z"}
```

### Reflection

The rule combines two indicators: a known mining process name such as `xmrig` and a connection to a common mining-pool port such as `3333`. It can miss renamed or custom-built miners, mining traffic proxied over HTTPS, and miners using non-standard ports. Because the rule has `CRITICAL` priority, it should enter the Critical SLA workflow: immediate ownership by the on-call or security team, containment of the workload, and investigation within 24 hours.
