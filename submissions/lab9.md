# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{"hostname":"9e3fe7a7164d","output":"2026-07-11T09:31:54.637635216+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=9965a6a599f6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9965a6a599f6","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783762314637635216,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-11T09:31:54.637635216Z"}
```

### Baseline alert B — Container drift (drop and execute new binary)
> Note: in Falco 0.43.1 the relevant default rule is named `"Drop and execute new binary in container"` (successor to the older `"Write below binary dir"` rule). It was triggered by copying an existing binary into `/usr/local/bin/` and executing it — a real drift-and-execute pattern, rather than just a plain text-file write.
```json
{"hostname":"9e3fe7a7164d","output":"2026-07-11T09:44:58.682419669+0000: Critical Executing binary not part of base image | proc_exe=/usr/local/bin/fake-binary proc_sname= gparent=systemd proc_exe_ino_ctime=1783763098680636080 proc_exe_ino_mtime=4707072802758275760 proc_exe_ino_ctime_duration_proc_start=18446744073670260079 proc_cwd=/ container_start_ts=1783673133883078682 evt_type=execve user=root user_uid=0 user_loginuid=-1 process=fake-binary proc_exepath=/usr/local/bin/fake-binary parent=containerd-shim command=fake-binary echo test terminal=0 exe_flags=EXE_WRITABLE|EXE_UPPER_LAYER container_id=9965a6a599f6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9965a6a599f6","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","container.start_ts":1783673133883078682,"evt.arg.flags":"EXE_WRITABLE|EXE_UPPER_LAYER","evt.time.iso8601":1783763098682419669,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.cmdline":"fake-binary echo test","proc.cwd":"/","proc.exe":"/usr/local/bin/fake-binary","proc.exe_ino.ctime":1783763098680636080,"proc.exe_ino.ctime_duration_proc_start":18446744073670260079,"proc.exe_ino.mtime":4707072802758275760,"proc.exepath":"/usr/local/bin/fake-binary","proc.name":"fake-binary","proc.pname":"containerd-shim","proc.sname":"","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Critical","rule":"Drop and execute new binary in container","source":"syscall","tags":["PCI_DSS_11.5.1","TA0003","container","maturity_stable","mitre_persistence","process"],"time":"2026-07-11T09:44:58.682419669Z"}
```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect any write to /tmp inside a running container
  condition: >
    open_write
    and container
    and fd.name startswith /tmp
  output: >
    Write to /tmp inside container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{"hostname":"9e3fe7a7164d","output":"2026-07-11T09:36:27.505237307+0000: Warning Write to /tmp inside container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=9965a6a599f6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9965a6a599f6","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783762587505237307,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-11T09:36:27.505237307Z"}
```

### Tuning consideration (Lecture 9 slide 8)
My custom "Write to /tmp by container" rule will fire on legitimate uses too — logging frameworks, healthcheck scripts, and cache updates commonly write temp files to /tmp. For tuning, I would use the `exceptions:` block (available since Falco 0.28+) rather than a long chain of `and not proc.name=...` conditions inside the rule itself. This keeps the base condition clean and makes exceptions easier to audit and maintain as a separate, structured list — instead of bloating the core detection logic as more legitimate processes get added over time.

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true (pod or container level)", [c.name])
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
  not c.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities (capabilities.drop not set)", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  c.securityContext.capabilities.drop
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must include \"ALL\" in capabilities.drop", [c.name])
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
  msg := sprintf("container %q image must be pinned by sha256 digest, not a tag", [c.name])
}
```

### Good manifest passes (juice-hardened.yaml)
> Note: `image` was updated from a version tag (`v19.0.0`) to a pinned sha256 digest (`bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d`), resolved via `docker inspect`, to satisfy the digest-pinning rule.

12 tests, 12 passed, 0 warnings, 0 failures, 0 exceptions

### Bad manifest fails (juice-unhardened.yaml)

FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" image must be pinned by sha256 digest, not a tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities (capabilities.drop not set)
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true (pod or container level)
12 tests, 7 passed, 0 warnings, 5 failures, 0 exceptions

All 5 hardening rules correctly fire — the unhardened manifest has no `securityContext`, no `resources`, and uses a mutable image tag (`:latest`) rather than a digest.

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running Conftest at CI-time (during PR review) catches misconfigured manifests early and cheaply — before they ever reach the cluster, giving developers immediate feedback right in the pull request. Running policy enforcement at admission-time (e.g. via OPA Gatekeeper or Kyverno on `kubectl apply`) acts as the last line of defense, catching anything that bypassed CI — a manual `kubectl apply`, a different deployment pipeline, or configuration drift after the fact. Combining both gives defense-in-depth: CI-time catches issues early for the common case at low cost, while admission-time guarantees that nothing non-compliant can actually run in the cluster, regardless of how it got there.
