# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Falco runtime

Falco 0.43.1 started successfully on Docker Desktop's LinuxKit VM with the modern BPF probe:

```text
Falco version: 0.43.1 (aarch64)
Opening 'syscall' source with modern BPF probe.
Loaded event sources: syscall
Enabled event sources: syscall
Loading rules from:
   /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
```

### Baseline alert A — Terminal shell in container

```json
{"hostname":"8b590008bc7d","output":"2026-07-03T14:36:07.050613263+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=0f8ae74c4488 container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0f8ae74c4488","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783089367050613263,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-03T14:36:07.050613263Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{"hostname":"8b590008bc7d","output":"2026-07-03T14:36:13.845228057+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=initd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=0f8ae74c4488 container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0f8ae74c4488","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783089373845228057,"evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"initd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-03T14:36:13.845228057Z"}
```

### Custom rule

```yaml
- rule: Write to /tmp by container
  desc: Detect writes to /tmp from any containerized process.
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Container wrote to /tmp
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired

```json
{"hostname":"8b590008bc7d","output":"2026-07-03T14:36:13.909934265+0000: Warning Container wrote to /tmp (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=0f8ae74c4488 container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0f8ae74c4488","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783089373909934265,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-03T14:36:13.909934265Z"}
```

### Tuning consideration

Writes to `/tmp` are common for caches, sockets, and temporary files, so the first tuning pass should use an `exceptions:` block for approved container/process/file-prefix combinations. I would keep the main rule broad and add narrow exceptions for expected writers, because a long chain of `and not proc.name=...` conditions tends to hide drift and becomes harder to audit during review.

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

containers := input.spec.template.spec.containers

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

container_security_context(container) := object.get(container, "securityContext", {})

container_dropped_capabilities(container) := object.get(object.get(container_security_context(container), "capabilities", {}), "drop", [])

container_runs_as_non_root(container) if {
  container_security_context(container).runAsNonRoot == true
}

container_runs_as_non_root(container) if {
  pod_security_context.runAsNonRoot == true
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not container_runs_as_non_root(container)
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not container_security_context(container).allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not "ALL" in container_dropped_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("container %q must pin image by sha256 digest", [container.name])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)

```text
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL Linux capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin image by sha256 digest
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes

```text
$ conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must drop ALL capabilities
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### Why CI-time vs admission-time

CI-time Conftest gives reviewers fast feedback before a risky manifest reaches the cluster, so fixes stay cheap and visible in the PR. Admission-time enforcement protects the runtime boundary from manual `kubectl apply`, stale branches, or a misconfigured CI path. Running both creates defense in depth: one control improves developer workflow, the other protects the production API server.

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- rule: Possible Cryptominer Activity
  desc: Detect container network activity that resembles mining-pool egress during lab simulation.
  condition: >
    evt.type=connect
    and container.id != host
    and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
    and (proc.cmdline contains "nc" or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity
    (container=%container.name process=%proc.name command=%proc.cmdline target=%fd.cip:%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{"hostname":"8b590008bc7d","output":"2026-07-03T14:36:35.217459859+0000: Critical Possible cryptominer activity (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 target=127.0.0.1:3333) container_id=0f8ae74c4488 container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0f8ae74c4488","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783089395217459859,"fd.cip":"127.0.0.1","fd.sport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-03T14:36:35.217459859Z"}
```

### Reflection

The rule combines a mining-pool destination port with a suspicious mining process or lab-safe `nc` simulation, which keeps the condition tied to network egress instead of only process names. It can miss miners that tunnel over HTTPS, change ports, or use renamed binaries, so it should be paired with image provenance, egress policy, and anomaly metrics. In the SLA matrix I would treat this as Critical runtime evidence: triage immediately, contain the container, and target the 24-hour Critical SLA for remediation closure.
