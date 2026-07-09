# Lab 9 - Submission

## Task 1: Runtime Detection with Falco

Falco was started with the syscall source and modern BPF probe:

```text
Loaded event sources: syscall
Opening 'syscall' source with modern BPF probe.
```

### Baseline alert A - Terminal shell in container

```json
{"hostname":"1b822cb48578","output":"2026-07-09T18:09:30.761911930+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=253940ef2788 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"253940ef2788","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783620570761911930,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-09T18:09:30.761911930Z"}
```

### Baseline alert B - Read sensitive file untrusted (`cat /etc/shadow`)

```json
{"hostname":"1b822cb48578","output":"2026-07-09T18:09:30.859708680+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=init ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=253940ef2788 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"253940ef2788","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783620570859708680,"evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"init","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-09T18:09:30.859708680Z"}
```

### Custom rule

```yaml
- rule: Write to /tmp by container
  desc: Detect writes to /tmp from containers.
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
  exceptions:
    - name: allowed_tmp_writers
      fields: [proc.name, container.name]
      comps: [in, in]
      values:
        - [[apk], [lab9-target]]

- rule: Possible Cryptominer Activity
  desc: Detect container egress to common mining-pool ports from miner-like or suspicious tooling.
  condition: >
    container.id != host and
    (
      (
        evt.type = connect and
        (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or
         fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) and
        (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nc) or
         proc.pname in (xmrig, ethminer, cgminer, t-rex, claymore) or
         proc.cmdline contains "xmrig")
      ) or (
        evt.type = execve and
        proc.name = nc and
        (proc.cmdline contains " 3333" or
         proc.cmdline contains " 4444" or
         proc.cmdline contains " 5555" or
         proc.cmdline contains " 7777" or
         proc.cmdline contains " 14444" or
         proc.cmdline contains " 19999" or
         proc.cmdline contains " 45700")
      )
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name target=%proc.cmdline fd_target=%fd.sip:%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired

```json
{"hostname":"1b822cb48578","output":"2026-07-09T18:09:30.941350554+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=253940ef2788 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"253940ef2788","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783620570941350554,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-09T18:09:30.941350554Z"}
```

### Tuning consideration

The `/tmp` drift rule is intentionally noisy because many legitimate workloads use `/tmp` for caches, sockets, and temporary files. I would tune this with an `exceptions:` block for known `(proc.name, container.name)` pairs, because it keeps the allowlist visible and structured; I would use `and not proc.name=...` only for one-off local tuning when the exception does not need to be reused.

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

containers contains container if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
}

run_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

run_as_non_root(container) if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

drops_all_capabilities(container) if {
  drop := container.securityContext.capabilities.drop[_]
  drop == "ALL"
}

deny contains msg if {
  container := containers[_]
  not run_as_non_root(container)
  msg := sprintf("container %q must run as non-root at pod or container level", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
  container := containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

deny contains msg if {
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
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must run as non-root at pod or container level
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation to false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes

```text
$ conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time

CI-time Conftest gives developers fast feedback during PR review, before a bad manifest reaches the cluster path. Admission-time policy is still needed because it protects the real cluster from manual `kubectl apply`, stale branches, or emergency changes that bypass CI. Running both creates defense in depth: CI optimizes for early correction, admission control optimizes for enforcement at the boundary.

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- rule: Possible Cryptominer Activity
  desc: Detect container egress to common mining-pool ports from miner-like or suspicious tooling.
  condition: >
    container.id != host and
    (
      (
        evt.type = connect and
        (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or
         fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) and
        (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nc) or
         proc.pname in (xmrig, ethminer, cgminer, t-rex, claymore) or
         proc.cmdline contains "xmrig")
      ) or (
        evt.type = execve and
        proc.name = nc and
        (proc.cmdline contains " 3333" or
         proc.cmdline contains " 4444" or
         proc.cmdline contains " 5555" or
         proc.cmdline contains " 7777" or
         proc.cmdline contains " 14444" or
         proc.cmdline contains " 19999" or
         proc.cmdline contains " 45700")
      )
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name target=%proc.cmdline fd_target=%fd.sip:%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{"hostname":"1b822cb48578","output":"2026-07-09T18:09:31.003860221+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc target=nc -w 2 127.0.0.1 3333 fd_target=<NA>:<NA>) container_id=253940ef2788 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"253940ef2788","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783620571003860221,"fd.sip":null,"fd.sport":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-09T18:09:31.003860221Z"}
```

### Reflection

The rule uses two indicators: a miner-like process or simulation tool (`xmrig`, `ethminer`, `cgminer`, `t-rex`, `claymore`, or `nc`) and a common mining-pool port (`3333`, `4444`, `5555`, `7777`, `14444`, `19999`, `45700`). It can miss miners that proxy over HTTPS, use domain fronting, rename the process, or hide inside a legitimate parent process. I would route this as a high-priority runtime finding in the Lecture 9 SLA matrix because active cryptomining is execution plus command-and-control behavior, then correlate it with image provenance and Kubernetes workload owner before remediation.
