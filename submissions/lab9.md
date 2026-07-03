# Lab 9 - Submission

Run snapshot: 2026-07-03, using Falco 0.43.1 in Docker, Docker Desktop 29.2.1, Conftest dev / OPA 1.15.2, and jq 1.7.1.

Falco engine proof:

```text
/etc/falco/rules.d/custom-rules.yaml | schema validation: ok
Loaded event sources: syscall
Opening 'syscall' source with modern BPF probe.
```

Docker Desktop's LinuxKit kernel emitted several TOCTOU tracepoint warnings, but the syscall source still opened with modern BPF and all required alerts fired.

## Task 1: Runtime Detection with Falco

### Baseline alert A - Terminal shell in container

```json
{"hostname":"b168d4468f23","output":"2026-07-03T13:35:21.446376896+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=e29ad30f0bbc container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e29ad30f0bbc","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783085721446376896,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-03T13:35:21.446376896Z"}
```

### Baseline alert B - Read sensitive file untrusted

```json
{"hostname":"b168d4468f23","output":"2026-07-03T13:35:20.858069895+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=initd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=e29ad30f0bbc container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e29ad30f0bbc","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783085720858069895,"evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"initd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-03T13:35:20.858069895Z"}
```

### Custom rule

```yaml
- list: miner_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: miner_processes
  items: [xmrig, ethminer, cgminer, t-rex, claymore]

- list: miner_test_clients
  items: [nc, ncat, netcat]

- rule: Write to /tmp by container
  desc: Detect a containerized process writing under /tmp.
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect container network activity that resembles common mining-pool traffic.
  condition: >
    container.id != host
    and (
      (evt.type = connect
       and fd.sport in (miner_ports)
       and (proc.name in (miner_processes)
            or proc.name in (miner_test_clients)
            or fd.sip.name contains "minexmr"))
      or
      (spawned_process
       and proc.name in (miner_test_clients)
       and (proc.cmdline contains " 3333"
            or proc.cmdline contains " 4444"
            or proc.cmdline contains " 5555"
            or proc.cmdline contains " 7777"
            or proc.cmdline contains " 14444"
            or proc.cmdline contains " 19999"
            or proc.cmdline contains " 45700"))
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name command=%proc.cmdline target=%fd.sip:%fd.sport target_name=%fd.sip.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired

```json
{"hostname":"b168d4468f23","output":"2026-07-03T13:35:19.129067478+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=e29ad30f0bbc container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e29ad30f0bbc","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783085719129067478,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-03T13:35:19.129067478Z"}
```

### Tuning consideration

The `/tmp` write rule is intentionally noisy because many legitimate runtimes, package managers, and logging libraries write temporary files. I would tune this with an `exceptions:` block for known-safe container/process/path tuples rather than a long chain of `and not proc.name=...`, because exceptions keep the allowlist structured and auditable. I would use `and not` only for a small emergency suppression while collecting enough examples to turn it into a reviewed exception.

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

has_run_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

has_run_as_non_root(container) if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

drops_all_capabilities(container) if {
  "ALL" in container.securityContext.capabilities.drop
}

uses_digest(image) if {
  contains(image, "@sha256:")
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not has_run_as_non_root(container)
  msg := sprintf("container %q must set runAsNonRoot=true at pod or container level", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not uses_digest(container.image)
  msg := sprintf("container %q must pin image by sha256 digest", [container.name])
}
```

### Compliant manifest passes

```text
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL Linux capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin image by sha256 digest
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot=true at pod or container level

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes

Hardened compose:

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

Bad compose:

```text
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time

CI-time Conftest gives developers fast feedback during PR review, before an unsafe manifest is merged or handed to an operator. Admission-time enforcement is still necessary because it catches direct `kubectl apply`, emergency changes, drift, or a CI bypass. Running both creates defense in depth: the same policy intent is checked early for ergonomics and late for enforcement.

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- list: miner_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: miner_processes
  items: [xmrig, ethminer, cgminer, t-rex, claymore]

- list: miner_test_clients
  items: [nc, ncat, netcat]

- rule: Possible Cryptominer Activity
  desc: Detect container network activity that resembles common mining-pool traffic.
  condition: >
    container.id != host
    and (
      (evt.type = connect
       and fd.sport in (miner_ports)
       and (proc.name in (miner_processes)
            or proc.name in (miner_test_clients)
            or fd.sip.name contains "minexmr"))
      or
      (spawned_process
       and proc.name in (miner_test_clients)
       and (proc.cmdline contains " 3333"
            or proc.cmdline contains " 4444"
            or proc.cmdline contains " 5555"
            or proc.cmdline contains " 7777"
            or proc.cmdline contains " 14444"
            or proc.cmdline contains " 19999"
            or proc.cmdline contains " 45700"))
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name command=%proc.cmdline target=%fd.sip:%fd.sport target_name=%fd.sip.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{"hostname":"b168d4468f23","output":"2026-07-03T13:37:55.936405090+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 target=127.0.0.1:3333 target_name=<NA>) container_id=e29ad30f0bbc container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e29ad30f0bbc","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783085875936405090,"fd.sip":"127.0.0.1","fd.sip.name":null,"fd.sport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-03T13:37:55.936405090Z"}
```

### Reflection

The rule uses two indicators: a common mining-pool port and either a known miner process, a DNS/name hint, or a network client used by the lab trigger. This misses miners that tunnel over normal HTTPS, use uncommon ports, rename their processes, or proxy through an internal service. In the Lecture 9 SLA matrix I would treat this as critical runtime evidence: page quickly, isolate the workload, preserve the Falco event and container metadata, then correlate it with image provenance/SBOM and recent deployment history.
