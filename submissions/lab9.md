# Lab 9 — Submission

## Environment

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
Kernel: 7.0.12-arch1-1
BTF: /sys/kernel/btf/vmlinux present
Falco image: falcosecurity/falco:0.44.1
Conftest image: openpolicyagent/conftest:v0.68.0
Target image: alpine:3.20
```

## Task 1: Runtime Detection with Falco

### Modern eBPF engine evidence

```text
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'podman' container engine.
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'docker' container engine.
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'cri' container engine.
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'containerd' container engine.
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'lxc' container engine.
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'libvirt_lxc' container engine.
2026-07-10T15:55:41+0000: [libs]: container: Enabled 'bpm' container engine.
2026-07-10T15:55:41+0000: The chosen syscall buffer dimension is: 8388608 bytes (8 MBs)
2026-07-10T15:55:41+0000: Loaded event sources: syscall
2026-07-10T15:55:41+0000: Enabled event sources: syscall
2026-07-10T15:55:41+0000: Opening 'syscall' source with modern BPF probe.
2026-07-10T15:55:41+0000: [libs]: Trying to open the right engine!
```

### Baseline alert A — Terminal shell in container

```json
{
  "hostname": "df5f828c7ed5",
  "output": "2026-07-10T15:55:47.811217351+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo shell-in-container-test terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=f0ce447bc170 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "f0ce447bc170",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1783698947811217351,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo shell-in-container-test",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "systemd",
    "proc.tty": 34816,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": [
    "T1059",
    "container",
    "maturity_stable",
    "mitre_execution",
    "shell"
  ],
  "time": "2026-07-10T15:55:47.811217351Z"
}
```

### Baseline alert B — Read sensitive file untrusted

```json
{
  "hostname": "df5f828c7ed5",
  "output": "2026-07-10T15:55:47.886505320+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=systemd command=cat /etc/shadow terminal=0 container_id=f0ce447bc170 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "f0ce447bc170",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783698947886505320,
    "evt.type": "open",
    "fd.name": "/etc/shadow",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.aname[2]": null,
    "proc.aname[3]": null,
    "proc.aname[4]": null,
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "proc.name": "cat",
    "proc.pname": "systemd",
    "proc.tty": 0,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-07-10T15:55:47.886505320Z"
}
```

### Custom Falco rules

```yaml
- list: mining_pool_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: known_miner_processes
  items: [xmrig, ethminer, cgminer, t-rex, claymore]

- rule: Write to /tmp by container
  desc: Detect creation or modification of files below /tmp from inside a container
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name container_id=%container.id
    user=%user.name process=%proc.name command=%proc.cmdline file=%fd.name)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect a container connecting to a common mining-pool port or using a known miner process name
  condition: >
    container.id != host
    and evt.type=connect
    and (
      fd.rport in (mining_pool_ports)
      or proc.name in (known_miner_processes)
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name container_id=%container.id
    process=%proc.name command=%proc.cmdline
    server=%fd.sip:%fd.sport remote=%fd.rip:%fd.rport fd=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired — Write to `/tmp`

```json
{
  "hostname": "df5f828c7ed5",
  "output": "2026-07-10T15:55:47.949984200+0000: Warning Write to /tmp by container (container=lab9-target container_id=f0ce447bc170 user=root process=sh command=sh -lc echo test > /tmp/my-write.txt file=/tmp/my-write.txt) container_id=f0ce447bc170 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "f0ce447bc170",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783698947949984200,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "proc.name": "sh",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-07-10T15:55:47.949984200Z"
}
```

### Tuning consideration

The `/tmp` drift rule intentionally starts broad because unexpected writes are useful
during baseline collection, but legitimate runtimes and logging libraries can create
noise. In production I would add a named `exceptions:` block keyed by trusted image,
container, process, and path combinations so exemptions remain reviewable data rather
than hidden condition changes. A narrow process exclusion is acceptable for a temporary
suppression, but structured exceptions are easier to audit and expire.

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

import rego.v1

is_deployment if {
  input.kind == "Deployment"
}

pod_spec := input.spec.template.spec if {
  is_deployment
}

containers := object.get(pod_spec, "containers", []) if {
  is_deployment
}

pod_runs_as_non_root if {
  pod_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_context, "runAsNonRoot", false) == true
}

container_runs_as_non_root(container) if {
  context := object.get(container, "securityContext", {})
  object.get(context, "runAsNonRoot", false) == true
}

deny contains msg if {
  is_deployment
  container := containers[_]
  not pod_runs_as_non_root
  not container_runs_as_non_root(container)
  msg := sprintf(
    "container %q must set runAsNonRoot=true at pod or container level",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf(
    "container %q must set allowPrivilegeEscalation=false",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  context := object.get(container, "securityContext", {})
  capabilities := object.get(context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])
  not "ALL" in dropped
  msg := sprintf(
    "container %q must drop the ALL capability set",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  resources := object.get(container, "resources", {})
  limits := object.get(resources, "limits", {})
  object.get(limits, "memory", "") == ""
  msg := sprintf(
    "container %q must define resources.limits.memory",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf(
    "container %q must set readOnlyRootFilesystem=true",
    [container.name],
  )
}
```

### Compliant Kubernetes manifest passes

```text
[32m10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions[0m
```

### Non-compliant Kubernetes manifest fails

```text
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must define resources.limits.memory
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop the ALL capability set
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation=false
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set readOnlyRootFilesystem=true
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot=true at pod or container level

[31m10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions[0m
```

### Shipped Compose policy — compliant manifest passes

```text
[32m4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions[0m
```

### Shipped Compose policy — deliberately bad manifest fails

```text
[31mFAIL[0m - labs/lab9/analysis/bad-compose.yml - compose.security - services must set an explicit non-root user
[31mFAIL[0m - labs/lab9/analysis/bad-compose.yml - compose.security - services must set read_only: true

[31m4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions[0m
```

### Why CI-time and admission-time controls should both run

CI-time Conftest gives developers fast feedback while the change is still a pull request,
where remediation is cheap and the policy failure is attributable to a specific diff.
Admission-time enforcement protects the cluster from bypasses, stale branches, direct
`kubectl` use, and compromised CI credentials. Running both provides defense in depth:
CI improves workflow and admission control protects the final trust boundary.

## Bonus: Cryptominer Detection Rule

The custom rules file combines two independent indicator classes: connections to common
mining-pool server ports and process names associated with known miner families.

### Triggered alert

```json
{
  "hostname": "df5f828c7ed5",
  "output": "2026-07-10T15:55:48.271102867+0000: Critical Possible Cryptominer Activity (container=lab9-target container_id=f0ce447bc170 process=nc command=nc -w 3 172.17.0.4 3333 server=172.17.0.4:3333 remote=172.17.0.4:3333 fd=172.17.0.2:42093->172.17.0.4:3333) container_id=f0ce447bc170 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "f0ce447bc170",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783698948271102867,
    "fd.name": "172.17.0.2:42093->172.17.0.4:3333",
    "fd.rip": "172.17.0.4",
    "fd.rport": 3333,
    "fd.sip": "172.17.0.4",
    "fd.sport": 3333,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 3 172.17.0.4 3333",
    "proc.name": "nc"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": [
    "container",
    "mitre_command_and_control",
    "mitre_execution"
  ],
  "time": "2026-07-10T15:55:48.271102867Z"
}
```

### Reflection

The test fired on a connection attempt to TCP port 3333, while the same rule also checks
for known miner process names such as `xmrig` and `cgminer`. This misses miners that use
renamed binaries and tunnel traffic over ordinary HTTPS or private relay infrastructure,
so it should be combined with image provenance, DNS/network telemetry, CPU anomaly
detection, and process-tree context. A CRITICAL alert should enter the SLA matrix with a
24-hour remediation target, while repeated noisy indicators should be tuned rather than
silently downgraded.

## Completion checklist

- [x] Falco ran with the modern eBPF engine.
- [x] `Terminal shell in container` fired.
- [x] `Read sensitive file untrusted` fired.
- [x] `Write to /tmp by container` fired.
- [x] Five Kubernetes hardening denies were implemented.
- [x] Hardened Kubernetes manifest passed.
- [x] Unhardened Kubernetes manifest failed with multiple distinct messages.
- [x] Shipped Compose policy passed and failed on the expected inputs.
- [x] Bonus cryptominer rule combines two indicator classes and fired.
