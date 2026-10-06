# Lab 9 - Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A - Terminal shell in container
JSON alert from Falco logs:
```json
{
  "hostname": "1b0a261f7934",
  "output": "2026-07-09T09:06:11.737342816+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo \"shell-in-container test\"; sleep 1 terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=6238ae4fa79b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "6238ae4fa79b",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1783587971737342816,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"; sleep 1",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "runc",
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
  "time": "2026-07-09T09:06:11.737342816Z"
}
```

### Baseline alert B - Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
  "hostname": "1b0a261f7934",
  "output": "2026-07-09T09:06:14.104289678+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=6238ae4fa79b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "6238ae4fa79b",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783587974104289678,
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
    "proc.pname": null,
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
  "time": "2026-07-09T09:06:14.104289678Z"
}
```

### Custom rule - Write to /tmp by container
```yaml
- rule: Write to /tmp by container
  desc: Detect a process writing to the /tmp directory inside a container
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: Write to /tmp by container (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

```

### Custom rule fired
```json
{
  "hostname": "1b0a261f7934",
  "output": "2026-07-09T09:40:58.239435015+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/final-write.txt command=sh -lc echo \"final-test\" > /tmp/final-write.txt) container_id=6238ae4fa79b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "6238ae4fa79b",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783590058239435015,
    "fd.name": "/tmp/final-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"final-test\" > /tmp/final-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-07-09T09:40:58.239435015Z"
}
```

### Tuning consideration (Lecture 9 slide 8)
For structured and reviewable allowlists, approved workloads or processes should be added through a Falco `exceptions:` block. A narrow temporary exclusion can be expressed with `and not proc.name=...`, but exceptions scale better and keep tuning separate from the core detection condition.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

pod_runs_as_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

container_runs_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

drops_all_capabilities(container) if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])

  "ALL" in dropped
}

# 1. Require runAsNonRoot at pod or container level.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not pod_runs_as_non_root
  not container_runs_as_non_root(container)

  msg := sprintf(
    "container %q must set runAsNonRoot: true at pod or container level",
    [container.name],
  )
}

# 2. Prevent processes from gaining additional privileges.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.securityContext.allowPrivilegeEscalation == false

  msg := sprintf(
    "container %q must set allowPrivilegeEscalation: false",
    [container.name],
  )
}

# 3. Require all Linux capabilities to be dropped.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not drops_all_capabilities(container)

  msg := sprintf(
    "container %q must drop ALL capabilities",
    [container.name],
  )
}

# 4. Require a memory limit for every container.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.resources.limits.memory

  msg := sprintf(
    "container %q must set resources.limits.memory",
    [container.name],
  )
}

# 5. Require immutable images pinned by SHA-256 digest.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not contains(container.image, "@sha256:")

  msg := sprintf(
    "container %q image must be pinned with an @sha256 digest",
    [container.name],
  )
}
```

### Compliant manifest passes (juice-hardened.yaml)
```text

10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" image must be pinned with an @sha256 digest
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```text
PASS - juice-compose.yml:

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

FAIL - /tmp/bad-compose.yml:
FAIL - C:/Users/user/AppData/Local/Temp/bad-compose.yml - compose.security - services must drop ALL capabilities
FAIL - C:/Users/user/AppData/Local/Temp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - C:/Users/user/AppData/Local/Temp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest gives developers feedback during pull-request review, before an unsafe manifest reaches the cluster. Admission-time enforcement repeats the policy check during `kubectl apply`, catching direct changes, configuration drift, and attempts to bypass CI; running both creates defense in depth.

## Bonus: Cryptominer Detection

### Bonus rule
```yaml
- list: known_miner_processes
  items: [xmrig, ethminer, cgminer, t-rex, claymore]

- rule: Possible Cryptominer Activity
  desc: Detect connections to common mining-pool ports or execution of known miner processes inside containers
  condition: >
    container.id != host
    and
    (
      (
        evt.type=connect
        and
        (
          fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
          or evt.args endswith ":3333"
          or evt.args endswith ":4444"
          or evt.args endswith ":5555"
          or evt.args endswith ":7777"
          or evt.args endswith ":14444"
          or evt.args endswith ":19999"
          or evt.args endswith ":45700"
        )
      )
      or
      (
        evt.type in (execve, execveat)
        and proc.name in (known_miner_processes)
      )
    )
  output: Possible Cryptominer Activity (container=%container.name process=%proc.name command=%proc.cmdline target=%evt.args connection=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
  "hostname": "1b0a261f7934",
  "output": "2026-07-09T10:08:58.989863273+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 target=res=-111(ECONNREFUSED) tuple=NULL fd=3(<4>0.0.0.0:0) addr=127.0.0.1:3333 connection=0.0.0.0:0) container_id=6238ae4fa79b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "6238ae4fa79b",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.args": "res=-111(ECONNREFUSED) tuple=NULL fd=3(<4>0.0.0.0:0) addr=127.0.0.1:3333",
    "evt.time.iso8601": 1783591738989863273,
    "fd.name": "0.0.0.0:0",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
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
  "time": "2026-07-09T10:08:58.989863273Z"
}
```

### Reflection
The rule combines two indicators: connections to common mining-pool ports and execution of known miner process names. It may miss a renamed miner that communicates through an ordinary HTTPS port, so runtime and network evidence should be correlated. Under the Lecture 9 SLA matrix, a CRITICAL alert requires immediate triage and containment, followed by validation to reduce false positives.
