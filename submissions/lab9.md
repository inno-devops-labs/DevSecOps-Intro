# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Modern eBPF engine evidence

Falco 0.43.1 successfully initialized the syscall event source with the modern eBPF probe:

```text
2026-07-10T18:12:47+0000: Loaded event sources: syscall
2026-07-10T18:12:47+0000: Enabled event sources: syscall
2026-07-10T18:12:47+0000: Opening 'syscall' source with modern BPF probe.
```

### Baseline alert A — Terminal shell in container

The built-in `Terminal shell in container` rule fired after executing an interactive shell in `lab9-target`:

```json
{
  "hostname": "ef96c886ad0a",
  "output": "2026-07-10T18:12:55.408470501+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=4bbbe59b59cd container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "4bbbe59b59cd",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1783707175408470501,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
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
  "time": "2026-07-10T18:12:55.408470501Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

The built-in `Read sensitive file untrusted` rule fired when `/etc/shadow` was opened by `cat` inside the container:

```json
{
  "hostname": "ef96c886ad0a",
  "output": "2026-07-10T18:12:55.440479663+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=containerd-shim ggparent=systemd gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=runc command=cat /etc/shadow terminal=0 container_id=4bbbe59b59cd container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "4bbbe59b59cd",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783707175440479663,
    "evt.type": "open",
    "fd.name": "/etc/shadow",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.aname[2]": "containerd-shim",
    "proc.aname[3]": "systemd",
    "proc.aname[4]": null,
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "proc.name": "cat",
    "proc.pname": "runc",
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
  "time": "2026-07-10T18:12:55.440479663Z"
}
```

### Custom Falco rules

`labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Write to /tmp by container
  desc: Detect successful file opens for writing below /tmp from inside a container
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
    - name: allowed_package_manager_tmp_writes
      fields: proc.name
      comps: in
      values: [apk]

- rule: Possible Cryptominer Activity
  desc: Detect successful container connections to common mining-pool ports or known miner process execution
  condition: >
    container.id != host and
    (
      (
        evt.type = connect and
        evt.dir = < and
        fd.sockfamily = ip and
        fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) and
        (evt.rawres >= 0 or evt.res = EINPROGRESS)
      ) or
      (spawned_process and proc.name in (xmrig, ethminer, cgminer, "t-rex", claymore))
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name command=%proc.cmdline target=%fd.name server_ip=%fd.sip server_port=%fd.sport result=%evt.res)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired

The `Write to /tmp by container` rule fired after writing `/tmp/my-write.txt`:

```json
{
  "hostname": "ef96c886ad0a",
  "output": "2026-07-10T18:12:58.504870353+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=4bbbe59b59cd container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "4bbbe59b59cd",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783707178504870353,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-07-10T18:12:58.504870353Z"
}
```

### Tuning consideration

The `/tmp` rule is deliberately broad because legitimate package managers, logging libraries, and application runtimes may also write below `/tmp`. In production, I would use a structured `exceptions:` block scoped to known process names together with the expected image or path, rather than accumulating broad `and not proc.name=...` clauses in the main condition; this keeps the detection logic readable and the allow-list auditable.

## Task 2: Conftest Policy-as-Code

### My policy file

`labs/lab9/policies/extra/hardening.rego`:

```rego
package main

import rego.v1

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    security_context := object.get(container, "securityContext", {})
    capabilities := object.get(security_context, "capabilities", {})
    dropped_capabilities := object.get(capabilities, "drop", [])
    not "ALL" in dropped_capabilities
    msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
```

The policy enforces four Kubernetes hardening requirements:

1. `runAsNonRoot` must be enabled at pod or container level.
2. `allowPrivilegeEscalation` must be `false`.
3. every container must drop the `ALL` Linux capability set;
4. every container must define `resources.limits.memory`.

### Compliant manifest passes (`juice-hardened.yaml`)

```text
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL Linux capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level

8 tests, 4 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes

The shipped `compose-security.rego` policy passed the hardened Compose manifest:

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

The same policy rejected a deliberately unhardened Compose manifest:

```text
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

This demonstrates that the same `deny` policy pattern can be applied to a different input shape: Kubernetes policies inspect `input.spec.template.spec`, while the Compose policy inspects `input.services`.

### Why CI-time and admission-time checks should both run

CI-time Conftest rejects insecure configuration while the pull request is still under review, giving developers fast feedback before the manifest is merged or released. Admission-time enforcement repeats the decision against the exact object submitted to the cluster and therefore blocks direct `kubectl apply`, stale pipelines, or post-review mutations. Running both provides defense in depth: CI prevents most policy violations early, while admission control protects the final deployment boundary.

## Bonus: Cryptominer Detection Rule

### Detection design

The `Possible Cryptominer Activity` rule, included in `custom-rules.yaml`, combines two indicator classes:

- outbound or local TCP connections to common Stratum-style mining ports;
- execution of well-known miner process names such as `xmrig`, `ethminer`, and `cgminer`.

The network branch was tested safely against a local listener on `127.0.0.1:3333`; no real mining pool was contacted.

### Trigger command

```sh
docker exec lab9-target /bin/sh -lc 'nc -z -w 3 127.0.0.1 3333'
```

### Triggered alert

```json
{
  "hostname": "ef96c886ad0a",
  "output": "2026-07-10T18:13:01.862369265+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc command=nc -z -w 3 127.0.0.1 3333 target=127.0.0.1:60960->127.0.0.1:3333 server_ip=127.0.0.1 server_port=3333 result=EINPROGRESS) container_id=4bbbe59b59cd container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "4bbbe59b59cd",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.res": "EINPROGRESS",
    "evt.time.iso8601": 1783707181862369265,
    "fd.name": "127.0.0.1:60960->127.0.0.1:3333",
    "fd.sip": "127.0.0.1",
    "fd.sport": 3333,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -z -w 3 127.0.0.1 3333",
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
  "time": "2026-07-10T18:13:01.862369265Z"
}
```

### Reflection

Port-based detection catches many default Stratum deployments, while process-name detection provides an independent signal when a known miner binary is executed. The rule can miss renamed miners and traffic tunneled through HTTPS, a private proxy, or a non-standard port, so the alert should be correlated with DNS/network telemetry, image findings, and abnormal CPU consumption. In an SLA matrix, this `CRITICAL` alert should receive immediate triage; lower-confidence single-indicator variants could be assigned a less aggressive response target.
