# Lab 9 — Submission

## Environment

- Host: macOS on Apple Silicon
- Docker backend: Colima
- Colima guest OS: Ubuntu 24.04
- Falco: 0.43.1
- Falco engine: modern BPF probe
- Conftest: installed through Homebrew
- OPA: 1.15.2

Falco was run inside Colima because Docker Desktop on macOS does not provide the required BTF-enabled Linux kernel. The BTF gate check succeeded:

```text
BTF OK: modern eBPF can be used
```

Falco startup confirmed the syscall source and modern eBPF engine:

```text
Loaded event sources: syscall
Enabled event sources: syscall
Opening 'syscall' source with modern BPF probe.
```

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container

The following command created an interactive shell inside the target container:

```bash
docker exec -it lab9-target /bin/sh -lc 'echo "shell-in-container test"; id; sleep 1'
```

JSON alert from Falco:

```json
{"hostname":"cee74423a486","output":"2026-07-10T09:21:10.028791311+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\"; id; sleep 1 terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=0fb1cd2199e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0fb1cd2199e5","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783675270028791311,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"; id; sleep 1","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T09:21:10.028791311Z"}
```

### Baseline alert B — Read sensitive file untrusted

The following command read `/etc/shadow` inside the target container:

```bash
docker exec lab9-target /bin/sh -lc 'cat /etc/shadow >/dev/null'
```

JSON alert from Falco:

```json
{"hostname":"cee74423a486","output":"2026-07-10T09:21:11.097425878+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=0fb1cd2199e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0fb1cd2199e5","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783675271097425878,"evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T09:21:11.097425878Z"}
```

### Custom rule

```yaml
- rule: Write to /tmp by container
  desc: Detect a file being opened for writing under /tmp inside a container
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name
    command=%proc.cmdline container_id=%container.id)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired

The custom rule detected a write to `/tmp/my-write.txt` inside the container:

```json
{"hostname":"cee74423a486","output":"2026-07-10T09:21:11.133592997+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt container_id=0fb1cd2199e5) container_id=0fb1cd2199e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0fb1cd2199e5","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783675271133592997,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T09:21:11.133592997Z"}
```

### Tuning consideration

A broad write-to-`/tmp` rule can produce false positives because many legitimate applications use temporary files. I would first use an `exceptions:` block for approved container images, processes, or paths because it keeps tuning data separate from the main detection condition. For a very small and stable exclusion, an `and not proc.name in (...)` condition is acceptable, but large inline exclusions make the rule harder to maintain.

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

container_run_as_non_root(container, pod_spec) if {
  container_security_context := object.get(container, "securityContext", {})
  object.get(container_security_context, "runAsNonRoot", false) == true
}

container_run_as_non_root(container, pod_spec) if {
  pod_security_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_security_context, "runAsNonRoot", false) == true
}

deny contains msg if {
  input.kind == "Deployment"

  pod_spec := input.spec.template.spec
  container := pod_spec.containers[_]

  not container_run_as_non_root(container, pod_spec)

  msg := sprintf(
    "container %q must set runAsNonRoot: true at pod or container level",
    [container.name],
  )
}

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})

  object.get(security_context, "allowPrivilegeEscalation", true) != false

  msg := sprintf(
    "container %q must set allowPrivilegeEscalation: false",
    [container.name],
  )
}

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped_capabilities := object.get(capabilities, "drop", [])

  not "ALL" in dropped_capabilities

  msg := sprintf(
    "container %q must drop ALL capabilities",
    [container.name],
  )
}

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]
  resources := object.get(container, "resources", {})
  limits := object.get(resources, "limits", {})

  not object.get(limits, "memory", false)

  msg := sprintf(
    "container %q must set resources.limits.memory",
    [container.name],
  )
}
```

The policy enforces four requirements:

1. `runAsNonRoot: true` at pod or container level.
2. `allowPrivilegeEscalation: false` for every container.
3. `capabilities.drop` must contain `ALL`.
4. `resources.limits.memory` must be configured.

### Compliant manifest passes

Command:

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml   --policy labs/lab9/policies/extra/
```

Output:

```text

[32m8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions[0m
```

### Non-compliant manifest fails

Command:

```bash
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml   --policy labs/lab9/policies/extra/
```

Output:

```text
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
[31mFAIL[0m - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level

[31m8 tests, 4 passed, 0 warnings, 4 failures, 0 exceptions[0m
```

The manifest fails four distinct hardening checks: non-root execution, privilege escalation, dropped capabilities, and memory limits.

### Compose policy generalizes

The shipped Compose policy uses the same `deny contains msg if` approach against the `input.services` shape.

Hardened Compose command:

```bash
conftest test labs/lab9/manifests/compose/juice-compose.yml   --policy labs/lab9/policies/compose-security.rego   --namespace compose.security
```

Output:

```text

[32m4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions[0m
```

Deliberately bad Compose manifest:

```yaml
services:
  app:
    image: nginx:latest
    ports:
      - "8080:80"
    cap_drop:
      - NET_RAW
    security_opt: []
```

Bad Compose command:

```bash
conftest test /tmp/bad-compose.yml   --policy labs/lab9/policies/compose-security.rego   --namespace compose.security
```

Output:

```text
[33mWARN[0m - /tmp/bad-compose.yml - compose.security - services should enable no-new-privileges
[31mFAIL[0m - /tmp/bad-compose.yml - compose.security - services must drop ALL capabilities
[31mFAIL[0m - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
[31mFAIL[0m - /tmp/bad-compose.yml - compose.security - services must set read_only: true

[31m4 tests, 0 passed, 1 warning, 3 failures, 0 exceptions[0m
```

### Why CI-time vs admission-time

CI-time policy checks give developers feedback during pull-request review, before an invalid manifest reaches a cluster. Admission-time checks protect the cluster even if CI is bypassed, a branch is misconfigured, or a manifest is applied manually. Running both provides defense in depth: CI improves developer feedback, while admission control enforces the final runtime boundary.

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- rule: Possible Cryptominer Activity
  desc: Detect a container process connecting to a common mining port or using a known miner process name
  condition: >
    evt.type=connect
    and container.id != host
    and
    (
      fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
      or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name command=%proc.cmdline
    target_ip=%fd.cip target_port=%fd.sport target_name=%fd.cip.name
    container_id=%container.id)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

A local listener was started on port 3333, then `nc` connected to it from the same container:

```bash
docker exec -d lab9-target /bin/sh -lc 'nc -l -p 3333 >/tmp/nc-listener.log 2>&1'
docker exec lab9-target /bin/sh -lc 'echo "stratum-test" | nc -w 3 127.0.0.1 3333'
```

Falco alert:

```json
{"hostname":"cee74423a486","output":"2026-07-10T09:31:18.784554198+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc command=nc -w 3 127.0.0.1 3333 target_ip=127.0.0.1 target_port=3333 target_name=<NA> container_id=0fb1cd2199e5) container_id=0fb1cd2199e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0fb1cd2199e5","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783675878784554198,"fd.cip":"127.0.0.1","fd.cip.name":null,"fd.sport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 3 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T09:31:18.784554198Z"}
```

### Reflection

The rule combines two categories of indicators: connections to common mining-pool ports and known miner process names such as `xmrig` or `cgminer`. The test triggered on port 3333, which is commonly associated with Stratum-style mining traffic.

This rule can miss miners that use renamed binaries, uncommon ports, HTTPS tunneling, proxies, or encrypted traffic that resembles normal web traffic. I would combine the critical Falco alert with the Lecture 9 SLA matrix so that high-confidence runtime detections receive a short acknowledgement and containment SLA, while lower-confidence indicators are correlated with CPU, DNS, and image telemetry before escalation.
