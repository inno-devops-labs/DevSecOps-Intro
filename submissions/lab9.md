# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container

JSON alert from Falco logs:

```json
{"hostname":"ace44f3d3b8d","output":"2026-07-09T10:10:38.674429137+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=09a8125e72dc container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"09a8125e72dc","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783591838674429137,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-09T10:10:38.674429137Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{"hostname":"ace44f3d3b8d","output":"2026-07-09T10:11:06.035481730+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=09a8125e72dc container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"09a8125e72dc","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783591866035481730,"evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-09T10:11:06.035481730Z"}
```

### Custom rule

```yaml
- rule: Write to /tmp by container
  desc: Detect write operations to /tmp inside containers
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Container wrote to /tmp
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- list: mining_pool_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: miner_process_names
  items: [xmrig, ethminer, cgminer, t-rex, claymore, nc]

- rule: Possible Cryptominer Activity
  desc: Detect container network connections or processes matching common cryptominer indicators
  condition: >
    container.id != host
    and evt.type = connect
    and (
      fd.sport in (mining_pool_ports)
      or proc.name in (miner_process_names)
      or fd.cip.name contains "minexmr"
    )
  output: >
    Possible cryptominer activity detected
    (container=%container.name process=%proc.name command=%proc.cmdline target=%fd.sip:%fd.sport target_name=%fd.cip.name user=%user.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired

```json
{"hostname":"ace44f3d3b8d","output":"2026-07-09T10:11:34.573859848+0000: Warning Container wrote to /tmp (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=09a8125e72dc container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"09a8125e72dc","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783591894573859848,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-09T10:11:34.573859848Z"}
```

### Tuning consideration

The custom write-to-/tmp rule can be noisy because many legitimate applications use `/tmp` for cache files, temporary uploads, sockets, or logs. I would tune it with an `exceptions:` block for known safe containers, users, paths, or processes instead of adding many hardcoded `and not proc.name=...` conditions. The `and not` pattern is still useful for a small number of obvious false positives, but exceptions are cleaner and easier to maintain when the allowlist grows.

---

## Task 2: Conftest Policy-as-Code

### My policy file

```rego
package main

containers := input.spec.template.spec.containers

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

container_run_as_non_root(container) if {
	object.get(object.get(container, "securityContext", {}), "runAsNonRoot", false) == true
}

pod_run_as_non_root if {
	object.get(pod_security_context, "runAsNonRoot", false) == true
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	not pod_run_as_non_root
	not container_run_as_non_root(container)

	msg := sprintf("container %q must set runAsNonRoot=true at pod or container securityContext", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false

	msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	drops := object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
	not "ALL" in drops

	msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	not object.get(object.get(object.get(container, "resources", {}), "limits", {}), "memory", false)

	msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
```

### Compliant manifest passes

```text
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL Linux capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot=true at pod or container securityContext

8 tests, 4 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time

CI-time policy checks catch insecure manifests early during pull request review, before they reach a cluster. Admission-time checks catch anything that bypasses CI or is applied manually with `kubectl apply`. Running both gives defense in depth: developers get fast feedback before merge, and the cluster still has a final security gate at deployment time.

---

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- list: mining_pool_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: miner_process_names
  items: [xmrig, ethminer, cgminer, t-rex, claymore, nc]

- rule: Possible Cryptominer Activity
  desc: Detect container network connections or processes matching common cryptominer indicators
  condition: >
    container.id != host
    and evt.type = connect
    and (
      fd.sport in (mining_pool_ports)
      or proc.name in (miner_process_names)
      or fd.cip.name contains "minexmr"
    )
  output: >
    Possible cryptominer activity detected
    (container=%container.name process=%proc.name command=%proc.cmdline target=%fd.sip:%fd.sport target_name=%fd.cip.name user=%user.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{"hostname":"ace44f3d3b8d","output":"2026-07-09T10:11:55.561104722+0000: Critical Possible cryptominer activity detected (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 target=<NA>:<NA> target_name=<NA> user=root) container_id=09a8125e72dc container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"09a8125e72dc","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783591915561104722,"fd.cip.name":null,"fd.sip":null,"fd.sport":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc","user.name":"root"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-09T10:11:55.561104722Z"}
```

### Reflection

I used mining-pool destination ports and suspicious miner-like process names as indicators because they are common and easy to detect at runtime. This can miss false-negative cases where a miner is renamed and tunnels traffic over normal HTTPS port 443. I would combine this rule with the Lecture 9 SLA matrix by treating critical runtime alerts as high-priority incidents with fast triage, escalation, and follow-up hardening in CI/admission policies.
