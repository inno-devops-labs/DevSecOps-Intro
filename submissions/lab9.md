# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"3dd35077ef1e","output":"2026-07-10T19:07:49.855582421+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=89095b9069b4 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"89095b9069b4","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783710469855582421,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T19:07:49.855582421Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"3dd35077ef1e","output":"2026-07-10T19:07:49.918771498+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=89095b9069b4 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"89095b9069b4","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783710469918771498,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T19:07:49.918771498Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"3dd35077ef1e","output":"2026-07-10T19:12:46.158441415+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/pwned command=sh -lc echo pwned > /tmp/pwned) container_id=89095b9069b4 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"89095b9069b4","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783710766158441415,"fd.name":"/tmp/pwned","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo pwned > /tmp/pwned","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T19:12:46.158441415Z"}
```

### Tuning consideration (Lecture 9 slide 8)
This rule is intentionally noisy because many normal applications write temporary
files under `/tmp`. The preferred tuning approach is to use an `exceptions:`
block for known-good container images, process names, or exact temp paths, so the
allowlist stays visible and auditable in the rule. For one-off local noise, a
narrow `and not proc.name=...` condition can be acceptable, but a long inline
list is harder to review than structured exceptions.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

containers := input.spec.template.spec.containers if {
  input.kind == "Deployment"
}

containers := input.spec.containers if {
  input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

pod_spec := input.spec if {
  input.kind == "Pod"
}

has_value(arr, value) if {
  some i
  arr[i] == value
}

capabilities_drop(container) := drop if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  drop := object.get(capabilities, "drop", [])
}

run_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

run_as_non_root(container) if {
  pod_spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
  container := containers[_]
  not run_as_non_root(container)
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  container := containers[_]
  not has_value(capabilities_drop(container), "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level

8 tests, 4 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
labs/lab9/manifests/compose/juice-compose.yml:
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

/tmp/bad-compose.yml:
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest gives fast feedback during PR review, before an unsafe manifest
is merged into the repository. Admission-time policy still matters because it
checks the final object at `kubectl apply`, including manual changes, generated
manifests, or changes from another pipeline. Running both creates defense in
depth: CI prevents most issues early, while admission control protects the
cluster from anything that bypasses CI.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect container activity matching common cryptominer network or process indicators
  condition: >
    container.id != host and
    (
      (evt.type=connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) 
      or
      proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
    )
  output: >
    Possible cryptominer activity
    (container=%container.name process=%proc.name command=%proc.cmdline
    target=%fd.name target_ip=%fd.sip target_port=%fd.rport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"3dd35077ef1e","output":"2026-07-10T19:49:47.347406885+0000: Critical Possible cryptominer activity (container=lab9-target process=xmrig command=xmrig -w 2 127.0.0.1 3333 target=<NA> target_ip=<NA> target_port=<NA>) container_id=89095b9069b4 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"89095b9069b4","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783712987347406885,"fd.name":null,"fd.rport":null,"fd.sip":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"xmrig -w 2 127.0.0.1 3333","proc.name":"xmrig"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T19:49:47.347406885Z"}
```

P.S: i had copy `/usr/bin/nc` into `/usr/bin/xmrig` to simulate XMRIG miner and trigger rule.

### Reflection (2-3 sentences)
The rule uses two indicators: connections to common mining-pool ports and known
miner process names such as `xmrig`, because together they cover both network
egress and local execution behavior. This can miss miners that rename the
process, tunnel traffic over HTTPS or another allowed port, or connect through a
proxy instead of a recognizable pool endpoint. In the SLA matrix this should be
treated as a high-severity runtime signal: critical alerts require fast triage,
container isolation, and follow-up image/workload investigation.
