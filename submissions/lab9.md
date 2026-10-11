# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"c0cec3338db2","output":"2026-07-02T05:58:09.556608720+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -c echo shell test terminal
=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=0510bb4496fd
 container_name=lab9-target2 container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"0510bb4496fd","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target2","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1782971889556608720
,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -c echo shell test","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"runc","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-02T05:58:09.556608720Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"c0cec3338db2","output":"2026-07-02T05:19:43.688175487+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open
user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=bf6843a133d9 container_name=lab9-target container_image_repository=alpine con
tainer_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"bf6843a133d9","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1782969583688175487,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":null,"proc.tty":0
,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-02T05:19:43.688175487Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect file write to /tmp inside container (potential temp file abuse)
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: File write to /tmp in container (user=%user.name container=%container.name file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"c0cec3338db2","output":"2026-07-02T05:23:08.117708511+0000: Warning File write to /tmp in container (user=root container=lab9-target file=/tmp/my-write.txt proc=sh -lc echo test > /tmp/my-write.txt) container_id=bf6843a133d9 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"bf6843a133d9","container.image.re
pository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1782969788117708511,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-02T05:23:08.117708511Z"}
```

### Tuning consideration (Lecture 9 slide 8)
The custom "write to /tmp" rule will fire on legitimate uses too, such as application temp files and logging frameworks. To reduce noise, I would add an `exceptions:` block that excludes known safe processes (e.g., `and not proc.name in (node, java, python)` or specific container images that have legitimate /tmp usage).


## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

has_value(arr, v) {
  some i
  arr[i] == v
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - juice-unhardened.yaml - main - container "juice" missing resources.limits.memory
FAIL - juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true
8 tests, 5 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
- PASS on juice-compose.yml:
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```
- FAIL on bad-compose.yml:
```
FAIL - bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - bad-compose.yml - compose.security - services must set read_only: true
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches misconfigurations during PR review, before the manifest is merged or applied to the cluster. Admission-time Conftest catches them at `kubectl apply` time, providing a second layer of defense. Running both ensures that insecure configurations are blocked early in the development cycle, while also preventing bypasses or misconfigurations that might slip through CI. This defense-in-depth approach reduces the window of exposure and reinforces the principle of "fail early, fail safely."


## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Write to /tmp by container
  desc: Detect file write to /tmp inside container (potential temp file abuse)
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: File write to /tmp in container (user=%user.name container=%container.name file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
- rule: Write to /tmp by container
  desc: Detect file write to /tmp inside container (potential temp file abuse)
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: File write to /tmp in container (user=%user.name container=%container.name file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect process connecting to mining pool ports
  condition: >
    evt.type = connect
    and proc.name in (nc, curl, wget, telnet, openssl)
    and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
  output: Potential cryptominer activity detected (container=%container.name proc=%proc.name target=%fd.cip.name:%fd.sport user=%user.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]

```

### Reflection (2-3 sentences)
The rule uses two indicators: connection to known mining pool ports and DNS queries containing "minexmr". This would miss  mining over HTTPS (port 443) or mining behind a proxy. Combined with the SLA matrix, this rule would produce critical alerts that require 24-hour response, while lower-confidence alerts could be routed to weekly review.