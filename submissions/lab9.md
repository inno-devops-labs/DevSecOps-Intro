# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"26a76fe9ed28","output":"2026-07-02T14:42:31.099983561+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo shell-in-container final test terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=999a8400ecae container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"999a8400ecae","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783003351099983561,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo shell-in-container final test","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":null,"proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-02T14:42:31.099983561Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"26a76fe9ed28","output":"2026-07-02T14:42:31.231860772+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=999a8400ecae container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"999a8400ecae","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783003351231860772,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":null,"proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-02T14:42:31.231860772Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect writes to /tmp inside a container.
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect container activity matching common cryptominer network or process indicators.
  condition: >
    container.id != host and
    (
      (evt.type=connect and
       (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or
        fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or
        evt.args contains "3333")) or
      (evt.type in (execve, execveat) and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)) or
      (evt.type in (execve, execveat) and proc.name=nc and proc.cmdline contains "3333")
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name evt=%evt.type cmdline=%proc.cmdline
    target=%fd.name sport=%fd.sport rport=%fd.rport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"26a76fe9ed28","output":"2026-07-02T14:42:31.362162906+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write-final.txt proc=sh -lc echo test > /tmp/my-write-final.txt) container_id=999a8400ecae container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"999a8400ecae","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783003351362162906,"fd.name":"/tmp/my-write-final.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo test > /tmp/my-write-final.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-02T14:42:31.362162906Z"}
```

### Tuning consideration (Lecture 9 slide 8)
The `/tmp` rule is useful for drift detection, but many legitimate frameworks write temporary files there. I would prefer an `exceptions:` block for approved container/process/path combinations because it is auditable; for a very small local case, an `and not proc.name=...` condition is acceptable but becomes hard to maintain as noise grows.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

containers := input.spec.template.spec.containers

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

security_context(container) := object.get(container, "securityContext", {})

capabilities(container) := object.get(security_context(container), "capabilities", {})

capability_drops(container) := object.get(capabilities(container), "drop", [])

has_value(arr, value) if {
  some i
  arr[i] == value
}

container_runs_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
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
  object.get(security_context(container), "allowPrivilegeEscalation", null) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not has_value(capability_drops(container), "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
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

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin image by sha256 digest
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
PASS - labs/lab9/manifests/compose/juice-compose.yml
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

FAIL - /tmp/bad-compose.yml - compose.security - services must drop ALL capabilities
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true
WARN - /tmp/bad-compose.yml - compose.security - services should enable no-new-privileges

4 tests, 0 passed, 1 warning, 3 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest fails unsafe manifests during PR review, when the fix is cheap and visible to reviewers. Admission-time policy blocks drift or emergency changes at `kubectl apply`, so running both gives defense in depth before and during deployment.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect container activity matching common cryptominer network or process indicators.
  condition: >
    container.id != host and
    (
      (evt.type=connect and
       (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or
        fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or
        evt.args contains "3333")) or
      (evt.type in (execve, execveat) and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)) or
      (evt.type in (execve, execveat) and proc.name=nc and proc.cmdline contains "3333")
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name evt=%evt.type cmdline=%proc.cmdline
    target=%fd.name sport=%fd.sport rport=%fd.rport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"26a76fe9ed28","output":"2026-07-02T14:42:32.611584608+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc evt=execve cmdline=nc -w 2 127.0.0.1 3333 target=<NA> sport=<NA> rport=<NA>) container_id=999a8400ecae container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"999a8400ecae","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783003352611584608,"evt.type":"execve","fd.name":null,"fd.rport":null,"fd.sport":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-02T14:42:32.611584608Z"}
```

### Reflection (2-3 sentences)
I used mining-pool ports and known miner process names because they are simple, high-signal runtime indicators. The `nc ... 3333` clause is included only to make the lab simulation deterministic; this still misses miners hidden behind HTTPS, renamed binaries, or private pools on normal ports. In the Lecture 9 SLA matrix, this CRITICAL alert should page the owner immediately and open a 24-hour remediation path with evidence attached.
