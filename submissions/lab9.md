# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"753144d3be64","output":"2026-07-05T18:50:59.111213264+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo shell-in-container test terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=452d47e1f06c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"452d47e1f06c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783277459111213264,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo shell-in-container test","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":null,"proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-05T18:50:59.111213264Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"753144d3be64","output":"2026-07-05T18:50:59.430325374+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=452d47e1f06c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"452d47e1f06c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783277459430325374,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-05T18:50:59.430325374Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect writes to /tmp inside any container (not host)
  condition: >
    open_write
    and container
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp by container (user=%user.name container=%container.name
    file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"753144d3be64","output":"2026-07-05T18:51:54.273675706+0000: Warning Write to /tmp by container (user=root container=lab9-target file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=452d47e1f06c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"452d47e1f06c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783277514273675706,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-05T18:51:54.273675706Z"}
```

### Tuning consideration (Lecture 9 slide 8)
Legitimate apps also write to `/tmp`, so this rule will create noise. I would use an
`exceptions:` block for trusted images or paths (for example known log directories). For one-off
trusted tools, I would add `and not proc.name=...` instead of weakening the whole rule.

---

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true (pod or container level)", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin image by digest (@sha256:...), not tag", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin image by digest (@sha256:...), not tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true (pod or container level)

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
# juice-compose.yml - PASS
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# bad-compose.yml - FAIL
FAIL - C:\Users\A0F1~1\AppData\Local\Temp\bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - C:\Users\A0F1~1\AppData\Local\Temp\bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches bad manifests in a PR before merge, so developers fix issues early.
Admission-time checks at `kubectl apply` block anything that still slips through. Using both
layers means fewer surprises in the cluster and stronger defense in depth.

---

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect possible cryptominer network or process activity in containers
  condition: >
    container
    and container.id != host
    and evt.type=connect
    and fd.sockfamily=ip
    and (
      fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
      or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
    )
  output: >
    Possible cryptominer activity (container=%container.name process=%proc.name
    connection=%fd.name target=%fd.cip.name:%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"753144d3be64","output":"2026-07-05T18:52:41.488175005+0000: Critical Possible cryptominer activity (container=lab9-target process=nc connection=127.0.0.1:39636->127.0.0.1:3333 target=<NA>:3333) container_id=452d47e1f06c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"452d47e1f06c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783277561488175005,"fd.cip.name":null,"fd.name":"127.0.0.1:39636->127.0.0.1:3333","fd.sport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-05T18:52:41.488175005Z"}
```

### Reflection (2-3 sentences)
I combined mining-pool ports (3333, 4444, etc.) with known miner process names (`xmrig`,
`ethminer`, …) so the rule catches renamed binaries and odd ports. It still misses miners
over HTTPS or custom ports. Per the Lecture 9 SLA matrix, I would treat this CRITICAL alert as
P1: page on-call fast and isolate the container.
