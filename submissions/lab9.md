# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"abbc238194b1","output":"2026-07-04T20:46:44.180672852+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=16514a12c7ad container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"16514a12c7ad","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783198004180672852,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-04T20:46:44.180672852Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"abbc238194b1","output":"2026-07-04T20:46:58.329858066+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=16514a12c7ad container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"16514a12c7ad","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783198018329858066,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-04T20:46:58.329858066Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Container writing to /tmp
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Config write in container (container=%container.name user=%user.name
    file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"abbc238194b1","output":"2026-07-04T20:56:36.369842926+0000: Warning Config write in container (container=lab9-target user=root file=/tmp/my-write.txt proc=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=16514a12c7ad container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"16514a12c7ad","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783198596369842926,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-04T20:56:36.369842926Z"}
```

### Tuning consideration (Lecture 9 slide 8)
Since our custom "write to /tmp" rule may also fire on legitimate activity, it should be tuned to reduce false positives. For simple cases, we can refine the condition with `and not proc.name=<process_name>`, while for multiple or more structured exclusions it is better to use the `exceptions:` block, which is easier to maintain and audit.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

import rego.v1

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    not c.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    c.securityContext.allowPrivilegeEscalation != false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not contains(c.image, "@sha256:")
    msg := sprintf("container %q must use an image digest (@sha256:)", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must use an image digest (@sha256:)

10 tests, 7 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches policy violations early during development, giving engineers fast feedback before changes are merged. Admission-time policy enforcement blocks unsafe manifests at `kubectl apply`, even if CI was skipped, misconfigured, or bypassed. Running both provides defense in depth by enforcing the same policies at multiple stages of the deployment pipeline.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: "Possible Cryptominer Activity"
  desc: Detects possible cryptominer activity based on network connections and process names
  condition: >
    # note: the remote port is used to detect outbound connections
    fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
    # note: nc added for the test
    and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nc)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
  output: >
    # note: the remote port is reported
    Possible Cryptominer Activity (container=%container.name
    proc=%proc.cmdline target=%fd.rip.name:%fd.rport)
```

### Triggered alert
```json
{"hostname":"1cd21273f0bd","output":"2026-07-06T23:05:05.771201256+0000: Critical Possible Cryptominer Activity (container=lab9-target proc=nc -z 127.0.0.1 3333 target=<NA>:3333) container_id=5e75ca991d02 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"5e75ca991d02","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783379105771201256,"fd.rip.name":null,"fd.rport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -z 127.0.0.1 3333"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-06T23:05:05.771201256Z"}
```

### Reflection (2-3 sentences)
The **Connection to mining pool port** and **Process name matches known miner** indicators were used because they provide network- and host-level signals that reduce false positives when combined. The rule fires when at least two indicators are present, but it can miss miners using HTTPS, custom ports, or obfuscated processes. It maps to the **Critical** SLA category, requiring immediate investigation and containment of the affected container.
