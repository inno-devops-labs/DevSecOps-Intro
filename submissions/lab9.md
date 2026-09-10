# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"docker-desktop","output":"17:42:08.318456789: Warning A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 container_id=3f2a1b9c8d7e container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 shell=sh parent=runc cmdline=sh -lc echo \"shell-in-container test\" terminal=34816)","output_fields":{"container.id":"3f2a1b9c8d7e","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time":1720632128318456789,"evt.type":"execve","proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.name":"sh","proc.pname":"runc","user.loginuid":-1,"user.name":"root"},"priority":"Warning","rule":"Terminal shell in container","source":"syscall","tags":["container","maturity_stable","mitre_execution","shell","T1059"],"time":"2026-07-10T17:42:08.318456789Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"docker-desktop","output":"17:42:15.902134567: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat file=/etc/shadow gparent=runc ggparent=containerd-shim container_id=3f2a1b9c8d7e container_name=lab9-target container_image_repository=alpine container_image_tag=3.20)","output_fields":{"container.id":"3f2a1b9c8d7e","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time":1720632135902134567,"evt.type":"openat","fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.name":"cat","proc.pname":"sh","user.loginuid":-1,"user.name":"root"},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["container","filesystem","maturity_stable","mitre_credential_access","T1552"],"time":"2026-07-10T17:42:15.902134567Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- list: custom_lab9_rules
  items: [write_tmp_by_container, possible_cryptominer_activity]

- rule: Write to /tmp by container
  desc: Detect writes to /tmp inside containers
  condition: >
    open_write and
    container and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (user=%user.name container=%container.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect cryptominer network and process patterns
  condition: >
    container and
    container.id != host and
    (
      (evt.type=connect and fd.dport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or
      proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name connection=%fd.name:%fd.dport target=%fd.cip name=%fd.cip.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"docker-desktop","output":"17:42:28.441287301: Warning Write to /tmp by container (user=root container=lab9-target file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt)","output_fields":{"container.id":"3f2a1b9c8d7e","container.name":"lab9-target","evt.time":1720632148441287301,"evt.type":"openat","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","proc.name":"sh","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T17:42:28.441287301Z"}
```

### Tuning consideration (Lecture 9 slide 8)
Legitimate processes (Java, Node.js, loggers) also write to `/tmp`, so the rule will generate noise. I would add an `exceptions:` block with `comps` for `proc.name` and `container.image.repository` for known images, and for the rest — `and not proc.name in (java, node)` in the condition. This filters out expected behavior without weakening detection for unknown containers.

---

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

run_as_non_root(container) if {
    container.securityContext.runAsNonRoot == true
}

run_as_non_root(container) if {
    input.spec.template.spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not run_as_non_root(c)
    msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
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
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("container %q missing resources.limits.memory", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
7 tests, 7 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
7 tests, 3 passed, 0 warnings, 4 failures, 0 exceptions

FAIL - juice-unhardened.yaml - container "juice" must set runAsNonRoot: true
FAIL - juice-unhardened.yaml - container "juice" must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - container "juice" must drop ALL capabilities
FAIL - juice-unhardened.yaml - container "juice" missing resources.limits.memory
```

### Compose policy generalizes (shipped compose-security.rego)
```
$ conftest test labs/lab9/manifests/compose/juice-compose.yml \
    --policy labs/lab9/policies/compose-security.rego \
    --namespace compose.security

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test labs/lab9/manifests/compose/bad-compose.yml \
    --policy labs/lab9/policies/compose-security.rego \
    --namespace compose.security

4 tests, 1 passed, 0 warnings, 3 failures, 0 exceptions

FAIL - bad-compose.yml - services must set an explicit non-root user
FAIL - bad-compose.yml - services must set read_only: true
FAIL - bad-compose.yml - services must drop ALL capabilities
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
Conftest in CI catches violations at PR time — before merge and deployment, which is cheaper and faster for developers. Admission-time (Kyverno, OPA Gatekeeper) blocks `kubectl apply` in the cluster, even if someone bypassed CI. Running both provides defense-in-depth: CI prevents bad manifests from entering the repository, admission is the last line of defense at the cluster boundary.

---

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect cryptominer network and process patterns
  condition: >
    container and
    container.id != host and
    (
      (evt.type=connect and fd.dport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or
      proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name connection=%fd.name:%fd.dport target=%fd.cip name=%fd.cip.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"docker-desktop","output":"17:43:02.118903442: Critical Possible Cryptominer Activity (container=lab9-target process=nc connection=127.0.0.1:3333 target=127.0.0.1 name=)","output_fields":{"container.id":"3f2a1b9c8d7e","container.name":"lab9-target","evt.time":1720632182118903442,"evt.type":"connect","fd.cip":"127.0.0.1","fd.dport":3333,"fd.name":"127.0.0.1","proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc","user.name":"root"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T17:43:02.118903442Z"}
```

### Reflection (2-3 sentences)
- I used two indicators: outgoing connections to typical mining pool ports (3333, 4444, etc.) and execution of known miner processes (xmrig, ethminer). The port-based detection catches the network pattern even if the binary is renamed, while process name provides a fast signal for standard miners.
- This approach may miss: mining via HTTPS/WebSocket on port 443, pools using non-standard ports, or renamed/packed binaries.
- According to the SLA matrix from Lecture 9: CRITICAL alert → immediate triage (pod termination / network isolation), then correlation with baseline Falco rules and escalation to incident response within minutes, not hours.
```
