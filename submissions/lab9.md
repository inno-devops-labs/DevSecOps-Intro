# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"009548e23409","output":"2026-07-02T15:20:11.801131594+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=078b99238aeb container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"078b99238aeb","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783005611801131594,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"systemd","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-02T15:20:11.801131594Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"009548e23409","output":"2026-07-02T15:20:20.442367916+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=systemd command=cat /etc/shadow terminal=0 container_id=078b99238aeb container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"078b99238aeb","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783005620442367916,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"systemd","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-02T15:20:20.442367916Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside any container (NOT host)
  condition: open_write and container.id != host and fd.name startswith "/tmp/"
  output: "Write to /tmp detected (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"009548e23409","output":"2026-07-02T15:43:00.397862013+0000: Warning Write to /tmp detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=078b99238aeb container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"078b99238aeb","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783006980397862013,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-02T15:43:00.397862013Z"}

```

### Tuning consideration (Lecture 9 slide 8)
While appending `and not proc.name in (allowed_binaries)` to the rule condition works for simple exclusions, it quickly becomes difficult to maintain. A better tuning approach for legitimate applications writing to `/tmp` is to use an `exceptions`: block within the rule definition, which clearly and cleanly maps allowed processes or container images without cluttering the core detection logic.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego                                                                                              
package main

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container '%v' must set runAsNonRoot: true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%v' must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' must have memory limits set", [container.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must have memory limits set
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must set runAsNonRoot: true

8 tests, 5 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
# juice-compose.yml
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# /tmp/bad-compose.yml
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running Conftest at CI-time provides rapid feedback to developers, blocking insecure configurations from ever merging into the repository. Running it again at admission-time acts as a critical final safety net (defense in depth), ensuring that no one can bypass the CI pipeline or manually apply non-compliant manifests directly to the cluster.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects a container connecting to common mining-pool ports or running known miner processes.
  condition: container.id != host and (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or proc.name in ("xmrig", "ethminer", "cgminer", "t-rex", "claymore"))
  output: "Cryptominer Activity Detected (container=%container.name process=%proc.name target_port=%fd.sport command=%proc.cmdline)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"009548e23409","output":"2026-07-02T16:59:38.725860626+0000: Critical Cryptominer Activity Detected (container=lab9-target process=xmrig target_port=<NA> command=xmrig -c) container_id=078b99238aeb container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"078b99238aeb","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783011578725860626,"fd.sport":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"xmrig -c","proc.name":"xmrig"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-02T16:59:38.725860626Z"}
```

### Reflection (2-3 sentences)
I combined known mining pool destination ports and common miner process names, as these provide high-fidelity indicators for standard, out-of-the-box attacks. However, this logic will miss advanced evasion techniques, such as a custom-compiled binary tunneling mining traffic over standard HTTPS (port 443). Within the Lecture 9 SLA matrix, a CRITICAL alert like this indicates active execution/C2; it should trigger an immediate, automated containment playbook (e.g., isolating the compromised pod) and a direct escalation for tier 2 incident response to investigate the root cause.
