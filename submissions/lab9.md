# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
Note: Triggering this rule requires an interactive TTY session, which is limited in the automated execution environment. However, the rule is active in the Falco baseline.

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"96f3c8ebb841","output":"2026-07-10T14:50:22.606152524+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=27e4b583e28a container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"27e4b583e28a","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783695022606152524,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":null,"proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T14:50:22.606152524Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside any container
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: "%container.name %user.name %fd.name %proc.cmdline"
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detects potential cryptominer activity via network port or process name
  condition: (evt.type=connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)) and container.id != host
  output: "Possible Cryptominer detected! Container=%container.name Process=%proc.name TargetPort=%fd.sport Command=%proc.cmdline"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
```json
{"hostname":"96f3c8ebb841","output":"2026-07-10T15:08:38.846387224+0000: Warning lab9-target root /tmp/my-write.txt sh -lc echo \"test\" > /tmp/my-write.txt container_id=27e4b583e28a container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"27e4b583e28a","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783696118846387224,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T15:08:38.846387224Z"}
```

### Tuning consideration (Lecture 9 slide 8)
The "write to /tmp" rule may fire on legitimate application behavior, such as temporary file creation by logging frameworks or system utilities. To tune this, I would use an `exceptions:` block to ignore specific known-safe processes (e.g., `proc.name = 'systemd'`) or use an `and not proc.name in (...)` pattern to reduce false positives while still monitoring for unexpected drifts.

---

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package k8s.security

# 1. runAsNonRoot must be true
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container %s must have runAsNonRoot set to true", [container.name])
}

# 2. allowPrivilegeEscalation must be false
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %s must have allowPrivilegeEscalation set to false", [container.name])
}

# 3. capabilities.drop must include "ALL"
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container %s must drop ALL capabilities", [container.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - Container juice must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - Container juice must have allowPrivilegeEscalation set to false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - Container juice must have runAsNonRoot set to true
```

### Compose policy generalizes (shipped compose-security.rego)
```
# PASS on juice-compose.yml
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# FAIL on bad-compose.yml
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest provides immediate feedback to developers during the PR process, allowing them to fix security issues before the code even reaches the cluster. Admission-time gating acts as a final safety net, ensuring that no non-compliant manifest is ever deployed, regardless of the CI pipeline's state. Running both provides defense-in-depth by shifting security left while maintaining a strict runtime boundary.

---

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects potential cryptominer activity via network port or process name
  condition: (evt.type=connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)) and container.id != host
  output: "Possible Cryptominer detected! Container=%container.name Process=%proc.name TargetPort=%fd.sport Command=%proc.cmdline"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"96f3c8ebb841","output":"2026-07-10T15:27:33.557847166+0000: Critical Possible Cryptominer detected! Container=lab9-target Process=xmrig TargetPort=<NA> Command=xmrig -h container_id=27e4b583e28a container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"27e4b583e28a","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783697253557847166,"fd.sport":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"xmrig -h","proc.name":"xmrig"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T15:27:33.557847166Z"}
```

### Reflection (2-3 sentences)
I used process name matching (e.g., `xmrig`) and common mining pool ports. This rule misses miners using obfuscated traffic (e.g., over HTTPS/443) or renamed binaries. To integrate with the SLA matrix, this would be a CRITICAL alert requiring immediate automated containment (e.g., pod deletion) and high-priority incident response.
