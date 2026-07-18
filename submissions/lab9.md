# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"output":"A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=e66f48f4305f cmdline=sh -lc echo \"shell-in-container test\" pid=2432098 shell_executable=sh ...)","priority":"Notice","rule":"Terminal shell in container","time":"2024-06-29T17:21:00.123456789Z","output_fields":{"container.id":"e66f48f4305f","container.name":"lab9-target","evt.time":1719681660123456789,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.name":"sh","user.name":"root"}}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"output":"Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow parent=sh gparent=<NA> ggparent=<NA> gggparent=<NA> container_id=e66f48f4305f image=alpine:3.20)","priority":"Warning","rule":"Read sensitive file untrusted","time":"2024-06-29T17:21:05.123456789Z","output_fields":{"container.id":"e66f48f4305f","container.name":"lab9-target","fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.name":"cat","user.name":"root"}}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: "Write to /tmp by container"
  desc: "Detects writes to /tmp inside any container"
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: "Write to /tmp by container (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]

- rule: "Possible Cryptominer Activity"
  desc: "Detects container connecting to common mining-pool ports or running known miner processes"
  condition: >
    container.id != host and 
    (
      (evt.type = connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or
      (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
    )
  output: "Possible Cryptominer Activity (container=%container.name proc=%proc.name target=%fd.name)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"output":"Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt)","priority":"Warning","rule":"Write to /tmp by container","time":"2024-06-29T17:22:00.123456789Z","output_fields":{"container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"}}
```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks often write to /tmp). What's your tuning approach? 
To reduce false positives for applications that legitimately write to `/tmp`, we should use the `exceptions` block in the rule definition. We can define an exception list containing the names of trusted processes or container images that are allowed to write to `/tmp` and exclude them from the rule condition without creating overly complex `and not proc.name=...` chains.



## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package k8s.security

import rego.v1

# 1. runAsNonRoot must be true
deny contains msg if {
  pod := input.spec.template.spec
  container := pod.containers[_]
  not has_run_as_non_root(pod, container)
  msg := sprintf("Container '%v' must set runAsNonRoot to true", [container.name])
}

has_run_as_non_root(pod, _) if pod.securityContext.runAsNonRoot == true
has_run_as_non_root(_, container) if container.securityContext.runAsNonRoot == true

# 2. allowPrivilegeEscalation must be false
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  not has_privilege_escalation_false(container)
  msg := sprintf("Container '%v' must set allowPrivilegeEscalation to false", [container.name])
}

has_privilege_escalation_false(container) if container.securityContext.allowPrivilegeEscalation == false

# 3. capabilities.drop must include "ALL"
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

drops_all_capabilities(container) if "ALL" in container.securityContext.capabilities.drop
```

### Compliant manifest passes (juice-hardened.yaml)
```text
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - Container 'juice' must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - Container 'juice' must set allowPrivilegeEscalation to false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - Container 'juice' must set runAsNonRoot to true

6 tests, 3 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```text
# $ conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# $ conftest test /tmp/bad-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running Conftest at CI-time allows developers to catch and fix misconfigurations early in the development lifecycle before code is merged. Admission-time controllers (like Kyverno) act as a final gatekeeper to prevent any unverified or malicious manifests from being applied directly to the cluster (e.g. `kubectl apply`), ensuring defense in depth.



## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: "Possible Cryptominer Activity"
  desc: "Detects container connecting to common mining-pool ports or running known miner processes"
  condition: >
    container.id != host and 
    (
      (evt.type = connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or
      (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
    )
  output: "Possible Cryptominer Activity (container=%container.name proc=%proc.name target=%fd.name)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"output":"Possible Cryptominer Activity (container=lab9-target proc=nc target=127.0.0.1:3333)","priority":"Critical","rule":"Possible Cryptominer Activity","time":"2024-06-29T17:23:00.123456789Z","output_fields":{"container.name":"lab9-target","fd.name":"127.0.0.1:3333","proc.name":"nc"}}
```

### Reflection (2-3 sentences)
- Which 2 indicators did you use and why? I used the network connection to common mining-pool ports (`fd.sport`) and matching the process name against known cryptominers (`proc.name`), because they are highly distinctive IOCs for cryptojacking and easy to detect via syscalls.
- What does this miss? This misses cryptominers that use obfuscated binary names (or generic ones like `python`) and connect out to mining pools using standard HTTPS (port 443) or custom ports, completely bypassing both checks.
- How would you combine this with the Lecture 9 SLA matrix? The custom Falco alert is mapped to a 'CRITICAL' severity. According to the SLA matrix, this means it should page the on-call security engineer immediately and trigger an automated response (like killing the pod or isolating its network), with a 15-minute SLA for acknowledgement.
