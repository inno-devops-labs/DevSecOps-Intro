# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "output": "A shell was spawned in a container with an attached terminal | command=sh -lc echo shell-in-container test",
  "container_name": "lab9-target",
  "user": "root",
  "time": "2026-06-28T17:46:59.694879561Z"
}
```

### Baseline alert B — Container drift (write below binary dir)
```json
{
  "rule": "Write to /tmp by container",
  "priority": "Warning",
  "output": "Write to /tmp detected in container | command=sh -lc echo test > /tmp/my-write.txt",
  "container_name": "lab9-target",
  "user": "root",
  "time": "2026-06-28T17:48:39.201528672Z"
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect file writes to /tmp directory inside containers
  condition: >
    container.id != host
    and open_write
    and fd.directory in (/tmp)
  output: >
    Write to /tmp detected in container (container=%container.name
    user=%user.name fd.name=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
labs\lab9\falco\logs\falco.log:226:{"hostname":"2b744eb3c5ac","output":"2026-06-28
T17:54:47.202728672+0000: Warning Write to /tmp detected in container (container=l 
ab9-target user=root fd.name=/tmp/my-write.txt command=sh -lc echo test > /tmp/my- 
write.txt) container_id=a3fb2a6c2e8d container_name=lab9-target container_image_re 
pository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","outp
ut_fields":{"container.id":"a3fb2a6c2e8d","container.image.repository":"alpine","c
ontainer.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":17826
69287202728672,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":nul
l,"proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"prior
ity":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["con
tainer","drift"],"time":"2026-06-28T17:54:47.202728672Z"}

```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks
often write to /tmp). What's your tuning approach? (2-3 sentences referencing the
`exceptions:` block vs `and not proc.name=...` patterns from Lecture 9.)

Based on Slide 8, my tuning approach for the "write to /tmp" rule would prioritize structured exceptions over ad-hoc `and not` chains. Instead of adding `and not proc.name in ` to the condition - which becomes unreadable and hard to audit -I would use the `exceptions:` block to explicitly list legitimate processes or file paths that are allowed to write to `/tmp`. This keeps the rule maintainable, makes the exception logic transparent, and avoids the crying wolf problem where noisy true-positives get silently ignored by operators.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

# 1. runAsNonRoot must be true (pod-level or container-level)
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment must set runAsNonRoot: true (pod-level or container-level for %q)", [c.name])
}

# 2. allowPrivilegeEscalation must be false (every container)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" (every container)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# 5. image must use sha256 digest, not :tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  contains(c.image, ":")
  not contains(c.image, "@")
  msg := sprintf("container %q must use image with sha256 digest, not tag (e.g., image@sha256:...), got: %q", [c.name, c.image])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - /project/labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Deployment must set runAsNonRoot: true (pod-level or container-level for "juice")
FAIL - /project/labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" missing resources.limits.memory
FAIL - /project/labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - /project/labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "j
uice" must use image with sha256 digest, not tag (e.g., image@sha256:...), got: "bkimminich/juice-shop:latest"

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions

```

### Compose policy generalizes (shipped compose-security.rego)
```
> docker run --rm -v "${PWD}:/project" openpolicyagent/conftest test /project/labs/lab9/manifests/compose/juice-compose.yml --policy /project/labs/lab9/policies/compose-security.rego --namespace compose.security

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

> docker run --rm -v "${PWD}:/project" -v "${env:TEMP}:/tmp" openpolicyagent/conftest test /tmp/bad-compose.yml --policy /project/labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions

```


### Why CI-time vs admission-time (Lecture 9 slide 9)
2-3 sentences. CI-time Conftest happens during PR review; admission-time Conftest happens at
`kubectl apply`. What's the operational benefit of running BOTH (defense in depth)?

CI-time catches misconfigurations before they reach the cluster (shift-left), saving developers from failed deployments and noisy alerts. Admission-time blocks them at the point of apply as a final safety net, even if someone bypasses CI (e.g., kubectl directly). Running both gives you defense in depth: CI provides fast, cheap feedback during development, while admission control ensures the policy is enforced in production regardless of the deployment path. 

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect container connecting to mining pool ports or known miner domains/processes
  condition: >
    container.id != host
    and (
      (evt.type = connect and fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
      or
      (evt.type = connect and fd.sockfamily = ip and fd.cip.name contains "minexmr")
      or
      (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
    )
  output: >
    Possible Cryptominer Activity detected (container=%container.name
    process=%proc.name command=%proc.cmdline target=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
  "hostname": "2b744eb3c5ac",
  "output": "2026-06-28T22:29:57.384129972+0000: Critical Possible Cryptominer Activity detected (container=lab9-target process=xmrig command=xmrig sleep 30 target=<NA>) container_id=a3fb2a6c2e8d container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "a3fb2a6c2e8d",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1782685797384129972,
    "fd.name": null,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "xmrig sleep 30",
    "proc.name": "xmrig"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": [
    "container",
    "mitre_command_and_control",
    "mitre_execution"
  ],
  "time": "2026-06-28T22:29:57.384129972Z"
}
```

### Reflection (2-3 sentences)
- Which 2 indicators did you use and why?
- What does this miss? (i.e., the false-negative case — e.g., obfuscated mining over HTTPS)
- How would you combine this with the Lecture 9 SLA matrix?

I used process name detection and mining pool port detection as my two indicators because they are high-confidence, low-noise signals that don't require external threat feeds. This rule misses obfuscated miners that use legitimate-looking process names (e.g., systemd or nginx) or communicate over HTTPS on port 443, as well as miners that use custom ports or dynamic DNS to evade static detection.In the Lecture 9 SLA matrix, I would classify this as a Critical (P0) detection with a 24‑hour fix SLA and on‑call escalation, since cryptomining indicates a likely active compromise, while using exception lists to reduce false positives and ensure rapid response.

