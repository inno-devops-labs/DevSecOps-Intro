# Lab 9 — Runtime Detection (Falco) + Policy-as-Code (Conftest)

## Task 1: Runtime Detection with Falco

### Environment
- Falco version: 0.43.1 (aarch64)
- Driver: modern BPF (`Opening 'syscall' source with modern BPF probe`)
- Colima used for BTF support on macOS Apple Silicon

### Baseline alert A — Terminal shell in container
```json
{"hostname":"78e9724e756c","output":"2026-07-10T18:36:30.058507097+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=e49a761766bf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e49a761766bf","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783708590058507097,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T18:36:30.058507097Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"78e9724e756c","output":"2026-07-10T18:36:47.170201324+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=e49a761766bf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e49a761766bf","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783708607170201324,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T18:36:47.170201324Z"}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detect any write to /tmp inside a container (potential drift or staging)
  condition: >
    open_write
    and container
    and fd.name startswith /tmp/
  output: >
    Write to /tmp detected in container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect container running known miner process names
  condition: >
    container
    and evt.type=execve
    and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, minerd, cpuminer)
  output: >
    Possible cryptominer activity detected
    (container=%container.name proc=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
```json
{"hostname":"78e9724e756c","output":"2026-07-10T18:44:01.021041714+0000: Warning Write to /tmp detected in container (container=lab9-target user=root file=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=e49a761766bf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e49a761766bf","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783709041021041714,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T18:44:01.021041714Z"}
```

### Tuning consideration (Lecture 9 slide 8)
The Write to /tmp by container rule will generate noise from legitimate processes — for example, many logging frameworks, package managers, and build tools write temporary files to /tmp as part of normal operation. The cleanest tuning approach is the exceptions: block rather than and not proc.name=... inline conditions: an exceptions block groups all the allowed processes in one place, making the allowlist auditable and easy to extend without touching the rule condition itself. For example, adding exceptions: - name: allowed_tmp_writers; fields: [proc.name]; values: [[npm], [yarn], [pip]] keeps the rule readable while suppressing known-good writers.

---

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "Deployment must explicitly set securityContext.runAsNonRoot: true"
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Container '%s' must explicitly set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	drop := object.get(container, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drop
	msg := sprintf("Container '%s' must drop ALL capabilities via capabilities.drop", [container.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml \
  --policy labs/lab9/policies/ --all-namespaces

FAIL - labs/lab9/manifests/k8s/juice-hardened.yaml - extra.pod - Deployment must set automountServiceAccountToken: false

38 tests, 37 passed, 0 warnings, 1 failure, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml \
  --policy labs/lab9/policies/ --all-namespaces

FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - extra.pod - Deployment must set automountServiceAccountToken: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

38 tests, 27 passed, 2 warnings, 9 failures, 0 exceptions
```

### Compose policy generalizes
```
# PASS on juice-compose.yml
conftest test labs/lab9/manifests/compose/juice-compose.yml \
  --policy labs/lab9/policies/compose-security.rego --namespace compose.security

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# FAIL on bad-compose.yml
conftest test /tmp/bad-compose.yml \
  --policy labs/lab9/policies/compose-security.rego --namespace compose.security

FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running Conftest during the CI process (while a pull request is being reviewed) allows policy violations to be detected before a manifest is deployed to the cluster. Developers receive feedback within seconds, can resolve the issue in the same PR, and prevent the invalid manifest from ever reaching the production environment. Enforcing the same policy at admission time (using Kyverno or OPA Gatekeeper) adds an additional layer of protection. If a misconfigured manifest bypasses CI—for example, through a direct `kubectl apply`, a faulty pipeline, or a manual hotfix—the admission controller blocks it before it can be applied to the cluster. Using both approaches provides defense-in-depth: CI identifies and resolves approximately 95% of policy violations early, while admission control prevents the remaining 5% that might bypass CI from affecting the cluster. As a result, the overall security of the cluster does not rely on a single enforcement mechanism.

---

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect cryptominer network/process pattern
  condition: >
    container
    and (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity detected (container=%container.name proc=%proc.name target=%fd.sip:%fd.sport cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"78e9724e756c","output":"2026-07-09T22:40:05.375190133+0000: Critical Possible cryptominer activity detected (container=lab9-target proc=xmrig cmdline=xmrig echo test) container_id=6ed501d92317 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-09T22:40:05.375190133Z"}
```

### Reflection
The rule relies on two indicators: process name matching (`proc.name in (xmrig, ethminer, ...)`) and the execution event (`evt.type=execve`). Together, they trigger as soon as a recognized cryptocurrency miner binary is executed inside any container, regardless of the method used to place it there. This approach detects the common post-compromise scenario in which an attacker uploads and launches a mining binary after obtaining access to a container, similar to the Tesla 2018 Kubernetes Dashboard incident.

The primary false-negative scenario involves obfuscated mining activity. For example, if an attacker renames the binary (e.g. `cp xmrig /tmp/kworker`), the process name check will no longer match. Likewise, miners that communicate with mining pools over HTTPS without using known hostnames or ports can avoid network-based detection.

According to the Lecture 9 SLA matrix, this CRITICAL rule should be classified as a P1 incident, requiring an alert within 1 minute and immediate notification of the on-call engineer. Active cryptomining not only consumes cluster resources but also indicates that the environment has already been compromised. Falco's sub-second detection capability, combined with PagerDuty integration, is sufficient to meet this SLA without requiring manual monitoring.
