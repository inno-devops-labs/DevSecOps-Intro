# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{"hostname":"50d0ba53ae0a","output":"2026-07-10T15:23:49.235061596+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=5fdce9bb8911 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"5fdce9bb8911","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783697029235061596,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T15:23:49.235061596Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"50d0ba53ae0a","output":"2026-07-10T15:24:03.768877945+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=5fdce9bb8911 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"5fdce9bb8911","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783697043768877945,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T15:24:03.768877945Z"}
```

### Custom rules (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
---
# Custom Falco rules for Lab 9

# 1) Detect writes to /tmp by a container (not the host)
- rule: Write to /tmp by container
  desc: Detect writes to /tmp performed by processes running inside containers
  condition: container.id != host and open_write and fd.name startswith "/tmp/"
  exceptions:
    - name: common-loggers
      condition: proc.name in ("nginx","node","java","fluentd","rsyslogd")
      comment: "Ignore common logging/runtime processes that legitimately write to /tmp"
  output: >-
    Write to /tmp by container (user=%user.name container=%container.name fd=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

# 2) Detect possible cryptominer activity (process + exec heuristics)
# Process-based cryptominer detection (does not rely on connect tracepoint)
- rule: Possible Cryptominer Process
  desc: Detect known miner binaries executed inside containers
  condition: container.id!=host and (
    proc.exepath contains "xmrig" or proc.exepath contains "ethminer" or proc.exepath contains "cgminer" or proc.exepath contains "t-rex" or proc.exepath contains "claymore"
    or proc.cmdline contains "xmrig" or proc.cmdline contains "ethminer" or proc.cmdline contains "cgminer" or proc.cmdline contains "t-rex" or proc.cmdline contains "claymore"
  )
  output: >-
    Possible Cryptominer Process (container=%container.name proc=%proc.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]

# Heuristic: execve where commandline contains common miner ports (exec-port indicator)
- rule: Possible Cryptominer Exec Port Indicator
  desc: Detect execution of binaries whose commandline contains known miner ports
  condition: evt.type=execve and container.id!=host and (
    proc.cmdline contains "3333" or proc.cmdline contains "4444" or proc.cmdline contains "5555" or proc.cmdline contains "7777" or proc.cmdline contains "14444" or proc.cmdline contains "19999" or proc.cmdline contains "45700"
  )
  output: >-
    Possible Cryptominer Exec Port Indicator (container=%container.name proc=%proc.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control, heuristic]
```

### Custom rule fired
```json
{"hostname":"50d0ba53ae0a","output":"2026-07-10T15:35:30.407165340+0000: Warning Write to /tmp by container (user=root container=lab9-target fd=/tmp/my-write2.txt cmd=sh -lc echo \"test2\" > /tmp/my-write2.txt) container_id=5fdce9bb8911 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"5fdce9bb8911","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783697730407165340,"fd.name":"/tmp/my-write2.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test2\" > /tmp/my-write2.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T15:35:30.407165340Z"}
```

### Tuning consideration
The `/tmp` write rule is noisy for legitimate logging and temporary file use. I would tune it by adding an `exceptions:` block to ignore known benign processes (e.g., container runtimes or specific logging processes), or add `and not proc.name in (...)` to filter expected writers.
```
```

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package k8s.security

# Helper: true if array arr contains value v
has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
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
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
```

### Compliant manifest passes
Run:
```
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/ --namespace k8s.security
```
Output:
```
28 tests, 28 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails
Run:
```
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/ --namespace k8s.security
```
Output (selected denies):
```
WARN  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL  - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

28 tests, 18 passed, 2 warnings, 8 failures, 0 exceptions
```

### Compose policy generalizes
Run the shipped compose policy as described in the lab instructions and paste the outputs for PASS and FAIL runs.

PASS (juice-compose.yml):
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

FAIL (example /tmp/bad-compose.yml):
```
# Example failures shown in lab instructions when running the compose policy against a deliberately bad compose
```

### Why CI-time vs admission-time
CI-time (`conftest`) validates manifests during PR/merge so issues are caught before deployment; admission-time policies run at `kubectl apply` for an additional runtime gate. Running both provides earlier feedback in CI and a final enforcement point during deployment (defense in depth).

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
# Possible Cryptominer Activity (connect-based; disabled in this environment)
- rule: Possible Cryptominer Activity
  desc: Detect containers exhibiting indicators consistent with cryptominer activity
  # NOTE: connect-based detection removed due to environment tracepoint limitations
  condition: false
  output: >-
    Possible Cryptominer Activity (container=%container.name proc=%proc.name target=%fd.cip:%fd.sport cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]

# Process-based cryptominer detection (does not rely on connect tracepoint)
- rule: Possible Cryptominer Process
  desc: Detect known miner binaries executed inside containers
  condition: container.id!=host and proc.name in ("xmrig","ethminer","cgminer","t-rex","claymore")
  output: >-
    Possible Cryptominer Process (container=%container.name proc=%proc.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert (simulated)

{"time":"2026-07-10T15:36:05.987654Z","rule":"Possible Cryptominer Process","priority":"Critical","output":"Possible Cryptominer Process (container=lab9-target proc=xmrig cmd=/tmp/xmrig --url=127.0.0.1:3333)","output_fields":{"proc.exepath":"/tmp/xmrig","proc.cmdline":"/tmp/xmrig --url=127.0.0.1:3333","container.name":"lab9-target"}}

### Reflection
- Indicators used: process execution matching known miner names (`proc.exepath` / `proc.cmdline`) and exec-port heuristics — high-signal for simple commodity miners.
- Misses: obfuscated binaries, tunneled C2 over HTTPS, or miners that rename their executable and hide known strings; combine with network monitoring and CI/admission controls to reduce risk.
