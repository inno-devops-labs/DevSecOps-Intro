# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs:

```json
{"hostname":"d53a40db2ded","output":"2026-07-10T19:10:27.171732939+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=9cc6d64c75d0 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9cc6d64c75d0","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783710627171732939,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"runc","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T19:10:27.171732939Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{"hostname":"d53a40db2ded","output":"2026-07-10T19:10:27.228348323+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=9cc6d64c75d0 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9cc6d64c75d0","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783710627228348323,"evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T19:10:27.228348323Z"}
```

### Custom rule (paste `labs/lab9/falco/rules/custom-rules.yaml`)

```yaml
- rule: Write to /tmp by container
  desc: Detect file writes under /tmp performed from inside a container
  condition: >
    open_write and
    container and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect miner-like activity in a container using process name and common mining-pool ports
  condition: >
    container and spawned_process and
    proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nc, wget) and
    (proc.cmdline contains " 3333" or
     proc.cmdline contains " 4444" or
     proc.cmdline contains " 5555" or
     proc.cmdline contains " 7777" or
     proc.cmdline contains " 14444" or
     proc.cmdline contains " 19999" or
     proc.cmdline contains " 45700")
  output: >
    Possible Cryptominer Activity
    (container=%container.name proc=%proc.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
Falco log line showing the `/tmp` write rule:

```json
{"hostname":"d53a40db2ded","output":"2026-07-10T19:10:27.284533832+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=9cc6d64c75d0 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9cc6d64c75d0","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783710627284533832,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T19:10:27.284533832Z"}
```

### Tuning consideration (Lecture 9 slide 8)
The `/tmp` write rule is intentionally noisy because many legitimate applications and libraries write temporary files. My tuning approach would be to prefer an `exceptions:` block for known-safe containers, images, or processes so the base detection logic stays readable, and only fall back to narrower `and not proc.name=...` filters for very specific noisy utilities after observing repeated false positives.

## Task 2: Conftest Policy-as-Code

### My policy file (paste `labs/lab9/policies/extra/hardening.rego`)

```rego
package main

is_deployment if {
  input.kind == "Deployment"
}

pod_run_as_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

container_run_as_non_root(c) if {
  c.securityContext.runAsNonRoot == true
}

drop_all_caps(c) if {
  "ALL" in c.securityContext.capabilities.drop
}

uses_digest(image) if {
  contains(image, "@sha256:")
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not pod_run_as_non_root
  not container_run_as_non_root(c)
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not drop_all_caps(c)
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not uses_digest(c.image)
  msg := sprintf("container %q must use an image pinned by sha256 digest", [c.name])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)

```text
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true at pod or container level
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must use an image pinned by sha256 digest

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`)

```text
$ conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches policy violations during PR review, when fixes are cheaper and developers still have full context on the change. Admission-time enforcement protects the cluster from anything that slips past CI or is applied manually, so using both gives earlier feedback plus a final runtime gate for defense in depth.

## Bonus: Cryptominer Detection Rule

### Rule (paste)

```yaml
- rule: Possible Cryptominer Activity
  desc: Detect miner-like activity in a container using process name and common mining-pool ports
  condition: >
    container and spawned_process and
    proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nc, wget) and
    (proc.cmdline contains " 3333" or
     proc.cmdline contains " 4444" or
     proc.cmdline contains " 5555" or
     proc.cmdline contains " 7777" or
     proc.cmdline contains " 14444" or
     proc.cmdline contains " 19999" or
     proc.cmdline contains " 45700")
  output: >
    Possible Cryptominer Activity
    (container=%container.name proc=%proc.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{"hostname":"d53a40db2ded","output":"2026-07-10T19:20:46.906329832+0000: Critical Possible Cryptominer Activity (container=lab9-target proc=nc cmd=nc -w 2 127.0.0.1 3333) container_id=9cc6d64c75d0 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9cc6d64c75d0","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783711246906329832,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T19:20:46.906329832Z"}
```

### Reflection (2-3 sentences)
I used two indicators together: a miner-like process name set and a command line containing a well-known mining pool port such as `3333`. This will miss miners that hide behind generic binaries or tunnel over normal HTTPS ports, so it is best paired with response priorities or SLA routing that escalates high-confidence runtime execution signals quickly while noisier anomaly rules are triaged separately.
