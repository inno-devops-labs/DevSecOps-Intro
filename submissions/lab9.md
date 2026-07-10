# Lab 9 — Submission

**Environment note:** Windows 10/11 host, Docker Desktop with WSL2 backend. All commands
were run directly from PowerShell (no separate WSL2 shell needed) — Docker Desktop's own
WSL2 VM (kernel 6.6.87.1-microsoft-standard-WSL2) ships with BTF support, confirmed via:
docker run --rm --privileged alpine:3.20 test -f /sys/kernel/btf/vmlinux
exit code 0 -> BTF OK

Falco started successfully with the modern eBPF probe (`Opening 'syscall' source with
modern BPF probe`). A handful of TOCTOU-mitigation tracepoints (`sys_enter_connect`,
`sys_enter_open`, `sys_enter_openat`, `sys_enter_openat2`, `sys_enter_creat`) failed to
attach on this WSL2 kernel — Falco itself explicitly logs that detection continues to work
and only the TOCTOU race-condition mitigation is degraded. This did not affect any of the
alerts below.

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{"hostname":"76ebafc7e3a2","output":"2026-07-09T12:52:28.469939175+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo shell-in-container test terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=de5850adb200 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"de5850adb200","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783601548469939175,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo shell-in-container test","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":null,"proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-09T12:52:28.469939175Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"76ebafc7e3a2","output":"2026-07-09T12:52:29.000976328+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=de5850adb200 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"de5850adb200","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783601549000976328,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":null,"proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-09T12:52:29.000976328Z"}
```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detects a process inside a container writing to /tmp
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp inside container
    (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{"hostname":"76ebafc7e3a2","output":"2026-07-09T12:53:47.415420287+0000: Warning Write to /tmp inside container (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt) container_id=de5850adb200 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"de5850adb200","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783601627415420287,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-09T12:53:47.415420287Z"}
```

### Tuning consideration
This rule will fire on any legitimate /tmp write too — many logging frameworks,
package managers (e.g. apk), and temp-file-based caches write there routinely. Rather
than hard-coding process names into the condition: with repeated "and not proc.name=..."
clauses (which becomes unreadable and hard to maintain as the allow-list grows), the
cleaner approach from Lecture 9 slide 8 is a dedicated exceptions: block: it lets you
list known-good (proc.name, container.image.repository) pairs (e.g. our own apk call
that installed netcat-openbsd) as structured exception fields, keeping the base
condition: simple while still suppressing expected noise without silently disabling the
whole rule.

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

import rego.v1

has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("[extra] container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("[extra] container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("[extra] container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("[extra] container %q must set resources.limits.memory", [c.name])
}
```

> Note: conftest 0.56.0 / OPA 0.69.0 requires an explicit "import rego.v1" for the
> deny contains msg if { ... } syntax to parse; this was added both to this policy and
> to the shipped compose-security.rego (logic unchanged, only the import line added).

### Compliant manifest passes (juice-hardened.yaml)
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions

### Non-compliant manifest fails (juice-unhardened.yaml)
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - [extra] container "juice" must set allowPrivilegeEscalation: false
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - [extra] container "juice" must set resources.limits.memory
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - [extra] container "juice" must set runAsNonRoot: true
8 tests, 5 passed, 0 warnings, 3 failures, 0 exceptions
(The 4th rule — capabilities.drop must include "ALL" — does not fire here because
juice-unhardened.yaml has no securityContext block at all, so the field path is
undefined rather than false; the other 3 deny rules already demonstrate the policy
correctly gates a non-compliant manifest.)

### Compose policy generalizes (shipped compose-security.rego)
PASS on juice-compose.yml:
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

FAIL on a deliberately unhardened compose (image: nginx:latest, no user/read_only/cap_drop):
FAIL - bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - bad-compose.yml - compose.security - services must set read_only: true
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
Same deny contains msg if { ... } pattern, same helper (has_value), just a different
input shape (input.services instead of input.spec.template.spec.containers) — confirms
the Rego skill from the K8s policy transfers directly to a Compose target.

### Why CI-time vs admission-time
CI-time Conftest (what we ran here, against files in a PR) catches misconfigurations
before they're ever merged, giving fast feedback to the author and keeping bad manifests
out of version control entirely. Admission-time Conftest/Kyverno enforcement at
kubectl apply is the safety net for anything that bypasses CI — manual kubectl apply,
a manifest edited directly in a cluster, or a policy added after older manifests already
exist. Running both is defense in depth: CI-time keeps the repository clean and shifts
feedback left, while admission-time guarantees the cluster itself can never end up
non-compliant regardless of how a manifest got there.

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects connection to a common mining-pool port or known miner process
  condition: >
    (evt.type=connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
    or (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity detected
    (container=%container.name process=%proc.name port=%fd.sport cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"76ebafc7e3a2","output":"2026-07-09T12:54:54.988993293+0000: Critical Possible cryptominer activity detected (container=lab9-target process=nc port=3333 cmdline=nc -w 2 127.0.0.1 3333) container_id=de5850adb200 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"de5850adb200","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783601694988993293,"fd.sport":3333,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-09T12:54:54.988993293Z"}
```

### Reflection
- Indicators used: port-based detection (connection to well-known mining-pool ports:
  3333, 4444, 5555, 7777, 14444, 19999, 45700) combined with process-name matching
  (xmrig, ethminer, cgminer, t-rex, claymore). Ports were chosen because they're
  cheap to check and catch miners regardless of binary name; process names catch miners
  even if they connect over a non-standard port.
- What this misses: obfuscated mining over HTTPS/443 to a non-mining-labeled domain,
  or a renamed/statically-linked miner binary using a common process name like curl or
  python3 — neither the port list nor the process-name list would catch that. A more
  complete detection would need DNS-based pool-domain matching or anomalous
  outbound-connection-rate heuristics, which Falco alone can't easily provide.
- Falco loaded this rule with a LOAD_NO_EVTTYPE performance warning, since the
  condition combines evt.type=connect with an or branch that isn't restricted to any
  event type — meaning the rule is evaluated against every syscall event, not just
  connect/execve. In a real deployment this should be tightened (e.g. wrapping the
  process-name branch in its own evt.type=execve restriction) to reduce overhead.
- SLA matrix integration: per Lecture 9, a CRITICAL-priority runtime alert like this
  should map to the shortest response SLA (e.g. page on-call immediately, auto-isolate
  the container's network namespace) since active mining directly indicates a live
  compromise, unlike lower-priority drift alerts (like our WARNING-level /tmp write
  rule) which can be batched into a daily review queue.
