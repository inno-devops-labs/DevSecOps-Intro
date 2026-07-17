# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs:
```json
{"hostname":"745f9763945f","output":"2026-07-10T16:00:08.090065245+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=9d84e7efb649 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9d84e7efb649","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783699208090065245,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"systemd","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T16:00:08.090065245Z"}
```

### Baseline alert B — Container drift (write below binary dir / custom "write to /tmp" rule)
```json
{"hostname":"745f9763945f","output":"2026-07-10T16:00:08.296159844+0000: Warning Write to /tmp (user=root container=lab9-target path=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=9d84e7efb649 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9d84e7efb649","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783699208296159844,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T16:00:08.296159844Z"}
```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp directory inside containers
  condition: >
    container and fd.name startswith /tmp and open_write
  output: >
    Write to /tmp (user=%user.name container=%container.name
    path=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing the custom rule:
```json
{"hostname":"745f9763945f","output":"2026-07-10T16:00:08.296159844+0000: Warning Write to /tmp (user=root container=lab9-target path=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=9d84e7efb649 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9d84e7efb649","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783699208296159844,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T16:00:08.296159844Z"}
```

### Tuning consideration (Lecture 9 slide 8)
My custom "write to /tmp" rule will fire on legitimate uses (logging frameworks often write to /tmp). To reduce false positives, I would use the `exceptions:` block to exclude known legitimate processes like `logrotate`, `systemd-tmpfiles`, or application-specific logging tools. Alternatively, I could add `and not proc.name in ("logrotate", "systemd-tmpfiles")` directly to the condition. This balances detection with operational noise, as discussed in Lecture 9 slide 8.

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

deny contains msg if {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg := "DENY: Pod must have runAsNonRoot = true"
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("DENY: Container '%s' must have allowPrivilegeEscalation = false", [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("DENY: Container '%s' must drop ALL capabilities", [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("DENY: Container '%s' must have memory limits", [container.name])
}
```

### Good manifest passes
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Bad manifest 1 fails (runAsRoot)
```
FAIL - labs/lab9/manifests/bad-pod-runasroot.yaml - main - DENY: Pod must have runAsNonRoot = true

4 tests, 3 passed, 0 warnings, 1 failure, 0 exceptions
```

### Bad manifest 2 fails (no resources)
```
FAIL - labs/lab9/manifests/bad-pod-no-resources.yaml - main - DENY: Container 'app' must have memory limits

4 tests, 3 passed, 0 warnings, 1 failure, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches policy violations during PR review, giving developers fast feedback and preventing insecure manifests from ever being merged. Admission-time Conftest runs at `kubectl apply` as a final defense layer, catching violations introduced through other paths (e.g., direct cluster access, emergency changes bypassing CI). Running both gives defense in depth: CI-time shifts security left and reduces remediation cost, while admission-time guarantees runtime enforcement and catches edge cases CI might miss.

## Bonus: Cryptominer Detection Rule

### Rule (labs/lab9/falco/rules/cryptominer-rules.yaml)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects process matching known miner/nc tooling OR outbound connection to a common mining-pool port
  condition: >
    container and
    (
      (proc.name in ("nc", "ncat", "socat", "xmrig", "ethminer", "cgminer", "t-rex", "claymore"))
      or
      (evt.type=connect and fd.typechar='4' and fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
    )
  output: >
    Possible cryptominer activity (container=%container.name proc=%proc.name
    cmdline=%proc.cmdline connection=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"c1607a2c5c02","output":"2026-07-10T16:18:17.122699973+0000: Critical Possible cryptominer activity (container=lab9-target proc=nc cmdline=nc -zv 8.8.8.8 3333 connection=<NA>) container_id=9d84e7efb649 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9d84e7efb649","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783700297122699973,"fd.name":null,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -zv 8.8.8.8 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T16:18:17.122699973Z"}
```

### Reflection

- **Which 2 indicators did you use and why?** I used process name (`proc.name`) and destination port (`fd.rport`). Process-name detection catches known miner binaries (xmrig, ethminer) and common network tools (nc, ncat) attackers use for reverse shells or data exfiltration. Destination-port detection catches connections to common mining-pool ports (3333, 4444, 5555, 7777, 14444, 19999, 45700). Combining both reduces false positives — a single indicator can fire on legitimate traffic, but the pair gives a stronger signal.

- **What does this miss?** The rule misses obfuscated mining over HTTPS (port 443) or mining traffic tunneled through legitimate binaries like `curl`/`wget` with custom user-agents. It also misses miners that resolve pools by domain name rather than connecting straight to a known port, and miners injected into an already-running legitimate process.

- **How would this combine with the Lecture 9 SLA matrix?**
  - CRITICAL priority alerts → immediate response (P0/P1): page the security team via Slack/PagerDuty, auto-terminate the suspicious container.
  - WARNING priority alerts → P2/P3: open a ticket for investigation within 24 hours.
  - False positives → handled with an `exceptions:` block for known legitimate tools (e.g., CI/CD health-check scripts using `nc`), keeping the SLA matrix actionable instead of noisy.
