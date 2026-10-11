# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

Falco 0.43.1 was run natively (modern eBPF) on an Ubuntu VM (real kernel with syscall tracepoints). Docker Desktop's WSL2 kernel does not expose tracepoints, so Falco was run inside a VirtualBox Ubuntu guest where the modern-eBPF probe opens cleanly and captures live events.

### Baseline alert A — Terminal shell in container

    {"priority":"Notice","rule":"Terminal shell in container","output":"A shell was spawned in a container with an attached terminal ... command=sh -c echo shell-in-container container_name=lab9-target image=alpine","tags":["T1059","container","mitre_execution","shell"]}

### Baseline alert B — Read sensitive file untrusted

    {"priority":"Warning","rule":"Read sensitive file untrusted","output":"Sensitive file opened for reading by non-trusted program | file=/etc/pam.d/common-session process=pkexec ...","tags":["T1555","container","filesystem","mitre_credential_access"]}

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)

    - rule: Write to /tmp by container
      desc: Detect any write to /tmp from within a container (possible staging of payloads or drift)
      condition: >
        open_write
        and container
        and fd.name startswith /tmp/
      output: >
        Write to /tmp detected in container
        (user=%user.name command=%proc.cmdline file=%fd.name
        container=%container.name image=%container.image.repository)
      priority: WARNING
      tags: [container, drift]

### Custom rule fired

    {"priority":"Warning","rule":"Write to /tmp by container","output":"Write to /tmp detected in container (user=root command=sh -c echo hello > /tmp/my-write.txt file=/tmp/my-write.txt container=lab9-target image=alpine)","tags":["container","drift"]}

### Tuning consideration (Lecture 9 slide 8)
A "write to /tmp" rule is inherently noisy — package managers, logging frameworks, and language runtimes all stage files there. The right tuning is an `exceptions:` block that whitelists known-legitimate writers by stable attributes rather than path, e.g. `exceptions: [{name: tmp_writers, fields: [proc.name], values: [[npm],[pip],[apt]]}]`. Using `exceptions:` is preferable to a long `and not proc.name=...` chain because exceptions are append-only and composable — new allow-listed processes are added as data, not by editing the core condition, so the rule's intent stays readable and auditable.

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)

    package main

    import rego.v1

    container := input.spec.template.spec.containers[_]

    # 1. runAsNonRoot must be true
    deny contains msg if {
        input.kind == "Deployment"
        not container.securityContext.runAsNonRoot == true
        msg := sprintf("container %q must set securityContext.runAsNonRoot: true", [container.name])
    }

    # 2. allowPrivilegeEscalation must be false
    deny contains msg if {
        input.kind == "Deployment"
        not container.securityContext.allowPrivilegeEscalation == false
        msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
    }

    # 3. capabilities.drop must include ALL
    deny contains msg if {
        input.kind == "Deployment"
        not "ALL" in container.securityContext.capabilities.drop
        msg := sprintf("container %q must drop ALL capabilities", [container.name])
    }

    # 4. resources.limits.memory must be set
    deny contains msg if {
        input.kind == "Deployment"
        not container.resources.limits.memory
        msg := sprintf("container %q must set resources.limits.memory", [container.name])
    }

    # 5. image must not use the mutable :latest tag
    deny contains msg if {
        input.kind == "Deployment"
        endswith(container.image, ":latest")
        msg := sprintf("container %q must not use the mutable :latest tag", [container.name])
    }

### Good manifest passes
`conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/`

    10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions

### Bad manifest 1 fails (juice-unhardened)

    FAIL - main - container "juice" must not use the mutable :latest tag
    FAIL - main - container "juice" must set allowPrivilegeEscalation: false
    FAIL - main - container "juice" must set resources.limits.memory
    FAIL - main - container "juice" must set securityContext.runAsNonRoot: true
    10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions

### Bad manifest 2 fails (bad-no-resources)
A manifest that sets securityContext but omits resource limits and uses `:latest`:

    FAIL - main - container "app" must not use the mutable :latest tag
    FAIL - main - container "app" must set resources.limits.memory
    5 tests, 3 passed, 0 warnings, 2 failures, 0 exceptions

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest runs during the pull request, so an insecure manifest fails the check before it is ever merged — the author sees the deny message with the full diff in front of them and fixes it cheaply. Admission-time Conftest (via a Kyverno/OPA Gatekeeper webhook) runs at `kubectl apply`, catching anything that bypassed CI — a manual apply, a manifest from another repo, or a drift from the merged version. Running both is defense in depth: CI gives fast developer feedback and keeps the main branch clean, while admission is the non-bypassable backstop that enforces the same rules at the cluster boundary even when CI was skipped or the manifest never went through a PR at all.

## Bonus: Cryptominer Detection Rule

### Rule (in labs/lab9/falco/rules/custom-rules.yaml)

    - list: miner_ports
      items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

    - rule: Possible Cryptominer Activity
      desc: Detect a container connecting to a known mining-pool port or running a known miner binary
      condition: >
        evt.type in (connect, sendto)
        and container
        and (fd.sport in (miner_ports) or fd.rport in (miner_ports)
             or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
      output: >
        Possible cryptominer activity in container
        (container=%container.name image=%container.image.repository
        process=%proc.name command=%proc.cmdline connection=%fd.name)
      priority: CRITICAL
      tags: [container, mitre_execution, mitre_command_and_control]

### Triggered alert
Connecting from inside the container to a known mining-pool port (`nc -w 2 8.8.8.8 3333`) fires the rule:

    {"priority":"Critical","rule":"Possible Cryptominer Activity","output":"Possible cryptominer activity in container (container=lab9-target image=alpine process=nc command=nc -w 2 8.8.8.8 3333 connection=172.17.0.2:43442->8.8.8.8:3333)","tags":["container","mitre_command_and_control","mitre_execution"]}

### Reflection
**Indicators used:** I combined two — (1) connection to a known mining-pool destination port (`fd.rport in miner_ports`, e.g. 3333/4444/5555), and (2) a known miner process name (`proc.name in (xmrig, ethminer, ...)`). Port-based detection catches the network beacon even if the binary is renamed; process-name detection catches the miner even if it talks over a non-standard port. Together they cover both the "renamed binary" and "non-standard port" evasions individually.

**What it misses (false negative):** A sophisticated miner that proxies its pool traffic over **HTTPS/443** (or a TLS-wrapped Stratum proxy) defeats the port indicator entirely, and a custom-compiled miner with an unknown process name defeats the name indicator. So a miner using `xmrig-proxy` over 443 with a renamed binary would slip through both checks — this rule raises the bar but is not a complete control.

**Combining with the Lecture 9 SLA matrix:** This is a CRITICAL/high-confidence-but-incomplete signal, so in the SLA matrix it belongs in the "page on-call / auto-isolate" tier for confirmed hits, but should be paired with lower-confidence behavioural signals (sustained high CPU + steady low-bandwidth egress) to catch the HTTPS-evasion case. The port/name rule gives fast, cheap detection of the common case; the metric-based rule is the slower backstop for the evasive case — layered per the matrix's signal-confidence-vs-response-cost tradeoff.