# Lab 9 — Runtime Detection and Policy as Code

> **Environment note:** Docker Desktop on macOS does not expose the host kernel to Falco. Colima was used instead: `colima start --vm-type vz --cpu 2 --memory 2`, providing a Linux 6.8.0-117-generic kernel on Ubuntu 24.04 inside the VM. All Docker commands below used the `colima` context. The TOCTOU attachment warnings in Falco startup are expected on this kernel (the lab notes this) and detection still works.

## Task 1

### 9.2 — Built-in rules triggered

**Rule 1: "Terminal shell in container"**

Triggered by: `docker exec -t lab9-target sh -lc 'echo hello-from-shell'`. The `-t` flag allocates a pseudo-TTY, which is what the rule keys on (`proc.tty != 0`).

Alert JSON:
```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-09-28T17:30:41.821853818+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "583d2dcec504",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
        "evt.time.iso8601": 1790616641821853818,
        "evt.type": "execve",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "sh -lc echo hello-from-shell",
        "proc.exepath": "/bin/busybox",
        "proc.name": "sh",
        "proc.pname": "containerd-shim",
        "proc.tty": 34816,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
    "time": "2026-09-28T17:30:41.821853818Z"
}
```

**Rule 2: "Read sensitive file untrusted"**

Triggered by: `docker exec lab9-target sh -c 'cat /etc/shadow'`. The `cat` process (not in the trusted-binaries list) opened `/etc/shadow`, which Falco classifies as a sensitive file.

Alert JSON:
```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-09-28T17:30:41.867307830+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "583d2dcec504",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1790616641867307830,
        "evt.type": "openat",
        "fd.name": "/etc/shadow",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.aname[2]": "systemd",
        "proc.aname[3]": null,
        "proc.aname[4]": null,
        "proc.cmdline": "cat /etc/shadow",
        "proc.exepath": "/bin/busybox",
        "proc.name": "cat",
        "proc.pname": "containerd-shim",
        "proc.tty": 0,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
    "time": "2026-09-28T17:30:41.867307830Z"
}
```

### 9.3 — Custom rule: write to /tmp in container

**Rule file (`labs/lab9/falco/rules/custom-rules.yaml`, first rule):**

```yaml
- rule: Write to tmp in container
  desc: Detects any file write to /tmp inside a container, which may indicate drift or staging of malicious content
  condition: >
    open_write
    and container.id != "host"
    and fd.name startswith "/tmp/"
  output: >
    Container /tmp write detected
    (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

Triggered by: `docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'` (after SIGHUP reload).

Alert JSON:
```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-09-28T17:33:12.111703397+0000: Warning Container /tmp write detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt) container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "583d2dcec504",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1790616792111703397,
        "fd.name": "/tmp/my-write.txt",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
        "user.name": "root"
    },
    "priority": "Warning",
    "rule": "Write to tmp in container",
    "source": "syscall",
    "tags": ["container", "drift"],
    "time": "2026-09-28T17:33:12.111703397Z"
}
```

**One incident-relevant JSON field not in the human-readable message:** `evt.time.iso8601` — `1790616792111703397`. This is the event timestamp in nanoseconds since epoch, at kernel-level precision. The human-readable `output` string carries only second-level precision and is formatted for readability. During incident response the nanosecond timestamp allows correlating this event with other kernel events (network connections, process forks) that happened within the same millisecond, and it does not depend on any user-space clock that could be tampered with.

**False positive scenario and tuning.** The rule fires on every `/tmp` write in every container — a perfectly legitimate workload that would trigger it constantly is any container using `/tmp` as scratch space for inter-process communication or for building a compiled binary: for example, a CI job running `make` writes object files to `/tmp`, a JVM writes its JIT compiled code cache there, or a Node.js application uses `tmp` for multipart upload staging. To keep the detection while dropping the noise: scope the rule to specific container images or namespaces with an additional condition (`container.image.repository != "ci-runner"`), add a macro excluding known-good binaries (`proc.name not in (node, java, javac, make, cc, ld)`), or fire only when the file written has an executable extension or is later executed. The most operationally useful refinement is probably: raise the alert only when the written file is subsequently `execve`d, which is a separate Falco rule rather than a condition change.

## Task 2

### 9.4 — Existing policy results

**`juice-hardened.yaml`:** `30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions`

**`juice-unhardened.yaml`:** `30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions`

Failures:
```
FAIL - container "juice" uses disallowed :latest tag
FAIL - container "juice" must set runAsNonRoot: true
FAIL - container "juice" must set allowPrivilegeEscalation: false
FAIL - container "juice" must set readOnlyRootFilesystem: true
FAIL - container "juice" must drop ALL capabilities
FAIL - container "juice" missing resources.requests.cpu
FAIL - container "juice" missing resources.requests.memory
FAIL - container "juice" missing resources.limits.cpu
FAIL - container "juice" missing resources.limits.memory
```

Warnings:
```
WARN - container "juice" should define readinessProbe
WARN - container "juice" should define livenessProbe
```

Two failures mapped to their Rego rules:

1. **`:latest` tag** — `container "juice" uses disallowed :latest tag` ← `deny contains msg if { input.kind == "Deployment"; c := input.spec.template.spec.containers[_]; endswith(c.image, ":latest"); ... }` in `k8s-security.rego:10-14`. The unhardened manifest has `image: bkimminich/juice-shop:latest`; the hardened one uses a digest reference.

2. **`runAsNonRoot` missing** — `container "juice" must set runAsNonRoot: true` ← `deny contains msg if { input.kind == "Deployment"; c := input.spec.template.spec.containers[_]; not c.securityContext.runAsNonRoot; ... }` in `k8s-security.rego:18-22`. The unhardened manifest has no `securityContext` at all.

**`juice-compose.yml`:** `15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions`

**Why a separate rule for Compose vs. Kubernetes:** The two formats represent the same security requirement through completely different data shapes — a Compose service's drop-all looks like `cap_drop: ["ALL"]` inside `services.<name>`, while Kubernetes puts it at `spec.template.spec.containers[_].securityContext.capabilities.drop`. Rego evaluates the literal structure of `input`, so the same `input.spec.template.spec.containers[_]` path is simply absent in a Compose document; a rule written for one format raises an undefined reference (and silently passes) against the other, rather than failing. The requirement is the same; the two packages (`k8s.security`, `compose.security`) exist because the schemas are different.

**What the Compose file passing tells you:** It tells you the Compose manifest was independently hardened to the same standard — `user`, `read_only`, `cap_drop: ALL`, and `no-new-privileges` are all set. The policy is actually exercising real checks and not trivially passing because the rules are broken or the file type is unrecognized. A policy set that only ever produces failures gives you no confidence that it would catch a real misconfiguration, because you can never tell whether a "pass" means "everything is correct" or "the rule never matched at all." A known-good file passing is the control that validates the rule is reachable.

### 9.5 — Extended policy

**Policy file (`labs/lab9/policies/extra/hardening.rego`):**

```rego
package k8s.security

# deny: image must be pinned by digest (@sha256:...), not just a tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...), not a mutable tag", [c.name])
}

# warn: automountServiceAccountToken should be explicitly disabled
warn contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
  msg := "Deployment should set automountServiceAccountToken: false to prevent unneeded API access"
}
```

**Manifest written to violate both rules (`/tmp/violates-my-policy.yaml`):**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-violates
spec:
  replicas: 1
  selector:
    matchLabels: { app: juice }
  template:
    metadata:
      labels: { app: juice }
    spec:
      automountServiceAccountToken: true
      containers:
        - name: juice
          image: bkimminich/juice-shop:v20.0.0    # tag, not digest
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "100m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          readinessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 10
            periodSeconds: 20
```

**Hardened manifest (with extra policy):**

```
WARN - k8s.security - Deployment should set automountServiceAccountToken: false to prevent unneeded API access

34 tests, 33 passed, 1 warning, 0 failures, 0 exceptions
```

(The warning fires because `juice-hardened.yaml` doesn't set `automountServiceAccountToken: false` explicitly; the digest-pinning deny does not fire because the hardened manifest already uses `@sha256:`.)

**Violating manifest:**

```
WARN - /tmp/violates-my-policy.yaml - k8s.security - Deployment should set automountServiceAccountToken: false to prevent unneeded API access
FAIL - /tmp/violates-my-policy.yaml - k8s.security - container "juice" image must be pinned by digest (@sha256:...), not a mutable tag

17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
```

**CI (Conftest) vs. runtime (Falco) — which to keep for image-digest pinning:** I would keep the **Conftest rule in CI**. Image-digest pinning is a preventive control — by the time a pod is running with a mutable tag, you have already lost the enforcement window. Conftest in CI blocks the deploy before it reaches the cluster; a Falco rule that fires after the pod is up only tells you about a violation you already allowed. What the **Falco rule still buys** even if you keep CI enforcement: it catches images that reach the cluster through paths CI does not cover — a `kubectl apply` run manually by an operator, a helm upgrade that bypasses the pipeline, or an image updated in-place after the initial deploy audit — giving you runtime visibility on the gap between what CI checked and what is actually running.

## Bonus — Cryptominer detection

**Rule file (`labs/lab9/falco/rules/custom-rules.yaml`, second rule):**

```yaml
- rule: Likely cryptomining outbound connection
  desc: Detects an outbound TCP connection to a common mining pool port from inside a container
  condition: >
    evt.type = connect
    and container.id != "host"
    and fd.rport in (3333, 4444, 5555, 7777, 14444)
  output: >
    Likely cryptomining connection from container
    (container=%container.name process=%proc.name dest=%fd.rip:%fd.rport cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_command_and_control, T1496]
```

Triggered by: `docker exec lab9-target sh -c 'nc -zw 2 8.8.8.8 3333'`

Alert JSON:
```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-09-28T17:33:50.839957399+0000: Critical Likely cryptomining connection from container (container=lab9-target process=nc dest=8.8.8.8:3333 cmdline=nc -zw 2 8.8.8.8 3333) container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "583d2dcec504",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1790616830839957399,
        "fd.rip": "8.8.8.8",
        "fd.rport": 3333,
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "nc -zw 2 8.8.8.8 3333",
        "proc.name": "nc"
    },
    "priority": "Critical",
    "rule": "Likely cryptomining outbound connection",
    "source": "syscall",
    "tags": ["T1496", "container", "mitre_command_and_control"],
    "time": "2026-09-28T17:33:50.839957399Z"
}
```

**Why a refused connection is enough:** Falco hooks the `connect` syscall at the kernel level, before the TCP handshake completes. The kernel delivers the `connect` event the moment the process issues the syscall — whether the remote host accepts the connection or refuses it (RST) or times out is irrelevant. The attacker's process had to call `connect`; that syscall is observable regardless of what the remote end does. This is what it means that Falco sits inside the kernel: it sees the attempt, not the outcome.

**Evasion analysis — what's cheap vs. expensive, and what to add.** The **cheap part to evade** is the destination port: a miner that connects to port 443 (TLS-wrapped Stratum) or a port not in this list costs the attacker nothing to change. The **expensive part** is the combination of a network connection from inside a container and a CPU-intensive process: if the miner is actually running, it will show up in `proc.cpu.usage` and in the burst of threads. Adding a second signal — such as `proc.cpu.user >= 80` sustained over multiple windows, or a condition on process names known to be mining binaries (`xmrig`, `t-rex`, `lolminer`) — makes the evasion progressively harder: the attacker has to rename their binary, cap their CPU, and randomize their port, which reduces profitability. A practical addition is a Falco rule on `execve` of any process whose name matches known mining binaries, regardless of network activity, which catches miners started but not yet connected.
