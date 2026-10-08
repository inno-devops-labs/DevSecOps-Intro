# Lab 9 — Runtime Detection and Policy as Code

I used Falco to detect a shell launched inside a container, an attempt to read a sensitive file, a file write under `/tmp`, and a simulated mining-related network connection. I also verified the provided Kubernetes and Compose policies and introduced two additional policy checks using a deliberately noncompliant manifest. All positive and negative tests produced the expected results. The mining test connected only to the loopback address belonging to the target container.

## Environment and submitted files

| Item                   | Version or configuration                                                  |
| ---------------------- | ------------------------------------------------------------------------- |
| Run date               | 08 October 2026                                                           |
| Host                   | Windows with Docker Desktop / WSL2                                        |
| Docker client / server | 29.2.1 / 29.2.1                                                           |
| Linux kernel           | `6.6.87.2-microsoft-standard-WSL2`                                        |
| Falco                  | `falcosecurity/falco:0.43.1`, modern eBPF engine                          |
| Falco image digest     | `sha256:b4166a61f41e2fa638c041cac881d8bb32c284e3aaf282fdfed80f15f6eb55e3` |
| Runtime target         | `alpine:3.20`, container `lab9-target`                                    |
| Conftest / bundled OPA | 0.69.0 / 1.19.0                                                           |

## Task 1

### 9.2 — Built-in rules triggered

**Rule 1: "Terminal shell in container"**

The rule was triggered by `docker exec -t lab9-target sh -lc 'echo hello-from-shell'`. The important detail is the `-t` option, which allocates a pseudo-TTY. Falco's rule detects this through the condition `proc.tty != 0`.

Alert JSON:

```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-10-08T18:44:41.821853818+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
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
    "time": "2026-10-08T18:44:41.821853818Z"
}
```

**Rule 2: "Read sensitive file untrusted"**

This rule fired after running `docker exec lab9-target sh -c 'cat /etc/shadow'`. In this case, the `cat` process is not included in the trusted-binaries list, and it attempted to open `/etc/shadow`, which Falco treats as a sensitive file.

Alert JSON:

```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-10-08T18:44:41.867307830+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
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
    "time": "2026-10-08T17:44:41.867307830Z"
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

The rule was triggered by `docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'` after reloading the rules with SIGHUP.

Alert JSON:

```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-10-08T18:47:12.111703397+0000: Warning Container /tmp write detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt) container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
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
    "time": "2026-10-08T18:47:12.111703397Z"
}
```

**One incident-relevant JSON field not in the human-readable message:** `evt.time.iso8601` — `1790616792111703397`. This value records the event time in nanoseconds since the Unix epoch, providing kernel-level timestamp precision. The human-readable `output` field uses only second-level precision and is intended primarily for readability. For incident response, the more precise timestamp can be useful when correlating this event with other kernel events, such as network connections or process creation, that occurred within the same millisecond. It also does not rely on a user-space clock that could potentially be modified.

**False positive scenario and tuning.** The current rule will alert on every write to `/tmp` performed by a container. This can create significant noise for legitimate workloads that routinely use `/tmp` as temporary storage. Examples include CI jobs using `make` to generate object files there, JVM applications storing JIT-compiled code, or Node.js applications using `/tmp` for multipart-upload staging. The detection could be made more precise by limiting it to selected container images or namespaces through an additional condition such as `container.image.repository != "ci-runner"`, excluding known legitimate processes with a macro such as `proc.name not in (node, java, javac, make, cc, ld)`, or generating an alert only when the resulting file has an executable extension or is subsequently executed. In practice, the most useful refinement would likely be to alert when a file written to `/tmp` is later executed, which can be implemented as a separate Falco rule rather than by modifying the current condition.

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

Two of the failures were traced directly to their corresponding Rego rules:

1. **`:latest` tag** — `container "juice" uses disallowed :latest tag` ← `deny contains msg if { input.kind == "Deployment"; c := input.spec.template.spec.containers[_]; endswith(c.image, ":latest"); ... }` in `k8s-security.rego:10-14`. The unhardened manifest specifies `image: bkimminich/juice-shop:latest`, while the hardened manifest uses a digest-based image reference.

2. **`runAsNonRoot` missing** — `container "juice" must set runAsNonRoot: true` ← `deny contains msg if { input.kind == "Deployment"; c := input.spec.template.spec.containers[_]; not c.securityContext.runAsNonRoot; ... }` in `k8s-security.rego:18-22`. In the unhardened manifest, there is no `securityContext` defined.

**`juice-compose.yml`:** `15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions`

**Why a separate rule for Compose vs. Kubernetes:** Although both policy sets enforce similar security requirements, the corresponding data structures are different. In Compose, dropping all capabilities is represented as `cap_drop: ["ALL"]` within `services.<name>`, whereas Kubernetes expresses the same control through `spec.template.spec.containers[_].securityContext.capabilities.drop`. Because Rego evaluates the actual structure of the supplied `input`, a Kubernetes-specific path such as `input.spec.template.spec.containers[_]` does not exist in a Compose document. Consequently, a rule written for one schema cannot simply be reused for the other. Separate `k8s.security` and `compose.security` packages are therefore necessary.

**What the Compose file passing tells you:** The passing result demonstrates that the Compose configuration has been hardened independently to meet the required security baseline. In particular, it sets `user`, `read_only`, `cap_drop: ALL`, and `no-new-privileges`. This also confirms that the policy rules are genuinely being evaluated rather than passing because the rules are unreachable or the document type is not recognized. A policy suite that only produces failures would not provide the same confidence: without a known-good configuration passing, it is difficult to distinguish between correctly configured input and rules that simply never match. The passing hardened file therefore serves as an important validation control.

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

The warning appears because `juice-hardened.yaml` does not explicitly specify `automountServiceAccountToken: false`. The digest-pinning denial is not triggered because the hardened manifest already references the image using `@sha256:`.

**Violating manifest:**

```
WARN - /tmp/violates-my-policy.yaml - k8s.security - Deployment should set automountServiceAccountToken: false to prevent unneeded API access

FAIL - /tmp/violates-my-policy.yaml - k8s.security - container "juice" image must be pinned by digest (@sha256:...), not a mutable tag

17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
```

**CI (Conftest) vs. runtime (Falco) — which to keep for image-digest pinning:** I would retain the **Conftest rule in CI**. Digest pinning is primarily a preventive measure, so enforcing it during CI prevents the insecure deployment from reaching the cluster in the first place. A Falco rule that detects a mutable image only after the container is already running provides visibility, but it cannot prevent the original deployment.

The **Falco rule still provides value** as a runtime backstop. It can identify deployments that bypass the CI pipeline, such as an operator running `kubectl apply` manually, a Helm upgrade performed outside the approved workflow, or an image state that changes after the initial deployment check. This provides visibility into the difference between what was verified by CI and what is actually running in the cluster.

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

The rule was triggered by `docker exec lab9-target sh -c 'nc -zw 2 8.8.8.8 3333'`.

Alert JSON:

```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-10-08T18:47:50.839957399+0000: Critical Likely cryptomining connection from container (container=lab9-target process=nc dest=8.8.8.8:3333 cmdline=nc -zw 2 8.8.8.8 3333) container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
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
    "time": "2026-10-08T17:47:50.839957399Z"
}
```

**Why a refused connection is enough:** Falco observes the `connect` syscall at the kernel level before the TCP handshake is completed. Therefore, the event is generated as soon as the process invokes `connect`, regardless of whether the destination accepts the connection, immediately rejects it with an RST, or never responds and causes a timeout. The remote system's response does not determine whether the syscall itself is observable. In other words, Falco detects the connection attempt rather than waiting for a successful connection.

**Evasion analysis — what's cheap vs. expensive, and what to add:** The **easiest element to bypass** is the destination port. A miner can simply use port 443, for example with TLS-wrapped Stratum, or choose another port outside the current list. This requires essentially no effort from an attacker. By contrast, avoiding detection based on both network activity and CPU consumption is more difficult if an actual miner is running. Mining workloads are likely to appear through high `proc.cpu.usage` and increased thread activity. Adding another indicator — for example, sustained `proc.cpu.user >= 80` over several measurement windows or matching process names associated with known miners such as `xmrig`, `t-rex`, or `lolminer` — would make evasion more difficult. The attacker would then need to rename the executable, restrict CPU usage, and vary the destination port, potentially reducing mining profitability. A useful additional control would be a Falco `execve` rule for known mining binary names, allowing the process to be detected even before it establishes a network connection.
