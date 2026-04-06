## Runtime Security Detection with Falco

### Baseline Alerts Observed

**Alert 1 - Terminal shell in container**

```json
{
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "time": "2026-04-06T12:41:26.366755344Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "alpine",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "proc.tty": 34816,
    "user.name": "root"
  },
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"]
}
```

Built-in rule that fires when an interactive shell is spawned inside a container with an attached TTY.
Maps to MITRE ATT&CK T1059. In production, unexpected shell sessions indicate potential attacker access.

**Alert 2 - Write Binary Under UsrLocalBin**

```json
{
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "time": "2026-04-06T12:42:18.642372872Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/usr/local/bin/custom-rule.txt",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER",
    "user.name": "root"
  },
  "tags": ["compliance", "container", "drift"]
}
```

### Custom Rule

**Purpose:** Detects any file creation or modification under `/usr/local/bin/` inside a running container. 
This directory is populated at image build time; runtime writes 
signal container drift - a planted binary, reverse shell, or crypto-miner.

**Should fire:**
- A process inside any container opens a file under `/usr/local/bin/` with write flags.

**Should NOT fire:**
- Host-side operations - filtered by `container.id != host`.
- Image build steps - Falco monitors runtime only.
- Read or execute of existing binaries - only write-open events match `evt.is_open_write=true`.

## Policy-as-Code with Conftest (Rego)

### Policy Violations

| Violation                                  | Reason                                                                                          |
|--------------------------------------------|-------------------------------------------------------------------------------------------------|
| `missing resources.limits.cpu`             | Without CPU limits a container can starve other workloads, causing DoS on the node.             |
| `missing resources.limits.memory`          | Unbounded memory lets a container trigger OOM-kills of itself or neighbors.                     |
| `missing resources.requests.cpu`           | The scheduler cannot make informed placement decisions, leading to contended nodes.             |
| `missing resources.requests.memory`        | Same scheduling issue; also required for QoS class assignment.                                  |
| `must set allowPrivilegeEscalation: false` | Allows a child process to gain more privileges via `setuid`/`setgid` binaries.                  |
| `must set readOnlyRootFilesystem: true`    | A writable root filesystem lets attackers drop binaries or plant web shells.                    |
| `must set runAsNonRoot: true`              | Running as UID 0 gives full control; combined with a kernel exploit it enables host compromise. |
| `uses disallowed :latest tag`              | `:latest` is mutable and non-reproducible, breaking auditability and rollback.                  |

| Warning                        | Recommendation                                                          |
|--------------------------------|-------------------------------------------------------------------------|
| `should define livenessProbe`  | Without it, Kubernetes cannot restart a deadlocked container.           |
| `should define readinessProbe` | Without it, traffic is routed before the container can handle requests. |

### Changes That Satisfy Policies

| Hardening Change                                    | Policy Satisfied               |
|-----------------------------------------------------|--------------------------------|
| `image: bkimminich/juice-shop:v19.0.0` (pinned tag) | No `:latest` tag               |
| `runAsNonRoot: true`                                | Non-root enforcement           |
| `allowPrivilegeEscalation: false`                   | Privilege escalation blocked   |
| `readOnlyRootFilesystem: true`                      | Immutable root filesystem      |
| `capabilities.drop: ["ALL"]`                        | All Linux capabilities dropped |
| `requests: { cpu: "100m", memory: "256Mi" }`        | Resource requests defined      |
| `limits: { cpu: "500m", memory: "512Mi" }`          | Resource limits defined        |
| `readinessProbe` (httpGet /:3000)                   | Readiness health check present |
| `livenessProbe` (httpGet /:3000)                    | Liveness health check present  |

### Docker Compose Analysis

| Compose Directive                          | What It Enforces                                       |
|--------------------------------------------|--------------------------------------------------------|
| `user: "10001:10001"`                      | Explicit non-root user                                 |
| `read_only: true`                          | Immutable root filesystem                              |
| `cap_drop: ["ALL"]`                        | All capabilities dropped                               |
| `security_opt: ["no-new-privileges:true"]` | Prevents privilege escalation                          |
| `tmpfs: ["/tmp"]`                          | Writable `/tmp` via tmpfs while keeping root read-only |
| `image: bkimminich/juice-shop:v19.0.0`     | Pinned version tag                                     |
