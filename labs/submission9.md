# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Falco Runtime Detection
I ran Falco and collected alerts. 
Full log file are available at `./labs/lab9/logs/falco.log`

Alert example (from logfile):
```json
{
  "hostname": "ee27d59148b8",
  "output": "2026-04-06T14:24:47.851410536+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=9adf36984d6b container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "9adf36984d6b",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "container.name": "lab9-helper",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1775485487851410536,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "runc",
    "proc.tty": 34816,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": [
    "T1059",
    "container",
    "maturity_stable",
    "mitre_execution",
    "shell"
  ],
  "time": "2026-04-06T14:24:47.851410536Z"
}
```

Few words about baseline Falco behavior:
- Falco event generator alerted multiple built-in alerts: Run shell untrusted, Detect release_agent File Container Escapes, Create Symlink Over Sensitive Files, Debugfs Launched in Privileged Container
- `drift-style` rule in container was triggered for `lab9-helper` after creation of a new file under `/usr/local/bin/`

Custom rule trigger:
```json
{
  "hostname": "ee27d59148b8",
  "output": "2026-04-06T14:31:42.115163199+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/drift.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=9adf36984d6b container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "9adf36984d6b",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "container.name": "lab9-helper",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER",
    "evt.time.iso8601": 1775402578114409197,
    "fd.name": "/usr/local/bin/drift.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "source": "syscall",
  "tags": [
    "compliance",
    "container",
    "drift"
  ],
  "time": "2026-04-05T15:22:58.114409197Z"
}
```

### Custom rule purpose and tuning

It detects container runtime drift when a process writes a new or modified file under `/usr/local/bin`

When it fires:
- Any write to `/usr/local/bin/` inside a container
- If an image content changed at runtime 

When it doenst fire:
- Write on host
- Read-only opens
- Writes outside `/usr/local/bin` (inside a contaner)

Tuning:
- In a real environment there might be exceptions for specific containers; If those containers are trusted, there should be an exception by container.name, container.image.repository, or proc.name

## Conftest Policy-as-code

Policy artifacts are stored in `labs/lab9/policies`


Commands used:
```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-unhardened.yaml -p /project/policies --all-namespaces \
  | tee labs/lab9/analysis/conftest-unhardened.txt

docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-hardened.yaml -p /project/policies --all-namespaces \
  | tee labs/lab9/analysis/conftest-hardened.txt

docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/compose/juice-compose.yml -p /project/policies --all-namespaces \
  | tee labs/lab9/analysis/conftest-compose.txt
```

### Conftest results:
```bash
unhardened Kubernetes manifest:
30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions

hardened Kubernetes manifest:
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

Docker Compose manifest:
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

#### Unhardened Kubernetes violations

| Violation                                 | Risk                                                       |
| ----------------------------------------- | ---------------------------------------------------------- |
| Uses `:latest` tag                        | Mutable tag weakens reproducibility and auditability       |
| Missing `runAsNonRoot: true`              | Running as root increases impact if compromised            |
| Missing `allowPrivilegeEscalation: false` | Can allow a compromised process to gain more privileges    |
| Missing `readOnlyRootFilesystem: true`    | Writable root filesystem enables tampering and persistence |
| Missing `resources.requests.cpu`          | Unpredictable scheduling and capacity planning             |
| Missing `resources.requests.memory`       | Unpredictable memory reservation                           |
| Missing `resources.limits.cpu`            | Container can consume excessive CPU                        |
| Missing `resources.limits.memory`         | Can exhaust memory and affect node stability               |
| Missing readiness & liveness probes       | Reduced ability for traffic control and self-healing       |

#### Hardened Kubernetes changes

| Change                                       | Benefit                                  |
| -------------------------------------------- | ---------------------------------------- |
| Pin image to `bkimminich/juice-shop:v19.0.0` | Ensures reproducibility and traceability |
| `runAsNonRoot: true`                         | Prevents running as root                 |
| `allowPrivilegeEscalation: false`            | Blocks privilege escalation              |
| `readOnlyRootFilesystem: true`               | Prevents runtime filesystem tampering    |
| `capabilities.drop: ["ALL"]`                 | Removes unnecessary Linux capabilities   |
| Add CPU & memory requests                    | Improves scheduling predictability       |
| Add CPU & memory limits                      | Prevents resource exhaustion             |
| Add readiness & liveness probes (port 3000)  | Enables health checks and self-healing   |

#### Docker manifest analysis

| Configuration                                     | Outcome                                   |
| ------------------------------------------------- | ----------------------------------------- |
| Uses pinned image `bkimminich/juice-shop:v19.0.0` | Reproducible builds                       |
| Runs as `10001:10001`                             | Enforces non-root execution               |
| `read_only: true`                                 | Protects root filesystem                  |
| `tmpfs: ["/tmp"]`                                 | Allows safe temporary writes              |
| `security_opt: ["no-new-privileges:true"]`        | Prevents privilege escalation             |
| `cap_drop: ["ALL"]`                               | Removes all Linux capabilities            |


### Key Takeaway
Using Conftest for policy-as-code brings automated and consistent security enforcement into the pipeline. The unhardened manifest fails eight critical checks—enough to block deployment—while the hardened version passes cleanly. By shifting security left, problems are caught early, eliminating risks that would otherwise surface later during runtime with tools like Falco