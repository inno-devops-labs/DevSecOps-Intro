# Lab 9 Submission — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

**Environment:** macOS host with Docker `28.5.2`; Docker server `linux/arm64`  
**Falco version used:** `0.43.0 (aarch64)`  
**Conftest image used:** `openpolicyagent/conftest:latest`

This report documents the work I completed locally for Lab 9 without making any git commits. All generated artifacts were saved under `labs/lab9/`, and this report summarizes the runtime-detection evidence and policy-as-code analysis from those saved files.

## Task 1 — Runtime Security Detection With Falco

### What I did

I prepared the lab directories:

```bash
mkdir -p labs/lab9/falco/rules labs/lab9/falco/logs labs/lab9/analysis
```

I added the required custom Falco rule at:

- `labs/lab9/falco/rules/custom-rules.yaml`

Then I started the helper container and Falco:

```bash
docker run -d --name lab9-helper alpine:3.19 sleep 1d

docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U \
        -o json_output=true \
        -o time_format_iso_8601=true
```

Falco started successfully with the modern eBPF probe and loaded the custom rule file. The full Falco log was saved to:

- `labs/lab9/falco/logs/falco.log`

### Triggered events

I used the helper container to trigger shell and file-write activity:

```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-tty-shell'

# write a new file under /usr/local/bin
docker exec --user 0 lab9-helper /bin/sh -lc 'cat > /usr/local/bin/upper-layer.sh <<\"EOF\"
#!/bin/sh
echo upper-layer
EOF
chmod +x /usr/local/bin/upper-layer.sh'

# create and execute a new upper-layer binary to trigger built-in drift detection
docker exec --user 0 lab9-helper /bin/sh -lc 'cp /bin/busybox /usr/local/bin/busycopy && /usr/local/bin/busycopy echo built-in-drift'
docker exec --user 0 lab9-helper /bin/sh -lc 'cp /bin/busybox /usr/local/bin/busybox && /usr/local/bin/busybox echo built-in-drift'
```

I also ran the Falco event generator for additional baseline validation:

```bash
docker run --rm --name eventgen \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

### Falco alert evidence

The most relevant alert lines from `labs/lab9/falco/logs/falco.log` were:

```text
2026-04-06T13:33:31.402638234Z | Terminal shell in container | Notice
A shell was spawned in a container with an attached terminal ... command=sh -lc echo hello-from-tty-shell ... container_name=lab9-helper

2026-04-06T13:32:39.743896304Z | Write Binary Under UsrLocalBin | Warning
Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/busycopy ...)

2026-04-06T13:32:39.745303804Z | Drop and execute new binary in container | Critical
Executing binary not part of base image ... proc_exe=/usr/local/bin/busycopy ... command=busycopy echo built-in-drift ... container_name=lab9-helper

2026-04-06T13:33:32.865563914Z | Run shell untrusted | Notice
Shell spawned by untrusted binary ... container_name=eventgen

2026-04-06T13:33:39.424798804Z | Detect release_agent File Container Escapes | Critical
Detect an attempt to exploit a container escape using release_agent file ... container_name=eventgen
```

### Baseline alerts observed

I observed the following baseline Falco behavior:

- `Terminal shell in container` was triggered for `lab9-helper` when I used a TTY-attached shell (`docker exec -it ...`).
- The Falco event generator produced multiple built-in alerts, including `Run shell untrusted`, `Detect release_agent File Container Escapes`, `Create Symlink Over Sensitive Files`, `Debugfs Launched in Privileged Container`, and `Execution from /dev/shm`.
- The built-in container drift-style rule `Drop and execute new binary in container` was triggered for `lab9-helper` after I copied `/bin/busybox` into `/usr/local/bin/` and executed the copied upper-layer binary.

One practical nuance in this environment is that a plain non-TTY `docker exec` shell did not produce the `Terminal shell in container` alert, while the TTY-attached shell did. That matches the rule semantics: the rule is specifically about an interactive terminal shell.

### Custom rule purpose and tuning notes

The custom rule is:

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and
             evt.is_open_write=true and
             fd.name startswith /usr/local/bin/ and
             container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

This rule fired for multiple writes under `/usr/local/bin/`, including:

- `/usr/local/bin/upper-layer.sh`
- `/usr/local/bin/busycopy`
- `/usr/local/bin/busybox`

That behavior is correct, because the rule is path-based and matches any writable open/create event under `/usr/local/bin/` inside a container.

The rule should fire when:

- a process inside a non-host container creates or opens a file for write under `/usr/local/bin/`
- the write represents container drift or unauthorized modification of a binary directory

The rule should not fire when:

- the event happens on the host (`container.id == host`)
- the file operation is read-only
- the write happens outside `/usr/local/bin/`

As a tuning note, the rule is intentionally broad for lab purposes. In a production deployment, I would likely reduce noise by limiting it to trusted images, selected namespaces, or executable file extensions if legitimate writes under `/usr/local/bin/` are expected during build/init workflows.

### Built-in drift validation

In this Falco version, the most relevant built-in drift-style rule for container filesystem mutation is `Drop and execute new binary in container`. It fires when a process executes an upper-layer executable that was not part of the base image.

To validate it, I copied the container's BusyBox binary into `/usr/local/bin/` and executed the copied file:

```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'cp /bin/busybox /usr/local/bin/busycopy && /usr/local/bin/busycopy echo built-in-drift'
```

That produced both pieces of evidence expected from the hardening/drift scenario:

- the custom write rule `Write Binary Under UsrLocalBin`
- the built-in rule `Drop and execute new binary in container`

This is stronger evidence than a write-only event because it proves not only that the container filesystem changed, but that a newly dropped upper-layer executable was actually run.

### Noise and environment-specific observations

This Falco environment also produced repeated `Fileless execution via memfd_create` alerts tied to the container runtime (`runc`/`dockerd`) on the host side. These events confirm that Falco was receiving syscall events correctly, but they are runtime noise for this lab. For that reason, I used only the lab-relevant alerts above as evidence in the report.

## Task 2 — Policy-as-Code With Conftest

### Files reviewed

I reviewed the provided manifests and policies:

- `labs/lab9/manifests/k8s/juice-unhardened.yaml`
- `labs/lab9/manifests/k8s/juice-hardened.yaml`
- `labs/lab9/manifests/compose/juice-compose.yml`
- `labs/lab9/policies/k8s-security.rego`
- `labs/lab9/policies/compose-security.rego`

### Commands used

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

Saved outputs:

- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`

### Conftest results

The unhardened Kubernetes manifest failed exactly as expected:

```text
30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

The hardened Kubernetes manifest passed:

```text
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

The Docker Compose manifest also passed:

```text
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

### Policy violations in the unhardened manifest and why they matter

The failures from `juice-unhardened.yaml` were:

- `container "juice" uses disallowed :latest tag`
- `container "juice" must set runAsNonRoot: true`
- `container "juice" must set allowPrivilegeEscalation: false`
- `container "juice" must set readOnlyRootFilesystem: true`
- `container "juice" missing resources.requests.cpu`
- `container "juice" missing resources.requests.memory`
- `container "juice" missing resources.limits.cpu`
- `container "juice" missing resources.limits.memory`

The warnings were:

- `container "juice" should define readinessProbe`
- `container "juice" should define livenessProbe`

Why each failure matters:

- Using `:latest` makes deployments non-deterministic and weakens change control because the image behind the tag can change without a manifest change.
- Missing `runAsNonRoot: true` allows the container to run as root, increasing the blast radius if the application is compromised.
- Missing `allowPrivilegeEscalation: false` leaves room for privilege escalation inside the container.
- Missing `readOnlyRootFilesystem: true` makes runtime tampering and persistence inside the container easier.
- Missing CPU/memory requests and limits weakens resource governance and can contribute to instability or denial-of-service conditions from unbounded consumption.
- Missing readiness/liveness probes reduces operational safety and slows safe recovery, though the provided policy treats them as warnings rather than hard failures.

### Hardening changes in the hardened manifest

The hardened manifest satisfies the policies because it adds the exact controls the Rego policy expects:

- It pins the image to `bkimminich/juice-shop:v19.0.0` instead of `:latest`.
- It sets `securityContext.runAsNonRoot: true`.
- It sets `securityContext.allowPrivilegeEscalation: false`.
- It sets `securityContext.readOnlyRootFilesystem: true`.
- It drops all Linux capabilities with `capabilities.drop: ["ALL"]`.
- It defines CPU and memory requests.
- It defines CPU and memory limits.
- It adds both `readinessProbe` and `livenessProbe`.

In other words, the hardened manifest directly maps to the policy requirements from `k8s-security.rego`, which is why it transitions from `8 failures` to `0 failures`.

### Docker Compose manifest analysis

The Compose manifest passed all checks because it already follows the expected hardening pattern:

- it sets an explicit non-root user with `user: "10001:10001"`
- it uses `read_only: true`
- it drops all capabilities with `cap_drop: ["ALL"]`
- it enables `no-new-privileges:true`
- it uses `tmpfs` for `/tmp`, which is a reasonable companion control for a read-only root filesystem

This aligns with the `compose-security.rego` policy, which enforces non-root execution, read-only mode, dropped capabilities, and recommends `no-new-privileges`.

## Cleanup

After collecting the evidence, the containers can be removed with:

```bash
docker rm -f falco lab9-helper eventgen 2>/dev/null || true
```

## Final Notes

- All required artifacts were created locally under `labs/lab9/` and `labs/submission9.md`.
- I did not create a branch, add files, commit, or push anything to git.
