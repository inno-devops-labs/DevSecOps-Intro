# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Falco Runtime Security Detection

### Environment
- Helper container: `alpine:3.19`
- Falco: `falcosecurity/falco:latest`
- Output: JSON logs
- Custom rules: `labs/lab9/falco/rules/custom-rules.yaml`

### Falco startup notes
Falco started successfully using the modern eBPF probe.  
The logs showed warnings about missing tracepoints for TOCTOU mitigation, but Falco explicitly reported that detection would continue to work. Therefore, the setup was considered functional.

### Baseline alert — Terminal shell in container

**Command used:**
```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**Observed Falco alert:**
```
{"hostname":"7b4b5fcbf1ad","output":"2026-04-13T17:23:50.577762099+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=82a64fb56557 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Notice","rule":"Terminal shell in container","source":"syscall"}
```

**Analysis:**

This alert indicates that an interactive shell was spawned inside a running container.
This is considered suspicious because production containers typically should not allow direct shell access during runtime.

### Custom Falco rule

**File:**

`labs/lab9/falco/rules/custom-rules.yaml`

**Rule:**

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and evt.is_open_write=true and fd.name startswith /usr/local/bin/ and container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

### Custom rule validation

**Command used:**

```
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

**Observed Falco alert:**

```json
{"hostname":"7b4b5fcbf1ad","output":"2026-04-13T17:27:18.264900871+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/custom-rule.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=82a64fb56557 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19 k8s_pod_name=<NA> k8s_ns_name=<NA>","priority":"Warning","rule":"Write Binary Under UsrLocalBin","source":"syscall"}
```

### Custom rule analysis

**Purpose:**

Detect file writes in `/usr/local/bin/` inside containers.

**Why it matters:**

Modifying binary directories at runtime may indicate:
- container drift
- unauthorized modification
- potential persistence mechanism

**When it should fire:**

- when a container process writes or creates a file under /usr/local/bin/

**When it should not fire:**

- host-level operations
- normal application activity outside this path

**Noise / false-positive tuning:**

- limited to containers (container.id != host)
- limited to write syscalls
- limited to `/usr/local/bin/`

## Task 2 — Policy-as-Code with Conftest

### Tested files
- `labs/lab9/manifests/k8s/juice-unhardened.yaml`
- `labs/lab9/manifests/k8s/juice-hardened.yaml`
- `labs/lab9/manifests/compose/juice-compose.yml`

### Unhardened Kubernetes manifest

**Command:**

```
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-unhardened.yaml -p /project/policies --all-namespaces
```

**Result:**

`2 warnings, 8 failures`

**Violations:**

- uses disallowed `:latest` tag
- missing `runAsNonRoot: true`
- missing `allowPrivilegeEscalation: false`
- missing `readOnlyRootFilesystem: true`
- missing `capabilities.drop: ["ALL"]`
- missing CPU requests
- missing memory requests
- missing CPU limits
- missing memory limits

**Warnings:**

- missing readinessProbe
- missing livenessProbe

### Analysis of violations

The unhardened manifest lacks critical security controls:

- Running as root increases the impact of compromise
- Privilege escalation may allow gaining additional permissions
- Writable root filesystem allows persistence and tampering
- Missing capability drop increases attack surface
- No resource limits may affect cluster stability
- Missing probes reduce reliability and observability

### Hardened Kubernetes manifest

**Command:**

```
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-hardened.yaml -p /project/policies --all-namespaces
```

**Result:**

`30 tests, 30 passed, 0 warnings, 0 failures`

### Hardening improvements
- replaced `:latest` with fixed version tag
- enabled `runAsNonRoot: true`
- disabled privilege escalation
- enabled read-only root filesystem
- dropped all Linux capabilities
- added CPU and memory requests/limits
- added readiness and liveness probes

### Docker Compose analysis

**Command:**

```
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/compose/juice-compose.yml -p /project/policies --all-namespaces
```

**Result:**

`15 tests, 15 passed, 0 warnings, 0 failures`

### Security controls in Compose
- runs as non-root user
- read-only filesystem enabled
- all capabilities dropped
- no-new-privileges enabled

### Conclusion

The hardened Kubernetes and Docker Compose configurations comply with defined security policies and demonstrate best practices for container security and deployment hardening.
