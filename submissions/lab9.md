# Lab 9 — Submission

## Environment

- Student: `msumakov366gmail.com`
- Branch: `feature/lab9`
- Docker: `29.2.0`
- Falco: `0.43.1`
- Conftest: `dev`
- OPA: `1.15.2`
- jq: `1.7.1`

Falco was run on macOS Docker Desktop with Docker Desktop's Linux VM. The lab command that mounted `/boot` failed because `/boot` is not shared from the macOS host, so Falco was started without that mount. Falco still opened the syscall source with the modern BPF probe.

```text
2026-07-10T13:22:51+0000: Falco version: 0.43.1 (aarch64)
2026-07-10T13:22:51+0000: Opening 'syscall' source with modern BPF probe.
2026-07-10T13:31:15+0000: /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
```

## Task 1: Runtime Detection with Falco

### Setup

Target container:

```bash
docker run -d --name lab9-target alpine:3.20 sleep 1d
```

Falco container:

```bash
docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:0.43.1 \
  falco -U \
        -o json_output=true \
        -o time_format_iso_8601=true
```

### Baseline Alert A — Terminal Shell In Container

Trigger command:

```bash
docker exec -it lab9-target /bin/sh -lc 'echo "shell-in-container test"'
```

Falco alert:

```json
{"hostname":"b0a207939263","output":"2026-07-10T13:26:25.699663725+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=2ad6611dc341 container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"2ad6611dc341","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783689985699663725,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T13:26:25.699663725Z"}
```

This maps to MITRE ATT&CK T1059 because a shell was spawned in a container with an attached terminal.

### Baseline Alert B — Container Drift

Trigger command:

```bash
docker exec --user 0 lab9-target /bin/sh -lc 'echo "drift" > /usr/local/bin/drift.txt'
```

The built-in Falco rule for writing below binary directories did not fire in this Docker Desktop environment. I checked with:

```bash
grep "Write below" labs/lab9/falco/logs/falco.log
```

No matching alert was produced. As an alternate runtime drift proof, the custom rule below detected a container write to `/tmp`, showing that Falco syscall runtime detection was functioning.

### Custom Rule

Rule file: `labs/lab9/falco/rules/custom-rules.yaml`

```yaml
- rule: Write to /tmp by container
  desc: Detect any write to /tmp directory inside a container
  condition: >
    open_write and
    container and
    fd.name startswith /tmp/
  output: >
    File write to /tmp detected (user=%user.name container=%container.name fd.name=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift, file]

- rule: Possible Cryptominer Activity
  desc: Detect connection to mining pool ports or known miner processes
  condition: >
    (evt.type=connect and fd.sockfamily=ip and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or
    (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity detected (user=%user.name container=%container.name proc=%proc.name fd.name=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

Rule validation:

```text
2026-07-10T13:49:49+0000: /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
2026-07-10T13:49:49+0000: /etc/falco/rules.d/custom-rules.yaml: Ok, with warnings
```

### Custom Rule Fired

Trigger command:

```bash
docker exec --user 0 lab9-target /bin/sh -lc 'echo "test" > /tmp/my-write.txt'
```

Falco alert:

```json
{"hostname":"b0a207939263","output":"2026-07-10T13:31:28.314659382+0000: Warning File write to /tmp detected (user=root container=lab9-target fd.name=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=2ad6611dc341 container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"2ad6611dc341","container.image.repository":"127.0.0.1:5000/juice-shop","container.image.tag":"v20.0.0-tampered","container.name":"lab9-target","evt.time.iso8601":1783690288314659382,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift","file"],"time":"2026-07-10T13:31:28.314659382Z"}
```

### Tuning Consideration

The `Write to /tmp by container` rule can create false positives because many legitimate workloads write temporary files. A maintainable tuning approach is to use an `exceptions:` block for trusted processes such as `java`, `node`, `python`, `nginx`, or database processes. An inline `and not proc.name in (...)` condition also works, but exceptions keep the core detection condition cleaner and make future tuning easier.

Example tuning:

```yaml
exceptions:
  - name: trusted_tmp_writers
    fields: [proc.name]
    comps: [in]
    values:
      - [java, node, python, nginx, postgres]
```

## Task 2: Conftest Policy-as-Code

### Policy File

Location: `labs/lab9/policies/extra/hardening.rego`

```rego
package main

# Rule 1: runAsNonRoot must be true
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container %v must have runAsNonRoot=true", [container.name])
}

# Rule 2: allowPrivilegeEscalation must be false
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container %v must have allowPrivilegeEscalation=false", [container.name])
}

# Rule 3: capabilities.drop must include "ALL"
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container %v must drop ALL capabilities", [container.name])
}

# Rule 4: resources.limits.memory must be set
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not container.resources.limits.memory
    msg := sprintf("Container %v must have memory limits set", [container.name])
}

# Rule 5: image must use sha256 digest
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %v must use image with sha256 digest (not tag)", [container.name])
}
```

### Rules Implemented

- `runAsNonRoot` must be `true`
- `allowPrivilegeEscalation` must be `false`
- `capabilities.drop` must include `ALL`
- `resources.limits.memory` must be set
- image must use a `sha256` digest instead of only a mutable tag

### Good Manifest Passes

Command:

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/
```

Output:

```text
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Bad Manifest Fails

Command:

```bash
conftest test labs/lab9/manifests/k8s/bad-pod-test.yaml --policy labs/lab9/policies/extra/
```

Output:

```text
FAIL - labs/lab9/manifests/k8s/bad-pod-test.yaml - main - Container bad-container must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/bad-pod-test.yaml - main - Container bad-container must have allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/bad-pod-test.yaml - main - Container bad-container must have memory limits set
FAIL - labs/lab9/manifests/k8s/bad-pod-test.yaml - main - Container bad-container must have runAsNonRoot=true
FAIL - labs/lab9/manifests/k8s/bad-pod-test.yaml - main - Container bad-container must use image with sha256 digest (not tag)

5 tests, 0 passed, 0 warnings, 5 failures, 0 exceptions
```

### Why CI-Time and Admission-Time Both Matter

CI-time Conftest gives fast feedback during pull request review, before a bad manifest is merged. Admission-time policy is still needed because it protects the Kubernetes API server if CI is bypassed, misconfigured, or if someone deploys manually. Running both gives defense in depth: developers learn and fix issues early, while the cluster still enforces the final safety net.

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- rule: Possible Cryptominer Activity
  desc: Detect connection to mining pool ports or known miner processes
  condition: >
    (evt.type=connect and fd.sockfamily=ip and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)) or
    (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity detected (user=%user.name container=%container.name proc=%proc.name fd.name=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Trigger Test

Command:

```bash
docker exec lab9-target /bin/sh -c 'nc -w 2 127.0.0.1 3333' 2>/dev/null || true
```

Result: the rule loaded successfully, but the local `nc` test did not produce a matching alert in this Docker Desktop environment. The likely causes are that the connection targeted loopback, no listening service completed the TCP flow, and Falco's eBPF probe on this kernel reported warnings around connect tracepoints.

### Reflection

I used two indicators: common mining-pool ports and known miner process names. Port indicators catch default pool connections, while process-name indicators catch common public miner binaries such as `xmrig`, `ethminer`, `cgminer`, `t-rex`, and `claymore`.

The rule misses miners that use HTTPS on port 443, renamed binaries, in-memory miners, proxy tunneling, or randomized pool ports. In a Lecture 9 SLA matrix, a CRITICAL cryptominer alert should trigger fast triage and containment, while lower-confidence signals should be correlated with CPU usage, egress volume, and destination reputation before escalation.

## Cleanup

```bash
docker stop falco lab9-target
docker rm falco lab9-target
pkill -f "docker logs -f falco" || true
```

## Acceptance Checklist

- [x] Falco started and opened syscall source with modern BPF probe
- [x] Baseline terminal shell alert captured
- [x] Container drift test attempted; custom write detection used as alternate runtime proof
- [x] Custom Falco rule exists and fired
- [x] Tuning discussion includes exception-based approach
- [x] Conftest policy file contains 5 hardening checks
- [x] Hardened manifest passes
- [x] Bad manifest fails with clear deny messages
- [x] Bonus cryptominer rule added with reflection and false-negative discussion
