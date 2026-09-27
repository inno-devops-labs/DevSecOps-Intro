# Lab 9 — Runtime Detection and Policy as Code

I used Falco to detect a terminal shell, a sensitive-file read, a write under
`/tmp`, and a simulated mining connection. I then tested the supplied Kubernetes
and Compose policies and added two checks with a deliberately noncompliant
manifest. All positive and negative checks behaved as described below; the
mining simulation contacted only the target container's own loopback address.

## Environment and submitted files

| Item | Version or configuration |
|---|---|
| Run date | 27 September 2026 |
| Host | Windows with Docker Desktop / WSL2 |
| Docker client / server | 29.2.1 / 29.2.1 |
| Linux kernel | `6.6.87.2-microsoft-standard-WSL2` |
| Falco | `falcosecurity/falco:0.43.1`, modern eBPF engine |
| Falco image digest | `sha256:b4166a61f41e2fa638c041cac881d8bb32c284e3aaf282fdfed80f15f6eb55e3` |
| Runtime target | `alpine:3.20`, container `lab9-target` |
| Conftest / bundled OPA | 0.69.0 / 1.19.0 |

The branch starts from `main` and adds four files:

- This report.
- [Custom Falco rules](../labs/lab9/falco/rules/custom-rules.yaml).
- [Additional Rego policy](../labs/lab9/policies/extra/hardening.rego).
- [Manifest that violates the new policy](../labs/lab9/manifests/k8s/juice-extra-violations.yaml).

The supplied manifests and policies are unchanged. Raw logs and temporary test
inputs remain in the ignored `labs/lab9/falco/logs/` directory; the evidence
needed to review the work is included below. The Kubernetes and Compose files
were evaluated statically, not deployed.

## Task 1

### Start Falco and trigger the built-in rules

I ran the following from the repository root in PowerShell:

```powershell
docker run -d --name falco --privileged `
  -v /proc:/host/proc:ro -v /boot:/host/boot:ro `
  -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro `
  -v /var/run/docker.sock:/host/var/run/docker.sock `
  -v "${PWD}/labs/lab9/falco/rules:/etc/falco/rules.d:ro" `
  falcosecurity/falco:0.43.1 `
  falco -U -o json_output=true -o time_format_iso_8601=true
docker run -d --name lab9-target alpine:3.20 sleep 1d
Start-Sleep -Seconds 10
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
docker exec lab9-target sh -c 'cat /etc/shadow'
Start-Sleep -Seconds 8
docker logs falco
```

Falco reported unavailable syscall tracepoints for TOCTOU mitigation on WSL2,
but continued detecting events. After the final reload and tests,
`docker inspect falco --format '{{.State.Status}} {{.RestartCount}}'` returned
`running 0`. Both trigger commands exited with code **0**; the shadow-file
contents are not part of the report.

| Built-in rule | Trigger and observed priority |
|---|---|
| `Terminal shell in container` | `docker exec -t` attached a terminal to `sh`; **Notice**. Without `-t`, this trigger does not satisfy the rule's terminal condition. |
| `Read sensitive file untrusted` | `cat` opened `/etc/shadow` for reading; **Warning**. |

Full alert JSON, formatted for readability without changing the values:

```json
{
  "hostname": "e70fe137c9b9",
  "output": "2026-09-27T08:27:14.829099350+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=dc92bcda507c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "dc92bcda507c",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1790497634829099350,
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
  "tags": [
    "T1059",
    "container",
    "maturity_stable",
    "mitre_execution",
    "shell"
  ],
  "time": "2026-09-27T08:27:14.829099350Z"
}
```

```json
{
  "hostname": "e70fe137c9b9",
  "output": "2026-09-27T08:27:14.937686706+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=dc92bcda507c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "dc92bcda507c",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1790497634937686706,
    "evt.type": "open",
    "fd.name": "/etc/shadow",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.aname[2]": null,
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
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-09-27T08:27:14.937686706Z"
}
```

### Detect writes under `/tmp`

The first rule in [custom-rules.yaml](../labs/lab9/falco/rules/custom-rules.yaml)
uses the shipped `open_write` macro, excludes `container.id=host`, and requires
`fd.name startswith /tmp/`. It has priority `WARNING`, tags `[container, drift]`,
and reports the container, user, path, and command line.

I read the actual macro from `/etc/falco/falco_rules.yaml`:

```yaml
- macro: open_write
  condition: (evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0)
```

This detects a successful open for writing, including a create or truncate;
it does not count each subsequent `write(2)` call or prove bytes were written.
After editing the host-side rule file, I reloaded it and triggered the rule:

```powershell
docker kill --signal=SIGHUP falco
Start-Sleep -Seconds 5
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
Start-Sleep -Seconds 7
docker logs falco
```

The command exited with code **0** and the final test window contained exactly
one `Container Write Under Tmp` alert:

```json
{
  "hostname": "e70fe137c9b9",
  "output": "2026-09-27T08:29:23.836378829+0000: Warning Container opened a temporary file for writing (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=dc92bcda507c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "dc92bcda507c",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1790497763836378829,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Container Write Under Tmp",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-09-27T08:29:23.836378829Z"
}
```

The top-level **`source: "syscall"`** is incident-relevant and is not present
in the human-readable `output` message. It identifies this as a syscall-source
event, helping an analyst distinguish a kernel-observed file operation from
an application's own log message when correlating evidence.

A legitimate image-processing service could write temporary thumbnails or
decoder scratch files under `/tmp`, so this broad rule would flag normal work.
I would first measure those alerts and identify the expected workload, executable,
user, and narrow scratch-directory prefix. I would add an exception for that
combination while keeping alerts for shells, unexpected processes, other paths,
and other containers. That preserves visibility without suppressing every
`/tmp` event merely because the container sometimes uses temporary files.

## Task 2

### Test the supplied policies before extending them

I ran each input against the original policy directory before adding my file:

```powershell
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies --all-namespaces
```

| Original policy set / input | Total | Passed | Warnings | Failures | Exit |
|---|---:|---:|---:|---:|---:|
| Hardened Kubernetes | 30 | 30 | 0 | 0 | 0 |
| Unhardened Kubernetes | 30 | 20 | 2 | 8 | 1 |
| Compose | 15 | 15 | 0 | 0 | 0 |

Conftest's counts include rule evaluations across the loaded namespaces and
input documents, including rules that do not apply to a given document. They
are not counts of independent security guarantees. The Kubernetes files each
contain a Deployment and a Service; the Compose file contains one document.

Exact unhardened output, with terminal color codes removed:

```text
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

All eight failures map to these `deny` conditions in
[k8s-security.rego](../labs/lab9/policies/k8s-security.rego):

| Failure | Rego condition that produced it |
|---|---|
| Disallowed `:latest` tag | `endswith(c.image, ":latest")` |
| Missing non-root setting | `not c.securityContext.runAsNonRoot` |
| Missing privilege-escalation restriction | `not c.securityContext.allowPrivilegeEscalation == false` |
| Missing read-only root filesystem | `not c.securityContext.readOnlyRootFilesystem == true` |
| Missing CPU request | `not c.resources.requests.cpu` |
| Missing memory request | `not c.resources.requests.memory` |
| Missing CPU limit | `not c.resources.limits.cpu` |
| Missing memory limit | `not c.resources.limits.memory` |

The two warnings come from the missing readiness and liveness probes. No
capability-drop failure appeared in this run: the supplied helper receives an
undefined `securityContext.capabilities.drop` for this manifest, so that rule
does not produce a message. I kept the supplied policy unchanged and report
the observed eight failures rather than assuming every intended check fired.

The same requirement needs separate rules because Compose stores settings under
`services`, while a Kubernetes Deployment nests them under
`spec.template.spec.containers` and uses different field names.
The Compose pass shows that these supplied settings satisfy the applicable
Compose checks and gives a positive control; it does not prove the application
is secure or that every possible policy defect has been tested.

### Add one deny rule and one warning

My [hardening.rego](../labs/lab9/policies/extra/hardening.rego) uses package
`k8s.extra`, which Conftest loads recursively with `--all-namespaces`:

```rego
package k8s.extra

# A version tag alone does not make an image reference immutable.
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not regex.match(`^.+@sha256:[a-fA-F0-9]{64}$`, object.get(c, "image", ""))
    msg := sprintf("container %q must pin its image with a SHA-256 digest", [c.name])
}

# Missing probes are already covered by k8s.security. Kubernetes defaults an
# omitted periodSeconds to 10; this check flags explicitly slow liveness checks.
warn contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    period := object.get(c.livenessProbe, "periodSeconds", 10)
    period > 30
    msg := sprintf("container %q livenessProbe.periodSeconds is %v; use at most 30", [c.name, period])
}
```

The deny rule requires a SHA-256 digest rather than a mutable tag. The warning
flags a liveness-probe interval above 30 seconds; omitted intervals use the
Kubernetes default of 10, and missing probes remain the shipped policy's
responsibility. Both messages name the affected container. These checks are
limited to the Deployment's regular containers, matching the supplied policy's
scope; they are not a complete validator for every Kubernetes workload type.

I copied the hardened fixture and changed only its resource names, image
reference to `bkimminich/juice-shop:v19.0.0`, and liveness interval from 20 to
60 seconds. The complete [violating manifest](../labs/lab9/manifests/k8s/juice-extra-violations.yaml)
is committed so the failure can be reproduced. It still passed all **30**
checks when tested against a local copy of only the shipped policies, confirming
that its new failures come from the extension.

```powershell
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-extra-violations.yaml --policy labs/lab9/policies --all-namespaces
```

Hardened result, exit **0**:

```text
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions
```

Deliberately violating result, exit **1**:

```text
WARN - labs/lab9/manifests/k8s/juice-extra-violations.yaml - k8s.extra - container "juice" livenessProbe.periodSeconds is 60; use at most 30
FAIL - labs/lab9/manifests/k8s/juice-extra-violations.yaml - k8s.extra - container "juice" must pin its image with a SHA-256 digest

34 tests, 32 passed, 1 warning, 1 failure, 0 exceptions
```

I also reran all supplied fixtures with the extension installed:

| Extended policy set / input | Total | Passed | Warnings | Failures | Exit |
|---|---:|---:|---:|---:|---:|
| Hardened Kubernetes | 34 | 34 | 0 | 0 | 0 |
| Unhardened Kubernetes | 34 | 23 | 2 | 9 | 1 |
| Compose | 17 | 17 | 0 | 0 | 0 |
| Deliberate extra violations | 34 | 32 | 1 | 1 | 1 |
| Digest violation only, local control | 34 | 33 | 0 | 1 | 1 |
| Slow liveness probe only, local control | 34 | 33 | 1 | 0 | 0 |

The separate controls show that each new rule works independently. A warning
alone does not fail Conftest by default; the combined fixture fails because
of its `deny`, not because warnings automatically block deployment.

For the immutable-image requirement I added, I would keep Conftest in CI if
I could have only one control, because it can reject a mutable image reference
before deployment. It can also point directly to an excessive probe interval
while the manifest is still being reviewed. Falco adds a different layer:
it observes what an accepted image actually does, including unexpected writes
or outbound connections after compromise. Neither the digest pin nor a healthy
probe proves that the running application will behave safely, and CI must be
mandatory to provide that pre-deployment gate.

## Bonus

### Detect a simulated mining connection

The second rule in [custom-rules.yaml](../labs/lab9/falco/rules/custom-rules.yaml)
combines a container's completed `connect` attempt, a common mining port, and
a process name from a small list (`xmrig`, `minerd`, `cpuminer`, `nc`, `ncat`).
It has priority `CRITICAL` and includes `mitre_command_and_control` in its tags.
Netcat is included as the lab simulator; a netcat connection alone is not proof
of mining, and this heuristic can also match legitimate diagnostic activity.

```yaml
- rule: Possible Container Mining Connection
  desc: Detect a miner-named process or the lab's netcat simulator connecting to a common mining port, including refused attempts.
  # A refused connect on this WSL2 kernel has no populated fd.sport; the
  # syscall's address argument still contains the attempted destination.
  condition: >-
    evt.type=connect and evt.dir=< and container.id != host
    and (fd.sport in (3333, 4444, 5555, 7777, 14444)
      or (evt.failed=true and
        (evt.arg.addr endswith :3333 or evt.arg.addr endswith :4444
         or evt.arg.addr endswith :5555 or evt.arg.addr endswith :7777
         or evt.arg.addr endswith :14444)))
    and proc.name in (xmrig, minerd, cpuminer, nc, ncat)
  output: Possible mining connection (container=%container.name process=%proc.name command=%proc.cmdline destination=%evt.arg.addr result=%evt.res)
  priority: CRITICAL
  tags: [container, network, mitre_command_and_control]
```

On this kernel, a refused connection had `fd.sport=null` and `fd.sip=null`,
while `evt.arg.addr` still contained `127.0.0.1:3333`. I therefore kept the
server-port check and added a fallback for failed events that checks the port
suffix in the syscall address. Both branches still require the process-name
signal; the fallback does not turn this into a port-only rule.

After SIGHUP and a five-second reload wait, I ran:

```powershell
docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'
Start-Sleep -Seconds 7
docker logs falco
```

Netcat exited with code **1** because the local port refused the connection.
Falco emitted this **Critical** alert:

```json
{
  "hostname": "e70fe137c9b9",
  "output": "2026-09-27T08:29:23.438933753+0000: Critical Possible mining connection (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 destination=127.0.0.1:3333 result=ECONNREFUSED) container_id=dc92bcda507c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "dc92bcda507c",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.res": "ECONNREFUSED",
    "evt.time.iso8601": 1790497763438933753,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.name": "nc"
  },
  "priority": "Critical",
  "rule": "Possible Container Mining Connection",
  "source": "syscall",
  "tags": [
    "container",
    "mitre_command_and_control",
    "network"
  ],
  "time": "2026-09-27T08:29:23.438933753Z"
}
```

Falco observes the syscall event when the `connect` attempt returns, including
its destination and `ECONNREFUSED` result. A completed syscall event does not
mean a successful TCP connection: no server or pool needs to accept it for the
rule to match. This places the observation at the kernel activity layer,
before any requirement for an application-level mining exchange.

Changing the port is almost free, and renaming the process is cheap too, so
neither signal in this simple rule is intrinsically expensive to evade.
For a miner seeking comparable throughput, hiding sustained compute use and
all communication with its controller or pool is harder, although throttling
and proxies can reduce those signals. I would correlate executable identity
and process ancestry with sustained CPU use, unexpected destinations, and
mining-protocol indicators where traffic is visible. That adds behavioral
evidence without treating one port or executable name as conclusive proof.

### Positive and negative runtime checks

These commands were run in one final observation window with the submitted
rules loaded; the table counts only the matching custom rule's alerts.

| Action inside `lab9-target` | Exit | Expected custom alert | Observed count |
|---|---:|---|---:|
| `echo test > /tmp/my-write.txt` | 0 | `Container Write Under Tmp` | 1 |
| `echo test > /var/tmp/my-write.txt` | 0 | None from the `/tmp` rule | 0 |
| `nc -w 2 127.0.0.1 3333` | 1 | `Possible Container Mining Connection` | 1 |
| `nc -w 2 127.0.0.1 3334` | 1 | None: port outside the list | 0 |
| `wget -T 2 -O /dev/null http://127.0.0.1:3333` | 1 | None: process outside the list | 0 |

The negative network controls exercise each signal independently, so the
positive result is not merely an alert on every outbound connection.

## Cleanup

After saving the evidence, I removed the two containers:

```powershell
docker rm -f falco lab9-target
```

The temporary diagnostic rule used to inspect connection fields was removed
before the final tests. Only the two intended Falco rules, the additional
Rego policy, the violating fixture, and this report are included in the PR.
