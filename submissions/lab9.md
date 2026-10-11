# Lab 9 — Runtime Detection and Policy as Code

## Task 1

### 1. Setup

Falco `falcosecurity/falco:0.43.1` was started with the lab's exact command (privileged, `-U`, JSON output, ISO-8601 time, `labs/lab9/falco/rules` mounted read-only at `/etc/falco/rules.d`). It runs on kernel `7.0.0-38-generic` with the modern eBPF probe:

```
Enabled event sources: syscall
Opening 'syscall' source with modern BPF probe.
libpman: failure while attaching TOCTOU mitigation program for 'connect' system call. Detection will continue to work, but TOCTOU mitigation may not properly work (errno: 2 | message: No such file or directory)
```

The TOCTOU warnings (`connect`, `creat`, `open`, `openat`, `openat2`) are the expected ones. This kernel has no `sys_enter_*` tracepoints for those syscalls, and detection still works. The target is `alpine:3.20` running `sleep 1d` as `lab9-target`. Every alert below is also saved, one JSON object per line, in `labs/lab9/falco/logs/falco-alerts.jsonl`.

### 2. The two built-in rules (9.2)

```
$ docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
      1 "rule":"Read sensitive file untrusted"
      1 "rule":"Terminal shell in container"
```

**`Terminal shell in container`** (Notice), triggered by `docker exec -t lab9-target sh -lc 'echo hello-from-shell'`:

```
2026-10-11T13:24:08.733776528+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=f331e09a1a4f container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>
```

The trigger was an `execve` of a shell (`shell_procs`) inside a container, with a TTY attached (`proc.tty != 0`, here `terminal=34816`) and launched as the container's entry point by `containerd-shim`. `-t` is what makes it fire: the same command without a TTY doesn't match `proc.tty != 0`.

**`Read sensitive file untrusted`** (Warning), triggered by `docker exec lab9-target sh -c 'cat /etc/shadow'`:

```
2026-10-11T13:24:08.777080028+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=f331e09a1a4f container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>
```

The trigger was an `open` for reading of a file in the `sensitive_file_names` list (`/etc/shadow`) by `cat`. `cat` isn't one of the programs trusted to read it (`sshd`, `login`, PAM helpers and similar).

### 3. My rule (9.3)

`labs/lab9/falco/rules/custom-rules.yaml`, the `/tmp` rule:

```yaml
- rule: Write below tmp in container
  desc: >
    A file under /tmp was opened for writing from inside a container. Containers
    built from an immutable image should not need scratch files; a write here is
    often the first step of dropping a payload (container drift).
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    File below /tmp opened for writing in a container
    (container=%container.name image=%container.image.repository:%container.image.tag
    user=%user.name uid=%user.uid file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

`open_write` is the shipped macro (`evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0`). `container.id != host` is the same test as the shipped `container` macro. I spelled it out because the lab names that field. After `docker kill --signal=SIGHUP falco`, the reload log showed `/etc/falco/rules.d/custom-rules.yaml | schema validation: ok`.

```
$ docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
$ docker logs falco 2>&1 | grep -c '"rule":"Write below tmp in container"'
1
```

```json
{
  "hostname": "fcc47d739556",
  "output": "2026-10-11T13:25:03.540164777+0000: Warning File below /tmp opened for writing in a container (container=lab9-target image=alpine:3.20 user=root uid=0 file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=f331e09a1a4f container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "f331e09a1a4f",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791725103540164777,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Write below tmp in container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-10-11T13:25:03.540164777Z"
}
```

### 4. A field that matters in an incident but isn't in the message

**`hostname`** (`"fcc47d739556"`). It tells you *which Falco sensor, and so which node*, saw the event. The human-readable line names the container but not the machine it ran on. With one laptop that doesn't matter. With a fleet of nodes it's the first thing you need in order to isolate the right host or pull its other logs. In this lab the value is the Falco container's own ID, because Falco runs in Docker and not on the host. In production you would set it to the node name. A close second is **`tags`**: on the `/etc/shadow` alert it carries `["T1555", "mitre_credential_access", …]`. That MITRE mapping drives routing and correlation in a SIEM, and it isn't in the message either.

### 5. Noise: a legitimate workload this rule flags

Every **JVM** container trips it on start-up: HotSpot writes `/tmp/hsperfdata_<user>/<pid>` for `jps`/`jstat` unless started with `-XX:-UsePerfData`. Python's `tempfile`, Node upload middleware (`multer`), `pip install` and most package managers do the same. On a real cluster this rule would fire thousands of times an hour and get ignored. To keep the detection and drop the noise, I would add Falco `exceptions:` keyed on **image + path prefix** (for example `container.image.repository = eclipse-temurin` with `fd.name startswith /tmp/hsperfdata_`), so each known writer is allowed only its own path. I would also lower this rule to INFO as an audit signal, and raise severity only when a `/tmp` write is followed by an `execve` of that file. The shipped `Drop and execute new binary in container` rule (seen in the Bonus) already covers that, at Critical. The structural fix is Lab 7's: `readOnlyRootFilesystem: true` plus an explicit `emptyDir` for `/tmp`. Then writes to anywhere else fail outright, and the rule can be narrowed to the few writable paths that are actually declared.

## Task 2

### 1. Counts for the shipped policies (9.4)

conftest 0.69.0 (OPA 1.19.0), `--policy labs/lab9/policies --all-namespaces`, before I added my policy:

| File | Tests | Passed | Warnings | Failures | Exit |
| ---- | ----: | -----: | -------: | -------: | ---: |
| `k8s/juice-hardened.yaml` | 30 | 30 | 0 | 0 | 0 |
| `k8s/juice-unhardened.yaml` | 30 | 20 | 2 | 8 | 1 |
| `compose/juice-compose.yml` | 15 | 15 | 0 | 0 | 0 |

The 8 failures and 2 warnings on `juice-unhardened.yaml` map to `labs/lab9/policies/k8s-security.rego` as follows:

| conftest message | Rego rule |
| ---------------- | --------- |
| `container "juice" uses disallowed :latest tag` | `deny` with `endswith(c.image, ":latest")` (the "No :latest tags" block) |
| `container "juice" must set runAsNonRoot: true` | `deny` with `not c.securityContext.runAsNonRoot` |
| `container "juice" must set allowPrivilegeEscalation: false` | `deny` with `not c.securityContext.allowPrivilegeEscalation == false` |
| `container "juice" must set readOnlyRootFilesystem: true` | `deny` with `not c.securityContext.readOnlyRootFilesystem == true` |
| `missing resources.requests.cpu` / `requests.memory` / `limits.cpu` / `limits.memory` | the four `deny` rules with `not c.resources.<requests\|limits>.<cpu\|memory>` |
| `should define readinessProbe` / `livenessProbe` (WARN) | the two `warn` rules with `not c.readinessProbe` / `not c.livenessProbe` |

Two of them in detail. `:latest` fails because the manifest has `image: bkimminich/juice-shop:latest` and the first `deny` rule matches the suffix. `runAsNonRoot` fails because the container has no `securityContext` at all: `c.securityContext.runAsNonRoot` is undefined, and `not undefined` is true.

**A ninth failure that should be there and isn't.** The shipped policy also has `deny … not has_value(c.securityContext.capabilities.drop, "ALL")`, and the unhardened container drops nothing, yet that rule stays silent. The cause is that `has_value()` is called with an **undefined argument**. In Rego, a call with an undefined argument is itself undefined, and the rule body stops before the `not` can apply. So the rule only fires when a `drop` list *exists* without `ALL`. I confirmed this with probe manifests. A container with `capabilities: {drop: [NET_RAW]}` fails with `must drop ALL capabilities`. Containers with no `securityContext`, with `securityContext` but no `capabilities`, and with `capabilities: {add: [NET_ADMIN]}` all pass this check silently. `compose-security.rego` has the same pattern (`not has_value(svc.cap_drop, "ALL")`).

### 2. Compose vs. Kubernetes, and what a pass means

The same requirement needs a separate rule for each format because the two inputs share no schema. Kubernetes nests it as `spec.template.spec.containers[].securityContext.capabilities.drop`, while Compose puts it at `services.<name>.cap_drop`, `read_only` and `user`, and a Rego rule can only test fields at paths it names.

The Compose file passing all 15 checks tells you only that *none of these four rules fired*, not that the service is hardened. I checked this with a Compose service that sets `user: "root"`, `privileged: true`, `image: …:latest` and no `cap_drop` at all. It also gets `15 tests, 15 passed, 0 warnings, 0 failures`: `not svc.user` is satisfied by any user, root included, nothing looks at `privileged` or the tag, and the `cap_drop` check has the undefined-argument hole from above. A policy is only as good as the bad inputs it has been tested against. That's why the Kubernetes pair (one passing, one failing) is more informative than a single green Compose run.

### 3. My policy (9.5)

`labs/lab9/policies/extra/hardening.rego`:

```rego
package k8s.hardening

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

all_containers contains c if {
  workload_kinds[input.kind]
  c := input.spec.template.spec.containers[_]
}

all_containers contains c if {
  workload_kinds[input.kind]
  c := input.spec.template.spec.initContainers[_]
}

deny contains msg if {
  c := all_containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest (image@sha256:...), got %q", [c.name, c.image])
}

warn contains msg if {
  c := all_containers[_]
  added := object.get(c, ["securityContext", "capabilities", "add"], [])
  count(added) > 0
  msg := sprintf("container %q adds Linux capabilities %v; justify each or remove them", [c.name, added])
}
```

- **deny, image pinned by digest.** The shipped policy only bans `:latest`, so `:v20.0.0` or no tag at all would pass. As Lab 8 showed, any tag can be re-pointed, so only `@sha256:` names the bytes that actually run.
- **warn, capabilities added back.** `drop: ["ALL"]` followed by `add: ["SYS_ADMIN"]` satisfies the shipped "drop ALL" check, but it puts the dangerous privileges right back.

Both rules also walk `initContainers`, which the shipped policy ignores, and they cover the other workload kinds. The package name `k8s.hardening` is picked up by `--all-namespaces` next to `k8s.security`. The `object.get(…, [])` default is there so the warn rule can't fall into the undefined-argument hole described above.

The manifest I wrote to violate it is otherwise compliant with the shipped policy (run as non-root, no privilege escalation, read-only rootfs, drop ALL, resources set, both probes):

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
      initContainers:
        - name: seed
          image: busybox:1.36
          command: ["sh", "-c", "true"]
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      containers:
        - name: juice
          image: bkimminich/juice-shop:v20.0.0
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
              add: ["NET_ADMIN", "SYS_PTRACE"]
          resources:
            requests: { cpu: "100m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          ports:
            - containerPort: 3000
          readinessProbe:
            httpGet: { path: /, port: 3000 }
          livenessProbe:
            httpGet: { path: /, port: 3000 }
```

Both runs:

```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions
exit=0

$ conftest test violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
WARN - violates-my-policy.yaml - k8s.hardening - container "juice" adds Linux capabilities ["NET_ADMIN", "SYS_PTRACE"]; justify each or remove them
FAIL - violates-my-policy.yaml - k8s.hardening - container "juice" must pin its image by digest (image@sha256:...), got "bkimminich/juice-shop:v20.0.0"
FAIL - violates-my-policy.yaml - k8s.hardening - container "seed" must pin its image by digest (image@sha256:...), got "busybox:1.36"
18 tests, 15 passed, 1 warning, 2 failures, 0 exceptions
exit=1
```

All the shipped `k8s.security` checks pass on this manifest, so every finding comes from `k8s.hardening`. Neither image uses `:latest`, so the shipped tag rule is happy with both, and the `add` list sits next to a valid `drop: ["ALL"]`. With my policy loaded, the other files give: `juice-unhardened.yaml` 34 tests, 23 passed, 2 warnings, **9** failures (the extra one is `must pin its image by digest, got "bkimminich/juice-shop:latest"`), and `juice-compose.yml` 17 tests, 17 passed. My rules don't apply to Compose input because of the `workload_kinds` guard.

### 4. CI or runtime, if I could keep only one

For these two controls I would keep **Conftest in CI**. Digest pinning and added capabilities are properties of the manifest, fully decided before anything runs, and they can be checked exactly, cheaply and with no false positives. Refusing the merge also means the unpinned image never runs at all, while a runtime rule could only tell me afterwards that something already ran. Falco still buys what CI can't see. CI only sees manifests that went through CI: a `kubectl apply` or `kubectl edit` straight from a laptop, a Helm `--set` override, or a tag re-pointed in the registry after the review all bypass the pipeline. And capabilities that are *used* at runtime show up only as syscalls. In practice the gap is closed by running the same Rego at admission (Gatekeeper/Kyverno) and keeping Falco as the detector for whatever got through anyway.

## Bonus

### 1. The rule and its alert

Added to `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- list: mining_pool_ports
  items: [3333, 4444, 5555, 7777, 14444]

- list: miner_and_tunnel_procs
  items: [xmrig, xmr-stak, minerd, cpuminer, cgminer, bfgminer, ethminer, t-rex, nbminer, nc, ncat, netcat, socat]

- macro: mining_pool_destination
  condition: >
    (fd.sport in (mining_pool_ports)
     or evt.arg.addr endswith ":3333"
     or evt.arg.addr endswith ":4444"
     or evt.arg.addr endswith ":5555"
     or evt.arg.addr endswith ":7777"
     or evt.arg.addr endswith ":14444")

- rule: Possible cryptominer outbound connection
  desc: >
    A process in a container attempted a connection to a port typically used by
    mining pools (stratum), and the process is either a known miner/tunnel binary
    or carries stratum arguments on its command line. Matches the connect() exit
    event whatever its result, so a refused or failed attempt still counts. The
    port is read from the syscall's own addr argument as well as the socket
    tuple, because a refused connect() leaves the tuple empty.
  condition: >
    evt.type = connect
    and container.id != host
    and mining_pool_destination
    and (proc.name in (miner_and_tunnel_procs)
         or proc.cmdline contains "stratum+tcp"
         or proc.cmdline contains "--donate-level")
  output: >
    Possible cryptominer connection from container
    (container=%container.name image=%container.image.repository:%container.image.tag
    process=%proc.name exepath=%proc.exepath command=%proc.cmdline parent=%proc.pname
    destination=%evt.arg.addr socket=%fd.name result=%evt.res user=%user.name)
  priority: CRITICAL
  tags: [container, network, mitre_command_and_control, mitre_impact, T1496]
```

It combines two signals: a connection to a stratum pool port, **and** a miner/tunnel process name or a stratum-style command line.

Two things differ from the hints, and both come from what Falco 0.43.1 actually did:

- **`evt.dir = <` is gone.** On reload Falco rejected it as deprecated: `LOAD_DEPRECATED_ITEM (Used deprecated item: field 'evt.dir'): due to the drop of enter events, 'evt.dir = <' always evaluates to true`. Falco 0.43 only produces exit events, so `evt.type = connect` already means "the completed attempt".
- **The port comes from `evt.arg.addr` as well as `fd.sport`.** The first version used only `fd.sport` and never fired. A temporary debug rule (removed afterwards) showed why. On a *refused* connect the socket tuple stays empty, and the destination exists only in the syscall argument:
  ```
  proc=nc args=[res=-111(ECONNREFUSED) tuple=NULL fd=3(<4>0.0.0.0:0) addr=127.0.0.1:3333] addr=127.0.0.1:3333 fdname=0.0.0.0:0 sport=<NA>
  ```
  `fd.sport` still covers successful connections, where the tuple is filled in.

The alert:

```
$ docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
$ docker logs falco 2>&1 | grep -c '"priority":"Critical"'
1
```

```json
{
  "hostname": "fcc47d739556",
  "output": "2026-10-11T13:27:02.788787369+0000: Critical Possible cryptominer connection from container (container=lab9-target image=alpine:3.20 process=nc exepath=/bin/busybox command=nc -w 2 127.0.0.1 3333 parent=containerd-shim destination=127.0.0.1:3333 socket=0.0.0.0:0 result=ECONNREFUSED user=root) container_id=f331e09a1a4f container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "f331e09a1a4f",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.res": "ECONNREFUSED",
    "evt.time.iso8601": 1791725222788787369,
    "fd.name": "0.0.0.0:0",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.exepath": "/bin/busybox",
    "proc.name": "nc",
    "proc.pname": "containerd-shim",
    "user.name": "root"
  },
  "priority": "Critical",
  "rule": "Possible cryptominer outbound connection",
  "source": "syscall",
  "tags": ["T1496", "container", "mitre_command_and_control", "mitre_impact", "network"],
  "time": "2026-10-11T13:27:02.788787369Z"
}
```

Negative checks: `nc -w 2 127.0.0.1 8080` (wrong port) and `wget http://127.0.0.1:3333/` (right port, process not on the list) both produced **no** Critical alert.

### 2. Why a refused connection is enough

Falco doesn't watch the network. It watches the **`connect()` system call** in the kernel, through eBPF on the syscall exit. The decision to contact a pool, the process that made it and the destination address are all known the moment the process calls `connect()`, whether a server answers or not: `result=ECONNREFUSED` is just the return value of that syscall. So Falco sits **inside the host kernel, on the workload's side of every connection**. It sees intent, not traffic. It needs no listening pool and no packet capture, it sees a connection that a firewall or NetworkPolicy then blocks, and it sees it before any TLS starts, so encrypted stratum makes no difference.

### 3. Evasion: cheap vs. expensive

Changing the **port is free** (pools listen on 443 and 80 as well), and so is the **process name**. I tested this: `cp /bin/busybox /tmp/busybox && /tmp/busybox nc -w 2 127.0.0.1 3333` makes the same connection as process `busybox`, and my mining rule stays silent. What's **expensive to evade** is everything the miner can't avoid doing. It has to get a binary into the container and run it, and that same command set off `Write below tmp in container` (`cp /bin/busybox /tmp/busybox`) and the shipped `Drop and execute new binary in container` (Critical, `exe_flags=EXE_WRITABLE|EXE_UPPER_LAYER`, `proc_exe=/tmp/…`). It also has to burn CPU for as long as it runs, and it has to keep a long-lived outbound connection to a host outside the cluster. To catch the evasion I would make those my main signals:

- alert on any `execve` from the container's upper layer or from `/tmp`/`/dev/shm` (drift);
- alert on any outbound connection from a workload that should have no egress, on *any* port (Lab 7's NetworkPolicy makes "should have no egress" an explicit fact);
- check resolved pool domains and IPs against a threat-intel list;
- correlate with sustained CPU at the limit from metrics.

Port and process name then stay only as cheap, high-confidence signals.
