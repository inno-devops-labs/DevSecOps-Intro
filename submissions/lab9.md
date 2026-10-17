# Lab 9 — Runtime Detection and Policy as Code

Branch: `feature/lab9`. Executed on 2026-10-10. Task 1, the optional Task 2, and
the bonus are all done.

| Tool | Version | How it ran |
| --- | --- | --- |
| Falco | **0.43.1** (x86_64), modern BPF probe, `container@0.6.4` plugin | `falcosecurity/falco:0.43.1`, the 9.1 command as given |
| Kernel | `6.18.33.1-microsoft-standard-WSL2` | Docker Desktop's WSL2 VM on Windows 11 |
| Conftest | **v0.69.0** (OPA 1.19.0) | `openpolicyagent/conftest:v0.69.0` container, repository mounted at `/project` |
| Docker | Engine 29.7.2 | host |

Deliverables:

- `labs/lab9/falco/rules/custom-rules.yaml`: the 9.3 rule and the bonus rule
- `labs/lab9/policies/extra/hardening.rego`: the 9.5 policy
- `labs/lab9/policies/extra/violates-my-policy.yaml`: the manifest written to violate it

Raw Falco output from the final clean run is in `labs/lab9/falco/logs/`, which
is git-ignored.

### Where this run departs from the lab text

1. **Git Bash path conversion.** MSYS rewrites `/proc`, `/usr` and so on into
   `C:/Program Files/Git/...`. Every `docker` command ran with
   `MSYS_NO_PATHCONV=1`, and the rules mount used `$(pwd -W)`. Nothing else
   changed in the 9.1 command.
2. **Conftest ran from its official image**, as
   `docker run --rm -v "$(pwd -W)":/project -w /project openpolicyagent/conftest:v0.69.0 test ...`.
3. **The violating manifest lives in the repository**, at
   `labs/lab9/policies/extra/violates-my-policy.yaml`, not in `/tmp`, so the
   `git add labs/lab9/policies/extra/` in the Submit step picks it up. Conftest
   loads only `.rego` from `--policy`, so a YAML file there does not affect the
   policy set (the hardened run below still reports 34/34).
4. **`evt.dir` is deprecated in Falco 0.43.** The bonus hint suggests
   `evt.dir=<`. Falco 0.43 loads such a rule with `LOAD_DEPRECATED_ITEM`:
   *"due to the drop of enter events, 'evt.dir = <' always evaluates to true"*.
   I removed it.
5. **On a refused connection `fd.sport` is empty.** This changes how the bonus
   rule has to be written (see [Bonus](#bonus)).
6. **The shipped Rego has a bug.** "Drop ALL capabilities" can never fail when
   the key is missing, in both the Kubernetes and the Compose policy (see
   [Task 2](#a-ninth-failure-that-never-fires)).

## Task 1

### 9.1 Falco and the target

Falco reported `Opening 'syscall' source with modern BPF probe.` and the
expected WSL2 tracepoint warnings, one per syscall with a TOCTOU program
(`connect`, `creat`, `open`, `openat2`, `openat`):

```text
[libs]: libpman: failure while attaching TOCTOU mitigation program for 'openat' system call. Detection will continue to work, but TOCTOU mitigation may not properly work (errno: 2 | message: No such file or directory
```

`docker ps`: `falco: Up 11 seconds`, `lab9-target: Up 11 seconds`.

### 9.2 The two built-in rules

```text
      1 "rule":"Read sensitive file untrusted"
      1 "rule":"Terminal shell in container"
```

**`Terminal shell in container`** (Notice), triggered by
`docker exec -t lab9-target sh -lc 'echo hello-from-shell'`:

```text
2026-10-10T16:43:34.133898531+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=03937e041ac2 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>
```

The condition is `spawned_process and container and shell_procs and proc.tty != 0 and container_entrypoint`.
`terminal=34816` is device 136:0, which is `/dev/pts/0`, the pseudo-terminal that `-t` allocated.
As a control, `docker exec lab9-target sh -lc 'echo no-tty'` (no `-t`) left the
count at 1. `parent=<NA>` is expected for `docker exec`: runc starts the process
from outside the container and does not stay around. The shipped rule's own
`desc` warns that the parent "may have legitimately already exited and be null".

**`Read sensitive file untrusted`** (Warning), triggered by
`docker exec lab9-target sh -c 'cat /etc/shadow'`:

```text
2026-10-10T16:43:34.485444121+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=03937e041ac2 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>
```

The condition is `open_read and sensitive_files` with `cat` not in any of the
trusted-program lists (`shell_binaries`, `user_mgmt_binaries`, ...). It fires
without a terminal (`terminal=0`), so plain `docker exec` is enough.

### 9.3 The custom rule

```yaml
# open(O_TMPFILE) creates an unnamed file that can later be linkat()-ed into
# place. Falco reports the fd as the directory (fd.name=/tmp, fd.typechar=d),
# so open_write (which requires fd.typechar='f') never sees it.
- macro: open_write_tmpfile
  condition: >
    (evt.type in (open,openat,openat2) and evt.is_open_write=true
     and evt.arg.flags contains O_TMPFILE and fd.num>=0)

- rule: Write below tmp in container
  desc: >
    A file under /tmp/ was opened for writing by a process inside a container
    (not on the host), including unnamed O_TMPFILE files created in /tmp.
    Every match is runtime drift from the image; tune with per-image
    exceptions rather than by narrowing the path.
  condition: >
    container
    and ((open_write and fd.name startswith /tmp/)
         or (open_write_tmpfile and (fd.name = /tmp or fd.name startswith /tmp/)))
  output: >
    File below /tmp opened for writing in a container
    (container=%container.name user=%user.name uid=%user.uid file=%fd.name
    command=%proc.cmdline parent=%proc.pname flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, drift]
```

The core is what the lab asks for: the shipped `open_write` macro
(`evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0`),
the shipped `container` macro (`container.id != host`), and
`fd.name startswith /tmp/`.

**Why the `O_TMPFILE` branch.** The first version of the rule had only that
core. I tested it against Python's `tempfile` in a container and
`TemporaryFile()` produced no alert. A temporary debug rule showed why:

```text
tmpfile probe fd.name=/tmp typechar=d flags=O_LARGEFILE|O_DIRECTORY|O_EXCL|O_RDWR|O_CLOEXEC|O_TMPFILE|FD_UPPER_LAYER is_open_write=true res=SUCCESS
```

`O_TMPFILE` includes `O_DIRECTORY`, so Falco names the fd after the directory
and types it `d`. Both `fd.typechar='f'` and `startswith /tmp/` miss it. That
is a way to write content into `/tmp` without a named open-for-write, and
`linkat()` can give it a name afterwards. With the branch added, the same test
fires (`file=/tmp flags=...|O_TMPFILE|...`).

The 9.3 commands, run against a freshly started Falco:

```text
$ docker kill --signal=SIGHUP falco && sleep 5
falco
$ docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
$ sleep 6
$ docker logs falco 2>&1 | grep -c '"rule":"Write below tmp in container"'
1
```

The alert JSON:

```json
{
  "hostname": "f17e8cccf11f",
  "output": "2026-10-10T16:44:02.740018686+0000: Warning File below /tmp opened for writing in a container (container=lab9-target user=root uid=0 file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt parent=<NA> flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER) container_id=03937e041ac2 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "03937e041ac2",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER",
    "evt.time.iso8601": 1791650642740018686,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "proc.pname": null,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Write below tmp in container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-10-10T16:44:02.740018686Z"
}
```

`O_F_CREATED` and `FD_UPPER_LAYER` show that the shell created a new file in the
container's writable layer.

Two operational notes from getting here:

- **A reload leaves a gap with no detection.** Falco handles SIGHUP by checking the new rules
  in a dry run, logging `SIGHUP received, restarting...`, and rebuilding its
  engine inside the same process. One test that started six seconds after a
  SIGHUP produced no alerts at all, not even the file write that fires every
  other time. The post-restart rule load was stamped five seconds after the
  signal. After that I waited for a new `Opening 'syscall' source` line before
  each test. An attacker who can trigger rule reloads gets a few seconds in which Falco sees nothing.
- **`rule_matching: first` is the default in 0.43.** Files in `rules.d/` load
  after `falco_rules.yaml`, so if a shipped rule matches the same event first,
  a custom rule never fires for it. None of the events here hit that.

### A field that matters in an incident and is not in the message

**`hostname`**. The human-readable line has the container ID, name and image
but nothing that says *which machine* the event happened on. Container IDs and
names only make sense on one node, and pods get rescheduled. The evidence
(`/tmp/my-write.txt` in the container's upper layer, the process tree, the
node's own logs) lives on the node, and once the container is deleted the node
is the only place left to look. In this run the value is `f17e8cccf11f`, which
is **Falco's own container ID** (`docker ps`: `f17e8cccf11f falco`), because
Falco ran in Docker without a hostname override. In a cluster it must be set to
the node name. Falco 0.43.1 reads `FALCO_HOSTNAME` for this (the string is in
the binary), and the Helm chart fills it from `spec.nodeName`. `rule` and `tags`
are also missing from the message, but they classify the alert rather than
locate the evidence.

### Noise and tuning

A legitimate workload this flags: any Python service that buffers uploads or
intermediate files with `tempfile`, which is what Werkzeug and Django do with
large request bodies. One process in `semgrep/semgrep` running
`NamedTemporaryFile()` and `TemporaryFile()` raised **three** alerts:
`gettempdir()`'s writability probe (`/tmp/epauefo8`), the named file, and the
`O_TMPFILE` one. By contrast, 40 seconds of Juice Shop v20.0.0 starting up
raised none. To keep the detection and drop the noise, I would add exceptions
keyed on *who* writes, not *where*. I tested this override, which suppresses
only the image's own interpreter writing below `/tmp`:

```yaml
- rule: Write below tmp in container
  exceptions:
    - name: known_tmp_writers
      fields: [container.image.repository, proc.exepath, fd.directory]
      comps: [=, =, startswith]
      values:
        - [semgrep/semgrep, /usr/bin/python3.12, /tmp]
  override:
    exceptions: append
```

With it loaded, the Python `tempfile` run produced no alerts. In the same image,
`cp /usr/bin/python3.12 /tmp/kworkerds && /tmp/kworkerds -c 'open("/tmp/payload","w")...'`
still raised `Write below tmp` twice (the copy and the payload), and the shipped
`Drop and execute new binary in container` fired at Critical. The alpine write
also still fired. Mounting `/tmp` as a `noexec` tmpfs or emptyDir, as the
Compose file already does with `tmpfs: ["/tmp"]`, means the writes that remain
cannot be executed, so this rule can stay a low-priority audit signal while the
exec rules page someone. (The override was a temporary file and is not part of
the submitted rules.)

## Task 2

### 9.4 The shipped policies

```text
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
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
30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions        (exit 1)

$ conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies --all-namespaces
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

| Manifest | Tests | Passed | Warnings | Failures |
| --- | --- | --- | --- | --- |
| `juice-hardened.yaml` | 30 | 30 | 0 | 0 |
| `juice-unhardened.yaml` | 30 | 20 | 2 | 8 |
| `juice-compose.yml` | 15 | 15 | 0 | 0 |

Every failure and warning, mapped to `labs/lab9/policies/k8s-security.rego`:

| Result | Rule (line) | Condition that matched |
| --- | --- | --- |
| FAIL `uses disallowed :latest tag` | `deny`, L10 | `endswith(c.image, ":latest")`: the image is `bkimminich/juice-shop:latest` |
| FAIL `must set runAsNonRoot: true` | `deny`, L18 | `not c.securityContext.runAsNonRoot`: there is no `securityContext` at all |
| FAIL `must set allowPrivilegeEscalation: false` | `deny`, L25 | `not c.securityContext.allowPrivilegeEscalation == false` |
| FAIL `must set readOnlyRootFilesystem: true` | `deny`, L32 | `not c.securityContext.readOnlyRootFilesystem == true` |
| FAIL `missing resources.requests.cpu` / `.memory` | `deny`, L47 / L54 | `not c.resources.requests.cpu` / `.memory`: no `resources` block |
| FAIL `missing resources.limits.cpu` / `.memory` | `deny`, L61 / L68 | `not c.resources.limits.cpu` / `.memory` |
| WARN `should define readinessProbe` / `livenessProbe` | `warn`, L76 / L83 | `not c.readinessProbe` / `not c.livenessProbe` |

**Where the counts come from.** With `--all-namespaces` every document is
evaluated against both packages: 11 rules in `k8s.security` plus 4 in
`compose.security` makes 15 per document. The Kubernetes files hold two
documents (Deployment and Service), which gives 30. Of the hardened file's
"30 passed", only the 11 Kubernetes rules on the Deployment test anything. The
Service passes the 11 because every rule starts with
`input.kind == "Deployment"`, and all 8 Compose checks pass because
`input.services` is undefined.

### A ninth failure that never fires

The unhardened container has no `securityContext`, so it also does not drop
ALL capabilities, yet `container "juice" must drop ALL capabilities` (L39) is
absent from the output. The trace (`--namespace k8s.security --trace`) shows
why:

```text
TRAC   | | Eval __local41__ = c.securityContext.capabilities.drop
TRAC   | | Unify __local41__ = c.securityContext.capabilities.drop
TRAC   | | Fail __local41__ = c.securityContext.capabilities.drop
TRAC   | | Redo c = input.spec.template.spec.containers[_]
```

OPA moves the call argument out into its own expression *before* the `not`.
When the path is undefined, that expression fails, the body stops, and
`not has_value(...)` is never evaluated. So the rule only catches a `drop` list
that exists without `ALL`. A Deployment with `drop: ["NET_RAW"]` does fail it.
`compose-security.rego` has the same pattern twice. A bare service
(`image: nginx:1.27` and nothing else) gets only 2 of the 4 failures it
deserves, `user` and `read_only`:

```text
15 tests, 13 passed, 0 warnings, 2 failures, 0 exceptions
```

`cap_drop: ["NET_RAW"]` plus `security_opt: ["seccomp:unconfined"]` does
produce the cap_drop failure and the no-new-privileges warning. The fix is to
give the argument a default, for example
`not has_value(object.get(c, ["securityContext", "capabilities", "drop"], []), "ALL")`.
I left the shipped files unchanged so that the counts above match the lab, and
used `object.get` throughout my own policy.

### Compose versus Kubernetes

The same requirement needs its own rule per format because Rego matches on
document structure, not on meaning. "Drop all capabilities" is `services.*.cap_drop` in
Compose and `spec.template.spec.containers[].securityContext.capabilities.drop`
in Kubernetes, and "non-root" is `user: "10001:10001"` in one and
`runAsNonRoot: true` in the other. The Compose file passing tells you only that
none of the 4 Compose rules found a violation, and that is weak evidence. 11 of
its 15 passes are Kubernetes rules that cannot apply, and the rule above shows
two of the remaining four cannot fail when their key is missing. A pass only
means something once you have seen each rule fail on a fixture written to break
it. The Kubernetes run against the unhardened manifest is that fixture, and it
is what exposed the drop-ALL gap.

### 9.5 The extra policy

`labs/lab9/policies/extra/hardening.rego`:

```rego
package k8s.security

# Extra checks that join the shipped k8s.security package, so they run with
# either --all-namespaces or --namespace k8s.security.
#
# Differences from the shipped rules, on purpose:
#   - every pod-bearing kind is covered, not only Deployment
#   - initContainers are walked as well as containers
#   - missing keys go through object.get with a default. The shipped
#     `not has_value(c.securityContext.capabilities.drop, "ALL")` never fires
#     when the key is absent: OPA evaluates the undefined argument before the
#     `not`, and the whole rule body fails.

template_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in template_kinds

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

workload_containers contains c if {
  some c in object.get(pod_spec, "containers", [])
}

workload_containers contains c if {
  some c in object.get(pod_spec, "initContainers", [])
}

pinned_by_digest(image) if regex.match(`@sha256:[a-f0-9]{64}$`, image)

# Images must be pinned by digest. A tag is a mutable pointer (Lab 8): the
# shipped check only rejects a literal ":latest" suffix, so "nginx" (implicit
# latest) and any re-pushed version tag pass it.
deny contains msg if {
  some c in workload_containers
  image := object.get(c, "image", "")
  not pinned_by_digest(image)
  msg := sprintf("container %q image %q is not pinned by digest (@sha256:...)", [c.name, image])
}

# drop: ["ALL"] satisfies the shipped capability check even when add: lists
# capabilities right next to it. Some adds are legitimate (NET_BIND_SERVICE
# for a non-root process on port 80), so this warns and names what was added.
warn contains msg if {
  some c in workload_containers
  added := object.get(c, ["securityContext", "capabilities", "add"], [])
  count(added) > 0
  msg := sprintf("container %q adds capabilities back after dropping: %v", [c.name, added])
}
```

It joins `package k8s.security`, so the shipped rules and mine are one rule set
whichever way Conftest is invoked. The **deny** requires an `@sha256:` digest.
The **warn** catches capabilities added back. Both name the container.

`labs/lab9/policies/extra/violates-my-policy.yaml` is `juice-hardened.yaml` with
the image referenced by tag (`bkimminich/juice-shop:v19.0.0`), `add: ["NET_ADMIN"]`
next to `drop: ["ALL"]`, and a tag-referenced init container
(`busybox:1.36`, no `securityContext`). Full file in the repository.

The two runs:

```text
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions        (exit 0)

$ conftest test labs/lab9/policies/extra/violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
WARN - labs/lab9/policies/extra/violates-my-policy.yaml - k8s.security - container "juice" adds capabilities back after dropping: ["NET_ADMIN"]
FAIL - labs/lab9/policies/extra/violates-my-policy.yaml - k8s.security - container "init-wait" image "busybox:1.36" is not pinned by digest (@sha256:...)
FAIL - labs/lab9/policies/extra/violates-my-policy.yaml - k8s.security - container "juice" image "bkimminich/juice-shop:v19.0.0" is not pinned by digest (@sha256:...)
17 tests, 14 passed, 1 warning, 2 failures, 0 exceptions         (exit 1)
```

The same manifest against **only the shipped files** passes cleanly:
`15 tests, 15 passed, 0 warnings, 0 failures`. So the violations are exactly
the ones my rules add, including an init container that runs as root with
default capabilities, which the shipped rules never inspect. The Compose file
is still clean with the new rules (17/17). The unhardened manifest now fails 9
times, the new one being `image "bkimminich/juice-shop:latest" is not pinned by digest`.
A quick check on other kinds: a `Pod` with `image: nginx`, an implicit
`latest` that the shipped `:latest` check misses, is denied, and a `CronJob`
container that adds `SYS_ADMIN` gets the warning.

### Conftest or Falco for this control

For digest pinning I would keep Conftest. How a manifest references its image
is a fact about the manifest. It is fully known before deployment, cheap to
check, and the check blocks the deploy before any code runs. By the time Falco
sees a container started from a tag, the mutable tag has already been resolved
to whatever someone pushed, and that code is running. What the runtime side
still buys is coverage of everything that never passed through CI: a
`kubectl run` or `kubectl edit` straight against the cluster, a `docker run`
on a node, a Helm value overridden at install time. It also shows whether a granted
capability is actually *used*. For example, the shipped
`Packet socket created in container` rule fires on an `AF_PACKET` socket,
which only works with `NET_RAW`. No manifest check can tell you that. Conftest only covers files
that go through the pipeline, so in production the same Rego belongs in an
admission controller as well.

## Bonus

### The rule

```yaml
- list: miner_pool_ports
  items: [3333, 4444, 5555, 7777, 14444]

- list: miner_binaries
  items: [xmrig, xmr-stak, minerd, cpuminer, ccminer, cgminer, bfgminer,
          ethminer, t-rex, nbminer, lolminer, nanominer, srbminer]

- list: raw_tcp_clients
  items: [nc, ncat, netcat, socat, telnet]

- macro: connect_to_pool_port
  condition: >
    (evt.type = connect
     and (fd.typechar = 4 or fd.typechar = 6)
     and (fd.sport in (miner_pool_ports)
          or evt.arg.addr regex ".*:(3333|4444|5555|7777|14444)"))

- macro: miner_like_process
  condition: >
    (proc.name in (miner_binaries)
     or proc.name in (raw_tcp_clients)
     or proc.cmdline contains "stratum+tcp://"
     or proc.cmdline contains "stratum+ssl://"
     or proc.is_exe_upper_layer = true)

- rule: Possible cryptominer connecting to mining pool port
  desc: >
    A container process that looks like a miner (known miner name, raw TCP
    client, stratum URL in its arguments, or a binary dropped at runtime)
    attempted a connection to a common mining-pool port. Fires on the
    connect() result, so a refused or blocked attempt is reported too.
  condition: container and miner_like_process and connect_to_pool_port
  output: >
    Possible cryptominer connecting to a mining-pool port
    (container=%container.name container_id=%container.id
    image=%container.image.repository:%container.image.tag
    process=%proc.name exepath=%proc.exepath exe_upper_layer=%proc.is_exe_upper_layer
    command=%proc.cmdline parent=%proc.pname user=%user.name
    dest=%evt.arg.addr result=%evt.res connection=%fd.name)
  priority: CRITICAL
  tags: [container, network, mitre_command_and_control, mitre_impact, T1496]
```

Both signals are required: a connection to a pool port, **and** a process that
looks like a miner. Loopback is deliberately not excluded (the shipped
`outbound` macro drops `127.0.0.0/8`), because miners are often pointed at a
local stratum proxy.

**Why `evt.arg.addr` and not only `fd.sport`.** The first version used
`fd.sport in (miner_pool_ports)` as the hint suggests, and the lab command gave
`0`. A debug rule on the same `connect` showed:

```text
connect probe proc=nc res=ECONNREFUSED rawres=-111 fd=3 typechar=4 l4=<NA> name=0.0.0.0:0 sip=<NA> sport=<NA> ... args=res=-111(ECONNREFUSED) tuple=NULL fd=3(<4>0.0.0.0:0) addr=127.0.0.1:3333
```

On a refused blocking connect the kernel side returns `tuple=NULL`, so
`fd.sport`, `fd.sip` and `fd.l4proto` are all `<NA>`. The destination the
process asked for survives only in the syscall argument `addr`. Falco's `regex`
operator is a full match: `":(3333|...)$"` matched nothing and `".*:(4444|5555)"`
matched, which I checked with probe rules. `fd.sport` stays in the condition
for successful and non-blocking connects, where the tuple is filled in.

### The alert

```text
$ docker kill --signal=SIGHUP falco && sleep 5
falco
$ docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
$ sleep 6
$ docker logs falco 2>&1 | grep -c '"priority":"Critical"'
1
```

```json
{
  "hostname": "f17e8cccf11f",
  "output": "2026-10-10T16:44:15.007608522+0000: Critical Possible cryptominer connecting to a mining-pool port (container=lab9-target container_id=03937e041ac2 image=alpine:3.20 process=nc exepath=/bin/busybox exe_upper_layer=false command=nc -w 2 127.0.0.1 3333 parent=<NA> user=root dest=127.0.0.1:3333 result=ECONNREFUSED connection=0.0.0.0:0) container_id=03937e041ac2 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "03937e041ac2",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.res": "ECONNREFUSED",
    "evt.time.iso8601": 1791650655007608522,
    "fd.name": "0.0.0.0:0",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.exepath": "/bin/busybox",
    "proc.is_exe_upper_layer": false,
    "proc.name": "nc",
    "proc.pname": null,
    "user.name": "root"
  },
  "priority": "Critical",
  "rule": "Possible cryptominer connecting to mining pool port",
  "source": "syscall",
  "tags": ["T1496", "container", "mitre_command_and_control", "mitre_impact", "network"],
  "time": "2026-10-10T16:44:15.007608522Z"
}
```

Each signal was also tested on its own, with nothing listening anywhere unless
stated:

| # | Command (container) | Expected | Result |
| --- | --- | --- | --- |
| 1 | `nc -w 2 127.0.0.1 3333` (alpine) | fire | Critical, `ECONNREFUSED`, `connection=0.0.0.0:0` |
| 2 | `nc -w 2 127.0.0.1 8080` (alpine) | silent: suspicious tool, wrong port | no alert |
| 3 | `nc -l -p 3333 &` then `nc 127.0.0.1 3333` (alpine) | fire | Critical, `SUCCESS`, `connection=127.0.0.1:33817->127.0.0.1:3333` |
| 4 | `python3 fakeminer.py` connecting to `:3333` (semgrep image) | silent: right port, ordinary process | no alert |
| 5 | same, with `-o stratum+tcp://127.0.0.1:3333 -u WALLET` in argv | fire | Critical, `EINPROGRESS` (non-blocking, tuple filled) |
| 6 | `cp python3 /tmp/kworkerds && /tmp/kworkerds fakeminer.py` | fire | Critical with `exe_upper_layer=true`, plus `Write below tmp` (the copy) and the shipped `Drop and execute new binary in container` (Critical) |

Case 6 is closest to a real dropper: one renamed miner produced three
independent alerts. A side effect for the lab's check is that
`grep -c '"priority":"Critical"'` also counts shipped Critical rules, so it is
not specific to this rule.

### Why a refused connection is enough

Falco does not watch the network. It watches syscalls, through eBPF programs
in the host kernel underneath every container. `connect()` is the process
telling the kernel "take me to 127.0.0.1:3333". Falco records that request,
its arguments and the return value whether or not a packet ever gets an
answer. The refusal is just `res=ECONNREFUSED` on an event that was already
captured, and the intent is in `addr`. This means Falco sits *in front of* every
network control. It still reports a miner whose egress is blocked by a
NetworkPolicy, an egress firewall or a dead pool, and those attempts never
appear as completed flows anywhere else. The same position has limits. Falco
sees what the process passed to the kernel, not the bytes on the wire, so it
cannot recognise the stratum protocol, and TLS to the pool would hide it anyway.
And on failure even the kernel's socket tuple is empty, which is why the rule
reads the syscall argument.

### Evasion

Changing the port is free: pool operators and stratum proxies listen on 443 or
any port the attacker likes. Renaming the binary (`kworkerds`) and moving the
pool URL from argv into `config.json` are just as free, so four of my five
process signals cost nothing to defeat. The expensive part is
`proc.is_exe_upper_layer`. To avoid it the miner must already be in the image,
which means getting it through the build, the registry and signature checks
from Lab 8. Or it must run filelessly, which the shipped
`Fileless execution via memfd_create` rule targets, or be written in an
interpreter the image already ships. The truly expensive thing to evade is the
economics: a miner has to burn CPU continuously and keep talking to a pool. To
catch the evasion I would alert on any outbound connection from workloads that
have no egress baseline, regardless of port, and enforce default-deny egress
NetworkPolicies so that those attempts are refused and logged by this
syscall-level rule. I would also alert on sustained CPU at the container's limit
from cgroup metrics, which no renaming defeats. The hardened manifest's
`limits.cpu: 500m` already caps how much a miner can earn.
