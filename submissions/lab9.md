# Lab 9 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (Falco built-ins + custom `/tmp` rule) · Task 2 (Conftest + custom Rego) · **Bonus Task** (cryptominer rule, +2 pts)

## Environment

| Item | Value |
|------|-------|
| Host | macOS + Docker Desktop (linuxkit 6.12) |
| Falco | `falcosecurity/falco:0.43.1` (privileged; `/boot` mount omitted — Docker Desktop blocks host `/boot`) |
| Conftest | 0.70.1 (Homebrew; lab cites 0.69.x — behaviour matches) |
| Target | `alpine:3.20` container `lab9-target` |

## Task 1

### Built-in rules from 9.2

```bash
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
docker exec lab9-target sh -c 'cat /etc/shadow'
```

| Rule | Priority | Trigger |
|------|----------|---------|
| `Terminal shell in container` | Notice | `docker exec -t` spawned `sh -lc echo hello-from-shell` with an attached TTY (`proc.tty=34816`) |
| `Read sensitive file untrusted` | Warning | `cat /etc/shadow` opened `/etc/shadow` from a non-trusted program |

Alert (terminal) — abbreviated JSON:

```json
{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "output": "A shell was spawned in a container with an attached terminal | … process=sh … command=sh -lc echo hello-from-shell … container_name=lab9-target …",
  "output_fields": {
    "container.name": "lab9-target",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "proc.tty": 34816,
    "user.name": "root"
  }
}
```

Alert (sensitive file):

```json
{
  "rule": "Read sensitive file untrusted",
  "priority": "Warning",
  "output": "Sensitive file opened for reading by non-trusted program | file=/etc/shadow … command=cat /etc/shadow … container_name=lab9-target …",
  "output_fields": {
    "fd.name": "/etc/shadow",
    "proc.cmdline": "cat /etc/shadow",
    "container.id": "002973cec461"
  }
}
```

### Custom rule — write under `/tmp`

[`labs/lab9/falco/rules/custom-rules.yaml`](../labs/lab9/falco/rules/custom-rules.yaml) uses the shipped `open_write` macro (`evt.type in (open,openat,openat2) and evt.is_open_write=true …`), requires `container.id != host`, and `fd.name startswith /tmp/`.

After `SIGHUP` (rules already mounted) and:

```bash
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
```

Alert JSON (proof it fired on `lab9-target`):

```json
{
  "rule": "Container Write Under Tmp",
  "priority": "Warning",
  "output": "Container opened a temporary file for writing (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) …",
  "output_fields": {
    "container.id": "002973cec461",
    "container.name": "lab9-target",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root"
  },
  "tags": ["container", "drift"]
}
```

**Incident-relevant field not in the human message alone:** `container.id` (and image repository/tag in `output_fields`). The readable line names the container, but the ID is what you correlate with `docker inspect`, audit logs, and orchestration UUIDs when names collide or are recycled.

### Noise from a broad `/tmp` rule

This rule fires on every container write under `/tmp`. A legitimate workload it flags constantly here is a Node/code-server style IDE container writing Rosetta/temp files under `/tmp/rosetta.*` (hundreds of alerts in minutes). To keep detection and drop noise: scope by image or name allow-list (`container.image.repository`), ignore known temp prefixes, raise priority only when the writer is an unexpected process (shell/`curl`/`wget` rather than the app’s runtime), or require a second signal (new executable dropped + write). Start narrow in prod; widen after baselines.

## Task 2

### Conftest counts

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies --all-namespaces
```

| Target | Result summary |
|--------|----------------|
| `juice-hardened.yaml` (shipped + `k8s.extra`) | **34** tests, **34** passed, 0 warn, 0 fail |
| `juice-unhardened.yaml` (shipped only) | **22** tests, 12 passed, **2** warn, **8** fail |
| `juice-unhardened.yaml` (shipped + `k8s.extra`) | **34** tests, 23 passed, **2** warn, **9** fail (+ digest deny) |
| `juice-compose.yml` | **17** tests, **17** passed |

(Lab brief’s “30 / 8+2 / 15” is the shipped policy alone on this tree’s older count; with Conftest 0.70 and our `k8s.extra` package the totals above are what this run produced. Shipped-only unhardened still shows **8 failures + 2 warnings**.)

Two failures mapped to Rego in `k8s-security.rego`:

| Failure message | Rule |
|-----------------|------|
| `container "juice" uses disallowed :latest tag` | `deny` on `endswith(c.image, ":latest")` |
| `container "juice" must set runAsNonRoot: true` | `deny` on `not c.securityContext.runAsNonRoot` |

**Compose vs Kubernetes:** the same control (e.g. no privileged, resource limits) lives in different document shapes — Compose uses `services.*.*` while Kubernetes uses `spec.template.spec.containers[_]` — so each needs its own Rego package. **Compose passing** means the Compose policy matches this file and the checks fire green; it does not prove the Kubernetes policy is correct, only that a green path exists for the Compose dialect.

### Custom policy (`k8s.extra`)

[`labs/lab9/policies/extra/hardening.rego`](../labs/lab9/policies/extra/hardening.rego):

- **deny:** image must match `@sha256:<64 hex>`
- **warn:** `livenessProbe.periodSeconds > 30`

Hardened run: pass (digest pin + period 20). Violating manifest [`labs/lab9/manifests/k8s/violates-extra.yaml`](../labs/lab9/manifests/k8s/violates-extra.yaml) (tag-only image + `periodSeconds: 60`):

```text
FAIL - … k8s.extra - container "juice" must pin its image with a SHA-256 digest
WARN - … k8s.extra - container "juice" livenessProbe.periodSeconds is 60; use at most 30
17 tests, 15 passed, 1 warning, 1 failure
```

### Conftest vs Falco for this control

If I could keep only one for **image digest pinning**, I would keep **Conftest in CI**: it blocks the bad manifest before anything runs, costs nothing at runtime, and digests are a deploy-time property. Falco still buys you detection when someone bypasses CI (manual `kubectl`, broken pipeline, or a running container that later downloads a tagged image and execs it) — runtime is the backstop for process, not for “what we intended to ship.”

## Bonus

### Mining rule + alert

Same file, rule `Possible Container Mining Connection`: `evt.type=connect` + `evt.dir=<`, container context, pool ports **or** failed connect whose `evt.arg.addr` ends with those ports, and process name in `(xmrig, minerd, cpuminer, nc, ncat)`. Priority **CRITICAL**, tags include `mitre_command_and_control`.

```bash
docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
```

```json
{
  "rule": "Possible Container Mining Connection",
  "priority": "Critical",
  "output": "Possible mining connection (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 destination=127.0.0.1:3333 … result=ECONNREFUSED) …",
  "output_fields": {
    "proc.name": "nc",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.res": "ECONNREFUSED",
    "container.name": "lab9-target"
  },
  "tags": ["container", "mitre_command_and_control", "network"]
}
```

### Why a refused connection is enough

Falco sits on **syscalls** (eBPF), not on successful sockets. The `connect` attempt is visible whether the peer accepts or returns `ECONNREFUSED`. That implies detection is on the **host kernel’s view of the container**, before application-layer success — you do not need a live pool.

### Evading the rule

Changing the **port** is cheap (pick 3334). Renaming the binary is also cheap (`cp nc /tmp/x`). What is expensive: avoiding any connect-like syscall to a mining endpoint while still mining, or blending into a process name and destination that look like normal app traffic. I would add destination reputation / DNS for known pool domains, CPU anomaly correlation, andalert on unexpected outbound from images that should be offline-only.

## Cleanup

`docker rm -f falco lab9-target`
