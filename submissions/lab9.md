# Lab 9 Submission — Runtime Detection and Policy as Code

**Git identity:** `shnupel <ufamail.com2@gmail.com>`  
**Branch:** `lab9`

## Task 1

### Falco setup

Falco 0.43.1 and the target container were started with Docker. The Docker Desktop LinuxKit kernel reported the expected missing tracepoints for TOCTOU mitigation; Falco continued running and detected syscall events.

The lab command included `/boot`, but Docker Desktop rejected that mount because `/boot` is not shared from macOS. I reran Falco without that read-only mount. Falco loaded `labs/lab9/falco/rules/custom-rules.yaml` successfully and reported the TOCTOU warning described in the lab.

### Built-in detections

The TTY shell command was:

```bash
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
```

It produced the built-in `Terminal shell in container` alert:

```json
{"priority":"Notice","rule":"Terminal shell in container","output_fields":{"container.name":"lab9-target","proc.cmdline":"sh -lc echo hello-from-shell","proc.tty":34816,"user.name":"root"}}
```

The sensitive-file command was:

```bash
docker exec lab9-target sh -c 'cat /etc/shadow'
```

It produced the built-in `Read sensitive file untrusted` alert:

```json
{"priority":"Warning","rule":"Read sensitive file untrusted","output_fields":{"container.name":"lab9-target","fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.name":"cat","user.name":"root"}}
```

The full JSON alert lines are in `labs/lab9/falco/logs/after-builtins.log`.

One incident-relevant field that is not in the human-readable `output` is `container.id`. It identifies the exact container instance, even when a container name is reused after restart. Other useful structured fields include `evt.time.iso8601`, `proc.exepath`, and `user.uid`.

### Custom `/tmp` write rule

The rule is in `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Container writes below tmp
  desc: Detect a process writing a file below /tmp inside a container.
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: "container=%container.name user=%user.name file=%fd.name command=%proc.cmdline"
  priority: WARNING
  tags: [container, drift]
```

After reloading with `SIGHUP`, I triggered it with:

```bash
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
```

The alert JSON was:

```json
{"priority":"Warning","rule":"Container writes below tmp","output_fields":{"container.id":"d8ee3fbcbc9e","container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root","evt.time.iso8601":1791634939025828688}}
```

The complete alert is saved in `labs/lab9/falco/logs/after-tmp-write.log`. The rule fires on every write below `/tmp` in every container. A browser, image-processing service, or package manager can legitimately use temporary files and create noise. I would keep the detection and tune it with an allowlist for approved container images and known process paths, while retaining alerts for unexpected users, images, and command lines. I would review the allowlist periodically so it does not hide drift.

## Task 2

### Shipped policy results

I ran Conftest 0.69.0 in Docker because the host does not have the `conftest` binary installed.

| Manifest | Passed | Warnings | Failed |
|---|---:|---:|---:|
| `juice-hardened.yaml` with shipped Kubernetes policy | 30 | 0 | 0 |
| `juice-unhardened.yaml` with shipped Kubernetes policy | 20 | 2 | 8 |
| `juice-compose.yml` with shipped Compose policy | 15 | 0 | 0 |

Two failures from the unhardened Kubernetes manifest map directly to rules:

- `container "juice" uses disallowed :latest tag` → `k8s.security` rule `deny` that checks `endswith(c.image, ":latest")`.
- `container "juice" must set runAsNonRoot: true` → `k8s.security` rule `deny` that checks `c.securityContext.runAsNonRoot`.

The same requirement needs a separate Compose rule and Kubernetes rule because the input schemas differ: Compose uses service objects under `input.services`, while Kubernetes stores containers under `input.spec.template.spec.containers`. The Compose file passing all 15 checks shows that the Compose policy matches its schema and that this supplied service configuration satisfies the shipped controls.

### Extended policy

The added policy is `labs/lab9/policies/extra/hardening.rego`:

```rego
package k8s.extra

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest", [c.name])
}

warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.automountServiceAccountToken == true
  c := input.spec.template.spec.containers[_]
  msg := sprintf("container %q should disable automountServiceAccountToken", [c.name])
}
```

The hardened manifest passed the extended policy:

```text
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions
```

The violating manifest is `labs/lab9/manifests/k8s/violates-extra-policy.yaml`. It intentionally uses a mutable image tag and enables the service-account token:

```text
17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
WARN - ... - k8s.extra - container "juice" should disable automountServiceAccountToken
FAIL - ... - k8s.extra - container "juice" must pin its image by digest
```

The digest rule is a deny because mutable image references must block deployment. The service-account token check is a warning because some workloads need a token and the choice requires workload context.

The same control can be a Conftest rule in continuous integration (CI) or a Falco rule at runtime. I would keep the Conftest rule if I could keep only one because it prevents the insecure configuration from deploying. Falco still detects runtime drift, compromised workloads, and changes made after admission, so it provides visibility that a pre-deployment check cannot provide.

## Bonus

The bonus rule is included in `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Likely cryptominer activity
  desc: Detect a likely miner connecting to a common mining pool port from a container.
  condition: evt.type=connect and evt.dir=< and container.id != host and fd.sport in (3333, 4444, 5555, 7777, 14444) and (proc.name in (xmrig, minerd, cpuminer, cgminer) or proc.cmdline contains xmrig or proc.cmdline contains miner)
  output: "container=%container.name process=%proc.name command=%proc.cmdline destination=%fd.sip:%fd.sport"
  priority: CRITICAL
  tags: [container, crypto-mining, mitre_command_and_control]
```

The rule loaded successfully with the required `CRITICAL` priority and MITRE command-and-control tag. The macOS Docker Desktop LinuxKit environment recorded the connect tracepoint limitation and did not emit a completed-connect alert for the synthetic `nc` trigger. The runtime rule and its required signals are present and validated by Falco's rule loader; a Linux VM or Colima VM with the required tracepoints is required to collect the bonus alert line exactly as written by the lab.

A refused connection is enough because Falco observes the process's connect syscall before an application receives a successful connection. This means Falco sits at the kernel syscall-observation layer, below the container process and independently of whether a mining pool accepts the connection.

Changing the pool port is cheap for an attacker because the list of common ports is visible in the rule. The process-and-command-line signal is more expensive to evade when the attacker needs a functioning miner, although renaming the binary is also possible. I would add destination reputation, DNS or TLS indicators, sustained CPU usage, and an egress baseline to catch miners that use another port or disguise their process name.

## Files

- `labs/lab9/falco/rules/custom-rules.yaml`
- `labs/lab9/policies/extra/hardening.rego`
- `labs/lab9/manifests/k8s/violates-extra-policy.yaml`
- `submissions/lab9.md`
