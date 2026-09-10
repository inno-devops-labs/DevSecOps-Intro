# Lab 9 — Submission

> **Environment note.** Falco was run through **Colima** (Ubuntu 24.04 VM, kernel 6.8.0-117-generic, aarch64)
> rather than Docker Desktop, whose LinuxKit VM kernel ships without BTF. Gate check before starting:
> `colima ssh -- test -f /sys/kernel/btf/vmlinux` → `BTF OK`.
> Falco confirmed the modern driver at startup: `Opening 'syscall' source with modern BPF probe.`

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{"hostname":"56df67e4ca48","output":"2026-07-10T16:19:46.382161841+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=b12f7b1ffc6b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.id":"b12f7b1ffc6b","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.type":"execve","proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T16:19:46.382161841Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"56df67e4ca48","output":"2026-07-10T16:19:46.441915591+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=openat user=root user_uid=0 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=b12f7b1ffc6b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.id":"b12f7b1ffc6b","container.image.repository":"alpine","container.name":"lab9-target","evt.type":"openat","fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.name":"cat","proc.tty":0,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T16:19:46.441915591Z"}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detect file writes under /tmp originating from inside a container
  condition: >
    open_write
    and container
    and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{"hostname":"56df67e4ca48","output":"2026-07-10T16:20:26.708003819+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=b12f7b1ffc6b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.id":"b12f7b1ffc6b","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T16:20:26.708003819Z"}
```

### Tuning consideration
Inlining `and not proc.name in (java, python3, nginx)` into the condition is the quickest fix, but it welds the exception to the rule text: every future carve-out edits the detection logic itself, the rule drifts from upstream, and the exemption is invisible to anyone auditing why a write was never alerted on. The `exceptions:` block is the better instrument — it keeps `condition:` as the pure statement of *what is suspicious* and expresses *who is allowed* as named, appendable tuples (`name`, `fields`, `comps`), so a logging framework can be exempted by `proc.name` + `container.image.repository` together rather than by process name alone, which an attacker could trivially satisfy by renaming their binary to `java`. In practice I would scope the exception on the image repository plus the exact path prefix the framework writes to, keeping `/tmp/` writes from every other process in the image loud.

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

has_value(arr, v) if {
	some i
	arr[i] == v
}

runs_as_non_root(c) if {
	c.securityContext.runAsNonRoot == true
}

runs_as_non_root(c) if {
	input.spec.template.spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not runs_as_non_root(c)
	msg := sprintf("container %q must set runAsNonRoot: true (pod- or container-level securityContext)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	drop := object.get(c, ["securityContext", "capabilities", "drop"], [])
	not has_value(drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin its image by sha256 digest, not a mutable tag", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/

10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/extra/
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin its image by sha256 digest, not a mutable tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true (pod- or container-level securityContext)

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
$ conftest test labs/lab9/manifests/compose/juice-compose.yml \
    --policy labs/lab9/policies/compose-security.rego --namespace compose.security

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml \
    --policy labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

The same `deny contains msg if` shape survives the change of target: only the iteration root moves from `input.spec.template.spec.containers[_]` (K8s Deployment) to `input.services[_]` (compose). The policy language is indifferent to the manifest dialect; what changes is the path expression.

### Note — a real Rego footgun found while writing this
`not has_value(c.securityContext.capabilities.drop, "ALL")` looks correct but silently never fires when `securityContext` is absent: an undefined *argument* makes the whole rule body undefined, so no `deny` is produced — it does not evaluate to `not undefined = true`. This is observable in the shipped starter policies: `k8s-security.rego` never emits "must drop ALL capabilities" against `juice-unhardened.yaml`, and `compose-security.rego` never emits "must drop ALL capabilities" against a compose file with no `cap_drop`. Both bad manifests therefore pass a check they should fail. My policy avoids this by materialising a default first: `drop := object.get(c, ["securityContext","capabilities","drop"], [])`, which is why the capabilities deny does fire above. The lesson generalises: a negated policy check over a possibly-absent path is a false negative, and a policy that never fires looks exactly like a policy that passes.

### Why CI-time vs admission-time
CI-time Conftest gives the fastest, cheapest feedback — the author sees the deny message in the PR, before the manifest exists anywhere — but it is advisory in the security sense: it can be bypassed by anyone who runs `kubectl apply` directly, and it never sees manifests that Helm or Kustomize only materialise at deploy time. Admission-time enforcement is the non-bypassable backstop: it inspects the object that is actually being admitted, catching out-of-band applies, operator-generated workloads, and post-merge drift, but it fails late, at deploy, when the fix is expensive and the deployer is under pressure. Running both is defense in depth across *time* rather than across layers: CI shifts the cost of the fix left to where it is nearly free, while admission guarantees that the invariant holds regardless of how the object arrived, so an unpatched CI pipeline degrades feedback quality but never the cluster's actual security posture.

---

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- list: miner_binaries
  items: [xmrig, ethminer, cgminer, t-rex, claymore, minerd, nbminer]

- list: miner_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- rule: Possible Cryptominer Activity
  desc: Detect a container connecting to a known mining-pool port or executing a known miner binary
  condition: >
    container
    and (
      (evt.type = connect and fd.sockfamily = ip and fd.sport in (miner_ports))
      or
      (evt.type in (execve, execveat) and proc.name in (miner_binaries))
    )
  output: >
    Possible cryptominer activity
    (container=%container.name image=%container.image.repository proc=%proc.name
     cmdline=%proc.cmdline connection=%fd.name port=%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"a06b705bbf60","output":"2026-07-10T16:25:03.038203034+0000: Critical Possible cryptominer activity (container=lab9-target image=alpine proc=nc cmdline=nc -w 2 127.0.0.1 3333 connection=127.0.0.1:35759->127.0.0.1:3333 port=3333) container_id=b12f7b1ffc6b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.id":"b12f7b1ffc6b","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","fd.name":"127.0.0.1:35759->127.0.0.1:3333","fd.sport":3333,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T16:25:03.038203034Z"}
```

> **Trigger caveat discovered while testing.** The lab's suggested trigger — `nc` to a port with nothing
> listening — cannot fire a port-based rule on Falco 0.43. A temporary debug rule showed that on a refused
> connect the kernel returns no socket tuple: `res=ECONNREFUSED  fd.name=0.0.0.0:0  fd.sport=<NA>`.
> The alert above was produced by first starting a listener (`nc -l -p 3333`) inside the target container so
> the `connect` actually completes and `fd.sport` is populated.

### Reflection
I combined the **mining-pool destination port** (`fd.sport in (3333, 4444, 5555, ...)`) with the **known miner binary name** (`proc.name in (xmrig, ethminer, ...)`), because they fail independently: the port catches a renamed or statically-linked miner whose binary name tells you nothing, and the process name catches a miner pointed at a pool on an unusual port or reached through a proxy. Requiring both would be strictly worse — an attacker only has to defeat one signal — so the rule ORs them and accepts the resulting noise, which is real: the `nc` in my own test is not a miner, and any developer connecting to a service on 4444 trips it.

The obvious false negative is obfuscated mining: stratum tunnelled over TLS to 443, a pool proxy on a benign port, a binary renamed to `nginx`, or in-browser/WASM mining that never spawns a process at all. Port and process name are both surface-level indicators, and neither survives an attacker who reads this rule. Catching those needs behavioural signals — sustained CPU saturation correlated with steady low-volume egress, or DNS resolution of pool domains before the connect — which is why this rule is a tripwire, not a detection strategy.

Against the Lecture 9 SLA matrix, priority is the routing key, and its meaning is *how long may this sit unexamined*. `CRITICAL` here means the container is already executing attacker code and burning money, so it pages the on-call and the response is containment first — cordon the node, kill the pod — with forensics after; the tolerable window is minutes. The `WARNING`-level `/tmp` drift rule from Task 1 is the opposite case: high volume, low confidence, ticketed and triaged within the business day, feeding the exception list rather than the pager. Wiring both into DefectDojo (Lab 10) as a runtime finding source lets the CRITICAL alert be correlated against the Grype/Trivy SBOM findings for the same image, so an operator can immediately ask the follow-up question that matters — was this image already known-vulnerable, and is the miner the payload of a CVE we shipped?
