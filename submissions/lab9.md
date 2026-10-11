# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

Falco `0.43.1` started with modern eBPF (`docker logs falco` confirms: `Opening 'syscall' source with modern BPF probe.`) against a WSL2 kernel (`6.18.33.2-microsoft-standard-WSL2`) that ships BTF — verified beforehand with `docker run --rm --privileged alpine test -f /sys/kernel/btf/vmlinux`.

### Baseline alert A — Terminal shell in container
```json
{"hostname":"7ce7bf9c2022","output":"2026-07-10T13:45:25.476520762+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo shell-in-container test terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=8f24dbce9227 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"8f24dbce9227","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","proc.cmdline":"sh -lc echo shell-in-container test","proc.name":"sh","proc.pname":"runc","user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T13:45:25.476520762Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"7ce7bf9c2022","output":"2026-07-10T13:45:25.616943685+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow ... process=cat proc_exepath=/bin/busybox command=cat /etc/shadow container_id=8f24dbce9227 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.id":"8f24dbce9227","container.name":"lab9-target","fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.name":"cat","user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T13:45:25.616943685Z"}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detects a write to /tmp inside any container (not the host)
  condition: >
    open_write and container.id != host and fd.name startswith /tmp/
  output: >
    Write to /tmp by container (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{"hostname":"7ce7bf9c2022","output":"2026-07-10T13:49:51.375830192+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=8f24dbce9227 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.id":"8f24dbce9227","container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T13:49:51.375830192Z"}
```

### Tuning consideration (Lecture 9 slide 8)
This rule will fire constantly in real workloads, since logging frameworks, package managers, and even shells routinely write scratch files to `/tmp`. Rather than a blanket `and not proc.name=...` clause (which only excludes one binary at a time and needs constant maintenance as new legit writers appear), a Falco `exceptions:` block is the better fit here: it lets you list known-safe `(container.image.repository, proc.name)` field-value pairs directly on the rule, so the base condition stays a clean, auditable "any /tmp write" check while the noise-suppression list is reviewable and versioned separately from the detection logic itself.

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

# 1. runAsNonRoot must be true (pod-level or container-level)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.runAsNonRoot == true
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := sprintf("container %q must set runAsNonRoot: true (pod- or container-level)", [c.name])
}

# 2. allowPrivilegeEscalation must be false on every container
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" on every container
# (object.get with a [] default avoids Rego's undefined-propagation trap: if
#  securityContext/capabilities is missing entirely, "in" on undefined is itself
#  undefined, and `not undefined` is undefined too — so the rule would silently
#  never fire on the worst-case manifests, exactly the ones it should catch.)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	drops := object.get(c, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drops
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. (bonus) resources.limits.memory must be set
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. (bonus) image must be pinned by sha256 digest, not a mutable tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must be pinned by sha256 digest, not a tag", [c.name])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)
```
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must be pinned by sha256 digest, not a tag
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs\lab9\manifests\k8s\juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true (pod- or container-level)
10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`)
Shipped, hardened compose (`juice-compose.yml`) — PASS:
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

Deliberately unhardened compose (`nginx:latest`, no user/read_only/cap_drop) — FAIL:
```
FAIL - ...\bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - ...\bad-compose.yml - compose.security - services must set read_only: true
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
Same `deny[msg]` skill from the K8s policy generalizes cleanly to `input.services` — only 2 of the 3 possible denies fired here because the shipped `cap_drop` check has the same undefined-propagation gap described above (it isn't guarded with `object.get`), which is enough evidence on its own for why the guard in rule 3 above matters.

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running Conftest at CI time (PR review) catches misconfigurations before they're ever merged, giving the fastest possible feedback loop and keeping bad manifests out of the default branch entirely. Running the same Rego at admission time (e.g. via Kyverno/OPA Gatekeeper at `kubectl apply`) is the safety net for everything that bypasses CI — a manual `kubectl apply`, a manifest generated by a different pipeline, or a policy that was added after older manifests were already merged. Defense in depth means a gap in one layer (someone skips CI, or a reviewer overrides a failing check) doesn't translate into an insecure workload actually running in the cluster.

---

## Environment notes
- Docker Desktop (Windows, WSL2 backend) — kernel `6.18.33.2-microsoft-standard-WSL2` has BTF support, so Falco's modern eBPF probe attached without needing the legacy driver fallback or a separate Colima VM (that workaround is macOS/Docker-Desktop-LinuxKit-specific).
- Conftest v0.68.2 / OPA 1.15.2 installed manually from GitHub releases (no winget package existed for `conftest`).
- Bonus (cryptominer detection rule) not attempted — out of scope per this submission's chosen coverage (Task 1 + Task 2).
