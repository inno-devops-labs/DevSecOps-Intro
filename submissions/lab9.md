# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs:
```json
{"output":"2026-07-10T13:56:04.845865133+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root process=sh proc_exepath=/bin/busybox command=sh -lc echo \"shell-in-container test\" container_id=d88f522d99a6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T13:56:04.845865133Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"output":"2026-07-10T13:56:08.279203170+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=open user=root process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow container_id=d88f522d99a6 container_name=lab9-target","output_fields":{"fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","user.name":"root"},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T13:56:08.279203170Z"}
```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect file writes to /tmp originating inside any container (not the host)
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp inside container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing the custom rule:
```json
{"output":"2026-07-10T13:57:54.328504354+0000: Warning Write to /tmp inside container (container=lab9-target user=root file=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=d88f522d99a6 container_name=lab9-target","output_fields":{"container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T13:57:54.328504354Z"}
```

### Tuning consideration (Lecture 9 slide 8)
This rule fires on legitimate `/tmp` writes too — logging frameworks, package managers and
language runtimes all scratch to `/tmp` constantly, so as written it would drown a SOC in noise.
The narrow fix is an inline negative condition (`and not proc.name in (node, npm, apt, gpg)`) to
exclude known-benign writers, which is quick but scatters exception logic across the condition and
is easy to forget. The cleaner, more maintainable approach is a dedicated `exceptions:` block on the
rule — a named, structured list of (proc.name, fd.name) comparisons that Falco appends as
allow-list tuples — because exceptions are self-documenting, can be extended without touching the
detection logic, and keep the core `condition` readable as the threat model rather than a pile of
`and not` clauses.

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package k8s.security

# --- NEW RULE 1: readinessProbe is required (deny, not just warn) ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.readinessProbe
	msg := sprintf("container %q must define a readinessProbe", [c.name])
}

# --- NEW RULE 2: livenessProbe is required (deny, not just warn) ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.livenessProbe
	msg := sprintf("container %q must define a livenessProbe", [c.name])
}

# --- NEW RULE 3: container must not add back any capabilities ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	count(object.get(c, ["securityContext", "capabilities", "add"], [])) > 0
	msg := sprintf("container %q must not add any Linux capabilities", [c.name])
}

# --- NEW RULE 4: container securityContext must exist ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext
	msg := sprintf("container %q must define a securityContext", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/ --namespace k8s.security
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

### Non-compliant manifest fails (juice-unhardened.yaml)
$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/ --namespace k8s.security
WARN - container "juice" should define livenessProbe
WARN - container "juice" should define readinessProbe
FAIL - container "juice" missing resources.limits.cpu
FAIL - container "juice" missing resources.limits.memory
FAIL - container "juice" missing resources.requests.cpu
FAIL - container "juice" missing resources.requests.memory
FAIL - container "juice" must define a livenessProbe
FAIL - container "juice" must define a readinessProbe
FAIL - container "juice" must define a securityContext
FAIL - container "juice" must set allowPrivilegeEscalation: false
FAIL - container "juice" must set readOnlyRootFilesystem: true
FAIL - container "juice" must set runAsNonRoot: true
FAIL - container "juice" uses disallowed :latest tag
30 tests, 17 passed, 2 warnings, 11 failures, 0 exceptions

(The three FAILs from my extra policy — `must define a securityContext`, `must define a
readinessProbe`, `must define a livenessProbe` — are stricter deny versions; note the shipped policy
only *warns* on missing probes, while my extension promotes them to hard denials.)

### Compose policy generalizes (shipped compose-security.rego)
$ conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
$ conftest test /tmp/bad-compose.yml --policy labs/lab9/policies/compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest runs during PR review, giving developers immediate feedback and blocking a
non-compliant manifest before it is ever merged — cheap to fix, and it keeps bad config out of the
repository. Admission-time Conftest (via an admission controller) runs at `kubectl apply` and is the
backstop that catches anything reaching the cluster through a path that bypassed CI — a manual
`kubectl apply`, a compromised pipeline, or a manifest edited after review. Running both is defense
in depth: CI shifts detection left where fixes are cheapest, while admission control enforces the
same policy at the trust boundary so no workload is admitted unchecked.
