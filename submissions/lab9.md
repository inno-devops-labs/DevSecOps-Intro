# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline Alert A — Terminal Shell in Container
Falco detected an interactive shell execution inside the target container. Note the `EXE_WRITABLE` flag and attached terminal (`proc.tty=34816`), which are strong indicators of manual intervention rather than automated orchestration.

```json
{
  "hostname": "89eba2f8a2df",
  "output": "2026-07-10T13:28:21.001674096+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 process=sh parent=runc command=sh -lc echo test_shell container_id=8a98414f402c container_name=lab9-target",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "tags": ["T1059", "container", "mitre_execution", "shell"]
}
```

### Baseline Alert B — Read Sensitive File Untrusted
Access to `/etc/shadow` by a non-trusted process (`cat`) triggered this warning. This maps directly to MITRE ATT&CK T1555 (Credentials from Password Stores).

```json
{
  "hostname": "89eba2f8a2df",
  "output": "2026-07-10T13:27:36.340140711+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow process=cat command=cat /etc/shadow container_id=8a98414f402c container_name=lab9-target",
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "tags": ["T1555", "container", "filesystem", "mitre_credential_access"]
}
```

### Custom Rule: Write to /tmp by Container
This rule detects writes to `/tmp` specifically within containers (excluding host writes). It combines the built-in `open_write` macro with container context filtering.

```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside any container
  condition: open_write and container and container.id != "host" and fd.name startswith "/tmp/"
  output: "Write to /tmp by container (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]
```

### Custom Rule Triggered
The rule successfully fired when `echo "test" > /tmp/my-write.txt` was executed inside `lab9-target`. The alert captures the exact file path and command line used.

```json
{
  "hostname": "89eba2f8a2df",
  "output": "2026-07-10T13:29:00.008630829+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo 'test' > /tmp/my-write.txt)",
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "tags": ["container", "drift"]
}
```

### Tuning Consideration (Lecture 9 Slide 8)
Writing to `/tmp` is common behavior for legitimate applications (e.g., log rotation, temp file creation by web servers). To reduce false positives without disabling the rule entirely, I would use the `exceptions:` block in the Falco rule definition. For example:
```yaml
exceptions:
  - name: trusted_procs
    fields: [proc.name]
    comps: [=]
    values: [[fluentd, logstash, nginx]]
```
Alternatively, using `and not proc.name in (...)` directly in the condition works but becomes hard to maintain as the allowlist grows. The `exceptions:` approach is preferred because it keeps the core logic clean and allows dynamic updates via configuration management without modifying the rule syntax itself.

---

## Task 2: Conftest Policy-as-Code

### My Policy File (`labs/lab9/policies/extra/hardening.rego`)
This policy enforces three critical security controls using Rego v1 syntax:

```rego
package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	pod_sec := object.get(input.spec.template.spec, "securityContext", {})
	not pod_sec.runAsNonRoot

	some container in input.spec.template.spec.containers
	cont_sec := object.get(container, "securityContext", {})
	not cont_sec.runAsNonRoot

	msg := sprintf("Container '%v' must have runAsNonRoot=true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	cont_sec := object.get(container, "securityContext", {})
	not cont_sec.allowPrivilegeEscalation == false

	msg := sprintf("Container '%v' must have allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	cont_sec := object.get(container, "securityContext", {})
	caps := object.get(cont_sec, "capabilities", {})
	drop := object.get(caps, "drop", [])
	not "ALL" in drop

	msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}
```

### Compliant Manifest Passes (`juice-hardened.yaml`)
All 6 tests passed with zero failures, confirming the hardened manifest meets all policy requirements.

```text
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-Compliant Manifest Fails (`juice-unhardened.yaml`)
Three distinct violations were detected, demonstrating the policy's ability to catch multiple security gaps simultaneously.

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must have allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must have runAsNonRoot=true

6 tests, 3 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose Policy Generalizes (`compose-security.rego`)
The same `deny[msg]` pattern adapts seamlessly to Docker Compose manifests by targeting `input.services` instead of K8s specs.

**Hardened Compose (PASS):**
```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

**Unhardened Compose (FAIL):**
```text
FAIL - bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-Time vs Admission-Time (Defense in Depth)
CI-time Conftest provides **developer feedback loops**: violations appear in PR checks before code merges, enabling fast iteration and preventing insecure manifests from polluting the repository history. However, CI can be bypassed (e.g., direct `kubectl apply`, emergency hotfixes). Admission-time enforcement (via OPA Gatekeeper/Kyverno) acts as the **final safety net**, guaranteeing that *no* workload enters the cluster without meeting policies, regardless of origin. Running both creates defense-in-depth: CI shifts security left for velocity, while admission control ensures runtime compliance for safety.

---

## Bonus: Cryptominer Detection Rule

### Rule Definition
Combines network port detection and process name matching to catch both standard miners and custom binaries connecting to known pools.

```yaml
- rule: Possible Cryptominer Activity
  desc: Detects container connecting to common mining-pool ports or known miner processes
  condition: container and evt.type=connect and (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: "Possible Cryptominer Activity (container=%container.name process=%proc.name target=%fd.sip:%fd.sport)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered Alert
Simulated connection to port 3333 via `nc` triggered the rule instantly.

```json
{
  "hostname": "89eba2f8a2df",
  "output": "2026-07-10T13:31:36.562140711+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc target=127.0.0.1:3333)",
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "tags": ["container", "mitre_execution", "mitre_command_and_control"]
}
```

### Reflection
**Indicators Used:** I combined `fd.sport` (mining pool ports like 3333) and `proc.name` (known miner binaries like xmrig). This dual-indicator approach catches both script-kiddie attacks using default tools and more sophisticated actors who might rename binaries but still connect to standard pool ports.

**False Negatives:** This rule misses miners tunneling over HTTPS (port 443), using domain fronting, or employing web-based JavaScript miners (cryptojacking) that don't spawn separate processes. Renamed binaries connecting to obscure pools would also evade detection.

**SLA Matrix Integration:** Given the CRITICAL priority and MITRE C2 tagging, this alert should trigger an automated response per the SLA matrix: immediate container isolation/termination + memory dump capture within 5 minutes. Financial impact from cryptomining escalates rapidly, so MTTD/MTTR targets must be aggressive compared to lower-severity drift alerts.
