# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"89eba2f8a2df","output":"2026-07-10T13:28:21.001674096+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo test_shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=8a98414f402c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"8a98414f402c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783690101001674096,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo test_shell","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"runc","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T13:28:21.001674096Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"89eba2f8a2df","output":"2026-07-10T13:27:36.340140711+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=8a98414f402c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"8a98414f402c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783690056340140711,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":null,"proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":null,"proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T13:27:36.340140711Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside any container
  condition: open_write and container and container.id != "host" and fd.name startswith "/tmp/"
  output: "Write to /tmp by container (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"89eba2f8a2df","output":"2026-07-10T13:29:00.008630829+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo 'test' > /tmp/my-write.txt) container_id=8a98414f402c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"8a98414f402c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783690140008630829,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo 'test' > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T13:29:00.008630829Z"}
```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks
often write to /tmp). What's your tuning approach?
*Answer:* My approach involves using the `exceptions:` block to whitelist known legitimate applications, or explicitly excluding processes in the rule itself via `and not proc.name in (fluentd, logstash, ...)`. This effectively reduces false positives and focuses only on suspicious activity.

---

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
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

### Compliant manifest passes (juice-hardened.yaml)
```
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must have allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container 'juice' must have runAsNonRoot=true

6 tests, 3 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
FAIL - bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
*Answer:* CI-time Conftest checks prevent manifests with poor security from entering the git repository and provide immediate feedback to developers. Admission-time checks are executed before deployment and provide a strict guarantee that no cluster changes, even outside of CI, violate security policies. The combination of these two methods provides a powerful defense in depth.

---

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects container connecting to common mining-pool ports or known miner processes
  condition: container and evt.type=connect and (fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700) or proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: "Possible Cryptominer Activity (container=%container.name process=%proc.name target=%fd.sip:%fd.sport)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"hostname":"89eba2f8a2df","output":"2026-07-10T13:31:36.562140711+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc target=127.0.0.1:3333) container_id=8a98414f402c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"8a98414f402c","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783690056340140711,"evt.type":"connect","fd.sip":"127.0.0.1","fd.sport":3333,"proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_execution","mitre_command_and_control"],"time":"2026-07-10T13:31:36.562140711Z"}
```

### Reflection (2-3 sentences)
- Which 2 indicators did you use and why?
*Answer:* I used known pool ports (fd.sport) and names of common miner programs (proc.name). These indicators cover most standard attacks: both script kiddies using standard programs and modified programs communicating with standard pool ports.
- What does this miss? (i.e., the false-negative case — e.g., obfuscated mining over HTTPS)
*Answer:* This rule will not detect miners connecting over standard ports like HTTPS (443) or routing traffic through proxies with non-standard ports. It will also miss miners with renamed binaries using unknown pools, or web-script-based mining.
- How would you combine this with the Lecture 9 SLA matrix?
*Answer:* Upon alert trigger (CRITICAL priority), pod isolation or container termination must be immediately automated, as this is a clear sign of C2 activity or malware execution. Memory dumps should be used for investigation, as a miner can rapidly consume resources and pose a financial risk to the infrastructure.
