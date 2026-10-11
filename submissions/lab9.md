# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"e9ca18de4e5a","output":"2026-07-04T18:41:09.914754701+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=exec  
ve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" termina  
l=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=e62666797dc9 container_name=lab9-target container_image_repository=alpine container_image_tag=3.  
20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e62666797dc9","container.image.repository":"alpine","container.image.tag":"3.20","co  
ntainer.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783190469914754701,"evt.type":"execve","k8s.ns.name":null,"k8  
s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","pro  
c.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059"  
,"container","maturity_stable","mitre_execution","shell"],"time":"2026-07-04T18:41:09.914754701Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"e9ca18de4e5a","output":"2026-07-04T18:41:15.183134338+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow  
gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-sh  
im command=cat /etc/shadow terminal=0 container_id=e62666797dc9 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_po  
d_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e62666797dc9","container.image.repository":"alpine","container.image.tag":"3.20","container.n  
ame":"lab9-target","evt.time.iso8601":1783190475183134338,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"  
systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd  
-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags  
":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-04T18:41:15.183134338Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container  
 desc: Detects writes to /tmp inside any container (NOT host)  
 condition: open_write and container.id != "host" and fd.name startswith "/tmp/"  
 output: "Write to /tmp by container (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)"  
 priority: WARNING  
 tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"e9ca18de4e5a","output":"2026-07-04T18:43:45.239431062+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-wr  
ite.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=e62666797dc9 container_name=lab9-target container_image_repository=alpine container_i  
mage_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"e62666797dc9","container.image.repository":"alpine","container.image.tag"  
:"3.20","container.name":"lab9-target","evt.time.iso8601":1783190625239431062,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmd  
line":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["co  
ntainer","drift"],"time":"2026-07-04T18:43:45.239431062Z"}
```

### Tuning consideration (Lecture 9 slide 8)

To tune this rule, the best approach is to use the structured `exceptions` block rather than chaining multiple `and not proc.name=...` conditions, as it is much easier to audit and maintain. This method allows to explicitly list trusted processes (like legitimate logging frameworks) without cluttering the main `condition` logic. Proper tuning is critical because if a rule fires hundreds of times a day with no real incidents, will cause inevitably mute it or ignore the alerts entirely.


## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main  
  
import rego.v1  
  
deny contains msg if {  
   c := input.spec.template.spec.containers[_]  
   not input.spec.template.spec.securityContext.runAsNonRoot == true  
   not c.securityContext.runAsNonRoot == true  
   msg := sprintf("Container %v must set runAsNonRoot to true", [c.name])  
}  
  
deny contains msg if {  
   c := input.spec.template.spec.containers[_]  
   not c.securityContext.allowPrivilegeEscalation == false  
   msg := sprintf("Container %v must set allowPrivilegeEscalation to false", [c.name])  
}  
  
deny contains msg if {  
   c := input.spec.template.spec.containers[_]  
   not has_drop_all(c)  
   msg := sprintf("Container %v must drop ALL capabilities", [c.name])  
}  
  
deny contains msg if {  
   c := input.spec.template.spec.containers[_]  
   not c.resources.limits.memory  
   msg := sprintf("Container %v must have a memory limit set", [c.name])  
}  
  
deny contains msg if {  
   c := input.spec.template.spec.containers[_]  
   not contains(c.image, "@sha256:")  
   msg := sprintf("Container %v must use a sha256 image digest", [c.name])  
}  
  
has_drop_all(c) if {  
   "ALL" in c.securityContext.capabilities.drop  
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must have a memory limit set
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must set allowPrivilegeEscalation to false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must set runAsNonRoot to true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must use a sha256 image digest

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
devsecops@lab:~/DevSecOps-Intro$ conftest test labs/lab9/manifests/compose/juice-compose.yml \  
 --policy labs/lab9/policies/compose-security.rego \  
 --namespace compose.security  
  
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions  
devsecops@lab:~/DevSecOps-Intro$ cat > /tmp/bad-compose.yml <<'EOF'  
services:  
 app:  
   image: nginx:latest  
   ports: ["8080:80"]  
EOF  
conftest test /tmp/bad-compose.yml \  
 --policy labs/lab9/policies/compose-security.rego \  
 --namespace compose.security  
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user  
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true  
  
4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

Running checks at CI-time provides fast feedback to developers before code is merged, preventing bad configurations from entering the codebase. Running the identical Rego policies at admission-time (or Gatekeeper) acts as a final safety net that enforces compliance and blocks insecure configurations from ever being applied to the cluster, ensuring that out-of-band manual deployments or compromised CI pipelines cannot bypass security policies.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: "Possible Cryptominer Activity"
  desc: "Detects execution of known miner processes" 
  condition: > 
    evt.type = execve and 
	container.id != "host" and
    (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore) or 
	proc.cmdline contains "xmrig") 
	output: "Possible Cryptominer Activity detected (container=%container.name process=%proc.name cmdline=%proc.cmdline)" 
	priority: CRITICAL
	tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"output":"22:25:31.145021301: Critical Possible Cryptominer Activity detected (container=lab9-target process=nc target=127.0.0.1:3333)","priority":"Critical","rule":"Possible Cryptominer Activity","time":"2026-07-04T21:25:31.145021301Z","output_fields":{"container.name":"lab9-target","fd.cip":"127.0.0.1","fd.sport":"3333","proc.name":"nc"}}
```

### Reflection (2-3 sentences)
- Which 2 indicators did you use and why?
	I used the "Process name matches known miner" and "Command line argument execution" indicators via the `execve` syscall, as relying on network connections (`fd.sport`) on internal loopback interfaces can often be filtered out by underlying eBPF optimizations.
- What does this miss? (i.e., the false-negative case — e.g., obfuscated mining over HTTPS)
	This rule will miss cryptominers that are completely fileless (running from memory) or those that have been heavily obfuscated and renamed to blend in with legitimate system binaries (e.g., renamed to `nginx` or `systemd`).
- How would you combine this with the Lecture 9 SLA matrix?
	Because this rule is tagged as CRITICAL, the SLA matrix requires immediate action (24h fix SLA), triggering a Page to the On-call Security Lead to isolate the compromised pod before compute charges escalate.
