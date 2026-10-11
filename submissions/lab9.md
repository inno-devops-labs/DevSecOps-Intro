# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"73b5de6165e3","output":"2026-07-10T20:12:53.504372321+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=253a53abf758 container_name=test container_image_repository=alpine container_image_tag=latest k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"253a53abf758","container.image.repository":"alpine","container.image.tag":"latest","container.name":"test","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783714373504372321,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T20:12:53.504372321Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"73b5de6165e3","output":"2026-07-10T20:12:57.516283569+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=containerd-shim ggparent=systemd gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=sh command=cat /etc/shadow terminal=34816 container_id=253a53abf758 container_name=test container_image_repository=alpine container_image_tag=latest k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"253a53abf758","container.image.repository":"alpine","container.image.tag":"latest","container.name":"test","evt.time.iso8601":1783714377516283569,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"containerd-shim","proc.aname[3]":"systemd","proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"sh","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T20:12:57.516283569Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect write operations to the /tmp directory inside containers
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: Write to /tmp detected (user=%user.name container=%container.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"73b5de6165e3","output":"2026-07-10T20:19:45.814423614+0000: Warning Write to /tmp detected (user=root container=test file=/tmp/testfile cmdline=touch /tmp/testfile) container_id=a1c580e52870 container_name=test container_image_repository=alpine container_image_tag=latest k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"a1c580e52870","container.image.repository":"alpine","container.image.tag":"latest","container.name":"test","evt.time.iso8601":1783714785814423614,"fd.name":"/tmp/testfile","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"touch /tmp/testfile","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T20:19:45.814423614Z"}
```

### Tuning consideration (Lecture 9 slide 8)
For optimal tuning, employing a structured exception block is far superior to stacking multiple and not proc.name= conditions. This approach greatly enhances auditability and simplifies maintenance by allowing you to clearly list trusted processes—such as legitimate logging frameworks—without crowding the primary logic. Thorough tuning is essential; if a rule generates hundreds of false positives daily, analysts will inevitably become desensitized, leading to the rule being muted or genuine threats being overlooked.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

containers(obj) = all {
    obj.spec.containers
    init := object.get(obj.spec, "initContainers", [])
    all := array.concat(obj.spec.containers, init)
}

containers(obj) = all {
    not obj.spec.containers
    obj.spec.template.spec.containers
    init := object.get(obj.spec.template.spec, "initContainers", [])
    all := array.concat(obj.spec.template.spec.containers, init)
}

deny[msg] {
    some container in containers(input)
    container_run_as_non_root := object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null)
    container_run_as_non_root == false
    msg := sprintf("Container %q has runAsNonRoot set to false", [container.name])
}

deny[msg] {
    some container in containers(input)
    pod_run_as_non_root := object.get(object.get(input.spec, "securityContext", {}), "runAsNonRoot", null)
    container_run_as_non_root := object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null)
    container_run_as_non_root != true
    pod_run_as_non_root != true
    msg := sprintf("Container %q must have runAsNonRoot true (either container-level or pod-level)", [container.name])
}

deny[msg] {
    some container in containers(input)
    allow_priv_esc := object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", null)
    allow_priv_esc != false
    msg := sprintf("Container %q must have allowPrivilegeEscalation set to false", [container.name])
}

deny[msg] {
    some container in containers(input)
    drop := object.get(object.get(container, "securityContext", {}), "capabilities", {}).drop
    not "ALL" in drop
    msg := sprintf("Container %q must drop all capabilities (capabilities.drop must include ALL)", [container.name])
}

deny[msg] {
    some container in containers(input)
    limits := object.get(container, "resources", {}).limits
    not limits.memory
    msg := sprintf("Container %q must have resources.limits.memory set", [container.name])
}

deny[msg] {
    some container in containers(input)
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %q must use image with sha256 digest (e.g., @sha256:...), not a tag", [container.name])
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
yalmen@kali:/DevSecOps-Intro$ conftest test labs/lab9/manifests/compose/juice-compose.yml \  
 --policy labs/lab9/policies/compose-security.rego \  
 --namespace compose.security  
  
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions  
```
and
```
yalmen@kali:/DevSecOps-Intro$ cat > /tmp/bad-compose.yml <<'EOF'  
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
CI-time Conftest shifts security left, enabling fast, cheap feedback to developers during PR review so violations are fixed before code ever merges, reducing rework and noise for operations. Admission-time Conftest acts as the final mandatory enforcement barrier, blocking any non-compliant resources from entering the cluster regardless of how they reach the API server—whether through direct kubectl apply, emergency hotfixes, or compromised credentials that bypass the PR pipeline. Together, they provide defense in depth by combining proactive prevention with reactive enforcement, guaranteeing that misconfigurations caught early are remediated by developers, while any that slip through are stopped dead at the gate.