# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"06222ed59dd3","output":"2026-07-10T17:12:01.152497084+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=fa2df48fba46 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"fa2df48fba46","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783703521152497084,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"systemd","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T17:12:01.152497084Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"hostname":"06222ed59dd3","output":"2026-07-10T17:12:07.480444938+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=fa2df48fba46 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"fa2df48fba46","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783703527480444938,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T17:12:07.480444938Z"}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect any write operation to the /tmp directory from within a container
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: Write to /tmp detected (container=%container.name user=%user.name fd=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"06222ed59dd3","output":"2026-07-10T17:22:13.386662789+0000: Warning Write to /tmp detected (container=lab9-target user=root fd=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=fa2df48fba46 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"fa2df48fba46","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783704133386662789,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T17:22:13.386662789Z"}

```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks
often write to /tmp). What's your tuning approach? (2-3 sentences referencing the
`exceptions:` block vs `and not proc.name=...` patterns from Lecture 9.)

I would use `exceptions: ` for broad exceptions, for categories of safe programs. And I would use `and not proc.name=...` for temporary or more specific overrides.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    not spec.securityContext.runAsNonRoot == true
    containers := spec.containers
    count([c | c := containers[_]; c.securityContext.runAsNonRoot == true]) != count(containers)
    msg := sprintf("runAsNonRoot must be true for pod or all containers in %s", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    c.securityContext.allowPrivilegeEscalation != false
    msg := sprintf("Container %s in %s must set allowPrivilegeEscalation: false", [c.name, input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    c.securityContext.capabilities.drop
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf("Container %s in %s must drop ALL capabilities", [c.name, input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("Container %s in %s must have memory limits set", [c.name, input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not contains(c.image, "@sha256:")
    msg := sprintf("Container %s in %s must use image with sha256 digest (not tag)", [c.name, input.metadata.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```

10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions

```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice in juice-unhardened must have memory limits set
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice in juice-unhardened must use image with sha256 digest (not tag)
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - runAsNonRoot must be true for pod or all containers in juice-unhardened

10 tests, 7 passed, 0 warnings, 3 failures, 0 exceptions

```

### Compose policy generalizes (shipped compose-security.rego)
```

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions


FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions

```

### Why CI-time vs admission-time (Lecture 9 slide 9)
Running both is double safety, CI is for problems that can be caugth and fixed early. Admission time is for something that somehow passes CI. So if one of tham fails - another still can catch the ptoblem.