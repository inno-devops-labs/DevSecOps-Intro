# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{"hostname":"fa9d6faec8cb","output":"2026-07-10T16:19:55.182258301+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=b515924008c6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"b515924008c6","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1783700395182258301,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":null,"proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T16:19:55.182258301Z"}
```
### Baseline alert B — Container drift (write below binary dir)
Alert B wasn't triggered.
### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: "Write to /tmp by container"
  desc: "Detect any write operation to /tmp directory inside a container"
  condition: >
    open_write and
    container and
    fd.name startswith /tmp/
  output: >
    Write to /tmp detected (container=%container.name user=%user.name fd=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```
### Custom rule fired
Falco log line showing your custom rule:
```json
{"hostname":"fa9d6faec8cb","output":"2026-07-10T16:39:57.750219345+0000: Warning Write to /tmp detected (container=lab9-target user=root fd=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=b515924008c6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"b515924008c6","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1783701597750219345,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T16:39:57.750219345Z"}
```
### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks often write to /tmp). What's your tuning approach? (2-3 sentences referencing the `exceptions:` block vs `and not proc.name=...` patterns from Lecture 9.)

My custom rule will fire on legitimate uses because some processes like logging frameworks frequently write temporary files to `/tmp`. To reduce false positives, I would first use an `exceptions:` block to whitelist known safe processes. This is cleaner and shorter than `and not proc.name=...` conditions in the rule body.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg = sprintf("Container %v must have runAsNonRoot=true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = sprintf("Container %v must have allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg = sprintf("Container %v must drop ALL capabilities", [container.name])
}
```
### Good manifest passes
`6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions`
### Bad manifest 1 fails (runAsRoot)
The `manifests` folder only contained one bad manifest called `juice-unhardened.yaml` in `k8s`.
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must have allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must have runAsNonRoot=true

6 tests, 4 passed, 0 warnings, 2 failures, 0 exceptions
```
### Why CI-time vs admission-time (Lecture 9 slide 9)
2-3 sentences. CI-time Conftest happens during PR review; admission-time Conftest happens at kubectl apply. What's the operational benefit of running BOTH (defense in depth)?

CI-time Conftest catches misconfigurations during PR review, before they are merged into the codebase, making fixes cheap and fast. Admission-time Conftest adds a second layer of defense, blocking any bad manifests that might have bypassed CI. The combined approach ensures that security controls are enforced at both the development and deployment stages, reducing the risk of misconfiguration reaching production.
