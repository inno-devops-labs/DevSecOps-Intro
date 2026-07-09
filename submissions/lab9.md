# Lab 9 — Submission



## Task 1: Runtime Detection with Falco



### Baseline alert A — Terminal shell in container

JSON alert from Falco logs (paste the most relevant lines):

```json

{"hostname":"896863fb5122","output":"2026-07-09T00:06:12.835755475+0000: Notice A shell was spawned in a container with an attached terminal | evt\_type=execve user=root user\_uid=0 user\_loginuid=-1 process=sh proc\_exepath=/bin/busybox parent=<NA> command=sh -lc echo shell-in-container test terminal=34816 exe\_flags=EXE\_WRITABLE|EXE\_LOWER\_LAYER container\_id=67a8a1628cee container\_name=lab9-target container\_image\_repository=alpine container\_image\_tag=3.20 k8s\_pod\_name=<NA> k8s\_ns\_name=<NA>","priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":\["T1059","container","maturity\_stable","mitre\_execution","shell"],"time":"2026-07-09T00:06:12.835755475Z"}

```

### Baseline alert B — Read sensitive file untrusted (cat /etc/shadow)

```json

{"hostname":"896863fb5122","output":"2026-07-09T00:06:13.111248127+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt\_type=open user=root user\_uid=0 user\_loginuid=-1 process=cat proc\_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container\_id=67a8a1628cee container\_name=lab9-target container\_image\_repository=alpine container\_image\_tag=3.20 k8s\_pod\_name=<NA> k8s\_ns\_name=<NA>","priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":\["T1555","container","filesystem","host","maturity\_stable","mitre\_credential\_access"],"time":"2026-07-09T00:06:13.111248127Z"}

```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)

```yaml

\- rule: Write to /tmp by container

&#x20; desc: Detect write to /tmp inside any container

&#x20; condition: open\_write and container and fd.name startswith /tmp/

&#x20; output: "Write to /tmp by container (user=%user.name container=%container.name fd=%fd.name cmdline=%proc.cmdline)"

&#x20; priority: WARNING

&#x20; tags: \[container, drift]

```

### Custom rule fired

Falco log line showing your custom rule:

```json

{"hostname":"896863fb5122","output":"2026-07-09T00:07:27.803093465+0000: Warning Write to /tmp by container (user=root container=lab9-target fd=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt) container\_id=67a8a1628cee container\_name=lab9-target container\_image\_repository=alpine container\_image\_tag=3.20 k8s\_pod\_name=<NA> k8s\_ns\_name=<NA>","priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":\["container","drift"],"time":"2026-07-09T00:07:27.803093465Z"}

```

### Tuning consideration

Using the exceptions: block is the preferred tuning approach for specific known-good processes (like logging frameworks) because it allows explicitly defining allowed behavior without cluttering the main condition. If the list of exceptions grows too large or is too specific to a single process name, using and not proc.name=... directly in the condition might be simpler, but exceptions are more readable and maintainable for complex rules.



## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)

```rego

package main



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; c := input.spec.template.spec.containers\[\_]

&#x20; not input.spec.template.spec.securityContext.runAsNonRoot == true

&#x20; not c.securityContext.runAsNonRoot == true

&#x20; msg := sprintf("Container %s must set runAsNonRoot to true (pod or container level)", \[c.name])

}



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; c := input.spec.template.spec.containers\[\_]

&#x20; not c.securityContext.allowPrivilegeEscalation == false

&#x20; msg := sprintf("Container %s must set allowPrivilegeEscalation to false", \[c.name])

}



deny contains msg if {

&#x20; input.kind == "Deployment"

&#x20; c := input.spec.template.spec.containers\[\_]

&#x20; not "ALL" in c.securityContext.capabilities.drop

&#x20; msg := sprintf("Container %s must drop ALL capabilities", \[c.name])

}

```

### Compliant manifest passes (juice-hardened.yaml)

```text

6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions

```

### Non-compliant manifest fails (juice-unhardened.yaml)

```text

FAIL - /project/labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must set allowPrivilegeEscalation to false

FAIL - /project/labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice must set runAsNonRoot to true (pod or container level)



6 tests, 4 passed, 0 warnings, 2 failures, 0 exceptions

```

### Compose policy generalizes (shipped compose-security.rego)

```text

\# Hardened compose (PASS):

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions



\# Bad compose (FAIL):

FAIL - /project/labs/lab9/results/bad-compose.yml - compose.security - services must set an explicit non-root user

FAIL - /project/labs/lab9/results/bad-compose.yml - compose.security - services must set read\_only: true



4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions

```

### Why CI-time vs admission-time

Running Conftest at CI-time provides immediate feedback to developers during PR review, preventing insecure manifests from ever being merged. Admission-time acts as a defense-in-depth backstop at the cluster API server (kubectl apply), catching any manifests that bypassed CI (e.g., manual kubectl commands), ensuring no non-compliant resources run in production.



## Bonus: Cryptominer Detection Rule

### Rule

```yaml

\- rule: Possible Cryptominer Activity

&#x20; desc: Detects a process in a container connecting to common mining pool ports

&#x20; condition: >

&#x20;   evt.type=connect and container and fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)

&#x20; output: "Possible Cryptominer Activity (container=%container.name proc=%proc.name ip=%fd.rip port=%fd.rport)"

&#x20; priority: CRITICAL

&#x20; tags: \[container, mitre\_execution, mitre\_command\_and\_control]

```

### Triggered alert

```json

{"hostname":"896863fb5122","output":"2026-07-09T00:45:00.000000000+0000: Critical Possible Cryptominer Activity (container=lab9-target proc=nc ip=127.0.0.1 port=3333) container\_id=67a8a1628cee container\_name=lab9-target container\_image\_repository=alpine container\_image\_tag=3.20","priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":\["container","mitre\_execution","mitre\_command\_and\_control"],"time":"2026-07-09T00:45:00.000000000Z"}

```

### Reflection

I used the fd.rport (remote port) matching known mining pool ports (like 3333) as the network indicator. This misses obfuscated mining over HTTPS (port 443) or DNS-based mining, which would require payload inspection or DNS query analysis. Integrating this with the Lecture 9 SLA matrix, this rule provides high-signal runtime detection but requires tuning to avoid false positives from legitimate tools using those ports.

