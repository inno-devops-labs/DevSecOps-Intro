# Lab 9 — Runtime Detection and Policy as Code

## Task 1 — Runtime detection with Falco

Falco ran with the modern eBPF engine. The engine was checked with:

```bash
docker logs falco 2>&1 | grep -E 'Falco version|Loaded event sources|Enabled event sources|Opening'
```

```text
2026-10-08T06:36:53+0000: Falco version: 0.43.1 (x86_64)
2026-10-08T06:36:53+0000: Loaded event sources: syscall
2026-10-08T06:36:53+0000: Enabled event sources: syscall
2026-10-08T06:36:53+0000: Opening 'syscall' source with modern BPF probe.
```


The two built-in rules were triggered with:

```bash
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
docker exec lab9-target sh -c 'cat /etc/shadow'
sleep 8
docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
```

```text
1 "rule":"Read sensitive file untrusted"
      1 "rule":"Terminal shell in container"
```


| Rule | Trigger |
|---|---|
| `Terminal shell in container` | `docker exec -t lab9-target sh -lc 'echo hello-from-shell'` attached a terminal to a shell in the container. |
| `Read sensitive file untrusted` | `docker exec lab9-target sh -c 'cat /etc/shadow'` opened `/etc/shadow` in the container. |

The JSON alert lines were filtered with:

```bash
docker logs falco 2>&1 | grep 'Terminal shell in container' | tail -1
docker logs falco 2>&1 | grep 'Read sensitive file untrusted' | tail -1
```

Raw Falco JSON alert lines:

```json
{"hostname":"78f63e9936ad","output":"2026-10-07T07:21:01.871149301+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=7b2fe2ae802f container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"7b2fe2ae802f","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.time.iso8601":1791357661871149301,"evt.type":"execve","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo hello-from-shell","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"systemd","proc.tty":34816,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-10-07T07:21:01.871149301Z"}
{"hostname":"78f63e9936ad","output":"2026-10-07T07:21:02.061048854+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=7b2fe2ae802f container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"7b2fe2ae802f","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1791357662061048854,"evt.type":"open","fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,"proc.aname[2]":"systemd","proc.aname[3]":null,"proc.aname[4]":null,"proc.cmdline":"cat /etc/shadow","proc.exepath":"/bin/busybox","proc.name":"cat","proc.pname":"containerd-shim","proc.tty":0,"user.loginuid":-1,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-10-07T07:21:02.061048854Z"}
```

The custom rule file is `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Write to /tmp by container
  desc: Detect writes under /tmp from inside a container
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Container wrote below /tmp
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect likely mining activity from a container
  condition: >
    evt.type=connect and
    container.id != host and
    ((evt.arg.addr contains ":3333" or
      evt.arg.addr contains ":4444" or
      evt.arg.addr contains ":5555" or
      evt.arg.addr contains ":7777" or
      evt.arg.addr contains ":14444") or
     proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer connection
    (container=%container.name process=%proc.name destination=%evt.arg.addr result=%evt.arg.res command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

The `/tmp` rule was reloaded and triggered with:

```bash
docker kill --signal=SIGHUP falco && sleep 5
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
sleep 6
docker logs falco 2>&1 | grep -c '"rule":"Write to /tmp by container"'
docker logs falco 2>&1 | grep 'Write to /tmp by container' | tail -1
```

```text
1
```

```json
{"hostname":"d22664480c7b","output":"2026-10-09T17:50:33.967194416+0000: Warning Container wrote below /tmp (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=49896b897783 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"49896b897783","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.time.iso8601":1791568233967194416,"fd.name":"/tmp/my-write.txt","k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-10-09T17:50:33.967194416Z"}
```


One incident-relevant JSON field that is not in the human-readable `output` message is `tags`; for this alert it includes `container` and `drift`, which helps route the event as container drift. A legitimate workload such as a test runner, installer, or application cache can write temporary files under `/tmp` and trigger this rule. The detection can be tuned narrowly with an `exceptions:` block or a condition like `and not proc.name=<known-safe-process>` for a specific expected process, reducing repeated noise while preserving alerts for unexpected `/tmp` writes from other commands or containers.

## Task 2 — The same rule, before deployment

The shipped Kubernetes policy was tested with:

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/k8s-security.rego --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/k8s-security.rego --all-namespaces
```

It passed on the hardened manifest and failed on the unhardened manifest:

```text
22 tests, 22 passed, 0 warnings, 0 failures, 0 exceptions
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

22 tests, 12 passed, 2 warnings, 8 failures, 0 exceptions
```

The shipped Compose policy was tested with:

```bash
conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies/compose-security.rego --all-namespaces
```

It passed on the provided Compose file:

```text
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```


Two Kubernetes failures mapped to `labs/lab9/policies/k8s-security.rego` are:

| Failure | Rego rule |
|---|---|
| `container "juice" uses disallowed :latest tag` | `deny contains msg` with `endswith(c.image, ":latest")` |
| `container "juice" must set allowPrivilegeEscalation: false` | `deny contains msg` checking `allowPrivilegeEscalation == false` |

The same requirement needs separate Compose and Kubernetes rules because the schemas are different: Kubernetes uses `spec.template.spec.containers`, while Compose uses `services`. The valid Compose file passing shows the policy can recognize a compliant file, not only produce failures.

The extra policy file is `labs/lab9/policies/extra/hardening.rego`:

```rego
package k8s.extra

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run as privileged", [c.name])
}

warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.hostNetwork == true
  c := input.spec.template.spec.containers[_]
  msg := sprintf("container %q should not use hostNetwork", [c.name])
}
```

The manifest written to violate the extra policy was:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: violates-extra-policy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: violates-extra-policy
  template:
    metadata:
      labels:
        app: violates-extra-policy
    spec:
      hostNetwork: true
      containers:
        - name: juice
          image: bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            privileged: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          ports:
            - containerPort: 3000
          readinessProbe:
            httpGet:
              path: /
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 20
```

The extra policy was tested with:

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test /tmp/violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
```

It passed on the hardened Kubernetes manifest and failed on the manifest written to violate it:

```text
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions
WARN - /tmp/violates-my-policy.yaml - k8s.extra - container "juice" should not use hostNetwork
FAIL - /tmp/violates-my-policy.yaml - k8s.extra - container "juice" must not run as privileged

17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
```


CI is the preferred enforcement point if only one can be kept, because it gives early feedback before the deployment reaches the cluster. Admission-time enforcement is still useful because it protects the real cluster if someone bypasses CI or applies YAML manually. Together they provide defense in depth: CI catches the issue early, and admission control is the last gate before workload creation.

## Bonus — Catch a cryptominer

The bonus rule is included in `labs/lab9/falco/rules/custom-rules.yaml` as `Possible Cryptominer Activity`. It uses two independent indicators: a destination using a common mining-pool port, or a known miner process name such as `xmrig`, `ethminer`, `cgminer`, `t-rex`, or `claymore`. In this lab, `nc` was used only to generate a `connect` syscall toward `127.0.0.1:3333`; the rule fired because of the destination port, not because `nc` is treated as a miner process.

The bonus trigger and alert check were:

```bash
docker kill --signal=SIGHUP falco && sleep 5
docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
sleep 6
docker logs falco 2>&1 | grep -c 'Possible Cryptominer Activity'
docker logs falco 2>&1 | grep 'Possible Cryptominer Activity' | tail -1
```

The rule produced one critical alert:

```text
1
```

```json
{"hostname":"4080e99d1a5e","output":"2026-10-09T15:32:41.341171767+0000: Critical Possible cryptominer connection (container=lab9-target process=nc destination=127.0.0.1:3333 result=ECONNREFUSED command=nc -w 2 127.0.0.1 3333) container_id=dbf49718a958 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"dbf49718a958","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.addr":"127.0.0.1:3333","evt.arg.res":"ECONNREFUSED","evt.time.iso8601":1791559961341171767,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"nc -w 2 127.0.0.1 3333","proc.name":"nc"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-10-09T15:32:41.341171767Z"}
```


A refused connection is enough because Falco observes the `connect` syscall attempt. The event still included `destination=127.0.0.1:3333` and `result=ECONNREFUSED`, so the rule fired before any successful application session existed. This shows Falco is watching runtime/kernel events.

### Reflection

Mining-pool destination ports and known miner process names were selected because they are complementary runtime indicators that Falco can observe directly. A false negative could occur if an attacker changes both the process name and destination port, so DNS, CPU, and suspicious-binary signals would improve coverage. Because this alert is `Critical`, the Lecture 9 SLA matrix applies: 24h fix SLA, `On-call + Security Lead` ownership, and `Page on creation`.
