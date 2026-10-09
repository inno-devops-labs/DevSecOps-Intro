# Lab 9 - Runtime Detection and Policy as Code


## Task 1

"Read sensitive file untrusted" triggered by `docker exec lab9-target sh -c 'cat /etc/shadow'`.

"Terminal shell in container" triggered by `docker exec -t lab9-target sh -lc 'echo hello-from-shell'`. 



```json
{
    "hostname": "3e7a9a5b2965",
    "output": "2026-10-09T13:28:22.743754690+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=b1c7c31d515c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "b1c7c31d515c",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
        "evt.time.iso8601": 1791552502743754690,
        "evt.type": "execve",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "sh -lc echo hello-from-shell",
        "proc.exepath": "/bin/busybox",
        "proc.name": "sh",
        "proc.pname": "containerd-shim",
        "proc.tty": 34816,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
    "time": "2026-10-09T13:28:22.743754690Z"
} 
{
    "hostname": "3e7a9a5b2965",
    "output": "2026-10-09T13:28:22.794880720+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=b1c7c31d515c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "b1c7c31d515c",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1791552502794880720,
        "evt.type": "open",
        "fd.name": "/etc/shadow",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.aname[2]": "systemd",
        "proc.aname[3]": null,
        "proc.aname[4]": null,
        "proc.cmdline": "cat /etc/shadow",
        "proc.exepath": "/bin/busybox",
        "proc.name": "cat",
        "proc.pname": "containerd-shim",
        "proc.tty": 0,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
    "time": "2026-10-09T13:28:22.794880720Z"
}
```

Custom rule:

```yaml
- rule: Write to tmp in container
  desc: Detects any file write to /tmp inside a container, which may indicate drift or staging of malicious content
  condition: >
    open_write
    and container.id != "host"
    and fd.name startswith "/tmp/"
  output: >
    Container /tmp write detected
    (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```


```json
{
    "hostname": "3e7a9a5b2965",
    "output": "2026-10-09T13:25:25.529637405+0000: Warning Container /tmp write detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt) container_id=b1c7c31d515c container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "b1c7c31d515c",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1791552325529637405,
        "fd.name": "/tmp/my-write.txt",
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
        "user.name": "root"
    },
    "priority": "Warning",
    "rule": "Write to tmp in container",
    "source": "syscall",
    "tags": ["container", "drift"],
    "time": "2026-10-09T13:25:25.529637405Z"
} 
```

Non-human-readable incedent-relevant json field: `evt.time.iso8601`: `1791552325529637405`. it is the nanosecond unix time stamp, useful for correlating and comparing processes that happened within milliseconds

The legitimate workloads that will get flagged are for example ci jobs that generate object files at tmp with make or jvm apps storing jit code. one of the options is to add conditionals to exclude legitimate processes. however the best refinement would be to alert when a tmp file is executed, which can be a separate rule rather than by modifying the current condition.



## Task 2


Hardened - 30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

Unhardened - 30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions

Compose - 15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions



container "juice" uses disallowed :latest tag:
```
deny contains msg if 
{ 
    input.kind == "Deployment"; 
    c := input.spec.template.spec.containers[_]; 
    endswith(c.image, ":latest"); 
``` 
k8s-security.rego

container "juice" must set runAsNonRoot: true:
```
deny contains msg if 
{ 
    input.kind == "Deployment"; 
    c := input.spec.template.spec.containers[_]; 
    not c.securityContext.runAsNonRoot; 
``` 
k8s-security.rego


policy and violation
```
package k8s.security

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %q image must be pinned by digest (@sha256:), not a mutable tag", [c.name])
}

warn contains msg if {
    input.kind == "Deployment"
    not input.spec.template.spec.automountServiceAccountToken == false
    msg := "Deployment should set automountServiceAccountToken: false to prevent unneeded API access"
}

apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-violates
spec:
  replicas: 1
  selector:
    matchLabels: { app: juice }
  template:
    metadata:
      labels: { app: juice }
    spec:
      automountServiceAccountToken: true
      containers:
        - name: juice
          image: bkimminich/juice-shop:v20.0.0
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "100m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          readinessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 10
            periodSeconds: 20

WARN - labs/lab9/manifests/k8s/juice-hardened.yaml - k8s.security - Deployment should set automountServiceAccountToken: false to prevent unneeded API access

34 tests, 33 passed, 1 warning, 0 failures, 0 exceptions
WARN - /tmp/violates-my-policy.yaml - k8s.security - Deployment should set automountServiceAccountToken: false to prevent unneeded API access
FAIL - /tmp/violates-my-policy.yaml - k8s.security - container "juice" image must be pinned by digest (@sha256:...), not a mutable tag

17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
```


I would keep the conftest rule in CI, image-digest pinning is preventive, conftest in CI blocks the deploy before reaching cluster, while falco rule would fire after allowing it to pass. However falco catches images that reach the cluster through paths not covered by ci, giving runtime visibility on the gap between what CI checked and what is running.


## Bonus

```
- rule: Likely cryptomining outbound connection
  desc: Detects an outbound TCP connection to a common mining pool port from inside a container
  condition: >
    evt.type = connect
    and container.id != "host"
    and fd.rport in (3333, 4444, 5555, 7777, 14444)
  output: >
    Likely cryptomining connection from container
    (container=%container.name process=%proc.name dest=%fd.rip:%fd.rport cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_command_and_control, T1496]
```

```json
{
    "hostname": "33e0b0ca261a",
    "output": "2026-10-09T13:28:22.743754690Z+0000: Critical Likely cryptomining connection from container (container=lab9-target process=nc dest=8.8.8.8:3333 cmdline=nc -zw 2 8.8.8.8 3333) container_id=583d2dcec504 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "output_fields": {
        "container.id": "b1c7c31d515c",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.time.iso8601": 1791552502794880720,
        "fd.rip": "8.8.8.8",
        "fd.rport": 3333,
        "k8s.ns.name": null,
        "k8s.pod.name": null,
        "proc.cmdline": "nc -zw 2 8.8.8.8 3333",
        "proc.name": "nc"
    },
    "priority": "Critical",
    "rule": "Likely cryptomining outbound connection",
    "source": "syscall",
    "tags": ["T1496", "container", "mitre_command_and_control"],
    "time": "2026-10-09T13:28:22.743754690Z"
}
```


Falco hooks the `connect` syscall at the kernel level, before the TCP handshake completes. The kernel delivers the `connect` event the moment the process issues the syscall — whether the remote host accepts the connection or refuses it (RST) or times out is irrelevant. The attacker's process had to call `connect`; that syscall is observable regardless of what the remote end does. This is what it means that Falco sits inside the kernel: it sees the attempt, not the outcome.


The cheap part to evade is the destination port: a miner that connects to port 443 (TLS-wrapped Stratum) or a port not in this list costs the attacker nothing to change. The expensive part is the combination of a network connection from inside a container and a CPU-intensive process: if the miner is actually running, it will show up in `proc.cpu.usage` and in the burst of threads. Adding a second signal makes the evasion progressively harder: the attacker has to rename their binary, cap their CPU, and randomize their port, which reduces profitability. A practical addition is a Falco rule on `execve` of any process whose name matches known mining binaries, regardless of network activity, which catches miners started but not yet connected.