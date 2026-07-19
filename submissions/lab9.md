# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{
  //...
  "output_fields": {
    //...
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    //...
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "runc",
    //...
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": [
    "T1059",
    "container",
    "maturity_stable",
    "mitre_execution",
    "shell"
  ],
  "time": "2026-07-17T08:12:23.072037770Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
  //...
  "output_fields": {
    //...
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    //...
    "fd.name": "/etc/shadow",
    //...
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "proc.name": "cat",
    //...
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-07-17T08:12:33.163894952Z"
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Container modifying system config under /tmp
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Config write in container (container=%container.name user=%user.name 
    file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{
  //...
  "output_fields": {
    //...
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    //...
    "fd.name": "/tmp/my-write.txt",
    //...
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-07-17T08:20:03.590751606Z"
}
```

### Tuning consideration (Lecture 9 slide 8)
To account for legitimate uses I can add
exception clause(s) (`and not proc.name=...`)
to allow certain processes to bypass this rule.

If the list grows too large, I'd switch to using the `exceptions:` block instead
to make the list better structured, easier to audit and configure.

As the last resort, it might be worth to disable the rule altogether if it becomes unmanageable.