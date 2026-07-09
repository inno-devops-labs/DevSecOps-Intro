# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

> **Note:** Falco запущен с `-o rule_matching=all`, чтобы кастомные правила срабатывали параллельно со встроенными (по умолчанию `first`). Baseline B: в Falco 0.43.1 правило «Write below monitored directory» удалено — запись в `/usr/local/bin` + запуск бинарника вызвало **Drop and execute new binary in container** (container drift).

### Baseline alert A — Terminal shell in container

```json
{
  "hostname": "3f2e28ef26c1",
  "output": "2026-07-09T13:52:44.225289164+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=36d2c1700354 container_name=lab9-target ...",
  "output_fields": {
    "container.name": "lab9-target",
    "evt.type": "execve",
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
    "proc.name": "sh",
    "proc.tty": 34816,
    "user.name": "root"
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "time": "2026-07-09T13:52:44.225289164Z"
}
```

**Trigger:** `docker exec -t lab9-target /bin/sh -lc 'echo "shell-in-container test"'`

### Baseline alert B — Container drift (write below binary dir)

```json
{
  "hostname": "3f2e28ef26c1",
  "output": "2026-07-09T13:52:44.385762944+0000: Critical Executing binary not part of base image | proc_exe=/usr/local/bin/drift-bin ... process=drift-bin ... container_name=lab9-target ...",
  "output_fields": {
    "container.name": "lab9-target",
    "evt.type": "execve",
    "proc.exe": "/usr/local/bin/drift-bin",
    "proc.name": "drift-bin",
    "proc.cmdline": "drift-bin drift-test"
  },
  "priority": "Critical",
  "rule": "Drop and execute new binary in container",
  "source": "syscall",
  "time": "2026-07-09T13:52:44.385762944Z"
}
```

**Trigger:** `docker exec --user 0 lab9-target /bin/sh -lc 'cp /bin/echo /usr/local/bin/drift-bin && chmod +x /usr/local/bin/drift-bin && /usr/local/bin/drift-bin drift-test'`

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)

```yaml
# Lab 9 — custom Falco rules

- rule: Write to /tmp by container
  desc: Detect writes to /tmp inside any container (not host)
  condition: >
    open_write
    and container
    and fd.name startswith /tmp
  output: >
    Write to /tmp by container (container=%container.name user=%user.name
    file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect known cryptominer process names or mining-pool port connections
  condition: >
    spawned_process
    and container
    and (
      proc.name in (xmrig, ethminer, cgminer, claymore)
      or
      (evt.type=connect and fd.sockfamily=ip and (fd.name endswith ":3333" or fd.name endswith ":4444" or fd.name endswith ":5555" or fd.name endswith ":7777"))
    )
  output: >
    Possible Cryptominer Activity (container=%container.name process=%proc.name
    user=%user.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired

```json
{
  "hostname": "3f2e28ef26c1",
  "output": "2026-07-09T13:52:44.511087456+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) ...",
  "output_fields": {
    "container.name": "lab9-target",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "time": "2026-07-09T13:52:44.511087456Z"
}
```

**Trigger:** `docker exec --user 0 lab9-target /bin/sh -lc 'echo "test" > /tmp/my-write.txt'`

### Tuning consideration (Lecture 9 slide 8)

Правило «write to /tmp» будет шуметь на легитимных приложениях (логи, временные файлы). Для снижения ложных срабатываний добавил бы блок `exceptions:` с `container.image.repository in (trusted_images)` для известных образов, а для конкретных процессов — `and not proc.name in (known_tmp_writers)`. Альтернатива — `and not proc.name in (node, java)` в `condition:`, но `exceptions:` чище: исключения видны отдельно и не раздувают основное условие.

---

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)

```rego
package main

import rego.v1

has_value(arr, v) if {
	some i
	arr[i] == v
}

# 1. runAsNonRoot must be true (pod-level or container-level)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not run_as_non_root(c)
	msg := sprintf("container %q must set runAsNonRoot: true (pod or container securityContext)", [c.name])
}

run_as_non_root(c) if {
	c.securityContext.runAsNonRoot == true
}

run_as_non_root(c) if {
	input.spec.template.spec.securityContext.runAsNonRoot == true
}

# 2. allowPrivilegeEscalation must be false (every container)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" (every container)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not has_value(c.securityContext.capabilities.drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# 5. image must use sha256 digest, not :tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q image must use @sha256: digest pinning, not tag", [c.name])
}
```

### Good manifest passes

```
5 tests, 5 passed, 0 warnings, 0 failures, 0 exceptions
```

### Bad manifest 1 fails (runAsRoot)

```
FAIL - labs/lab9/manifests/bad-pod-runasroot.yaml - main - container "app" must set runAsNonRoot: true (pod or container securityContext)

5 tests, 4 passed, 0 warnings, 1 failure, 0 exceptions
```

### Bad manifest 2 fails (no resources)

```
FAIL - labs/lab9/manifests/bad-pod-no-resources.yaml - main - container "app" missing resources.limits.memory

5 tests, 4 passed, 0 warnings, 1 failure, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

CI-time Conftest в PR даёт разработчику быстрый фидбек до merge — ошибки видны в code review, без доступа к кластеру. Admission-time (Kyverno/Gatekeeper/OPA на API server) — последний рубеж: блокирует уже собранный манифест при `kubectl apply`. Запуск **обоих** — defense in depth: CI ловит 95% проблем дёшево, admission ловит обход CI (прямой apply, compromised pipeline).

---

## Bonus: Cryptominer Detection Rule

### Rule (paste)

См. блок `Possible Cryptominer Activity` в `labs/lab9/falco/rules/custom-rules.yaml` выше.

### Triggered alert

```json
{
  "hostname": "3f2e28ef26c1",
  "output": "2026-07-09T13:52:44.654116405+0000: Critical Possible Cryptominer Activity (container=lab9-target process=ethminer user=root cmdline=ethminer pool-test) ...",
  "output_fields": {
    "container.name": "lab9-target",
    "proc.cmdline": "ethminer pool-test",
    "proc.name": "ethminer",
    "user.name": "root"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "time": "2026-07-09T13:52:44.654116405Z"
}
```

**Trigger:** `docker exec lab9-target /bin/sh -c 'cp /bin/echo /tmp/ethminer && chmod +x /tmp/ethminer && /tmp/ethminer pool-test'` (с `-o rule_matching=all`)

### Reflection (2-3 sentences)

- **Индикаторы:** (1) `proc.name in (xmrig, ethminer, …)` — известные имена майнеров; (2) `connect` на порты 3333/4444/5555/7777 — типичные mining-pool порты. На WSL2 `connect` tracepoint недоступен, поэтому сработал индикатор по имени процесса.
- **False negative:** майнинг через HTTPS/WebSocket на порт 443 или обфусцированный бинарник без известного имени — правило не увидит.
- **SLA matrix (Lecture 9):** CRITICAL-алерт → triage в течение 15 мин, эскалация on-call; в DefectDojo (Lab 10) такие runtime findings получают высший приоритет и короткий SLA на расследование.
