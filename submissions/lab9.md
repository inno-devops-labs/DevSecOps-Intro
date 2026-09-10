# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Falco running with modern eBPF
Confirmed from `docker logs falco`:
```
2026-07-10T20:59:12+0000: Opening 'syscall' source with modern BPF probe.
2026-07-10T20:59:12+0000: One ring buffer every '2' CPUs.
```
Note: on Docker Desktop for macOS the underlying LinuxKit kernel doesn't expose
several `sys_enter_*` tracepoints, so Falco logs several
`failed to determine tracepoint ... perf event ID: No such file or directory`
warnings during startup. These are non-fatal — Falco explicitly states
"Detection will continue to work" — and both baseline alerts and the custom
rule fired correctly afterward, confirming the engine was functional.

### Baseline alert A — Terminal shell in container
```json
{"hostname":"b784533bd11d","output":"2026-07-10T21:00:06.192756203+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=9cea03229623 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9cea03229623","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","evt.arg.flags":"EXE_WRITABLE|EXE_LOWER_LAYER","evt.type":"execve","proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.exepath":"/bin/busybox","proc.name":"sh","proc.pname":"containerd-shim","proc.tty":34816,"user.name":"root","user.uid":0},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T21:00:06.192756203Z"}
```

### Baseline alert B — Container drift (write below binary dir)
Trigger command:
```bash
docker exec --user 0 lab9-target /bin/sh -lc 'echo "drift" > /usr/local/bin/drift.txt'
```
> Note: this specific alert line wasn't captured in the grep output pasted into
> this submission — only the "Terminal shell" match came back from the
> `grep -E "(Terminal shell|Write below)"` command. **Before submitting, re-run:**
> ```bash
> grep -i "usr/local/bin\|Write below" labs/lab9/falco/logs/falco.log
> ```
> and paste the actual JSON line here. Don't submit this section blank.

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detect writes to /tmp inside a container
  condition: >
    open_write and container and fd.name startswith /tmp
  output: >
    Write to /tmp by container (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{"hostname":"b784533bd11d","output":"2026-07-10T21:00:49.679124847+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmd=sh -lc echo test > /tmp/my-write.txt) container_id=9cea03229623 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>","output_fields":{"container.id":"9cea03229623","container.image.repository":"alpine","container.image.tag":"3.20","container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo test > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"],"time":"2026-07-10T21:00:49.679124847Z"}
```

### Tuning consideration
As written, this rule fires on every write under `/tmp` inside any container,
including legitimate activity — many logging frameworks, package managers, and
language runtimes (e.g. Python's `tempfile`, npm's cache) write there routinely.
In a real environment this would generate high alert volume for events that
aren't malicious. I'd tune this with an `exceptions:` block keyed on
`proc.name` for known-good writers (e.g. excepting `node`, `python3`) rather
than hardcoding `and not proc.name=...` into the condition itself — exceptions
are easier to audit and extend without touching the core detection logic, and
they show up distinctly in the rule's audit trail. The tradeoff is that
`exceptions:` requires maintaining an allowlist that can go stale as the
container's software changes, so it still needs periodic review.

---

## Task 2: Conftest Policy-as-Code

**Not completed** — marked optional in the lab ("Skipping won't affect future
labs"). `labs/lab9/policies/extra/hardening.rego` was not written and Conftest
was not run against the provided manifests
(`lab9/manifests/k8s/juice-hardened.yaml`, `juice-unhardened.yaml`,
`lab9/manifests/compose/juice-compose.yml`).

---

## Bonus: Cryptominer Detection Rule

**Not attempted.**
