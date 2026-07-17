# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- **Host kernel:**

```text
Linux DESKTOP-PDSBGHH 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

- **KVM accessible:**

```text
crw-rw---- 1 root kvm 10, 232 Jul 17 15:43 /dev/kvm
KVM acceleration can be used
```

- **containerd version:**

```text
containerd github.com/containerd/containerd/v2 2.2.1
```

- **nerdctl version:**

```text
nerdctl version 2.3.4
```

### Kata installation

- **Kata version:** `3.32.0`

The host uses containerd 2.2.1 with the version 3 CRI configuration layout.

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

The Kata shim is available through:

```text
/usr/local/bin/containerd-shim-kata-v2 -> /opt/kata/bin/containerd-shim-kata-v2
```

The Kata host check reported:

```text
System is capable of running Kata Containers
System can currently create Kata Containers
```

### Kernel inside containers

**runc:**

```text
Linux 4151a1c38fd7 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 5 18:30:46 UTC 2025 x86_64 Linux
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25
```

**Kata:**

```text
Linux 314f3719dd73 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25
```

### Why the kernel differs

A regular runc container shares the host's WSL2 Linux kernel, which is why the
host and runc container both report kernel `6.6.87.2-microsoft-standard-WSL2`.
Kata starts the workload inside a lightweight virtual machine with its own guest
kernel, which reports version `6.18.35`. As discussed in Reading 12 and Lecture 7,
this additional hypervisor boundary reduces direct exposure of the host kernel
and container runtime to runc escape vulnerability classes such as
CVE-2024-21626, although it does not eliminate every possible attack.

---

## Task 2: Isolation + Performance

### Isolation: `/dev` comparison

```diff
--- runc-devs.txt
+++ kata-devs.txt
@@ -1,4 +1,3 @@
-core
 fd
 full
 mqueue
```

The runc container exposed the `/dev/core` compatibility link, while it was not
present in the Kata guest. Most standard pseudo-devices were available in both
environments.

### Isolation: capability sets

**runc:**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

**Kata:**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

The capability bitmaps were identical in this experiment. This demonstrates
that Linux capabilities describe permissions inside the container environment,
but do not by themselves show Kata's principal isolation mechanism. Kata's main
security boundary is the separate guest kernel and micro-VM, rather than a
different default capability mask.

### Startup benchmark

Five measured runs produced the following results:

```text
runc run 1: 0.772950203 s
runc run 2: 0.625171033 s
runc run 3: 0.653670532 s
runc run 4: 0.685911737 s
runc run 5: 0.678398917 s

kata run 1: 2.181425961 s
kata run 2: 0.373159042 s
kata run 3: 1.985170394 s
kata run 4: 1.850029085 s
kata run 5: 1.940046188 s
```

| Runtime | Average startup |
|---------|----------------:|
| runc | 0.683220 s |
| Kata | 1.665966 s |

**Measured Kata startup overhead: approximately 2.44×.**

The unusually fast second Kata result demonstrates that VM startup measurements
can vary because of caching and warm runtime state. Nevertheless, the average
still shows a clear startup cost compared with runc.

### I/O benchmark

The test copied 100 MB from `/dev/zero` to `/dev/null`.

| Runtime | Time | Reported throughput |
|---------|-----:|--------------------:|
| runc | 0.002893 s | 33.8 GB/s |
| Kata | 0.003562 s | 27.4 GB/s |

Kata achieved approximately 81% of the runc throughput in this synthetic test,
or about 19% lower reported throughput.

### Trade-off analysis

I would deploy Kata for multi-tenant CI runners, untrusted build jobs, plugin
execution, or SaaS workloads where different customers' code runs on the same
host. In those environments, the separate guest kernel provides a meaningful
containment boundary if a container runtime or guest kernel is compromised. I
would not necessarily use Kata for trusted single-tenant batch jobs where startup
latency and operational simplicity matter more than an additional isolation
layer. The decision should therefore depend on workload trust, tenant separation,
performance requirements, and the consequences of a container escape.

---

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B — privileged-container host write.
- **Why:** This vector is reproducible without installing a deliberately
  vulnerable historical version of runc. It demonstrates the danger of granting
  a container both privileged mode and a writable host bind mount.

### runc: host write succeeds

Command:

```bash
sudo nerdctl run --rm \
  --privileged \
  -v /tmp:/host_tmp \
  alpine:3.20 \
  sh -c '
    printf "%s\n" "OVERWRITTEN BY RUNC CONTAINER" \
      > /host_tmp/lab12-target
    cat /host_tmp/lab12-target
  '
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

Host-side verification:

```text
OVERWRITTEN BY RUNC CONTAINER
```

The verification was performed from the host after the container had exited,
confirming that the runc container modified the host file.

### Kata: same privileged attempt is blocked

Before the Kata test, the host file was reset to:

```text
original
```

Command:

```bash
sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  --privileged \
  -v /tmp:/host_tmp \
  alpine:3.20 \
  sh -c '
    printf "%s\n" "ATTEMPTED OVERWRITE FROM KATA" \
      > /host_tmp/lab12-target
    cat /host_tmp/lab12-target
  '
```

Relevant Kata output:

```text
warning: cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"

failed to create shim task: Creating container device LinuxDevice {
  path: "/dev/full",
  typ: C,
  major: 1,
  minor: 7
}

Caused by:
EEXIST: File exists
```

Kata attempt exit code:

```text
1
```

Host-side verification after the failed attempt:

```text
original
```

In this environment, the Kata runtime rejected the privileged container during
guest-device creation, before the workload could modify the target file. The
result therefore demonstrates that the exact privileged attempt which modified
the host under runc did not reach the host under Kata. It is important to state
that this particular result was caused by the Kata device-setup failure rather
than claiming that the write successfully occurred only inside the guest.

### Threat-model implication

Kata normally places the container process and its kernel-facing operations
inside a separate micro-VM, adding a hypervisor boundary between untrusted code
and the host kernel. This is valuable for multi-tenant CI runners and
misconfigured Kubernetes workloads where a privileged container could otherwise
have severe host impact. In this test, runc modified the host file, while the
same Kata invocation failed and the independently verified host file remained
unchanged. However, this experiment does not prove that every explicitly shared
host directory is harmless, and Kata does not prevent every class of attack,
including kernel or hardware side channels, cross-tenant timing attacks, and
vulnerabilities in the hypervisor or file-sharing implementation.

---

## Conclusion

Kata Containers successfully ran the Alpine workload using a kernel different
from the host kernel. Compared with runc, Kata introduced approximately 2.44×
average startup overhead and moderately lower synthetic I/O throughput, while
providing a separate VM-backed isolation boundary. The privileged host-write
test modified the host under runc, whereas the same Kata invocation failed and
left the host target unchanged.
