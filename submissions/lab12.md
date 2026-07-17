# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux Ruslan 6.6.87.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Mon Apr 21 17:08:54 UTC 2025 x86_64 GNU/Linux` (WSL2 on Windows 11, KVM nested virtualization enabled)
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 Jul 17 18:19 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd v1.7.22 7f7fdf5fed64eb6a7caf99b3e12efcf9d60e311c`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  privileged_without_host_devices = true
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
Linux 16a5de94701a 6.6.87.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Mon Apr 21 17:08:54 UTC 2025 x86_64 Linux
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25

**kata:**
Linux 4045e5a5adef 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25

### Why the kernel differs (Reading 12)
The runc container shares the host's kernel directly — namespaces and cgroups isolate the process view, but syscalls still land on the same kernel instance as the host (6.6.87.1-microsoft-standard-WSL2 in both cases). Kata instead boots a minimal guest kernel (6.18.35) inside a dedicated micro-VM via the Dragonball hypervisor, so the container's syscalls are handled by a completely separate kernel that only the guest touches.

This directly maps to CVE-2024-21626 ("Leaky Vessels"): that class of runc bugs works because a container process can, through a file-descriptor leak, reach into the *host's* runc/kernel process space and escape into the same kernel the host itself is running. Since Kata's guest kernel is a physically separate kernel instance running under KVM, a leaked FD or process-namespace escape inside the Kata guest still only lands you in the guest kernel — there is no host kernel process space to leak into in the first place, so this entire CVE class doesn't apply to Kata containers by construction.

## Task 2: Isolation + Performance

### Isolation: /dev diff
1d0
< core
The only difference is `/dev/core` (typically a symlink to `/proc/kcore`, i.e. a raw view of kernel memory) present under runc but absent under Kata — Kata's guest `/proc` has no such handle onto host kernel memory since it isn't the host's `/proc` at all.

### Isolation: capability sets
runc:
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
kata:
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

The raw capability bitmasks are identical, since containerd applies the same default capability set regardless of runtime. The real isolation difference isn't in *which* capabilities are granted, but in *what they act on*: under runc these capabilities (e.g. `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) operate directly on the host kernel's namespaces and devices, while under Kata the identical capability bits only give the process full control over the guest kernel inside the micro-VM — they cannot reach host kernel state at all.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.780 |
| kata | 2.527 |

**Overhead: ~3.2× cold start** (lower than Reading 12's ~5× reference figure, likely because Kata here uses the lightweight Dragonball hypervisor rather than full QEMU)

Raw runs — runc: 0.867, 0.733, 0.796, 0.783, 0.720 s. kata: 2.579, 2.672, 2.477, 2.456, 2.449 s.

### I/O throughput (100MB dd, /dev/zero → /dev/null)
| Runtime | Throughput |
|---------|-----------|
| runc | 18.5 GB/s |
| kata | 15.2 GB/s |

### Trade-off analysis
Kata's ~3.2× cold-start overhead and near-native CPU/synthetic-I/O throughput mean the cost is mostly paid once, at container start, not throughout the workload's life. That makes the isolation gain worth it for **multi-tenant CI runners or SaaS platforms executing untrusted, arbitrary customer code**, where a single kernel-level runc escape (like CVE-2024-21626) could compromise every other tenant on the host — the extra ~1.7s startup is a rounding error next to that blast-radius reduction. It is **not** worth it for **short-lived, high-throughput, single-tenant batch jobs** (e.g. an internal nightly ETL job running trusted, first-party code on a dedicated host) — there the workload is already fully trusted, so paying a 3× startup tax and losing some raw I/O throughput on every invocation buys no meaningful additional security.

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (privileged-container host write)
- **Why:** Simplest to set up reproducibly without needing a deliberately-vulnerable old runc build or a cgroup v1 host, and the underlying misconfiguration (`--privileged` + broad bind mount) is the most common real-world root cause of container escapes.

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:
OVERWRITTEN BY RUNC CONTAINER

Host verification:
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER

### Kata: same command also succeeds — and here's why that's the honest, more important finding

Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged \
  --security-opt privileged-without-host-devices -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"'
```

Container output:
ATTEMPTED OVERWRITE FROM KATA
---host view---

Host verification:
$ sudo cat /tmp/lab12-target
ATTEMPTED OVERWRITE FROM KATA

**This bonus's expected result (Kata blocks it) does not actually hold for vector B, and it's worth being explicit about why.** A `-v /tmp:/host_tmp` bind mount is an *operator-granted, explicit* share of a host directory. Kata's virtio-fs/9p layer is specifically designed to transparently reflect writes in that shared directory back to the real host path — that's the entire point of a bind mount, and it works identically to runc's bind mount because both are honoring the same explicit configuration the operator (me) supplied. `--privileged` here only controls in-guest capabilities and device access; it has no bearing on whether an *intentionally* shared bind-mounted directory is writable — of course it is, on both runtimes.

Along the way, `--privileged` on Kata additionally required the `privileged_without_host_devices` mitigation (containerd config, for CRI-managed workloads) or nerdctl's own `--security-opt privileged-without-host-devices` flag (needed here since nerdctl talks to containerd directly, bypassing the CRI plugin). Without it, Kata tries to hot-plug every host block device into the guest and fails outright with an `EEXIST` on `/dev/full`, because that device path already exists by default in the guest's own `/dev`. That failure mode is itself informative: Kata's *default* privileged behavior tries to expose real host block devices to the guest (a deliberate, documented weakening of isolation for legacy compatibility), and the safer default has to be turned on explicitly.

### Threat model implication
- Kata's actual isolation boundary is the **kernel**, not shared storage: it blocks escapes that rely on a container process reaching into the *host kernel's* process/memory space (CVE-2019-5736, cgroup v1 `release_agent` writes such as CVE-2022-0492, `/dev/kcore` reads), because the guest simply runs a different, physically separate kernel under KVM. A bind mount is not part of that threat model — it's explicit, intentional shared storage, and any container runtime will honor it by design.
- The real-world takeaway: Kata protects a multi-tenant CI runner or Kubernetes cluster against a compromised container using an *unintended* kernel-level bug to pivot into the host or other tenants. It does **not** protect against a misconfigured pod that was handed a bind mount (or hostPath volume) it shouldn't have had — that's an access-control/configuration problem, not a kernel-isolation problem, and no VM-based runtime fixes bad volume grants.
- What Kata does *not* block regardless: pure side-channel attacks against the physical CPU/cache shared across guest and host (cross-tenant timing attacks), and, as shown above, any data reachable through explicitly-granted shared mounts. Reading 12's Confidential Containers section addresses the side-channel/memory-confidentiality gap; the bind-mount gap is addressed by not granting broad host-path mounts to untrusted workloads in the first place.
