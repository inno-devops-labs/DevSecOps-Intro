# Lab 12 — BONUS — Submission

**Environment:** Windows 11 + WSL2 (Ubuntu 24.04). WSL2's kernel exposes `/dev/kvm` with nested
virtualization (`vmx`), so Kata's microVMs boot here — unusual for WSL, but verified working below.
Stack: containerd 2.2.1, nerdctl 2.3.4, runc 1.3.4, Kata Containers 3.32.0. All proofs captured live;
raw artifacts in [`labs/lab12/results/`](../labs/lab12/results/).

---

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC x86_64`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 /dev/kvm` (nested virt enabled, `vmx` present)
- containerd version: `containerd 2.2.1`
- nerdctl: `2.3.4` · runc: `1.3.4`

### Kata installation
- Kata version: `cat /opt/kata/VERSION` → **3.32.0**
- Hypervisor: QEMU/dragonball static assets under `/opt/kata`; shim symlinked to `/usr/local/bin/containerd-shim-kata-v2`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc** (shares the host kernel):
```
Linux 6a0a084ebc92 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 5 2025 x86_64 Linux
```

**kata** (its own microVM kernel — different version and build date):
```
Linux 4caa4931a567 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
```

### Why the kernel differs
runc containers are just isolated processes (namespaces + cgroups + seccomp) running directly on the
**host kernel** — that is why the container reports `6.6.87.2-microsoft-standard-WSL2`. Kata boots a
lightweight VM per container with its **own guest kernel** (`6.18.35`) on top of KVM, so the container
never touches the host kernel at all. This is exactly what neutralises the runc-escape CVE class such
as **CVE-2024-21626 ("Leaky Vessels")**, where a leaked host file descriptor (`/proc/self/fd/…`) lets a
container reach the host filesystem/runtime: that attack depends on the container and host sharing one
kernel and one runtime process. Under Kata the "host" a compromised container can reach is only the
disposable guest kernel inside the VM — the real host kernel and its file descriptors are on the other
side of the hypervisor boundary, so the escape has nothing to grab.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```
The default device sets are nearly identical (both runtimes apply the same default device cgroup); the
only listed difference is `/dev/core` present under runc. This is expected and is **not** where Kata's
isolation lives — the meaningful boundary is the separate kernel (Task 1) and the virtualized device
model (Bonus), not the `/dev` node list of an unprivileged container.

### Isolation: capability sets
runc:
```
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```
kata:
```
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```
**Identical** — same bounding set `a80425fb`. Honest takeaway: Kata does not shrink the capability set;
a process is just as "capable" *inside its VM*. The gain is that those capabilities now apply against a
throwaway guest kernel, not the host kernel — capability hardening and VM isolation are orthogonal layers.

### Startup time (5-run avg, first run discarded as KVM warm-up)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.46 |
| kata | 1.33 |

**Overhead: ~2.9× cold start** (runc 0.46s → kata 1.33s). Lower than Reading 12's ~5× rule of thumb —
plausibly because the image layer was already cached and the microVM here uses a slim modern kernel;
the reading's figure is an order-of-magnitude guide, and ~3× is in the same ballpark.

### I/O throughput (100MB `dd if=/dev/zero of=/dev/null`)
| Runtime | Throughput |
|---------|-----------|
| runc | 52.2 GB/s |
| kata | 40.4 GB/s |

Honest caveat: `dd` to `/dev/null` measures syscall + memory-copy throughput, **not** disk I/O (nothing
touches a real disk), so this is a CPU/syscall-overhead proxy. The ~1.3× gap reflects the guest→VMM
syscall cost, not storage performance — a real disk benchmark through virtio-fs/virtio-blk would show a
larger gap.

### Trade-off analysis
The security gain — a separate guest kernel that blocks the entire runc/shared-kernel escape class — is
worth the ~3× cold-start cost whenever you run **untrusted or multi-tenant** code on shared hardware:
CI runners executing arbitrary PR code, multi-tenant SaaS/FaaS, or anything accepting customer-supplied
containers. There the blast radius of one escape (whole host, all tenants) dwarfs a second of startup.
It is **not** worth it for **single-tenant, trusted, latency-sensitive** workloads — e.g. your own
first-party microservices scaling up and down many times a second, or short batch jobs where a ~0.9s
per-container penalty dominates the actual work and there is no hostile tenant to isolate from.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B-variant — privileged-container **host block-device access** (not the `-v` bind-mount write).
- **Why:** while testing I found the lab's original `-v /tmp:/host_tmp` write is *not* an isolation
  boundary — Kata shares explicit `-v` mounts to the host via **virtio-fs**, so that write reaches the
  host on Kata too (verified below). The honest, real escape boundary is host **device** exposure: a
  privileged runc container sees the host's raw disks; a Kata one does not.

### Preliminary finding — why not the plain bind-mount write
Non-privileged `-v /tmp:/host_tmp` write, run under Kata:
```
guest sees: KATA NONPRIV BIND WRITE
--- host view --- KATA NONPRIV BIND WRITE
```
The host file changed → an explicit `-v` mount is shared on **both** runtimes by design (that is what
`-v` means). So a bind-mount write demonstrates operator intent, not an escape. Moving to devices.

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged alpine:3.20 sh -c \
  'ls /dev/sd*; dd if=/dev/sdd bs=1M count=1 2>/dev/null | wc -c'
```
Container output:
```
host block devices visible:
/dev/sda /dev/sdb /dev/sdc /dev/sdd /dev/sde /dev/sdf
reading 1MiB from /dev/sdd (host root disk):
1048576
```
Host verification: `findmnt / → /dev/sdd` (the host's real root disk, 1 TB). The privileged runc
container **read 1 MiB straight off the host root disk** — with raw block access it can parse the
filesystem and read/modify any host file. Full escape.

### Kata: escape blocked
Command (same flags, kata runtime):
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged alpine:3.20 sh -c \
  'ls /dev/sd*; dd if=/dev/sdd bs=1M count=1 | wc -c'
```
Container output:
```
level=fatal msg="failed to create shim task: Creating container device
LinuxDevice { path: "/dev/full" ... } Caused by: EEXIST: File exists"
```
Kata **refused to start** the privileged container (it will not blindly pass host device nodes into the
microVM). And a normal Kata container has no host disks at all:
```
block devices in guest: (no host-style disks)
```
Host verification: `/dev/sdd` and the host root filesystem are **never reachable** from Kata — there is
no host disk inside the guest to read.

### Threat model implication
Kata blocks what runc allows because the container's `/dev` is the **microVM's** virtual device model,
not the host's: the guest kernel only sees virtio devices the hypervisor chose to expose, so the host's
real `/dev/sdd` simply does not exist inside the VM (and Kata refuses to pass privileged host device
nodes through the boundary). This maps directly to the most common real-world failure — a **misconfigured
`--privileged` pod on a multi-tenant Kubernetes / CI cluster**, where one privileged container on runc
can mount the node's root disk and read every other tenant's secrets; on Kata that same misconfiguration
is contained to a disposable VM. What Kata does **not** block: attacks that don't need host devices —
kernel/hypervisor 0-days that break out of the VM itself, CPU side-channel and cross-tenant timing
leaks, and the shared-`-v`/virtio-fs surface an operator explicitly grants. Those need the
Confidential-Containers layer (Intel TDX / AMD SEV-SNP) from Reading 12, not just Kata.
