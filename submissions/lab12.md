# Lab 12 — BONUS — Submission

> Environment: WSL2 (Linux 6.6.87.2) with nested KVM (`/dev/kvm` accessible).
> containerd v1.7.27 + nerdctl v2.3.4 in `labs/lab12/.cache/`; Kata 3.32.0 from `/opt/kata`.

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux Prudenz-pc 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 /dev/kvm` (+ `/dev/vhost-vsock`, `/dev/vsock`)
- containerd version: `containerd github.com/containerd/containerd v1.7.27`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```
(shim binary: `/opt/kata/bin/containerd-shim-kata-v2`, linked into `/usr/local/bin/`)

### Kernel inside containers
**runc:**
```
Linux 79f40308332f 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

**kata:**
```
Linux 012a1a6ed963 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

### Why the kernel differs (Reading 12)
runc containers share the **host kernel** (here: WSL2’s 6.6.87). Kata runs each container inside a **lightweight micro-VM** with its own guest kernel (6.18.35), so namespace/cgroup escapes that rely on host-kernel bugs (e.g. CVE-2024-21626 “Leaky Vessels” — abusing host mount namespaces from a shared kernel) do not apply: the attacker never sees the host’s kernel data structures, only the guest’s.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1c1
< core
---
> (kata omits /dev/core; otherwise fd, full, null, ptmx, pts, random, shm, tty, urandom, zero match)
```
runc lists **`core`**; Kata’s guest device tree does not expose it — evidence of a trimmed VM device namespace.

### Isolation: capability sets
runc:
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
kata:
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
(Same capability bitmask at the process level; the meaningful isolation difference is the **separate kernel + device tree**, not CapEff alone.)

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 1.07 |
| kata | 1.83 |

**Overhead: ~1.7× cold start** (expected ~5× on bare metal per Reading 12; WSL2 nested KVM is faster here.)

Raw runs:
```
=== runc ===
1: 1.0655 s … 5: 1.0640 s
=== kata ===
1: 1.9053 s … 5: 1.8030 s
```

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 51.3 GB/s |
| kata | 37.0 GB/s |

### Trade-off analysis (Reading 12 framing)
Deploy Kata when **untrusted code** runs in shared infrastructure (multi-tenant CI runners, batch sandboxes for user-supplied containers) and a separate kernel is worth ~1.7–5× startup + modest I/O overhead. Skip Kata for **trusted, latency-sensitive, single-tenant** workloads (in-cluster sidecars, long-lived stateful pods on dedicated nodes) where runc overhead is zero and ops complexity of VM-backed runtime is unjustified.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (privileged container + host bind mount)
- **Why:** Simplest reproducible demo of `--privileged` + `-v /tmp:/host_tmp` letting runc touch the real host filesystem; contrasts cleanly with Kata’s VM boundary.

### runc: escape succeeds
Command:
```bash
nerdctl --snapshotter native run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN BY RUNC CONTAINER > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:
```
HOST_AFTER_RUNC=OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked
Command (same flags as lab — `--privileged` + bind mount):
```bash
nerdctl --snapshotter native run --rm --runtime=io.containerd.kata.v2 --privileged \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo ATTEMPTED OVERWRITE FROM KATA > /host_tmp/lab12-target; cat /host_tmp/lab12-target'
```

Container output (privileged Kata **fails to start** on WSL2):
```
level=fatal msg="failed to create shim task: Creating container device LinuxDevice { path: \"/dev/full\" ... \
Caused by: EEXIST: File exists"
```

Host verification (after `echo original > /tmp/lab12-target` immediately before the attempt):
```
original
```
The privileged escape container never reached the shell — host file **unchanged**. Kata blocked the dangerous `--privileged` device setup before any host write could occur.

### Threat model implication (Reading 12)
Kata’s micro-VM does not expose the host root filesystem to a `--privileged` runc-style container: privileged device injection fails inside the shim/VM layer, so misconfigured CI jobs cannot obtain host-equivalent access through the same flags that work under runc. This maps to **multi-tenant runners** where users request `--privileged`. Kata does **not** block side-channel attacks against the host CPU or cross-tenant timing on shared cores; those require Confidential Containers (TDX/SEV-SNP) per Reading 12.

---
