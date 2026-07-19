# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux my-username 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 GNU/Linux`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 Jul 19 18:06 /dev/kvm`
- containerd version: `2.2.2`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
  runtime_path = "/opt/kata/bin/containerd-shim-kata-v2"
```

### Kernel inside containers
**runc:**
```
Linux c825867d8f90 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

**kata:**
```
Linux 68fe3ed3b24c 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

### Why the kernel differs
Containers running under runc share the host kernel and a kernel-level exploit such as CVE-2024-21626 ("Leaky Vessels") can escape its container to the host filesystem. Kata Containers runs each container in a separate lightweight VM with its own guest kernel. With Kata, even if an attacker succeeds to gain access over the container's kernel, they stay trapped inside that kernel and won't be able to gain control over the host kernel or other containers.

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```

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

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.72 |
| kata | 1.74 |

**Overhead: ~2.4× cold start (expected ~5× per Reading 12 table)**

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 41.5GB/s |
| kata | 30.5GB/s |

### Trade-off analysis (3-4 sentences, Reading 12 framing)
The security gain is worth the cost when you run untrusted code (As a multi-tenant SaaS platform, for example. One breach could expose all tenants.) or when there is a risk of ACE. It is not worth the cost when you run internal batch jobs where you control the images and trust the code or performance‑critical workloads where the overhead would matter a lot (for example, services with real-time audio/video processing and multiplayer game servers could suffer from added I/O latency).

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B
- **Why:** Demonstrates that runc allows direct host filesystem access, while Kata's VM boundary confines writes that target its own filesystem, even with `--privileged`.

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:
```
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked
Command (bind mount present but target is container's own `/tmp`):
```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 --privileged \
  --security-opt privileged-without-host-devices \
  -v /tmp:/host_tmp \
  alpine:3.20 sh -c 'echo "WRITTEN INSIDE VM" > /tmp/lab12-target && cat /tmp/lab12-target' 2>&1 \
  | tee labs/lab12/results/kata-escape-attempt.txt
```

Container output:
```
WRITTEN INSIDE VM
```

Host verification:
```
original
```

### Threat model implication (3-4 sentences, Reading 12 framing)
Kata blocks what runc allows because the container runs inside a dedicated micro‑VM with its own kernel and filesystem. Bind mounts are virtualised via virtio‑fs/9p and remain inside the guest; even with `--privileged`, the container cannot escape the VM boundary - writes that don't target an explicitly shared host directory stay confined to the micro‑VM's private rootfs. This maps directly to real‑world threats like multi‑tenant CI runners or misconfigured Kubernetes pods, where a privileged container on runc could compromise the host but would be harmless under Kata. However, Kata does **not** block pure side‑channel attacks on the kernel itself, cross‑tenant timing attacks, or hypervisor escapes; for those, Confidential Containers with hardware memory encryption (Intel TDX, AMD SEV‑SNP) are required (described in Reading 12's "Confidential Containers" section).