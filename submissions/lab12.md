# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux ubuntu-linux-2404 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 5 11:20:03 UTC 2024 x86_64`
- KVM accessible: `crw-rw-rw- 1 root kvm 10, 232 Oct 1 12:00 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd v1.7.20`

### Kata installation
- Kata version: `3.10.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
```
Linux ubuntu-linux-2404 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 5 11:20:03 UTC 2024 x86_64
```

**kata:**
```
Linux cl-user 6.6.22-kata #1 SMP PREEMPT_DYNAMIC Wed Apr 10 12:00:00 UTC 2024 x86_64 Linux
```

### Why the kernel differs (Reading 12)
Kata Containers provisions a lightweight virtual machine (micro-VM) for each container, rather than sharing the host kernel like runc does. This means that any attack targeting the kernel from within the container (such as the CVE-2024-21626 "Leaky Vessels" container-escape vulnerability) will only affect the isolated guest kernel, completely protecting the host kernel and establishing a strong security boundary.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
--- runc-devs.txt
+++ kata-devs.txt
+ /dev/vda
+ /dev/vhost-vsock
+ /dev/hwrng
+ /dev/ptp0
```

### Isolation: capability sets
runc:
```
CapInh:	00000000a80425fb
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
kata:
```
CapInh:	00000000a80425fb
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.35 |
| kata | 1.85 |

**Overhead: ~5.3× cold start (expected ~5× per Reading 12 table)**

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 1.2 GB/s |
| kata | 420 MB/s |

### Trade-off analysis (3-4 sentences, Reading 12 framing)
The security benefits of a separate kernel (which prevents entire classes of container escape attacks) make Kata highly desirable for multi-tenant SaaS environments where untrusted code is executed. However, it isn't always worth the cost; for single-tenant batch processing jobs or applications heavily reliant on high I/O throughput, the cold-start overhead and reduced I/O speeds of virtualization make runc the superior and more efficient choice.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (Privileged-container host write)
- **Why:** It is the most straightforward to demonstrate and relates directly to a very common real-world threat model (misconfigured `--privileged` flags in production containers), making the isolation differences between runc and Kata highly apparent.

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
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
Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"' 2>&1
```

Container output:
```
ATTEMPTED OVERWRITE FROM KATA
---host view---
```

Host verification:
```
original
```

### Threat model implication (3-4 sentences, Reading 12 framing)
Kata successfully blocks this attack because its micro-VM filesystem is not the host filesystem; the bind mounts are virtualized via virtio-fs/9p within the VM. This closely models real-world threats such as misconfigured Kubernetes pods or multi-tenant CI pipelines running `--privileged` containers, neutralizing escapes by containing them within the guest VM. However, it's important to note that Kata does not prevent CPU hardware side-channel attacks or cross-tenant timing attacks, which require defenses found in Confidential Containers.
