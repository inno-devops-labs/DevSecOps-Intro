# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): Linux user-pc 6.2.0-26-generic #26~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Jul 13 16:27:29 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
- KVM accessible: crw-rw-rw-+ 1 root kvm 10, 232 июл 18 00:57 /dev/kvm
- containerd version: github.com/containerd/containerd/v2

### Kata installation
- Kata version: 3.32.0
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
```
Linux b559366f1102 6.2.0-26-generic #26~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Jul 13 16:27:29 UTC 2 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**kata:**
```
Linux cd8710ef7f17 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernel differs
runc uses the host's shared kernel, isolating processes only via cgroups and namespaces. This makes it vulnerable to kernel-level escapes (like CVE-2024-21626 "Leaky Vessels"). Kata Containers runs each container inside a lightweight micro-VM with its own dedicated kernel. This creates a hardware isolation boundary, completely neutralizing attacks that exploit shared kernel vulnerabilities.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```
*Kata mounts only a minimal set of devices via virtio, while runc exposes many host devices.*

### Isolation: capability sets
**runc:**
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
**kata:**
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

### Startup time (5-run avg)
```
=== runc ===
1: .514315803 s
2: .479825192 s
3: .546855511 s
4: .437731875 s
5: .435932158 s
=== kata ===
1: 6.591858750 s
2: 6.336846318 s
3: 6.462606288 s
4: 7.314010542 s
5: 6.146478519 s
```
*Overhead: Kata has a higher cold start time (~5x) due to the necessity of booting the micro-VM and initializing the agent.*

### I/O throughput (100MB dd)
```
=== runc I/O ===
104857600 bytes (100.0MB) copied, 0.004442 seconds, 22.0GB/s
=== kata I/O ===
104857600 bytes (100.0MB) copied, 0.015831 seconds, 6.2GB/s
```

### Trade-off analysis
Kata's security gain (separate kernel, blocking runc-CVE class attacks) is worth the performance cost for **multi-tenant SaaS workloads** or **untrusted CI/CD runners** where code from untrusted sources is executed. However, it is not justified for **single-tenant batch jobs** or internal trusted microservices where maximum density and minimal latency are required, as the VM boot and I/O virtualization overhead makes runc a better choice.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (Privileged-container host write)
- **Why:** It's the most common vector for real-world incidents (misconfigured `--privileged` flag in Kubernetes/Docker). It clearly demonstrates the difference in bind mount handling between runc and Kata.

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "OVERWRITTEN BY RUNC" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```
Container output:
```
OVERWRITTEN BY RUNC
```
Host verification:
```
OVERWRITTEN BY RUNC
```

### Kata: escape blocked
Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "ATTEMPTED FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target'
```
Container output:
```

```
Host verification:
```
original
```

### Threat model implication
Kata blocks this attack because the bind mount (`-v /tmp:/host_tmp`) is virtualized via `virtio-fs` or `9p` **inside** the micro-VM's filesystem. The container writes to the VM's virtual disk, not the actual host filesystem. This is critical for protecting multi-tenant CI runners or clusters where an attacker might gain control of a pod with elevated privileges. However, it's important to note that Kata **does NOT protect** against side-channel attacks (like Spectre/Meltdown) or hypervisor timing attacks, which require Confidential Containers (CoCo) for defense.
