# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): Linux egor-MCLF-XX 6.17.0-29-generic
- KVM accessible: crw-rw---- 1 root kvm /dev/kvm
- containerd version: v2.0.2
- nerdctl version: 1.7.5

### Kata installation
- Kata version: 3.32.0

containerd config snippet:
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  runtime_path = "/opt/kata/bin/containerd-shim-kata-v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration.toml"

### Kernel inside containers

runc:
Linux f1f6e55e8a65 6.17.0-29-generic
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6

kata:
Linux 0970397e62c7 6.18.35
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6

### Why the kernel differs

Kata Containers launches each container inside a lightweight virtual machine with its own Linux kernel, while runc directly uses the host kernel through namespaces and cgroups. This is the fundamental difference: runc shares the kernel with the host, making it vulnerable to container escape attacks (e.g., CVE-2024-21626 "Leaky Vessels"). Kata, having a separate kernel per container, isolates kernel-level attacks - even if a container is compromised, the attacker is trapped inside the VM, not on the host.

## Task 2: Isolation + Performance

### Isolation: /dev diff

1d0
< core

The /dev/core device is available in runc but not in Kata. This demonstrates that Kata provides a more restricted device access, reducing the attack surface.

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

The capability sets are identical. However, the key difference is that in Kata, these capabilities are applied within the VM's kernel, not the host's. This means even with the same capability bits, the scope is contained to the micro-VM.

### Startup time (5-run avg)

| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.541 |
| kata | 1.593 |

Overhead: ~2.94x cold start

### I/O throughput (100MB dd)

| Runtime | Throughput |
|---------|-----------|
| runc | 13.4 GB/s |
| kata | 7.7 GB/s |

### Trade-off analysis

Kata Containers provides significant security advantages through VM-level isolation, effectively blocking container escape attacks. However, this comes at a cost of approximately 3x slower cold startup and ~43% lower I/O throughput. This makes Kata ideal for multi-tenant environments where security is critical (e.g., cloud-based CI/CD runners, shared Kubernetes clusters), but overkill for single-user development environments where performance matters more than strong isolation. Additionally, Kata is well-suited for compliance-heavy workloads (e.g., GDPR, HIPAA) where strong workload isolation is mandated.

## Bonus: Container-Escape PoC

### Vector chosen
- Option: B (privileged / host-namespace access), tested via two angles: explicit bind-mount write, and host PID-namespace access (`--pid=host`).
- Why: The bind-mount case is the textbook example, but testing it revealed a subtlety worth documenting honestly (below). The `--pid=host` case gives a cleaner, unambiguous demonstration of the VM-isolation boundary.

### Observation 1 — explicit bind-mount is proxied to the host (both runtimes)

runc command:

    sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
      sh -c 'echo "OVERWRITTEN BY RUNC" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'

Host after runc: `OVERWRITTEN BY RUNC`

kata command (same, runtime swapped):

    sudo nerdctl run --rm --runtime=io.containerd.kata.v2 -v /tmp:/host_tmp alpine:3.20 \
      sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target'

Host after kata: `ATTEMPTED OVERWRITE FROM KATA`

**Honest finding:** An *explicitly requested* bind mount (`-v /tmp:/host_tmp`) is written through to the host under Kata too — because that is exactly what virtio-fs is designed to do: proxy a named host directory into the guest with write-back. Kata does NOT silently sandbox a volume the operator deliberately mounted. So the bind-mount "escape" is not blocked by Kata — it is an operator-granted share, not a container escape. This corrects my initial assumption.

### Observation 2 — host PID namespace IS blocked by Kata (the real isolation boundary)

This is the unambiguous demonstration. Identical flags, only the runtime differs.

runc (`--pid=host`):

    PID   USER     COMMAND
    1 root  {systemd} /sbin/init splash
    2 root  [kthreadd]
    ...
    total host procs visible: 445

kata (`--pid=host`):

    PID   USER     COMMAND
    1 root  sh -c ps aux ...
    2 root  ps aux
    3 root  head -5
    total procs visible: 4

**runc exposes all 445 host processes** — `--pid=host` joins the host PID namespace, a classic escape/privilege-escalation surface (inspect, signal, or inject into host processes). **Kata sees only 4** — its own micro-VM processes. `--pid=host` cannot cross the VM boundary: there is no host PID namespace to join, because the container runs under a *different kernel* in a *different VM*.

### Threat model implication

Kata's isolation boundary is the **virtual machine / kernel boundary**, not the volume layer. It does not un-grant resources an operator explicitly hands the container (a `-v` bind mount via virtio-fs is honored, with write-back to the host — same as runc). What it *does* block is everything that depends on **sharing the host kernel and its namespaces**: `--pid=host`, host process injection, and crucially the runc/kernel container-escape CVE class (e.g. CVE-2024-21626 "Leaky Vessels"), where an attacker breaks the namespace boundary to reach the host. Under runc those break out to the real host (445 host processes prove the shared-namespace exposure); under Kata they stay trapped in a throwaway VM with its own guest kernel. This maps to the real-world case of multi-tenant CI runners or Kubernetes nodes running untrusted or `--privileged` pods: Kata contains a kernel-level breakout that would own a runc host. What Kata does NOT defend against: CPU side-channel attacks (Spectre/Meltdown), cross-tenant timing attacks, or anything an operator explicitly mounts/grants — those need Confidential Containers (Intel TDX / AMD SEV-SNP) or simply not mounting host paths into untrusted workloads.

### Note on `--privileged` under Kata

Adding `--privileged` to the Kata runs on this build fails at device setup (`Creating container device /dev/full ... EEXIST: File exists`), a rough edge of privileged-device passthrough in this Kata static build. The `--pid=host` comparison above was therefore run without `--privileged` so the flags match exactly between runtimes; the isolation result (4 vs 445 processes) is unaffected by that flag.

## Summary

| Metric | runc | kata | Difference |
|--------|------|------|------------|
| Kernel | Host kernel | Dedicated VM kernel | Kata provides kernel isolation |
| /dev/core | Available | Not available | Kata reduces attack surface |
| Startup time | 0.541s | 1.593s | ~2.94x overhead |
| I/O throughput | 13.4 GB/s | 7.7 GB/s | ~43% lower |
| Explicit bind mount (`-v`) | Writes to host | Writes to host (virtio-fs) | Operator-granted, not an isolation boundary |
| Host PID namespace (`--pid=host`) | 445 host procs visible | 4 procs visible | Kata blocks host-namespace access |

Key Takeaway: Kata Containers isolates at the VM/kernel boundary — it contains host-kernel and host-namespace escapes (the runc-CVE class) that would compromise a shared-kernel runc host — at the cost of ~3x cold-start and ~43% I/O overhead. It does not revoke resources an operator explicitly grants (bind mounts via virtio-fs behave like runc). Suited to multi-tenant/untrusted workloads, unnecessary for single-tenant performance-sensitive ones.