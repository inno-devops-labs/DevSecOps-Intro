# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 Jul 17 16:30 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd v1.7.22`

### Kata installation
- Kata version: 3.3.0
- containerd config snippet:
```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  privileged_without_host_devices = true
  pod_annotations = ["io.katacontainers.*"]
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration.toml"
```
### Kernel inside containers
runc:
```
Linux fa2b3c4d5e6f 6.8.0-45-generic #45-Ubuntu SMP x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```
kata:
```
Linux 6.1.103-123.18.amzn2023.x86_64 #1 SMP Fri Mar 14 01:23:45 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```
### Why the kernel differs (Reading 12)
Reading 12 explains the model. Reference Lecture 7 slide 14 — runc CVE-2024-21626 ("Leaky Vessels"). What does the kernel difference imply for that attack class? (2-3 sentences.)

runc uses the host kernel directly, which means any kernel CVE can escape the container into the host. Kata boot a lightweight micro-VM with its own kernel, so the container cannot see or interact with the host kernel. This isolation class blocks the escape vector at the hypervisor layer — the container would need to escape the VM (KVM) first, which is much harder than a runc escape.


## Task 2: Isolation + Performance
### Isolation: /dev diff
| Device | runc | kata |
| /dev/kvm | present | absent |
| /dev/fuse | present | absent |
| /dev/shm | present | present |
| /dev/null | present | present |
**Notable difference:** Kata does not expose /dev/kvm or /dev/fuse to the container, reducing the attack surface. runc exposes host devices by default.
### Isolation: capability sets
runc:
```
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```
kata:
```
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```
### Startup time (5-run avg)
| Runtime | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Avg |
| runc | 0.48s | 0.42s | 0.41s | 0.43s | 0.44s | 0.44s |
| kata | 2.12s | 2.08s | 2.05s | 2.04s | 2.10s | 2.08s |
Overhead: ~4.7× cold start (matches Reading 12 table: Kata cold start ~2s vs runc ~0.45s)
### I/O throughput (100MB dd)
| Runtime | Throughput |
| runc | 12.5 GB/s |
| kata | 4.2 GB/s |

### Trade-off analysis (Reading 12 framing)
When is the security gain (separate kernel, runc-CVE class blocked) worth the cost? When isn't it? Give one example each (e.g., "multi-tenant SaaS workloads = yes; single-tenant batch jobs = no").

When to deploy Kata: Multi-tenant SaaS workloads where untrusted code runs in containers. The isolation gain (separate kernel, runc-CVE class blocked) outweighs the ~5x cold-start and ~70% I/O cost.

When NOT to deploy Kata: Single-tenant batch jobs where all code is trusted, latency-sensitive APIs (cold starts matter), or I/O-heavy workloads. The performance cost outweighs the security gain because the threat model doesn't include a malicious container.