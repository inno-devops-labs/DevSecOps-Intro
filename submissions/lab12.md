## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux mycomputer 6.17.0-40-generic #40~24.04.1-Ubuntu`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 /dev/kvm`
- containerd version: `containerd v2.2.1`

### Kata installation
- Kata version: `3.20.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_path = "/opt/kata/bin/containerd-shim-kata-v2"
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
```
Linux 58bd0734e287 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

**kata:**
```
time="2026-07-17T22:50:16+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
Linux de3c4480f41e 6.12.42 #1 SMP Wed Aug 20 13:18:36 UTC 2025 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

### Why the kernel differs (Reading 12)
Reading 12 explains the model. Reference Lecture 7 slide 14 — runc CVE-2024-21626 ("Leaky Vessels").
What does the kernel difference imply for that attack class? (2-3 sentences.)

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
| runc | 0.7 |
| kata | 2.61 |

**Overhead: ~3.7× cold start (expected ~5× per Reading 12 table)**

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 11.2 GB/s |
| kata | 8.0 GB/s |

### Trade-off analysis (3-4 sentences, Reading 12 framing)
When is the security gain (separate kernel, runc-CVE class blocked) worth the cost?
When isn't it? Give one example each (e.g., "multi-tenant SaaS workloads = yes;
single-tenant batch jobs = no").

Kata's security gain is worth the cost when containers run untrusted code from different sources, a kernel escape in `runc` compromises the entire host, while Kata's VM isolation limits the blast radius to a single micro-VM. And it's not worth it when all workloads are trusted and startup latency directly impacts throughput or user experience.

- worth it: multi-tenant CI\CD runners, sandboxed malware analysis
- not worth it: single tenant microservices

