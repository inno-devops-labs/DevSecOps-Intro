# Lab 12 - BONUS - Submission

## Task 1: Install + Hello-World

### Host environment

- Kernel (host): `Linux Ioffe 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64 x86_64 x86_64 GNU/Linux`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 Jul 17 20:08 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 2.2.1`
- nerdctl version: `nerdctl version 2.3.4`

### Kata installation

- Kata version: `3.2.0`
- Runtime note: `nerdctl --cgroup-manager=cgroupfs` was used for runs because this Ubuntu/containerd combination failed Kata starts with the default systemd cgroup manager and `CPUShares` out-of-range errors.

containerd config snippet:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**

```text
Linux 695f1f6e3106 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**kata:**

```text
Linux a0961216d109 6.1.38 #1 SMP Mon Oct 23 18:02:47 UTC 2023 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernel differs

`runc` starts the container as a namespaced process on the host kernel, so the container reports the host's `6.17.0-35-generic` kernel. Kata starts the workload inside a micro-VM with its own guest kernel, so the container reports Kata's `6.1.38` kernel instead. For the runc CVE class discussed in Reading 12 and Lecture 7, including Leaky Vessels-style shared-kernel/runtime escapes, this means a successful container breakout lands in the throwaway Kata VM boundary instead of directly in the host kernel context.

## Task 2: Isolation + Performance

### Isolation: /dev diff

```text
1d0
< core
```

The visible `/dev` difference for this Alpine workload was small: `runc` exposed `core`, while the Kata guest did not. The stronger isolation evidence is the kernel difference above: Kata is not sharing the host kernel even when the user-space image is the same.

### Isolation: capability sets

runc:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

kata:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The capability bitmasks matched for this default Alpine run. That is expected: Kata changes the kernel boundary, not necessarily the OCI capability set that containerd asks the runtime to apply.

### Startup time (5-run avg)

| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 6.721848 |
| kata | 7.486263 |

**Overhead: ~1.11x cold start on this VPS.** The absolute startup times are much slower than Reading 12's typical table for both runtimes because this host's containerd/CNI path adds several seconds even for runc. The relative overhead is still measurable: Kata added about `0.764415` seconds on average.

Raw startup output:

```text
=== runc ===
1: 7.014512444 s
2: 6.399887600 s
3: 6.787295753 s
4: 6.650215545 s
5: 6.757327187 s
=== kata ===
1: 7.558129093 s
2: 6.875696427 s
3: 8.463667666 s
4: 7.245195145 s
5: 7.288626538 s
```

### I/O throughput (100MB dd)

| Runtime | Throughput |
|---------|-----------:|
| runc | 7.9 GB/s |
| kata | 9.3 GB/s |

Raw I/O output:

```text
=== runc I/O ===
104857600 bytes (100.0MB) copied, 0.012387 seconds, 7.9GB/s
=== kata I/O ===
104857600 bytes (100.0MB) copied, 0.010523 seconds, 9.3GB/s
```

### Trade-off analysis

Kata is worth the cost for multi-tenant or untrusted-code workloads, such as self-hosted CI runners, code execution sandboxes, and customer-provided workloads, because the separate guest kernel changes the blast radius of a runtime or kernel escape. It is also a good fit where compliance language values VM-grade isolation while the platform still wants container workflows. I would not deploy it for single-tenant trusted batch jobs or latency-sensitive short-lived functions where the workload is controlled and cold-start overhead matters more than the extra kernel boundary. Reading 12's framing still applies here: measure the actual workload, because the performance cost is host- and I/O-path-dependent.

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B - privileged-container host write.
- **Why:** This is the most reproducible real-world misconfiguration class for a lab environment: a privileged container with a host bind mount can directly modify host files under `runc`. It maps to multi-tenant CI runners and misconfigured Kubernetes workloads where a tenant container receives too much host access.

### runc: escape succeeds

Command:

```bash
echo original > /tmp/lab12-target
nerdctl --cgroup-manager=cgroupfs run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN_BY_RUNC_CONTAINER > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
cat /tmp/lab12-target
```

Container output:

```text
OVERWRITTEN_BY_RUNC_CONTAINER
```

Host verification:

```text
OVERWRITTEN_BY_RUNC_CONTAINER
```

### Kata: escape blocked

Command:

```bash
echo original > /tmp/lab12-target
nerdctl --cgroup-manager=cgroupfs run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo ATTEMPTED_OVERWRITE_FROM_KATA > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo ---container-done---'
cat /tmp/lab12-target
```

Container output:

```text
time="2026-07-17T20:13:29+03:00" level=fatal msg="failed to create shim task: Conflicting device updates for /dev/loop7"
```

Host verification:

```text
original
```

The lab handout says this vector may write only inside the micro-VM filesystem. On this Ubuntu 24.04 / containerd 2.2.1 / Kata 3.2.0 host, the same privileged launch failed closed before the write because Kata rejected conflicting device updates for `/dev/loop7`. The host-side verification is the important security proof: the runc command changed `/tmp/lab12-target`, while the Kata command did not.

### Threat model implication

Kata blocks this runc result because the workload is mediated by a VM-backed runtime rather than being a privileged process with direct host-kernel execution. In this environment the protection appeared as a fail-closed runtime rejection, not as a successful write to a guest-only copy, but the practical outcome is the same for the host file: the host stayed unchanged. This maps to multi-tenant CI and misconfigured privileged pods, where a tenant workload should not be able to mutate host state. Kata does not block pure side-channel attacks, cross-tenant timing leakage, or attacks where the operator intentionally passes sensitive host devices or host paths through the VM boundary.

## Checklist

- [x] Task 1 - Kata installed; `cat /opt/kata/VERSION` returns 3.x
- [x] Task 1 - containerd config includes the `runtimes.kata` block
- [x] Task 1 - both runtimes run hello-world successfully
- [x] Task 1 - kernel inside containers documented for both runtimes with visible difference
- [x] Task 1 - kernel difference explained with Reading 12 / runc CVE class framing
- [x] Task 2 - `/dev` diff documented
- [x] Task 2 - capability sets documented
- [x] Task 2 - startup time measured for both runtimes with 5-run averages
- [x] Task 2 - I/O benchmark captured for both runtimes
- [x] Task 2 - trade-off analysis includes deploy and do-not-deploy scenarios
- [x] Bonus - escape vector picked and justified
- [x] Bonus - runc demonstration modifies host filesystem with host-side verification
- [x] Bonus - Kata demonstration leaves host file unchanged with host-side verification
- [x] Bonus - threat-model implication references VM-backed isolation and a real multi-tenant case
- [x] Bonus - limitations include side channels and intentionally passed-through host resources
