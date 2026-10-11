# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

* Host OS: Ubuntu 24.04.4 LTS
* Host kernel:

```text
Linux karina-IdeaPad-Slim-3-16IAH8 6.17.0-20-generic #20~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Mar 19 01:28:37 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

* KVM accessible:

```text
crw-rw----+ 1 root kvm 10, 232 Jul 13 20:15 /dev/kvm
```

* KVM module:

```text
kvm_intel             569344  0
kvm                  1445888  2 vboxdrv,kvm_intel
irqbypass              16384  1 kvm
```

* containerd version:

```text
containerd github.com/containerd/containerd 1.7.28
```

* nerdctl version:

```text
nerdctl version 2.2.2
```

### Kata installation

* Kata version:

```text
3.32.0
```

* Kata shim:

```text
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.32.0, commit: 337b6002681479fb6a605ca8a7a1138e81b6098c
```

* containerd configuration:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

#### runc

```text
Linux 0dee0d4da4e4 6.17.0-20-generic #20~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Mar 19 01:28:37 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

#### Kata

```text
Linux 10c2747f741e 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernels differ

A runc container shares the Linux kernel of the host, which is why the kernel version inside the runc container is the same `6.17.0-20-generic` version used by the host. Kata runs the workload inside a lightweight virtual machine with its own guest kernel, which is visible here as kernel `6.18.35`.

This separate kernel boundary reduces exposure to attacks that target a shared host-kernel or conventional runtime boundary, including the class of container-escape risks illustrated by runc vulnerabilities such as CVE-2024-21626. A compromise of the guest environment does not automatically provide direct execution in the host kernel.

## Task 2: Isolation + Performance

### Isolation: `/dev` comparison

The captured diff was:

```diff
1d0
< core
```

The runc container exposed a `/dev/core` entry, while the Kata container did not. Most basic pseudo-devices were otherwise identical in this test.

### Isolation: capability sets

#### runc

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

#### Kata

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The visible capability masks were identical. However, the security meaning is different: in the runc case, capabilities operate against the shared host kernel, while in Kata they operate inside the guest VM and its separate kernel boundary.

### Startup benchmark

Five cold-start measurements were collected for each runtime.

| Runtime |   Run 1 |   Run 2 |   Run 3 |   Run 4 |   Run 5 |     Average |
| ------- | ------: | ------: | ------: | ------: | ------: | ----------: |
| runc    | 0.681 s | 0.663 s | 0.682 s | 0.676 s | 0.833 s | **0.707 s** |
| Kata    | 2.200 s | 2.352 s | 2.306 s | 2.004 s | 2.081 s | **2.189 s** |

Kata had approximately **3.10× greater cold-start latency** than runc in this environment.

One Kata cleanup operation printed `Sandbox not running` after the workload had completed, but all five workload executions returned timing values and were included in the result file.

### I/O benchmark

The workload copied 100 MB from `/dev/zero` to `/dev/null`.

| Runtime |       Time |    Throughput |
| ------- | ---------: | ------------: |
| runc    | 0.006269 s | **15.6 GB/s** |
| Kata    | 0.007436 s | **13.1 GB/s** |

Kata throughput was approximately **16% lower** in this synthetic test.

This benchmark mainly measures memory and syscall processing rather than persistent storage performance, because both the input and output are special devices.

### Trade-off analysis

Kata is suitable for workloads where the additional VM boundary is more valuable than minimum startup latency. Examples include multi-tenant SaaS platforms, untrusted CI jobs, plugin execution, or customer-provided workloads.

The separate guest kernel limits the impact of attacks against the conventional shared-kernel container boundary. In this test, that security boundary cost approximately 1.48 seconds of additional average startup time and reduced synthetic I/O throughput by around 16%.

For trusted, single-tenant batch jobs or short-lived internal command-line tasks, the startup overhead may not be justified. Standard runc containers combined with least privilege, seccomp, AppArmor, read-only filesystems, and restricted capabilities may be sufficient for those workloads.

## Bonus: Privileged Host-Write Attempt

### Vector chosen

* **Option:** B — privileged container with a writable host bind mount.
* **Reason:** Combining `--privileged` with a writable host mount demonstrates how an unsafe runtime configuration can give a container direct influence over the host filesystem.

### runc: host write succeeds

Command:

```bash
sudo nerdctl run --rm --privileged \
  -v /tmp:/host_tmp \
  alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:

```text
OVERWRITTEN BY RUNC CONTAINER
```

The runc container successfully modified `/tmp/lab12-target` on the host.

### Kata attempt

Equivalent command:

```bash
sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  --privileged \
  -v /tmp:/host_tmp \
  alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

The Kata container did not reach workload execution.

With the Go shim, privileged container creation failed while processing an existing guest device:

```text
Creating container device LinuxDevice { path: "/dev/full", ... }

Caused by:
    EEXIST: File exists
```

A second test using the Rust shim also failed during privileged container creation:

```text
failed to handle message create container

Caused by:
    0: get host path failed
    1: No such file or directory (os error 2)
```

Host verification after the failed Kata attempts:

```text
original
```

### Interpretation and threat-model implications

The host file remained unchanged, but this result is not proof that the micro-VM successfully intercepted or blocked the write. The Kata container did not start, so the write command was never executed. The result therefore demonstrates a privileged-device compatibility failure in this Kata 3.32.0 environment rather than a completed side-by-side host-write prevention test.

Kata still provides a meaningful security improvement because normal Kata workloads run inside a VM with a separate guest kernel. This is useful for multi-tenant CI runners, customer-controlled workloads, and other environments in which a container may be hostile.

However, an explicitly configured writable host bind mount is an operator-granted access path and should not be assumed to become an isolated copy solely because the workload uses Kata. Kata also does not eliminate all side-channel, timing, hypervisor, or hardware-level attacks.

## Result files

The following evidence files are included under `labs/lab12/results/`:

* `runc-kernel.txt`
* `kata-kernel.txt`
* `runc-devs.txt`
* `kata-devs.txt`
* `dev-diff.txt`
* `runc-caps.txt`
* `kata-caps.txt`
* `startup-bench.txt`
* `io-bench.txt`
* `runc-escape-container.txt`
* `runc-escape-host.txt`
* `kata-escape-attempt.txt`
* `kata-escape-host.txt`
