# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- Host kernel:

```text
Linux workpc 7.1.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 07 Jul 2026 05:05:48 +0000 x86_64 GNU/Linux
```

- KVM accessible:

```text
crw-rw-rw- 1 root kvm 10, 232 Jul 13 18:57 /dev/kvm
```

- containerd version:

```text
containerd github.com/containerd/containerd/v2 v2.3.2 fff62f14765df376e5fc36f5a8f8e795b5670f61.m
```

### Kata installation

- Kata version: `3.32.0`

- containerd configuration:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

The Kata shim was installed under `/opt/kata/bin/containerd-shim-kata-v2` and exposed through the system PATH so containerd could resolve the `io.containerd.kata.v2` runtime.

### Kernel inside containers

**runc:**

```text
Linux dd3c46fda6c6 7.1.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 07 Jul 2026 05:05:48 +0000 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**Kata:**

```text
Linux 0a754e29110c 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernel differs

The `runc` container shares the host kernel, which is why both the host and the container report kernel `7.1.3-arch1-1`. The Kata container runs inside a hardware-virtualized microVM with its own guest kernel, which reports version `6.18.35`. Therefore, a container-escape vulnerability that crosses the normal container boundary, such as the runc CVE class discussed in Reading 12 and Lecture 7, reaches the isolated guest VM boundary rather than directly reaching the host kernel.

---

## Task 2: Isolation + Performance

### Isolation: `/dev` diff

```diff
--- labs/lab12/results/runc-devs.txt
+++ labs/lab12/results/kata-devs.txt
@@ -1,4 +1,3 @@
-core
 fd
 full
 mqueue
```

The visible device sets were almost identical in this environment, with `core` present in the runc container and absent in the Kata container. The small `/dev` difference alone is not the primary isolation guarantee: the stronger boundary comes from the separate guest kernel and hardware virtualization used by Kata.

### Isolation: capability sets

**runc:**

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

**Kata:**

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The capability masks are identical. However, capabilities in the Kata container apply within the guest microVM boundary rather than directly against the host kernel, so identical capability masks do not imply equivalent host exposure.

### Startup time

Five measured runs:

```text
=== runc ===
1: .736890124 s
2: .656916647 s
3: .561243921 s
4: .600262998 s
5: .674892832 s
=== kata ===
1: 2.240004940 s
2: 2.291398319 s
3: 2.352571837 s
4: 2.294324311 s
5: 2.358548637 s
```

| Runtime | Average startup time |
|---------|---------------------:|
| runc | 0.646 s |
| Kata | 2.307 s |

**Measured cold-start overhead: approximately 3.57×.**

The result confirms the expected trade-off from Reading 12: Kata requires additional startup time because it must create and boot a microVM before starting the container workload.

### I/O benchmark

```text
=== runc I/O ===
104857600 bytes (100.0MB) copied, 0.015526 seconds, 6.3GB/s
=== kata I/O ===
104857600 bytes (100.0MB) copied, 0.008344 seconds, 11.7GB/s
```

| Runtime | Measured throughput |
|---------|--------------------:|
| runc | 6.3 GB/s |
| Kata | 11.7 GB/s |

This specific microbenchmark copies data from `/dev/zero` to `/dev/null`, so it does not exercise persistent disk storage or provide a complete measurement of virtualization I/O overhead. On this host, the short synthetic test did not reproduce the expected Kata slowdown and instead showed substantial run-to-run sensitivity. A filesystem-backed benchmark such as `fio` would be more representative for production storage-performance analysis.

### Trade-off analysis

Kata is worth the additional startup time and memory overhead for untrusted or multi-tenant workloads such as CI runners, code-execution sandboxes, and customer-controlled containers, because a compromised workload remains separated from the host by a microVM and its own kernel. For trusted single-tenant application workloads where the organization controls the images and cold-start latency or I/O performance is important, standard `runc` is usually the simpler and more efficient choice. A mixed-runtime Kubernetes environment can therefore keep trusted infrastructure on `runc` while assigning untrusted workloads to Kata through `RuntimeClass`.

---

## Bonus: Container-Escape Demonstration

### Vector chosen

- **Option:** Privileged container with host PID namespace access.
- **Why:** A privileged `runc` container using the host PID namespace can reach the host root filesystem through `/proc/1/root`, providing a direct demonstration of how a dangerous runtime misconfiguration can expose the host. The same privileged workload was then attempted with Kata to evaluate the additional microVM boundary.

### runc: host write succeeds

Command:

```bash
sudo nerdctl run --rm --net=none \
  --privileged \
  --pid=host \
  alpine:3.20 \
  sh -c '
    echo "OVERWRITTEN VIA HOST PID NAMESPACE" > /proc/1/root/tmp/lab12-target
    cat /proc/1/root/tmp/lab12-target
  '
```

Container output:

```text
OVERWRITTEN VIA HOST PID NAMESPACE
```

Host-side verification:

```text
OVERWRITTEN VIA HOST PID NAMESPACE
```

The write performed from inside the `runc` container was immediately visible on the real host filesystem.

### Kata: privileged attack attempt does not reach the host

The equivalent privileged Kata workload was attempted with the same host-PID attack concept:

```bash
sudo nerdctl run --rm --net=none \
  --runtime=io.containerd.kata.v2 \
  --privileged \
  --pid=host \
  alpine:3.20 \
  sh -c '
    echo "ATTEMPTED OVERWRITE FROM KATA" > /proc/1/root/tmp/lab12-target
    cat /proc/1/root/tmp/lab12-target
  '
```

Kata output:

```text
time="2026-07-14T03:15:51+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-14T03:15:53+03:00" level=fatal msg="failed to create shim task: QMP command failed: Could not open '/dev/sdc': No medium found"
```

Host-side verification:

```text
original
```

The host target remained unchanged. In this specific Kata 3.32.0 environment, the equivalent privileged workload did not reach payload execution because VM creation failed while QEMU attempted to open `/dev/sdc`. Therefore, this result must not be interpreted as a clean demonstration of successful payload execution inside a microVM followed by isolation; rather, the attack failed before the workload started, and the host remained unaffected.

### Threat-model implication

The `runc` demonstration shows why privileged containers combined with host namespace access are dangerous: because `runc` shares the host kernel, `/proc/1/root` can expose the host filesystem when the container joins the host PID namespace. Kata introduces a separate microVM and guest kernel, so under normal operation the container's PID 1 belongs to the guest environment rather than the physical host. This security model is particularly valuable for multi-tenant CI runners, code-execution sandboxes, and other workloads executing untrusted code. However, Kata does not eliminate all threats: side-channel attacks, cross-tenant timing attacks, hypervisor vulnerabilities, and attacks against the confidentiality of workload memory require additional defenses, including Confidential Computing technologies such as Intel TDX or AMD SEV-SNP.

### Environment-specific limitation

Standard Kata containers successfully ran on this host and demonstrated a separate guest kernel (`6.18.35` versus host kernel `7.1.3-arch1-1`). Both Dragonball and QEMU-backed configurations were tested. However, privileged Kata workloads failed during VM device setup with:

```text
QMP command failed: Could not open '/dev/sdc': No medium found
```

For reproducibility and accuracy, this limitation is explicitly documented rather than claiming that the attack payload successfully executed inside the Kata microVM.

---

## Conclusion

Kata Containers 3.32.0 was successfully installed and registered with containerd. Side-by-side testing demonstrated that `runc` shares the host kernel while Kata uses a separate guest kernel inside a microVM. The measured Kata cold-start time was approximately 3.57× higher than `runc`, illustrating the performance cost of stronger isolation. A privileged host-PID attack successfully modified the real host filesystem under `runc`; the equivalent Kata attempt did not modify the host, although an environment-specific QEMU device error prevented the attack payload itself from executing inside the microVM.
