# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- **Operating system:** Ubuntu 20.04.6 LTS (REMnux)
- **Kernel (host):**

```text
Linux remnux 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

- **KVM accessible:**

```text
=== loaded KVM modules ===
kvm_intel             380928  0
kvm                  1019904  1 kvm_intel

=== /dev/kvm ===
crw-rw----+ 1 root kvm 10, 232 Jul 17 11:55 /dev/kvm
```

- **containerd version:**

```text
containerd github.com/containerd/containerd 1.7.24
```

- **nerdctl version:**

```text
nerdctl version 2.3.4
```

- **runc version:**

```text
runc version 1.1.12-0ubuntu2~20.04.1
spec: 1.0.2-dev
go: go1.21.1
libseccomp: 2.5.1
```

### Kata installation

- **Kata version:** `3.32.0`
- **Kata hypervisor configuration:** QEMU through the runtime-rs configuration
  `/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml`.
  QEMU was used because the Dragonball runtime did not complete reliably under nested virtualization in VirtualBox.
- **containerd runtime configuration:**

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**

```text
Linux 9730d7860109 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 Linux
--- cpuinfo ---
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

**Kata:**

```text
Linux 1c60be6cde44 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
--- cpuinfo ---
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

The runc container reports the same `5.15.0-139-generic` kernel as the host because runc isolates processes with Linux namespaces and cgroups while sharing the host kernel. The Kata container reports a separate `6.18.35` guest kernel because the workload executes inside a dedicated micro-VM. Consequently, the exact runc-specific code path involved in CVE-2024-21626 is not used as the Kata container boundary. Even if code compromises the guest workload, reaching the outer host additionally requires a vulnerability in the Kata runtime, hypervisor, or a shared-device interface.

Evidence:

- [`runc-kernel.txt`](../labs/lab12/results/runc-kernel.txt)
- [`kata-kernel.txt`](../labs/lab12/results/kata-kernel.txt)
- [`kernel-release-comparison.txt`](../labs/lab12/results/kernel-release-comparison.txt)

## Task 2: Isolation + Performance

### Isolation: `/dev` diff

```diff
--- runc-devs.txt
+++ kata-devs.txt
@@ -1,4 +1,3 @@
-core
 fd
 full
 mqueue
```

The device lists were almost identical for this minimal Alpine workload, but the runc container exposed the additional `/dev/core` compatibility link while the Kata guest did not. The small visible diff does not mean the runtimes provide equivalent isolation: the primary boundary is the separate guest kernel and VMM, not the number of device entries.

### Isolation: capability sets

**runc:**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

**Kata:**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

The capability masks were identical. Capabilities constrain processes relative to the kernel that services their system calls: with runc this is the host kernel, whereas with Kata it is the guest kernel. Therefore, identical masks do not remove Kata's additional VM boundary.

### Startup time

One warm-up run was performed for each runtime, followed by five measured runs.

| Runtime | Run 1 (s) | Run 2 (s) | Run 3 (s) | Run 4 (s) | Run 5 (s) | Average (s) | Median (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| runc | 0.5266 | 0.5523 | 0.4812 | 0.4239 | 0.3721 | **0.4712** | 0.4812 |
| Kata | 7.8558 | 7.5746 | 7.0677 | 6.5455 | 7.2109 | **7.2509** | 7.2109 |

**Measured cold-start overhead: approximately `15.39×`.**

This is higher than the approximate `5×` reference value discussed in Reading 12. The measurement was performed inside REMnux running under VirtualBox with nested VT-x, so each Kata start includes micro-VM initialization through an additional virtualization layer. The result is valid for this test environment but should not be generalized to bare-metal Kata deployments.

### I/O throughput: 100 MiB `dd` through `/dev/null`

| Runtime | Elapsed time | Reported throughput |
|---|---:|---:|
| runc | 0.004719 s | **20.7 GB/s** |
| Kata | 0.023807 s | **4.1 GB/s** |

For this synthetic in-memory copy, Kata achieved approximately one fifth of the runc throughput, or roughly `5.05×` lower throughput. This benchmark does not represent persistent disk performance because both input and output were memory-backed pseudo-devices; it primarily captures guest execution and virtualization overhead for this specific command.

### Trade-off analysis

Kata is appropriate for multi-tenant CI runners, hosted build systems, plugin execution, and SaaS platforms that execute code supplied by mutually untrusted customers. In those environments, isolating each workload behind a separate guest kernel materially reduces the impact of host-kernel and runc-runtime escape classes, and the measured startup cost can be accepted or amortized by longer-running workloads. It is less attractive for trusted, single-tenant, short-lived batch jobs or latency-sensitive functions where the additional VM boot time dominates useful execution. A production decision should also account for operational complexity, memory density, workload compatibility, and whether the threat model actually includes hostile tenants.

Evidence:

- [`dev-diff.txt`](../labs/lab12/results/dev-diff.txt)
- [`runc-caps.txt`](../labs/lab12/results/runc-caps.txt)
- [`kata-caps.txt`](../labs/lab12/results/kata-caps.txt)
- [`startup-bench.csv`](../labs/lab12/results/startup-bench.csv)
- [`startup-summary.txt`](../labs/lab12/results/startup-summary.txt)
- [`runc-io.txt`](../labs/lab12/results/runc-io.txt)
- [`kata-io.txt`](../labs/lab12/results/kata-io.txt)

## Bonus: Privileged-Container Host Escape Demonstration

### Vector chosen

- **Option:** B — privileged-container host write, implemented through the host PID namespace and `/proc/1/root`.
- **Why:** A privileged runc container with `--pid=host` can resolve PID 1's root filesystem through `/proc/1/root` and modify a host file without an explicit host-directory bind mount. The same request is rejected by the Kata runtime and the host file remains unchanged.

The assignment's suggested writable bind-mount form was not used as the isolation proof. A writable bind mount explicitly delegates the selected host path to the workload and Kata normally transports such shared directories through virtio-fs or another host–guest filesystem mechanism. Successful access to an explicitly shared path is therefore not, by itself, a VM escape.

### Test preparation

```bash
sudo touch /tmp/lab12-target
sudo chown root:root /tmp/lab12-target
printf '%s\n' original | sudo tee /tmp/lab12-target
```

### runc: host write succeeds

Command:

```bash
sudo nerdctl run \
  --name lab12-pid-runc \
  --rm \
  --net=none \
  --privileged \
  --pid=host \
  alpine:3.20 \
  sh -c '
    echo "OVERWRITTEN THROUGH HOST PID NAMESPACE" \
      > /proc/1/root/tmp/lab12-target
    cat /proc/1/root/tmp/lab12-target
  '
```

Container output:

```text
OVERWRITTEN THROUGH HOST PID NAMESPACE
```

Host verification:

```bash
sudo cat /tmp/lab12-target
```

```text
OVERWRITTEN THROUGH HOST PID NAMESPACE
```

Result: container exit status `0`; the host file was modified.

### Kata: same host-namespace request is blocked

After resetting the target to `original`, the same request was run with the Kata runtime:

```bash
sudo nerdctl run \
  --name lab12-pid-kata \
  --rm \
  --net=none \
  --runtime=io.containerd.kata.v2 \
  --privileged \
  --pid=host \
  alpine:3.20 \
  sh -c '
    echo "ATTEMPTED THROUGH KATA PID NAMESPACE" \
      > /proc/1/root/tmp/lab12-target
    cat /proc/1/root/tmp/lab12-target
  '
```

Runtime output:

```text
time="2026-07-17T12:00:28-04:00" level=fatal msg="failed to create shim task: ... get host path failed ... No such file or directory (os error 2)"
```

Host verification:

```bash
sudo cat /tmp/lab12-target
```

```text
original
```

Result: Kata container creation returned exit status `1`; the host file remained unchanged.

### Threat-model implication

With runc and `--pid=host`, the container shares the host PID namespace, so `/proc/1/root` resolves to the host init process's root filesystem. Combined with `--privileged`, this allows direct host modification and demonstrates why privileged host-namespace containers are effectively outside the normal container security boundary. Kata cannot expose the outer host PID namespace in the same way because the workload is created inside a separate VM with its own kernel and process namespace; in this run, the runtime rejected the required host-path mapping before container creation.

This maps to multi-tenant CI runners and misconfigured Kubernetes workloads that grant privileged mode or host namespace access to untrusted jobs. Kata adds a strong boundary against this class, but it does not make privileged workloads harmless and does not address every threat. It does not inherently eliminate hypervisor vulnerabilities, virtio-fs/shared-device bugs, denial of service, microarchitectural side channels, cross-tenant timing leakage, or attacks against resources that the operator explicitly shares with the guest. Confidential Containers are required when the threat model also treats the host administrator or host infrastructure as untrusted.

Evidence:

- [`bonus-pid-summary.txt`](../labs/lab12/results/bonus-pid-summary.txt)
- [`bonus-pid-runc-container.txt`](../labs/lab12/results/bonus-pid-runc-container.txt)
- [`bonus-pid-runc-host.txt`](../labs/lab12/results/bonus-pid-runc-host.txt)
- [`bonus-pid-kata-container.txt`](../labs/lab12/results/bonus-pid-kata-container.txt)
- [`bonus-pid-kata-host.txt`](../labs/lab12/results/bonus-pid-kata-host.txt)
- [`collector-status.txt`](../labs/lab12/results/collector-status.txt)

## Result summary

| Requirement | Result |
|---|---|
| Kata 3.x installed | PASS — `3.32.0` |
| containerd Kata runtime registered | PASS — `io.containerd.kata.v2` |
| runc workload runs | PASS |
| Kata workload runs | PASS |
| Different kernels demonstrated | PASS — host/runc `5.15.0-139`, Kata `6.18.35` |
| `/dev` comparison captured | PASS |
| Capability comparison captured | PASS |
| Five startup measurements per runtime | PASS |
| I/O benchmark captured | PASS |
| runc privileged host write | PASS — host file overwritten |
| Kata host-write attempt blocked | PASS — runtime rejected request, host file unchanged |
| Collector final status | **SUCCESS** |
