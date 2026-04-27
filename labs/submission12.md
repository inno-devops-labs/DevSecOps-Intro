# Lab 12 — Kata Containers: VM-backed Container Sandboxing

## Task 1 — Install and Configure Kata

### Shim version

```
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: d5785b4eba8c05dc9a82bdf35199b6298816936d
```

The shim was built from source inside a Rust container using `labs/lab12/setup/build-kata-runtime.sh` and installed to `/usr/local/bin/containerd-shim-kata-v2`.

### Successful Kata test run

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux efe7a49165ae 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

The container ran successfully under the `io.containerd.kata.v2` runtime. containerd was configured with the kata runtime stanza and restarted to apply the change.

---

## Task 2 — Run and Compare Containers (runc vs kata)

### 2.1 juice-runc health check

```
juice-runc: HTTP 200
```

Juice Shop started on port 3012 under the default runc runtime and responded with HTTP 200.

### 2.2 Kata containers — successful runs

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux efe7a49165ae 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
6.18.15

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
model name	: Intel(R) Xeon(R) Processor
```

### 2.3 Kernel version comparison

| Runtime | Kernel |
|---------|--------|
| Host / runc | `6.19.12-arch1-1` (Arch Linux host kernel) |
| Kata guest | `6.18.15` (separate Kata-built VM kernel, compiled Apr 18 2026) |

runc containers share the host kernel — they see the same `uname -r` as the host. Kata containers boot a dedicated micro-VM with its own kernel (`6.18.15`), completely separate from the host. A vulnerability in the host kernel is not directly exploitable from inside a Kata container and vice versa.

### 2.4 CPU model comparison

| Runtime | CPU model |
|---------|-----------|
| Host (runc) | `13th Gen Intel(R) Core(TM) i5-13500H` |
| Kata VM | `Intel(R) Xeon(R) Processor` (virtualized via KVM/QEMU) |

The Kata VM sees a generic virtual CPU model rather than the real hardware, confirming the hardware abstraction layer introduced by the hypervisor.

### Isolation implications

- **runc**: Processes run directly on the host kernel using Linux namespaces and cgroups. The kernel attack surface is fully exposed — a kernel exploit or namespace escape from within the container can reach the host.
- **Kata**: Each container runs inside a lightweight VM with its own kernel. The isolation boundary is the hypervisor (KVM), not just namespaces. Even a full kernel compromise inside the VM does not grant direct access to the host kernel or other containers.

---

## Task 3 — Isolation Tests

### 3.1 dmesg — kernel ring buffer

```
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.18.15 (@1612ad5dd3e1) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Sat Apr 18 10:30:20 UTC 2026
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target ... root=/dev/vda1 rootfstype=ext4 ...
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
```

The Kata container's `dmesg` shows VM boot messages starting from timestamp `0.000000`, proving the container booted its own kernel. A runc container's `dmesg` would show host kernel boot messages (or be blocked by capability restrictions), but the kernel itself is shared. The Kata guest kernel's command line reveals Kata-specific parameters (`kata-containers.target`, `virtio_mmio`, `agent.log_vport`), confirming the micro-VM architecture.

### 3.2 /proc filesystem visibility

| Context | /proc entry count |
|---------|------------------|
| Host | 442 |
| Kata VM | 51 |

The Kata VM's `/proc` contains only the processes running inside the VM (the Kata agent plus the container workload). On the host, `/proc` exposes all 442 processes system-wide. This means a Kata container cannot enumerate host processes through `/proc`, eliminating a common information-leakage vector.

### 3.3 Network interfaces (Kata VM)

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.4.0.15/24 brd 10.4.0.255
```

The VM has its own isolated loopback and a virtual ethernet interface (`eth0`) on the `10.4.0.0/24` network managed by Kata's virtual networking layer. This is a fully virtual network stack, distinct from the host's physical interfaces. There is no visibility into other containers' or the host's network interfaces.

### 3.4 Kernel module counts

| Kernel | Module count |
|--------|-------------|
| Host | 333 |
| Kata guest | 72 |

The Kata guest kernel loads only the minimal modules needed to run containers (virtio drivers, ext4, etc.), compared to the 333 modules on the host. A smaller module surface reduces exposure to kernel module vulnerabilities inside the VM.

### Isolation boundary differences

- **runc**: The isolation boundary is Linux namespaces (PID, net, mnt, UTS, IPC) and cgroups. These are kernel features, so the container and host share the same kernel code paths. A bypass of namespace isolation reaches the host directly.
- **Kata**: The isolation boundary is a hardware-enforced hypervisor (KVM). Even with full control inside the VM (root, dmesg, arbitrary kernel modules), an attacker is still trapped within the VM's virtualized hardware view.

### Security implications

- **Container escape in runc** = host compromise. A kernel exploit, namespace escape, or privileged capability abuse inside the container grants full host access, affecting all other containers and the host OS.
- **Container escape in Kata** = VM boundary reached, not the host. An attacker who escapes from the container into the VM guest kernel still faces the hypervisor barrier (KVM + QEMU). Reaching the host requires a separate hypervisor-level exploit, significantly raising the attack cost and reducing blast radius.

---

## Task 4 — Performance Comparison

### 4.1 Container startup time

```
=== Startup Time Comparison ===
runc:
    Executed in  393.85 millis    fish    external
Kata:
    Executed in  882.07 millis    fish    external
```

| Runtime | Startup time |
|---------|-------------|
| runc | ~394 ms |
| Kata | ~882 ms |

Kata takes approximately **2.2× longer** to start, spending the extra ~488 ms booting the micro-VM, initializing the guest kernel, and starting the Kata agent before the container workload runs. This overhead is the fixed VM boot cost — it does not scale with container count significantly once the infrastructure is warm.

### 4.2 HTTP response latency (juice-runc baseline)

```
Results for port 3012 (juice-runc):
avg=0.0012s  min=0.0006s  max=0.0027s  n=50
```

The runc-backed Juice Shop served 50 requests with a 1.2 ms average latency, demonstrating near-native performance with no VM overhead. Kata's runtime overhead for steady-state HTTP throughput would be small (virtio network adds microseconds per packet), but startup dominates the cold-path cost.

### Performance trade-off analysis

- **Startup overhead**: Kata adds ~500 ms per container for VM boot. This matters for short-lived jobs (lambda-style, CI runners, batch tasks) and is negligible for long-running services.
- **Runtime overhead**: Steady-state CPU and memory overhead is low for Kata (KVM hardware virtualization uses near-native CPU performance). I/O has slight overhead through virtio drivers, typically <5% for network-heavy workloads.
- **CPU overhead**: KVM uses hardware VT-x/AMD-V extensions, so CPU virtualization overhead is minimal. The VM does reserve dedicated vCPUs, increasing memory footprint per container (~100–200 MB for the guest kernel + agent).

### When to use each

- **Use runc when**: maximum performance and minimal startup latency are required, workloads are trusted or already hardened, and the threat model does not require kernel-level isolation (e.g., internal microservices, dev environments, CI/CD pipelines with trusted code).
- **Use Kata when**: untrusted or multi-tenant workloads run on shared infrastructure (e.g., public FaaS, SaaS with user-submitted code, regulated environments), a container escape must not mean host compromise, or compliance/security requirements mandate hardware-enforced isolation boundaries.
