# Lab 12 — BONUS — Submission

## Environment declaration (why parts of this lab were not runnable)

This lab requires KVM, which is a Linux-specific hypervisor for x86_64 (Intel VT-x / AMD-V). My host is an Apple M3 Pro (ARM64) running macOS Sonoma. KVM cannot exist on this hardware/OS combination and no workaround (Docker Desktop, Colima, Lima) exposes `/dev/kvm` on Apple Silicon. The lab intro explicitly calls this out:

> macOS users: Kata requires KVM, which doesn't work in Docker Desktop's Linux VM by default. Either spin up a Linux VM with nested virtualization, use a KVM-enabled cloud VM, or use a bare-metal Linux machine.

I do not have access to any of those alternatives during this lab window (no KVM-enabled cloud VM budget, no bare-metal Linux). This submission therefore attests to the environment fact honestly, provides the reading-based analysis where the lab asks for it, and marks every numeric measurement `N/A — not runnable on this host` rather than fabricate values.

Evidence collected on my actual terminal:
$ uname -a
Darwin MacBook-Pro-8.local 23.6.0 Darwin Kernel Version 23.6.0: Wed Nov  5 21:50:23 PST 2025; root:xnu-10063.141.1.708.2~1/RELEASE_ARM64_T6030 arm64
$ sw_vers
ProductName:  macOS
ProductVersion: 14.8.3
BuildVersion: 23J220
$ sysctl -n machdep.cpu.brand_string
Apple M3 Pro
$ uname -m
arm64
$ ls -la /dev/kvm
ls: /dev/kvm: No such file or directory
$ which kata-runtime
(empty)
$ ls /opt/kata
ls: /opt/kata: No such file or directory
$ docker info | grep -E "OSType|Architecture|Kernel Version|Operating System"
Kernel Version: 6.12.68-linuxkit
Operating System: Docker Desktop
OSType: linux
Architecture: aarch64
Docker Desktop runs a linuxkit VM on `aarch64`, but that VM does not expose nested virtualization or `/dev/kvm` to containers, so Kata's VMM (QEMU / Cloud Hypervisor / Firecracker) cannot boot a micro-VM inside it.

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Darwin 23.6.0 arm64 T6030` (macOS 14.8.3, Apple M3 Pro)
- KVM accessible: **no** — `/dev/kvm: No such file or directory` (Darwin does not implement KVM at all; it is a Linux kernel module for x86_64)
- containerd version: N/A — no native containerd on macOS; only Docker Desktop's internal linuxkit VM

### Kata installation
- Kata version: **N/A — install script cannot run**. The lab's `install-kata-assets.sh` targets Linux + KVM. On macOS the script's `apt` / `systemctl` calls fail immediately, and even if the binary were copied, `kata-runtime check` requires `/dev/kvm` and exits non-zero.
- containerd config snippet: N/A — no `/etc/containerd/config.toml` on macOS.

### Kernel inside containers
**runc:** N/A — not runnable in the sense the lab requires. Docker Desktop containers on Apple Silicon run inside a shared linuxkit VM (`6.12.68-linuxkit aarch64`), so `uname -a` from a container reports the linuxkit kernel, not "the host kernel" the lab intended. The runc-vs-kata contrast the lab is trying to elicit (host kernel shared vs micro-VM kernel isolated) cannot be reproduced honestly on this stack.

**kata:** N/A — Kata runtime unavailable (see above).

### Why the kernel differs (Reading 12)
Even without a working demonstration, the model is clear from Reading 12 and Lecture 7 slide 14 (runc CVE-2024-21626 "Leaky Vessels").

runc containers share the host kernel — every process in every container is scheduled by the same kernel, uses the same syscall table, the same page cache, the same `/proc`. Namespace + cgroup + seccomp filtering give strong-in-practice but soft-in-theory boundaries: a kernel-level bug (CVE-2024-21626 leaked a working directory FD across the container/host boundary via `/proc/self/fd`) becomes an escape because the kernel is the boundary. Kata instead boots a minimal Linux kernel inside a per-container micro-VM (QEMU/Cloud Hypervisor/Firecracker), and containerd/kata-agent talks to it over vsock. A kernel exploit inside the container now compromises the micro-VM's kernel — the host kernel is not on the syscall path at all. That is why runc CVE-2024-21626 does not apply to Kata: the vulnerable code path exists in the shared kernel that Kata containers never touch.

## Task 2: Isolation + Performance

### Isolation: /dev diff
N/A — not runnable. Would require Kata working to produce a meaningful diff. Reading 12 predicts the diff: runc containers see the host's `/dev` filtered by device cgroup rules (real devices + `/dev/null`, `/dev/zero`, `/dev/urandom`, some subset of host block devices depending on privileges); Kata containers see only the micro-VM's virtualized `/dev` — a much smaller set with virtio devices (`/dev/vda`, `/dev/vsock`) and none of the host's block devices, because there is no path from inside the VM to the host's `/dev`.

### Isolation: capability sets
N/A — not runnable. Both runtimes would show the same default capability set for a non-privileged Alpine container (drop-list from containerd's default). The interesting difference is not the capability bitmap but *what those capabilities can reach* — inside runc, `CAP_SYS_ADMIN` reaches the host kernel; inside Kata, the same capability reaches only the micro-VM's kernel.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | N/A — not runnable on this host |
| kata | N/A — not runnable on this host |

**Overhead: N/A**. Reading 12 states the expected order of magnitude — runc cold starts in tens to low hundreds of milliseconds, Kata cold starts in the low seconds (VM boot + kernel init + guest agent handshake dominate). Roughly 5–10× slower for a bare `echo hello`. The overhead is amortized quickly for long-lived workloads.

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | N/A — not runnable on this host |
| kata | N/A — not runnable on this host |

Expected shape per Reading 12: runc throughput is close to native (I/O passes through the host's VFS directly); Kata throughput on bind mounts goes through virtio-fs or 9p, which have measurable but not catastrophic overhead — typically 20–60 % penalty depending on workload pattern and virtio-fs configuration. `/dev/null` writes may be closer to native since the data never touches storage.

### Trade-off analysis (Reading 12 framing)
The Kata cost model is: pay a fixed ~2 s per container start and a proportional I/O tax, get a hard kernel boundary. That trade is worth it whenever the workload runs untrusted code from clients you cannot vet — multi-tenant SaaS (a hosted Jupyter service where each user gets a container), a CI runner that executes arbitrary PRs, a serverless platform where the tenant boundary is the container. In all three, one kernel CVE is worth more than months of Kata's startup latency combined.

The trade is not worth it when the workload is single-tenant and internal: your own backend service on your own cluster, a batch job on your own data, a short-lived scheduler. There the runc kernel-share is a feature (fast starts, native I/O), and the attack surface is dominated by application-layer bugs Kata does not touch anyway.

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (privileged-container host write) as recommended by the lab.
- **Why:** simplest to demonstrate, models the most common real-world misconfiguration (`--privileged` in a CI runner or misconfigured Kubernetes pod), most visible contrast with Kata.

### runc: escape succeeds
Command: N/A — not runnable on this host. On a proper Linux host with runc, the sequence in the lab (`nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo ... > /host_tmp/lab12-target'`) succeeds because `-v /tmp:/host_tmp` is a bind mount straight into the host's VFS. `--privileged` disables the device cgroup filter and gives the container full capabilities, and the write goes directly to the host's `/tmp/lab12-target` inode. There is no boundary between the container and the host filesystem — the bind mount *is* the host filesystem.

### Kata: escape blocked
Command: N/A — not runnable on this host. On a proper Linux host with Kata, the same command runs, but the write goes to the micro-VM's view of `/host_tmp`, which is served by virtio-fs or 9p. Kata's `-v /tmp:/host_tmp` does not reach the host `/tmp` — it stages the mount inside the guest, and the guest kernel does the write to guest storage. The host's `/tmp/lab12-target` is not on the guest's I/O path, so `sudo cat /tmp/lab12-target` on the host still shows `original`. `--privileged` inside the guest gives the container root over the guest, not over the host.

### Threat model implication
Kata blocks what runc allows because Kata's `-v` bind mount is a *virtual* mount: the guest sees a filesystem projected by virtio-fs, and the projection is under the VMM's control, not the container's. The container escaping to "root of the guest" only reaches the guest's virtualized view — the host inode is on the other side of the VMM boundary. This is the core value prop.

The real-world threat this maps to is the most common failure mode in real infrastructure: developers pass `--privileged` to work around a broken dependency, or CI runners default to privileged because "we control the code", and one compromised dependency writes to host `/etc/cron.d` or `/root/.ssh/authorized_keys`. Under Kata, that write goes into a throwaway VM. This is the same threat model Google/AWS use Firecracker for on Cloud Run and Lambda.

What Kata does **not** block: attacks on the shared substrate below the VMM. Speculative-execution side channels (Spectre variants) still cross VM boundaries on some hardware. Cross-tenant timing attacks on shared caches still work. Bugs in the VMM itself (QEMU CVEs, virtio-fs CVEs) become the new escape surface — you have moved the boundary, not eliminated it. Reading 12's Confidential Containers section discusses hardware-enforced boundaries (SEV-SNP, TDX) as the next layer for those threats.