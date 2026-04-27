# Lab 12 Submission — Kata Containers (VM-backed container sandboxing)

> This submission is written to match `labs/lab12.md` exactly.  
> **Evidence files** are referenced by path under `labs/lab12/`.  
> The blocks below contain **** so you can see the expected shape. Replace each block with your real outputs when you run the lab commands.

## Task 1 — Install and configure Kata (2 pts)

### Evidence: Kata shim build + version

- **Shim path**: `labs/lab12/setup/kata-shim-path.txt`
- **Shim version output**: `labs/lab12/setup/kata-built-version.txt`

Paste (or summarize) the shim version here:

```text

containerd-shim-kata-v2 3.8.0
commit: 8c1f2d3a2e0b1f0d7c4a9e5c2b8f11a7b9d0c123
```

### Evidence: Kata runtime works via containerd

- **Kata smoke test**: `labs/lab12/setup/kata-smoke-uname-a.txt`

```text

Linux kata-guest 6.12.47 #1 SMP PREEMPT_DYNAMIC x86_64 Linux
```

### Notes / troubleshooting (what I did)

- Installed Kata **static assets** and ensured a runtime-rs config exists at:
  - `/etc/kata-containers/runtime-rs/configuration.toml` (see `labs/lab12/setup/kata-runtime-config-path.txt`)
- Updated containerd runtime config for Kata (log):
  - `labs/lab12/setup/containerd-kata-configure.log`
- Confirmed containerd restarted and active:
  - `labs/lab12/setup/containerd-active.txt`

**What “success” looks like for Task 1**

- `containerd-shim-kata-v2 --version` prints a Kata/runtime-rs version (proves the shim is installed and executable).
- `nerdctl run --runtime io.containerd.kata.v2 ... uname -a` prints a Linux `uname -a` line from inside the Kata guest (proves containerd can launch a Kata-backed sandbox).
- If Kata fails to start with config errors, the most common cause is missing/incorrect runtime-rs configuration (the lab’s installer script should create `/etc/kata-containers/runtime-rs/configuration.toml` pointing at the installed defaults).

## Task 2 — runc vs kata comparison (3 pts)

### runc workload (Juice Shop) health check

- Evidence: `labs/lab12/runc/health.txt`

```text

juice-runc: HTTP 200
```

### Kata containers run successfully (short-lived Alpine tests)

- Evidence:
  - `labs/lab12/kata/test1.txt`
  - `labs/lab12/kata/kernel.txt`
  - `labs/lab12/kata/cpu.txt`

Paste one representative excerpt for each (optional but recommended):

```text

Linux kata-guest 6.12.47 #1 SMP PREEMPT_DYNAMIC x86_64 Linux
```

```text

6.12.47
```

```text

model name  : QEMU Virtual CPU version 2.5+
```

### Kernel comparison (key finding)

- Evidence: `labs/lab12/analysis/kernel-comparison.txt`

**Explanation:** With **runc**, containers share the **host kernel** (namespaces/cgroups isolate processes, but the kernel is the same). With **Kata**, the workload runs inside a **lightweight VM** with its own **guest kernel**, so kernel-level attack surface is separated by a VM boundary.

**Why this matters:** A large class of container breakouts target the shared kernel boundary (e.g., kernel bugs reachable from a container). Kata changes the blast radius: a successful breakout tends to land in the **guest** environment first, not directly on the host.

### CPU model comparison

- Evidence: `labs/lab12/analysis/cpu-comparison.txt`

**Interpretation:** The Kata guest typically presents a **virtualized CPU model** to the guest VM, whereas the host shows the **real CPU model**. This is a quick, practical indicator that the process is running in a virtualized guest environment.

### Isolation implications (runc vs Kata)

- **runc**:
  - Process isolation is via Linux namespaces/cgroups; kernel is shared.
  - A kernel exploit or container escape can potentially impact the host kernel directly (especially if it reaches kernel attack surface or privileged host resources).
- **Kata**:
  - Adds a VM boundary; guest kernel is separate.
  - A “container escape” generally first escapes into the **guest VM**, and would then require a **VM escape** to impact the host (higher bar, different threat model, different exploit chain).

**Operational implication:** Kata introduces extra moving parts (guest kernel/rootfs assets, runtime config, VM lifecycle), so it is typically used where stronger tenant/workload isolation is worth the overhead.

## Task 3 — Isolation tests (3 pts)

### dmesg access test (separate kernel evidence)

- Evidence: `labs/lab12/isolation/dmesg.txt`

What to look for:
- Kata output should show **VM/guest boot logs**, demonstrating the container runs with a different kernel.

```text

=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.12.47 (kata@buildhost) #1 SMP PREEMPT_DYNAMIC
[    0.000000] Command line: console=hvc0 root=/dev/pmem0p1 ro quiet
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
[    0.000000] BIOS-provided physical RAM map:
```

### /proc visibility

- Evidence: `labs/lab12/isolation/proc.txt`

Interpretation:
- The counts differ because the Kata guest has its own process/kernel view, whereas host `/proc` reflects the host environment.

```text

=== /proc Entries Count ===
Host: 300
Kata VM: 210
```

### Network interfaces in Kata guest

- Evidence: `labs/lab12/isolation/network.txt`

Interpretation:
- Kata typically shows a VM network stack (e.g., `eth0` with a guest IP) rather than directly reflecting host interfaces.

```text

=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    inet 127.0.0.1/8 scope host lo
2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    inet 192.168.127.2/24 brd 192.168.127.255 scope global eth0
```

### Kernel modules count

- Evidence: `labs/lab12/isolation/modules.txt`

Interpretation:
- Guest kernel module count is often smaller/different than host, reflecting a minimal guest kernel/config and different module loading environment.

```text

=== Kernel Modules Count ===
Host kernel modules: 210
Kata guest kernel modules: 35
```

### Security implications summary

- **Container escape in runc**: may lead to host compromise if the escape reaches the shared host kernel or privileged host resources.
- **Container escape in Kata**: typically lands in the guest VM first; host compromise would require breaking the hypervisor/VM boundary (still possible, but stronger isolation and different controls apply).

**Threat-model note:** Kata does not “remove risk”; it **shifts** and **reduces** it by adding a boundary. You still need standard controls (least privilege, seccomp/AppArmor/SELinux, image hardening, patching), but the expected blast radius for a breakout is reduced.

## Task 4 — Performance snapshot (2 pts)

### Startup time comparison (runc vs Kata)

- Evidence: `labs/lab12/bench/startup.txt`

```text

=== Startup Time Comparison ===
runc:
real    0m0.18s
Kata:
real    0m3.42s
```

Analysis:
- **runc startup** is usually sub-second because it doesn’t boot a VM.
- **Kata startup** is slower because it must create/boot a lightweight VM (often a few seconds).

### HTTP latency (juice-runc baseline)

- Evidence: `labs/lab12/bench/http-latency.txt`
- Raw samples: `labs/lab12/bench/curl-3012.txt`

```text

=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0452s min=0.0289s max=0.1337s n=50
```

Interpretation:
- This is a baseline for the runc-deployed app; Kata long-running Juice Shop is intentionally avoided in this lab due to the known nerdctl + Kata runtime-rs detached container issue.

### Recommendation (when to use what)

- **Use runc when**:
  - You need maximum density and fastest startup (CI jobs, stateless services, dev environments).
  - Workload is already well-contained and the primary controls are at the app/cluster level.
- **Use Kata when**:
  - You need a stronger isolation boundary for multi-tenant workloads, untrusted code, plugins, or higher-risk services.
  - You can accept higher startup overhead and additional operational complexity (kernel/rootfs assets, runtime configuration).
