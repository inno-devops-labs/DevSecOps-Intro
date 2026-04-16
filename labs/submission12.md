# Lab 12 Submission — Kata Containers: VM-backed Container Sandboxing

---

## Task 1 — Install and Configure Kata

### Kata shim version

```
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.28.0, commit: 660e3bb6535b141c84430acb25b159857278d596
```

### Installation steps

1. Downloaded Kata static assets (pre-built kernel + rootfs + shim) via `install-kata-assets.sh` — assets extracted to `/opt/kata/`
2. Installed `containerd-shim-kata-v2` from `/opt/kata/bin/` to `/usr/local/bin/`
3. Installed nerdctl v2.2.0 to `/usr/local/bin/`
4. Installed CNI plugins to `/opt/cni/bin/` (bridge, host-local, loopback, etc.)
5. Configured containerd via `configure-containerd-kata.sh` which added:
   ```toml
   [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
     runtime_type = 'io.containerd.kata.v2'
   ```
6. Restarted containerd and verified the kata runtime with a test container

### Successful Kata test run

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux ba4f242aa6d1 6.18.15 #1 SMP Tue Mar 17 01:39:00 UTC 2026 x86_64 Linux
```

The container started and ran in a separate guest VM with kernel 6.18.15 — different from the host kernel (6.17.0-19-generic). This confirms Kata is working correctly.

---

## Task 2 — Run and Compare Containers (runc vs kata)

### juice-runc health check

```
$ sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
juice-runc: HTTP 200
```

Juice Shop running under runc on port 3012 — responds normally.

### Kata containers running successfully

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 4d0fbab7b23a 6.18.15 #1 SMP Tue Mar 17 01:39:00 UTC 2026 x86_64 Linux

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
6.18.15

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
model name	: AMD Ryzen 5 5500U with Radeon Graphics
```

### Kernel version comparison

| Runtime | Kernel |
|---------|--------|
| Host (runc uses this) | `6.17.0-19-generic` |
| Kata guest VM | `6.18.15` (built Tue Mar 17 01:39:00 UTC 2026) |

runc containers share the host kernel — there is only one kernel running. Kata starts a lightweight VM and boots a separate, purpose-built guest kernel (6.18.15) for each container. These are completely different kernel instances.

### CPU comparison

Both host and Kata VM report: `AMD Ryzen 5 5500U with Radeon Graphics`

This is expected — Kata uses CPU passthrough (not emulation), so the VM sees the real CPU model. The difference is that the Kata VM has its own virtual CPU context isolated from the host — system calls go to the guest kernel, not the host kernel.

### Isolation implications

**runc:** The container shares the host kernel directly. All system calls made inside the container go to the same kernel that runs everything else on the host. If an attacker escapes the namespace/seccomp boundary, they are already on the host kernel.

**Kata:** Each container runs inside its own VM with a dedicated guest kernel. System calls go to the guest kernel first. An attacker would need to escape the container process, then escape the guest kernel/VM hypervisor boundary, and then reach the host. Two separate layers of isolation.

---

## Task 3 — Isolation Tests

### dmesg — separate kernel boot logs

```
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.18.15 (@cc3ea47c641d) (gcc ...) #1 SMP Tue Mar 17 01:39:00 UTC 2026
[    0.000000] Command line: tsc=reliable no_timer_check rcupdate.rcu_expedited=1 ... root=/dev/pmem0p1 rootflags=dax ...
[    0.000000] x86 CPU feature dependency check failure: CPU0 has '18*32+31' enabled but '18*32+26' disabled.
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
```

The Kata container's `dmesg` shows its own kernel boot log starting from timestamp `0.000000`. This is the VM booting its own guest kernel — it has no visibility into the host kernel's ring buffer. A runc container's `dmesg` would show the host system boot log (or be blocked by permissions). This is direct proof that Kata runs in a completely separate kernel.

### /proc filesystem visibility

| Context | /proc entries |
|---------|--------------|
| Host | 716 |
| Kata VM | 55 |

The host /proc shows 716 entries — all running processes on the entire host system. The Kata VM's /proc has only 55 entries — only the processes running inside that VM (the kata-agent, the container process, and a few VM-internal processes). A Kata container cannot enumerate host processes through /proc.

### Network interfaces in Kata VM

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
    inet 127.0.0.1/8
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 10.4.0.11/24
```

The Kata VM has its own virtual network interfaces (lo + eth0) with its own IP address (10.4.0.11). The networking stack is completely isolated inside the VM — it cannot see host network interfaces, other containers' virtual eth devices, or bridge interfaces on the host.

### Kernel modules count

| Context | Module count |
|---------|-------------|
| Host | 337 |
| Kata guest VM | 76 |

The host has 337 loaded kernel modules. The Kata VM guest kernel has only 76 — a minimal set needed to run the container. The guest kernel is purpose-built and stripped down. An attacker inside a Kata container cannot exploit host kernel modules they cannot see or reach.

### Isolation boundary differences

**runc:** The isolation boundary is Linux namespaces (PID, network, mount, UTS, IPC) and cgroups. These are kernel-level abstractions — they restrict visibility but everything runs in the same kernel. A kernel vulnerability (privilege escalation, namespace escape) can break out directly to the host.

**Kata:** The isolation boundary is the hypervisor/VMM. The container is inside a VM with its own kernel. To escape to the host, an attacker would need to: (1) escape the container inside the VM, (2) exploit the guest kernel, and (3) break the VMM/hypervisor layer to reach the host. That is a much harder chain to pull off.

### Security implications

**Container escape in runc** = host compromise. Once you're past namespace isolation (one kernel vulnerability is enough), you're on the host machine with potential access to all other containers, host filesystem, and network.

**Container escape in Kata** = you're still inside the VM. You've escaped the container process but you're still isolated inside a lightweight VM with its own kernel. You would need a second exploit — a hypervisor/VMM escape — to reach the actual host. This is a significantly higher bar for attackers.

---

## Task 4 — Performance Comparison

### Container startup time

```
runc:
real    0m0.717s

Kata:
real    0m2.159s
```

Kata takes about 3x longer to start (~2.2s vs ~0.7s). This overhead comes from booting the lightweight VM: starting the hypervisor, loading the guest kernel, initializing the VM devices, and starting the kata-agent inside the VM before the container process even runs.

### HTTP response latency (juice-runc baseline)

```
Results for port 3012 (juice-runc):
avg=0.0032s  min=0.0024s  max=0.0055s  n=50
```

Juice Shop on runc responds in ~3ms average. This is the baseline with no VM overhead.

### Performance trade-offs analysis

**Startup overhead:** Kata adds ~1.5s per container start due to VM boot. For short-lived batch jobs or containers that start/stop frequently, this is significant. For long-running services like web servers or databases that start once and run for hours, this cost is negligible.

**Runtime overhead:** Once running, Kata's overhead is minimal. System calls go through the guest kernel (fast, same hardware), not through an emulation layer. The 3ms HTTP response time on runc would be nearly identical on a Kata-hosted service in practice. QEMU-lite and dragonball VMM (what Kata uses) are optimized specifically to keep runtime overhead low.

**CPU overhead:** Near zero. Kata uses hardware virtualization (Intel VT-x / AMD-V) with CPU passthrough — the VM runs directly on hardware, no software emulation. The CPU model reported inside the VM is the same as the host (AMD Ryzen 5 5500U).

### When to use each

**Use runc when:**
- Workload is trusted (internal services, your own code)
- You need the fastest possible container startup (CI pipelines, auto-scaling)
- You run many short-lived containers (startup overhead adds up)
- Multi-tenancy is not a concern

**Use Kata when:**
- Running untrusted or third-party code (e.g., user-submitted workloads, SaaS platforms)
- Multi-tenant environments where strong isolation between customers is required
- Compliance requirements demand workload isolation beyond namespaces
- Security-sensitive workloads where a kernel exploit would be catastrophic
- Cloud providers running containers for different customers on shared hardware
