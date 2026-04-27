# Lab 12 Submission — Kata Containers: VM-backed Container Sandboxing

**Environment:** Windows 11 + WSL2 Ubuntu 22.04, nested virtualization enabled
**Kata version:** 3.29.0 | **Runtime:** io.containerd.kata.v2 (Dragonball VMM)

---

## Task 1 — Kata Install + Runtime Config

### Kata shim version

```
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.29.0, commit: 8dccf4cf37aeea4b6c2caacf3e61510d6eef2f71
```

Installed via the official `kata-static-3.29.0-amd64.tar.zst` release package to `/opt/kata/`.
Shim binary placed at `/usr/local/bin/containerd-shim-kata-v2`.

### containerd configured

`/etc/containerd/config.toml` updated with:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

Runtime-rs config linked to `/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml`.

### Test run with io.containerd.kata.v2

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 0e11a8cf5483 6.18.15 #1 SMP Sat Apr 18 10:30:46 UTC 2026 x86_64 Linux
```

Kata guest kernel `6.18.15` confirms a separate VM kernel is running — distinct from the WSL2 host kernel `6.6.87.2-microsoft-standard-WSL2`.

---

## Task 2 — runc vs Kata Runtime Comparison

### Juice Shop (runc) health check

```
juice-runc: HTTP 200
```

Juice Shop running on port 3012 via default runc runtime.

### Kata containers running

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 337db288fe22 6.18.15 #1 SMP Sat Apr 18 10:30:46 UTC 2026 x86_64 Linux

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
6.18.15
```

### Kernel version comparison

```
=== Kernel Version Comparison ===
Host kernel (runc uses this): 6.6.87.2-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.18.15 (@41d05172fa80) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3)
  11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Sat Apr 18 10:30:46 UTC 2026
```

The host runs the Microsoft WSL2 kernel (`6.6.87.2-microsoft-standard-WSL2`). Kata containers run kernel `6.18.15` — a separate minimal kernel compiled specifically for Kata, built inside a VM managed by the Dragonball VMM.

### CPU model comparison

```
=== CPU Model Comparison ===
Host CPU:
model name      : Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz
Kata VM CPU:
model name      : Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz
```

The CPU model string is identical because KVM uses hardware passthrough mode by default — the guest sees the real CPU model. This is intentional for performance. Despite the same model string, isolation is enforced at the hypervisor level: the Kata VM cannot access host memory, host kernel state, or host devices beyond what the VMM explicitly exposes.

### Isolation implications

- **runc**: Containers share the host kernel (`6.6.87.2-microsoft-standard-WSL2`). Namespace and cgroup boundaries are enforced in software by the same kernel. A kernel exploit or namespace escape gives direct access to the host.
- **Kata**: Each container runs inside a lightweight VM with its own kernel (`6.18.15`). The hypervisor (Dragonball VMM) is the trust boundary. Malicious code inside the container can only interact with the guest kernel — breaking out requires defeating hardware virtualization, a fundamentally harder task.

---

## Task 3 — Isolation Tests

### dmesg access (key isolation proof)

```
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.18.15 (@41d05172fa80) (gcc 11.4.0) #1 SMP Sat Apr 18 10:30:46 UTC 2026
[    0.000000] Command line: tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1
               i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k
               root=/dev/pmem0p1 rootflags=dax,data=ordered ... systemd.unit=kata-containers.target
               agent.cdh_api_timeout=50 cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000007ffddfff] usable
```

These are VM boot logs from the Kata guest kernel. The kernel command line reveals Kata-specific parameters (`kata-containers.target`, `pmem0p1` rootfs, `agent.cdh_api_timeout`). A runc container's `dmesg` would show the same host kernel ring buffer — there is no separate boot log.

### /proc filesystem visibility

```
=== /proc Entries Count ===
Host: 140
Kata VM: 54
```

The host `/proc` exposes 140 entries — all host processes, kernel threads, and system state. The Kata VM `/proc` shows only 54 entries: just the processes running inside that VM's isolated kernel. runc containers see a filtered view of the *same* host process table via PID namespaces; Kata containers see a completely separate process table from a separate kernel.

### Network interfaces (Kata VM)

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    inet 10.4.0.15/24 brd 10.4.0.255 scope global eth0
```

The Kata VM has its own virtual NIC (`eth0` at `10.4.0.15/24`) connected via a virtual bridge managed by the VMM. The guest network stack is entirely separate from the host network stack — there is no shared kernel netfilter, no shared routing table, no access to host sockets.

### Kernel modules count

```
=== Kernel Modules Count ===
Host kernel modules: 211
Kata guest kernel modules: 76
```

The host has 211 loaded kernel modules — drivers, filesystems, networking subsystems. The Kata guest kernel has only 76: a minimal set chosen for container workloads. This reduced attack surface means fewer kernel code paths that can be exploited from inside the container.

### Isolation boundary differences

- **runc**: Isolation is *logical* — namespaces (pid, net, mnt, uts, ipc) and cgroups partition a single shared kernel. All containers ultimately share one kernel memory space, one set of syscall handlers, and one set of kernel modules. A single kernel vulnerability can affect every container on the host.
- **Kata**: Isolation is *physical* — each container runs in a hardware VM. The guest kernel, guest memory, and guest devices are isolated by the CPU's virtualization extensions (Intel VT-x). The hypervisor mediates all interaction between guest and host.

### Security implications

- **Container escape in runc** = the attacker is on the host. They have access to host processes, host network, host filesystem (if mounted), and can leverage host kernel vulnerabilities. The blast radius is the entire host.
- **Container escape in Kata** = the attacker is still inside the VM guest OS. They can control the guest kernel but cannot directly reach the host kernel or other containers. A second, much harder escape from the hypervisor layer (VMM vulnerability or CPU virtualization bug) is required to reach the host. This two-layer defence significantly reduces blast radius.

---

## Task 4 — Performance Snapshot

### Startup time comparison

```
=== Startup Time Comparison ===
runc:
real    0m0.700s
Kata:
real    0m1.953s
```

Kata adds ~1.25s of startup overhead on this system. The Dragonball VMM (Kata's Rust-based lightweight VMM, used by runtime-rs) is notably faster than QEMU — typical QEMU-based Kata startup is 3–5s. On WSL2 with nested virtualization the overhead is comparable to bare-metal KVM because Hyper-V exposes hardware virtualization extensions to the WSL2 VM.

### HTTP latency (juice-runc baseline)

```
Results for port 3012 (juice-runc), 50 requests:
avg=0.0023s  min=0.0016s  max=0.0050s  n=50
```

Sub-3ms average response time confirms runc has negligible network overhead. Kata was not benchmarked for HTTP latency because long-running detached containers have a known race condition with nerdctl + runtime-rs v3 (see lab known issues). In production Kubernetes deployments, Kata runtime overhead for established connections is typically <5%.

### Performance trade-offs

- **Startup overhead**: Kata adds ~1.25s per container start (Dragonball VMM boot). For short-lived workloads (batch jobs, CI runners, FaaS), this matters. For long-running services, it is a one-time cost.
- **Runtime overhead**: Once running, Kata containers have minimal CPU overhead (~2–5%) from the hypervisor. Memory overhead is higher — each VM requires a dedicated guest kernel and agent process (typically 50–100MB baseline RAM per container).
- **CPU overhead**: On my system (Intel i5-10210U with VT-x, nested virt via WSL2/Hyper-V), the overhead is low because hardware virtualization is fully accelerated. Environments without hardware virt support would fall back to software emulation with severe performance penalties.

### When to use each

- **Use runc when**: Workloads are trusted or already isolated at a higher level (dedicated VMs per tenant), startup latency is critical (CI pipelines, serverless cold starts), maximum density is needed, or host kernel is already hardened (seccomp, AppArmor, rootless containers).
- **Use Kata when**: Running untrusted or multi-tenant workloads (user-submitted code, third-party container images), compliance mandates hardware-level isolation (financial services, healthcare, government), defence-in-depth is required against container escapes, or the threat model includes sophisticated adversaries capable of kernel exploits.
