# Lab 12 — Kata Containers: VM-backed Container Sandboxing (Local)

## Environment

- Date: 2026-04-10
- Branch: `feature/lab12`
- Host OS: macOS 26.3 (Darwin 25.3.0, arm64)
- CPU: Apple M4
- RAM: 16 GB
- Docker client: `29.2.0`
- Host Docker runtimes: `runc`, `io.containerd.runc.v2`
- Nested Linux strategy: `docker run --privileged ubuntu:24.04` with containerd 2.2.1 + nerdctl 2.2.0

Host prechecks are in `labs/lab12/setup/environment-check.txt`.

---

## Task 1 — Install and Configure Kata (2 pts)

### 1.1 Kata Installation

Kata 3.28.0 was installed inside a nested privileged Ubuntu 24.04 container
(macOS does not support KVM natively).

**Shim version** (`labs/lab12/setup/kata-built-version.txt`):

```
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.28.0, commit: 660e3bb6535b141c84430acb25b159857278d596
```

Installation steps performed inside nested Linux:
1. Installed containerd 2.2.1, nerdctl 2.2.0, and dependencies (curl, jq, zstd, iproute2)
2. Downloaded `kata-static-3.28.0-arm64.tar.zst` from GitHub releases
3. Extracted to `/opt/kata/` — installs shim, QEMU, kernel, and rootfs image
4. Symlinked shim: `/opt/kata/bin/containerd-shim-kata-v2` → `/usr/local/bin/`
5. Linked config: `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml` → `/etc/kata-containers/runtime-rs/configuration.toml`

### 1.2 containerd Configuration

**containerd kata section** (`labs/lab12/setup/containerd-kata-config.txt`):

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
```

**Kata QEMU config** (`labs/lab12/setup/configuration-qemu-runtime-rs.toml`) points to:
- `path = "/opt/kata/bin/qemu-system-aarch64"`
- `kernel = "/opt/kata/share/kata-containers/vmlinux.container"`
- `image = "/opt/kata/share/kata-containers/kata-containers.img"`

### 1.3 Test Run Attempt

```
$ nerdctl run --rm --net=none --runtime io.containerd.kata.v2 alpine:3.19 uname -a
FATAL: failed to create shim task: Unix syslog delivery error
kata_exit_code=1
```

**Root cause:** Docker Desktop's LinuxKit VM does not expose `/dev/kvm`, which QEMU
requires. Verified with `ls -la /dev/kvm` → `No such file or directory`. Kata needs
a Linux host with Intel VT-x/AMD-V (or nested KVM enabled in a cloud VM).

Full log: `labs/lab12/setup/kata-nested-attempt.txt`

---

## Task 2 — Run and Compare Containers (runc vs kata) (3 pts)

### 2.1 runc Workload (Juice Shop)

```bash
docker run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
```

**Health check** (`labs/lab12/runc/health.txt`):

```
juice-runc: HTTP 200
```

**Container status** (`labs/lab12/runc/ps.txt`):

```
CONTAINER ID   NAMES        PORTS                                         STATUS
f0541fb51d9c   juice-runc   0.0.0.0:3012->3000/tcp, [::]:3012->3000/tcp   Up 24 seconds
```

**runc Alpine tests** (`labs/lab12/runc/test1.txt`):

```
Linux bba9dc63fad0 6.12.67-linuxkit #1 SMP Sun Jan 25 02:26:28 UTC 2026 aarch64 Linux
```

### 2.2 Kata Containers

Kata containers did not start in this environment (no KVM). See Task 1.3 for details.

Artifacts with expected behavior documented:
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`
- `labs/lab12/kata/cpu.txt`

### 2.3 Kernel Comparison

`labs/lab12/analysis/kernel-comparison.txt`:

| Component | Kernel Version |
|-----------|---------------|
| Host (macOS) | Darwin 25.3.0 |
| runc container | `6.12.67-linuxkit` (Docker Desktop LinuxKit VM) |
| Kata guest (expected) | `6.12.x` or similar — separate guest kernel |

Key finding: runc containers share the LinuxKit VM kernel (`6.12.67-linuxkit`).
Kata would boot its own guest kernel from `/opt/kata/share/kata-containers/vmlinux.container`,
completely separate from the host.

### 2.4 CPU Comparison

`labs/lab12/analysis/cpu-comparison.txt`:

| Component | CPU |
|-----------|-----|
| Host | Apple M4 |
| runc container | `processor : 0` (same physical CPU, passthrough) |
| Kata guest (expected) | Virtualized CPU model via QEMU |

### Isolation Implications

- **runc:** Uses Linux namespaces and cgroups for isolation. Shares the host kernel — any kernel vulnerability is a potential escape vector. The container sees the same `6.12.67-linuxkit` kernel, the same CPU model, and can access host kernel logs if run with `--privileged`.

- **Kata:** Each container runs inside a lightweight VM with its own guest kernel. A kernel exploit inside the container only affects the guest, not the host. The attacker would need a hypervisor escape (QEMU/KVM vulnerability) to reach the host — a much harder attack.

---

## Task 3 — Isolation Tests (3 pts)

### 3.1 dmesg Access

`labs/lab12/isolation/dmesg.txt`:

**runc (unprivileged):**
```
dmesg: klogctl: Operation not permitted
```

**runc (privileged) — shows HOST kernel boot logs:**
```
[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x610f0000]
[    0.000000] Linux version 6.12.67-linuxkit (root@buildkitsandbox) ...
[    0.000000] OF: reserved mem: Reserved memory: No reserved-memory node in the DT
[    0.000000] Zone ranges:
[    0.000000]   DMA      [mem 0x0000000070000000-0x00000000ffffffff]
```

**Key observation:** Privileged runc containers see the LinuxKit VM's kernel ring buffer directly. Kata containers would see their own VM's boot sequence — a completely separate kernel, proving hardware-level isolation.

### 3.2 /proc Filesystem Visibility

`labs/lab12/isolation/proc.txt`:

| Scope | /proc entries |
|-------|---------------|
| runc container | **58** |
| Kata VM (expected) | Minimal (only guest VM's own processes) |

The runc container's /proc exposes `docker`, `driver`, `fs` — host-kernel-level entries. A Kata VM's /proc would only reflect the guest VM's minimal process tree.

### 3.3 Network Interfaces

`labs/lab12/isolation/network.txt`:

runc container sees **11 interfaces** including:
- `lo` (loopback)
- `tunl0`, `gre0`, `gretap0`, `erspan0` (tunnel devices from host kernel)
- `ip_vti0`, `ip6_vti0`, `sit0`, `ip6tnl0`, `ip6gre0` (more kernel tunnel modules)
- `eth0@if42` (veth pair to host bridge, `172.17.0.5/16`)

A Kata VM would expose only `lo` and a single `eth0` (virtio-net device), because it runs its own network stack inside the guest kernel.

### 3.4 Kernel Modules

`labs/lab12/isolation/modules.txt`:

| Scope | Module count |
|-------|-------------|
| runc container | **145** (host kernel modules visible via /sys/module) |
| Kata VM (expected) | ~10-20 (minimal guest kernel modules) |

runc containers see all 145 host kernel modules (8021q, bonding, bridge, etc.). Kata's guest VM would only load a minimal set required for the microVM.

### Isolation Boundary Analysis

| Aspect | runc | Kata |
|--------|------|------|
| Kernel | Shared host kernel | Separate guest kernel |
| dmesg | Host kernel logs (if privileged) | Own VM boot logs only |
| /proc | 58 entries, host-level info exposed | Minimal guest-only entries |
| Network | 11 interfaces, host tunnel devices visible | Only lo + virtio-net |
| Modules | 145 host modules visible | ~10-20 guest modules |
| Escape impact | Direct host kernel access | Must escape VM first (hypervisor exploit needed) |

### Security Implications

- **Container escape in runc:** Grants direct host-kernel access. A kernel exploit (e.g., CVE in namespace handling) can compromise the entire host. The shared kernel is the single biggest attack surface.

- **Container escape in Kata:** The attacker breaks out of the container into the guest VM's kernel — which is isolated from the host. To reach the host, a second exploit is needed: a QEMU/KVM hypervisor escape. This defense-in-depth approach makes exploitation significantly harder.

---

## Task 4 — Performance Comparison (2 pts)

### 4.1 Container Startup Time

`labs/lab12/bench/startup.txt`:

| Runtime | Run 1 | Run 2 | Run 3 | Avg |
|---------|-------|-------|-------|-----|
| runc | 0.207s | 0.180s | 0.174s | ~0.19s |
| Kata (expected) | — | — | — | 3-5s |

Kata's overhead is ~15-25x slower at startup due to VM boot (QEMU initialization, guest kernel boot, rootfs mount).

### 4.2 HTTP Latency (Juice Shop on runc)

`labs/lab12/bench/http-latency.txt`, `labs/lab12/bench/curl-3012.txt`:

| Metric | Value |
|--------|-------|
| Requests | 50 |
| Average | 0.0012s |
| Minimum | 0.0009s |
| Maximum | 0.0046s |

### Performance Trade-off Analysis

| Factor | runc | Kata |
|--------|------|------|
| **Startup overhead** | ~0.19s (process fork only) | 3-5s (VM boot + guest kernel init) |
| **Runtime overhead** | Near-native (shared kernel syscalls) | Low-to-moderate (~5-10% CPU for virtio I/O) |
| **Memory overhead** | Container metadata only (~few MB) | VM overhead (~128-256 MB per VM for QEMU + guest kernel) |
| **Density** | Hundreds of containers per host | Tens of VMs (limited by RAM for VM overhead) |

### When to Use Each Runtime

- **Use runc when:** Workloads are trusted, startup latency matters (serverless, CI/CD), high container density is needed, and namespace/cgroup isolation is sufficient.

- **Use Kata when:** Running untrusted or multi-tenant workloads, regulatory compliance requires strong isolation boundaries, the threat model includes kernel exploits, and the 3-5s startup overhead is acceptable (long-running services, batch processing).

---

## Artifacts Produced

Generated under `labs/lab12/`:

| Directory | Files |
|-----------|-------|
| `setup/` | `environment-check.txt`, `kata-built-version.txt`, `containerd-kata-config.txt`, `kata-nested-attempt.txt`, `configuration-qemu-runtime-rs.toml`, `build-kata-runtime.sh` |
| `runc/` | `health.txt`, `ps.txt`, `test1.txt`, `kernel.txt`, `cpu.txt` |
| `kata/` | `test1.txt`, `kernel.txt`, `cpu.txt` |
| `analysis/` | `kernel-comparison.txt`, `cpu-comparison.txt` |
| `isolation/` | `dmesg.txt`, `proc.txt`, `network.txt`, `modules.txt` |
| `bench/` | `startup.txt`, `http-latency.txt`, `curl-3012.txt` |

---

## Final Status

- Kata 3.28.0 shim installed and version verified inside nested Linux container.
- containerd configured with `io.containerd.kata.v2` runtime.
- Kata container execution blocked by absence of `/dev/kvm` in Docker Desktop's LinuxKit VM (macOS Apple M4 does not expose hardware virtualization to nested containers).
- runc baseline fully captured: Juice Shop health check (HTTP 200), isolation tests (dmesg, /proc, network, modules), startup time (~0.19s), HTTP latency (avg 0.0012s over 50 requests).
- Theoretical Kata behavior documented throughout, based on Kata architecture and official documentation.
- Full Kata acceptance (successful `io.containerd.kata.v2` container run) requires a native Linux host with KVM support.
