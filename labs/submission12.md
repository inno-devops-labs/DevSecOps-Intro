# Lab 12 — Kata Containers: VM-backed Container Sandboxing

**Name:** Baha Alimi
**Branch:** `feature/lab12`
**Host:** Windows 11 / WSL2 (Ubuntu 24.04.1 LTS) / Docker Desktop
**WSL2 Kernel:** 5.15.167.4-microsoft-standard-WSL2

---

## Environment & Prerequisites
```
CPU virtualization: egrep -c '(vmx|svm)' /proc/cpuinfo → 24
KVM device:         /dev/kvm present (crw-rw---- root kvm)
OS:                 Ubuntu 24.04.1 LTS (Noble Numbat)
containerd:         1.7.28
nerdctl:            2.2.0
Kata shim:          3.28.0 (runtime-rs / Rust)
CNI plugins:        1.6.2
```

**WSL2 note:** The Microsoft WSL2 kernel (`5.15.167.4`) does not include the `vhost_vsock`
module required by the default Kata QEMU configuration. Kata runtime-rs with the Dragonball
hypervisor (`configuration-dragonball.toml`) was used instead — it communicates over
virtio-mmio and does not require vsock, making it fully compatible with WSL2 KVM.

---

## Task 1 — Install and Configure Kata

### 1.1 Approach: Provided Scripts vs Manual Steps

Three scripts were provided in `labs/lab12/`:

| Script | Purpose | Used? |
|--------|---------|-------|
| `setup/build-kata-runtime.sh` | Build shim from source via Docker | No — used pre-built binary from static release (faster, identical result) |
| `scripts/install-kata-assets.sh` | Download static release, extract, link config | Equivalent steps performed manually due to WSL2 config path adjustment |
| `scripts/configure-containerd-kata.sh` | Idempotently update containerd config | Equivalent steps performed manually |

The `install-kata-assets.sh` script links config to
`/etc/kata-containers/runtime-rs/configuration.toml`. On WSL2 with Dragonball, the config
needed to be placed at `/etc/kata-containers/configuration.toml` directly. Manual steps
were used to control this path precisely.

### 1.2 Installation Steps

Downloaded Kata 3.28.0 static release (1.5 GB) and extracted to `/opt/kata/`:
```bash
KATA_VERSION=3.28.0
curl -fL -o /tmp/kata-static.tar.zst \
  "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-amd64.tar.zst"
sudo tar -C / -xf /tmp/kata-static.tar.zst
```

Installed the runtime-rs shim (vsock-free, WSL2-compatible):
```bash
sudo install -m 0755 /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/
```

**Shim version (`labs/lab12/setup/kata-built-version.txt`):**
```
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.28.0, commit: 660e3bb6535b141c84430acb25b159857278d596
```

Kata configuration (Dragonball hypervisor for WSL2 compatibility):
```bash
sudo mkdir -p /etc/kata-containers
sudo cp /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml \
  /etc/kata-containers/configuration.toml
```

### 1.3 containerd Configuration

Equivalent to running `configure-containerd-kata.sh` — added Kata runtime to
`/etc/containerd/config.toml`:
```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

Restarted containerd and verified:
```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

**Output (`labs/lab12/kata/test1.txt`):**
```
Linux c58fd2f034a2 6.12.47 #1 SMP Tue Mar 17 01:38:02 UTC 2026 x86_64 Linux
```

✅ Kata runtime working — guest kernel `6.12.47` confirms VM boot, completely separate
from WSL2 host kernel `5.15.167.4`.

---

## Task 2 — Run and Compare Containers (runc vs Kata)

### 2.1 runc Container — Juice Shop
```bash
sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
```

**Health check result (`labs/lab12/runc/health.txt`):**
```
juice-runc: HTTP 200
```

✅ Juice Shop running under runc on port 3012.

### 2.2 Kata Containers — Alpine Tests
```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```
```
Linux c58fd2f034a2 6.12.47 #1 SMP Tue Mar 17 01:38:02 UTC 2026 x86_64 Linux
```
```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
```
```
6.12.47
```

### 2.3 Kernel Version Comparison (`labs/lab12/analysis/kernel-comparison.txt`)

| Runtime | Kernel |
|---------|--------|
| Host (WSL2) | `5.15.167.4-microsoft-standard-WSL2` |
| runc container | `5.15.167.4-microsoft-standard-WSL2` *(shares host kernel)* |
| Kata guest VM | `6.12.47` *(separate, purpose-built guest kernel)* |

**Key finding:** runc containers share the host kernel — a kernel vulnerability is directly
exploitable from inside the container. Kata boots an entirely separate guest kernel (`6.12.47`),
making the host kernel completely invisible and unreachable from within the VM.

### 2.4 CPU Model Comparison (`labs/lab12/analysis/cpu-comparison.txt`)
```
Host CPU:    model name : 12th Gen Intel(R) Core(TM) i5-12450H
Kata VM CPU: model name : Intel(R) Xeon(R) Processor
```

The Dragonball hypervisor presents a virtualized CPU model (`Intel Xeon Processor`) rather
than exposing the real hardware (`i5-12450H`). This prevents guest fingerprinting of host
hardware and confirms a genuine hardware virtualization boundary is in place.

### 2.5 Isolation Implications

| Aspect | runc | Kata |
|--------|------|------|
| Kernel | Shares host kernel directly | Separate guest kernel (6.12.47) |
| CPU visibility | Real hardware model exposed | Virtualized CPU model presented |
| Syscall path | Direct to host kernel | Via guest kernel → hypervisor → host |
| Isolation boundary | Linux namespaces + cgroups | Full VM hardware boundary |
| Attack surface | Host kernel syscall table | Guest kernel only |

---

## Task 3 — Isolation Tests

### 3.1 Kernel Ring Buffer (dmesg)
```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 dmesg 2>&1 | head -5
```

**Output (`labs/lab12/isolation/dmesg.txt`):**
```
[    0.000000] Linux version 6.12.47 (@8d7cdb68e89d) (gcc (Ubuntu 11.4.0) 11.4.0) #1 SMP Tue Mar 17 01:38:02 UTC 2026
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000007fffffff] usable
```

**Analysis:** The dmesg output shows the boot log of the Kata guest VM kernel (`6.12.47`),
not the host. Kata-specific boot parameters are visible (`kata-containers.target`,
`virtio_mmio`, `agent.log_vport`) — proof that a fully independent kernel booted inside a VM.
A runc container's dmesg would show the host WSL2 kernel boot log, exposing host system
information to any process inside the container.

### 3.2 /proc Filesystem Visibility (`labs/lab12/isolation/proc.txt`)
```
Host /proc entries:    119
Kata VM /proc entries:  52
```

**Analysis:** The host `/proc` exposes 119 entries including PIDs of every process on the
host, kernel configuration, hardware details, and system-wide networking state. The Kata
guest sees only 52 entries — the processes and state of its own isolated VM. The host
process table is completely invisible inside the Kata VM.

### 3.3 Network Interfaces in Kata VM (`labs/lab12/isolation/network.txt`)
```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
   inet 127.0.0.1/8
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
   inet 10.4.0.10/24
```

**Analysis:** The Kata VM has its own isolated network stack with a dedicated virtual NIC
(`eth0`) on a private subnet (`10.4.0.10/24`). The VM has no visibility into the host's
network interfaces, other containers' networks, or the physical NIC.

### 3.4 Kernel Module Count (`labs/lab12/isolation/modules.txt`)

| Environment | Kernel Modules |
|-------------|----------------|
| Host (WSL2) | 114 |
| Kata guest VM | 72 |

**Analysis:** The host exposes 114 kernel modules — the full set loaded by the WSL2 kernel.
The Kata guest has only 72 modules belonging to its own minimal purpose-built guest kernel.
Host kernel modules are completely unreachable from inside the VM.

### 3.5 Isolation Boundary Summary

| Test | runc | Kata |
|------|------|------|
| dmesg | Shows host kernel boot log | Shows guest VM boot log only |
| /proc entries | 119 (host-level visibility) | 52 (VM-isolated) |
| Network | Shared host namespace | Dedicated virtual NIC (10.4.0.10/24) |
| Kernel modules | 114 (host kernel modules) | 72 (guest kernel modules only) |

### 3.6 Security Implications

**Container escape in runc** reaches the host kernel directly. A successful kernel exploit
immediately gives the attacker root on the host — full access to all other containers, the
host filesystem, and the network. The only barrier is Linux namespace and cgroup isolation,
which has historically had bypasses (Dirty COW, runc CVE-2019-5736, etc.).

**Container escape in Kata** first requires breaking out of the guest VM — exploiting the
hypervisor (Dragonball) or the Kata agent. Even a successful guest kernel exploit only gives
the attacker control of the VM, not the host. A second, separate exploit of the hypervisor
layer is required to reach the host. This two-layer defence makes full host compromise
significantly harder and narrows the exploitable attack surface to the hypervisor boundary
rather than the entire host kernel syscall table.

---

## Task 4 — Performance Comparison

### 4.1 Container Startup Time (`labs/lab12/bench/startup.txt`)

| Runtime | real | user | sys |
|---------|------|------|-----|
| runc | 1.148s | 0.003s | 0.007s |
| Kata | 2.664s | 0.005s | 0.004s |

Kata takes approximately **2.3× longer** to start than runc. This overhead is the cost of
booting a lightweight VM — initializing the Dragonball hypervisor, booting the guest kernel,
starting the Kata agent, and then launching the container process inside the VM. For
long-running services like Juice Shop this is a one-time cost that becomes irrelevant once
the container is running.

### 4.2 HTTP Response Latency — juice-runc (`labs/lab12/bench/http-latency.txt`)

50 consecutive requests to `http://localhost:3012/`:
```
avg=0.0030s   min=0.0019s   max=0.0094s   n=50
```

The runc-based Juice Shop serves requests in ~3ms average with very low variance (max 9.4ms),
representing the baseline performance of a standard runc container with no VM overhead in
the request path.

### 4.3 Performance Trade-off Analysis

**Startup overhead:** Kata's ~2.7s vs runc's ~1.1s is the most significant difference. For
short-lived workloads (CI jobs, batch tasks, serverless functions) this is noticeable. For
long-running services it is a one-time cost.

**Runtime overhead:** Once running, Kata containers have near-native throughput for CPU-bound
tasks since Dragonball uses KVM hardware virtualization with no emulation overhead. Memory
and I/O access are slightly higher latency due to the VM boundary and virtio driver path.

**CPU overhead:** The hypervisor consumes a small amount of CPU for VM management — typically
1–3% additional overhead for steady-state workloads, negligible for most production services.

### 4.4 When to Use Each Runtime

| Scenario | Runtime | Reason |
|----------|---------|--------|
| Multi-tenant SaaS (untrusted user code) | **Kata** | VM boundary prevents cross-tenant escapes |
| CI/CD pipelines running arbitrary code | **Kata** | Isolates build environments from host |
| Processing untrusted data/documents | **Kata** | Contains potential exploits in VM |
| Regulated workloads (PCI-DSS, HIPAA) | **Kata** | Stronger isolation for compliance |
| Internal microservices (trusted code) | **runc** | Lower overhead, faster startup |
| Development and testing | **runc** | Fast iteration, easier debugging |
| Serverless / FaaS (short-lived) | **runc** | Startup latency matters at scale |

---

## Setup Challenges & Solutions

| Challenge | Root Cause | Solution |
|-----------|-----------|----------|
| `vhost_vsock` module not found | WSL2 Microsoft kernel excludes this module | Switched to runtime-rs + Dragonball hypervisor (virtio-mmio, no vsock required) |
| CNI bridge plugin missing | nerdctl requires CNI plugins for networking | Installed `cni-plugins` v1.6.2 to `/opt/cni/bin/` |
| `iptables` not found | Minimal WSL2 Ubuntu install | `sudo apt-get install -y iptables` |
| `/etc/containerd/` directory missing | Fresh containerd install | `sudo mkdir -p /etc/containerd` before generating default config |
| kata-static 404 on `.tar.xz` | Release format changed to `.tar.zst` in Kata 3.x | Checked GitHub API for actual asset names before downloading |

---

## File Inventory
```
labs/lab12/
├── setup/
│   └── kata-built-version.txt          # containerd-shim-kata-v2 --version output
├── runc/
│   └── health.txt                      # HTTP 200 health check for juice-runc
├── kata/
│   ├── test1.txt                       # uname -a inside Kata container
│   └── kernel.txt                      # uname -r inside Kata container (6.12.47)
├── isolation/
│   ├── dmesg.txt                       # Kata VM boot log (guest kernel dmesg)
│   ├── proc.txt                        # /proc entry counts (host: 119, Kata: 52)
│   ├── network.txt                     # Kata VM network interfaces
│   └── modules.txt                     # Kernel module counts (host: 114, Kata: 72)
├── bench/
│   ├── startup.txt                     # runc: 1.148s, Kata: 2.664s
│   ├── curl-3012.txt                   # Raw 50-request latency measurements
│   └── http-latency.txt                # avg=0.0030s min=0.0019s max=0.0094s
└── analysis/
    ├── kernel-comparison.txt           # Host vs Kata kernel version
    └── cpu-comparison.txt              # i5-12450H vs Intel Xeon (virtualized)
```

---

## Conclusion

Kata Containers provides a qualitatively stronger isolation boundary than runc by placing
each container inside a lightweight VM with its own kernel, memory space, CPU context, and
network stack. The evidence collected makes the boundary concrete:

- Guest kernel `6.12.47` is completely separate from host kernel `5.15.167.4`
- dmesg shows only the VM's own boot log — host kernel activity is invisible
- `/proc` has 52 entries vs 119 on the host — the VM's process namespace is fully isolated
- CPU presents as virtualized `Intel Xeon` rather than the real `i5-12450H`
- Network is a dedicated virtual NIC (`10.4.0.10/24`), not the host stack
- Kernel module set is minimal and guest-only (72 vs 114 on host)

The cost is a ~1.5s additional startup time and small hypervisor overhead — acceptable for
security-sensitive workloads where the threat model includes container escape attempts. For
internal trusted services, runc remains the pragmatic default. A mature container security
programme deploys both: runc for efficiency-sensitive internal workloads, Kata for any
surface exposed to untrusted code or data.