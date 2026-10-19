# Lab 12 — VM-Backed Container Isolation with Kata

Environment: Linux guest inside Colima VZ with `--nested-virtualization` (`/dev/kvm` present). Kata **4.1.0** (`/opt/kata/VERSION`), containerd + `nerdctl`. Nested KVM QMP handshake failed on this Apple Silicon host, so the QEMU binary was wrapped to force `accel=tcg` (same Kata runtime path, software virt). Timings include that cost; runc vs Kata comparison remains fair because both go through the same `nerdctl`/containerd stack.

## Task 1

### Kernels
| Where | `uname -r` |
|-------|------------|
| Host (Colima VM) | `6.8.0-117-generic` |
| `runc` | `6.8.0-117-generic` |
| Kata (`io.containerd.kata.v2`) | `6.18.35` |

Kata does **not** match the host — it boots its own guest kernel (`vmlinux-6.18.35-202`).

### Devices and capabilities (unprivileged)
| Runtime | `ls /dev \| wc -l` | `CapEff` |
|---------|-------------------:|----------|
| runc | **15** | `00000000a80425fb` |
| Kata | **14** | `00000000a80425fb` |

### What `uname -r` tells an attacker
On `runc`, the container’s kernel release **is** the host’s. That single line fingerprints the host kernel for exploit selection (known CVEs, available syscalls, module layout assumptions) without leaving the namespace. On Kata the answer is a different kernel inside a VM: the attacker is targeting the **guest** kernel and cannot directly drive the host’s syscall table; escaping means breaking the hypervisor boundary first, not just a namespace.

## Task 2

### Startup (warm-up discarded; five timed `nerdctl run --rm … true`)
| # | runc (s) | Kata (s) |
|--:|---------:|---------:|
| 1 | 0.11 | 8.78 |
| 2 | 0.10 | 8.79 |
| 3 | 0.10 | 8.76 |
| 4 | 0.10 | 8.78 |
| 5 | 0.12 | 8.78 |
| **median** | **0.10** | **8.78** |

(~88× slower for Kata here; TCG nested virt inflates the absolute Kata numbers vs bare-metal KVM.)

### I/O
Write to a file in the container FS (not `/dev/null`) so the path crosses the runtime’s storage layer.

| Runtime | Result |
|---------|--------|
| runc | `512 MiB` in `0.197 s` → **~2.5 GB/s** |
| Kata | Bulk `dd`/`write` inside the TCG guest repeatedly **SIGSEGV (139)** on this nested setup; tiny create still pays the ~9 s VM start. On real KVM the storage path is virtio-fs/block into a second kernel — slower and more copies than runc’s host VFS. |

We write to a file (not `/dev/null`) because `/dev/null` never touches the filesystem stack that differs between runc and a VM-backed runtime.

### Memory overhead
Idle `alpine sleep` measured via cgroup `memory.current` (nerdctl stats under-reports the hypervisor):

| Runtime | `memory.current` |
|---------|-----------------:|
| runc | **339 968 B** (~332 KiB) |
| Kata | **491 384 832 B** (~469 MiB) |

Overhead ≈ **469 MiB per sandbox** here (guest RAM + VMM), vs a few hundred KiB for runc.

### Workload verdicts
| Workload | Verdict | Why |
|----------|---------|-----|
| Stateless API pods, dense pack, cold-start sensitive | **runc** | Median start 0.1 s vs ~9 s; memory density matters |
| Untrusted multi-tenant batch / CI job with host mounts forbidden | **Kata** | Second kernel contains kernel exploits; worth the RAM |
| GPU training with vendor modules | **needs more information** | Device passthrough and driver support dominate; neither answer is automatic |

### When the order-of-magnitude start cost does not matter
Long-running services that start once and stay up for days (databases, always-on APIs, workers with sticky pools): an extra ~9 s at boot is noise next to hours of uptime and is paid once per sandbox, not per request.

## Bonus

### Escape runs
**runc** (privileged + host bind):
```text
echo original | sudo tee /tmp/lab12-target
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN > /host_tmp/lab12-target'
# host file → OVERWRITTEN
# privileged: ls /dev → 192 ; CapEff → 000001ffffffffff
```

**Kata** (identical flags + `--runtime=io.containerd.kata.v2`):
```text
# create fails: get host path failed (privileged device enumeration under this nested/TCG setup)
# host file remains: original
```

`--privileged` on runc expands the container’s view to ~192 `/dev` nodes and a full capability mask, and a bind mount is the **host** filesystem — writing `/host_tmp` is writing `/tmp` on the host. On Kata, `--privileged` grants privileges **inside the guest VM’s kernel**, not over the host; in this environment the privileged create path aborted before a write, and the host file stayed `original`.

### Honest limit
Kata does **not** stop a malicious workload that you voluntarily share host paths into via virtio-fs: an **unprivileged** `-v /tmp/lab12share:/host_tmp` Kata container still wrote `FROM_KATA` through to the host. Isolation is a second kernel, not a substitute for “don’t mount the crown jewels.”

Also: supply-chain / app RCE inside the guest, and hypervisor bugs, remain in scope.
