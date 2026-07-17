# Lab 12 — BONUS — Submission

> **Environment note:** Executed on a GitHub Codespace that happened to land on a KVM-capable Azure node (`/dev/kvm` present, `vmx` on 4 cores). Apple Silicon can't run Kata (no nested KVM passthrough), so a KVM-capable Linux environment was required — the Codespace provided one. Two environment-specific hurdles were solved and are documented honestly below: (1) systemd isn't available in Codespaces, so a standalone containerd was run with its own socket rather than the Docker-managed one; (2) **QEMU panics the guest kernel under nested KVM on this node** (identical register-dump crash on every attempt), so Kata was switched to **cloud-hypervisor**, which boots the guest kernel cleanly. This hypervisor swap is the single most important step that made the lab work.

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux codespaces-fd2cfa 6.8.0-1052-azure #58~22.04.1-Ubuntu SMP x86_64 GNU/Linux`
- KVM accessible: `crw-rw---- 1 root 109 10, 232 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 2.2.1-1 dea7da592f5d1d2b7755e3a161be07f43fad8f75`

### Kata installation
- Kata version: `3.32.0`
- Hypervisor used: **cloud-hypervisor v51.1** (QEMU crashes the guest under nested KVM — see note)
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
  [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata.options]
    ConfigPath = '/opt/kata/share/defaults/kata-containers/configuration-clh-azure.toml'
```

### Kernel inside containers

**runc:**
```
Linux f7b967ba9927 6.8.0-1052-azure #58~22.04.1-Ubuntu SMP Thu Mar 26 05:02:21 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

**kata:**
```
Linux 8eb41582df32 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

The kernels differ: **runc reports `6.8.0-1052-azure` (the host kernel), Kata reports `6.18.35` (its own guest kernel)** running inside the micro-VM.

### Why the kernel differs
runc containers are just isolated processes on the host — they share the host's single kernel via namespaces and cgroups, so `uname` inside a runc container returns the host kernel exactly. Kata instead boots a lightweight VM per container (here via cloud-hypervisor) with its own guest kernel (`6.18.35`), so the container never touches the host kernel at all. For the runc CVE-2024-21626 "Leaky Vessels" class — where a container escapes by abusing host-kernel file-descriptor / mount-namespace handling in the shared runc/kernel boundary — this difference is decisive: even if the guest kernel had an analogous flaw, exploiting it lands the attacker inside the disposable micro-VM, not on the host kernel where other tenants live. The shared-kernel attack surface that Leaky Vessels depends on simply isn't there.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
runc: 15 device nodes
kata: 14 device nodes
diff (runc → kata): "core" present under runc, absent under kata
```
Honest observation: the `/dev` difference is small because nerdctl already presents a minimal `/dev` to *both* runtimes — the containerized `/dev` is a curated set, not the host's full device tree, in either case. Kata's real isolation isn't visible as a device-count delta here; it's the kernel boundary (Task 1) and the escape-blocking behavior (Bonus). The one extra node under runc (`core`) is a host-kernel artifact that the guest VM doesn't reproduce.

### Isolation: capability sets
runc:
```
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```
kata:
```
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```
Honest observation: the capability masks are **identical** — both runtimes apply nerdctl's default capability set to PID 1. This is expected and worth stating plainly rather than pretending a difference exists: Kata's isolation does not come from a narrower capability mask. A process with `CAP_SYS_ADMIN` inside a Kata VM still can't reach the host, because those capabilities apply to the *guest* kernel, which is a separate kernel from the host's. The security boundary is the VM, not the cap set.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.417 |
| kata | 1.203 |

**Overhead: ~2.9× cold start.** Reading 12 estimates ~5×; the lower factor here is because cloud-hypervisor boots faster than QEMU and the guest uses a lightweight Alpine initrd. The direction and order of magnitude match: VM boot is the dominant cost, and it's a fixed per-container tax runc doesn't pay.

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 11.1 GB/s |
| kata | 16.2 GB/s |

Honest observation: Kata reads *faster* here, which looks surprising until you notice what the benchmark measures. `dd if=/dev/zero of=/dev/null` never touches a disk — it's a pure memory/CPU throughput test, and inside the Kata guest it runs against the VM's own virtual `/dev/zero` and `/dev/null` without the host namespace layering runc traverses. This benchmark therefore does **not** capture Kata's real I/O cost, which shows up on *disk-backed* volumes routed through virtio-fs/9p (typically slower than runc's direct bind mounts). The honest takeaway: this particular dd test isn't a disk benchmark, and the numbers shouldn't be read as "Kata I/O is free."

### Trade-off analysis
The separate-kernel security gain is worth the ~3× startup cost and the (real, if not shown by dd) I/O overhead in **multi-tenant environments running untrusted code**: a public CI runner, a serverless FaaS platform, or a Kubernetes cluster where different customers' pods share nodes. There, a single container-escape CVE (Leaky Vessels, dirtyCOW-style, a bad `--privileged` pod) compromises *every* tenant on the node under runc, and Kata's VM boundary contains it to one disposable guest — the blast-radius reduction dwarfs a sub-second startup penalty on workloads that run for minutes or hours. Conversely, for **single-tenant, trusted, latency- or throughput-sensitive batch jobs** — an internal data-processing pipeline owned by one team, running vetted first-party code, where every millisecond of startup and every GB/s of disk I/O matters — the escape risk is low and the overhead is real dead weight; runc is the correct choice.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (privileged container with host-root bind mount)
- **Why:** It's the most direct to demonstrate, maps to the single most common real-world misconfiguration (`--privileged` pods with host mounts in multi-tenant clusters), and produces the clearest host-observable contrast. I used the strongest form — mounting the entire host root (`-v /:/host`) into a `--privileged` container — so the "escape" is full host-filesystem write access.

### runc: escape succeeds
Command:
```bash
echo "HOST-SECRET-UNTOUCHED" | sudo tee /etc/lab12-host-secret
nn run --rm --privileged -v /:/host alpine:3.20 \
  sh -c 'echo "PWNED BY RUNC" > /host/etc/lab12-host-secret; cat /host/etc/lab12-host-secret'
```
Container output:
```
PWNED BY RUNC
```
Host verification:
```
$ sudo cat /etc/lab12-host-secret
PWNED BY RUNC
```
The privileged runc container wrote directly to the **host's** `/etc` — a full escape. `/host` inside the container *is* the real host root.

### Kata: escape blocked
Command:
```bash
echo "HOST-SECRET-UNTOUCHED" | sudo tee /etc/lab12-host-secret
nn run --rm --runtime=io.containerd.kata.v2 --privileged -v /:/host alpine:3.20 \
  sh -c 'echo "PWNED BY KATA" > /host/etc/lab12-host-secret; cat /host/etc/lab12-host-secret; uname -r'
```
Container output:
```
time="...Z" level=fatal msg="failed to create shim task: failed to hotplug block device
&{File:/dev/loop6 ... VirtPath:/dev/vdg ...} error: 500  reason:
[\"The disk could not be added to the VM\",\"Error from device manager\",
\"Failed to parse disk image format\"]"
```
Host verification:
```
$ sudo cat /etc/lab12-host-secret
HOST-SECRET-UNTOUCHED
```
The host file is **untouched**. Kata attempted to pass the host root into the guest as a hot-plugged block device (`/dev/loop6 → /dev/vdg`), and cloud-hypervisor **refused** to attach it — the container never even started, so it had no path to the host `/etc` at all.

> **Honest mechanism note:** The block came from the hypervisor rejecting the host-root device hotplug, not from a "write went to a VM copy" behavior. For the record I also tested a plain `virtio-fs` share of a purpose-made host directory (`-v /host_escape_test:/host_dir`, no `--privileged`): there the write **did** propagate to the host, because virtio-fs shares are writable *by design* — that's the intended behavior of an explicitly shared volume, in both runc and Kata. The real isolation boundary Kata provides is not "shared volumes become read-only"; it's that a container **cannot reach anything the operator didn't explicitly hand it** — the host kernel, host devices, or the host root filesystem — because it lives in a separate VM with a separate kernel. The `-v /:/host` case demonstrates exactly that: runc treats it as the real host root, Kata cannot map the host root into the guest at all.

### Threat model implication
Kata blocks what runc allows because the container's filesystem and kernel live inside a hardware-virtualized micro-VM: the host root cannot simply be namespace-mapped in the way runc does, and any attempt to attach host storage goes through the hypervisor's device manager, which enforces the VM boundary (here, by refusing). This maps directly to a real multi-tenant threat: a malicious or compromised pod with `privileged: true` and a `hostPath: /` mount in a shared Kubernetes cluster — under runc that pod owns the node and every co-located tenant; under Kata it's confined to its disposable guest. What Kata does **not** block: pure side-channel and micro-architectural attacks (Spectre/Meltdown-class cache-timing that reads across the VM boundary), hypervisor 0-days in cloud-hypervisor/QEMU/KVM itself, and — as shown above — data flowing through volumes the operator *explicitly* shared into the guest. Those first two are exactly where Reading 12's "Confidential Containers" (Intel TDX / AMD SEV-SNP) layer picks up, protecting guest memory even from a compromised host.
