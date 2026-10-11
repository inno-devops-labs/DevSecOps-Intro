# Lab 12 — BONUS — Submission

> Ran on **Ubuntu WSL2** (kernel `6.6.87.2-microsoft-standard-WSL2`, which exposes `/dev/kvm` via
> nested virtualization — Docker Desktop's engine does not, so this lab needs the real distro).
> Runtimes driven with `nerdctl` over `containerd 2.2.2`. Kata micro-VMs boot on KVM via QEMU.

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `6.6.87.2-microsoft-standard-WSL2`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 /dev/kvm` ✅
- containerd version: `2.2.2`

### Kata installation
- Kata version: **3.32.0** (`kata-static`, installs QEMU + cloud-hypervisor + firecracker + micro-VM kernel/rootfs under `/opt/kata`)
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
```
host: 6.6.87.2-microsoft-standard-WSL2
runc: 6.6.87.2-microsoft-standard-WSL2      # identical to host — shares the host kernel
kata: 6.18.35                                # a DIFFERENT kernel — Kata's own micro-VM kernel
```

### Why the kernel differs
`runc` is a namespaces+cgroups sandbox: the container process runs directly on the **host kernel** —
so `uname -r` inside equals the host's. Kata boots each container inside a lightweight **VM with its
own guest kernel** (6.18.35 here), reached only through the hypervisor. That difference is the whole
defense against the **runc-CVE class** (e.g. CVE-2024-21626 "Leaky Vessels", Lecture 7 slide 14):
those exploits abuse the *shared* host kernel / runc's host-side file descriptors to break out. With
Kata there is no shared kernel to break out *to* — an in-guest exploit lands the attacker in a
throwaway VM, not on the host.

---

## Task 2: Isolation + Performance

### Isolation: /dev
| Runtime | `/dev` entries |
|---------|---------------:|
| runc | 15 (host device nodes, filtered by the container's cgroup) |
| kata | 14 (the micro-VM's *own* virtual device set — not the host's) |

### Isolation: capability set
```
runc CapEff: 00000000a80425fb
kata CapEff: 00000000a80425fb
```
The default effective capability *mask* is the same — capabilities are a same-kernel control. The
real isolation Kata adds is orthogonal to caps: it's the **kernel/VM boundary** (Task 1 + the Bonus),
not a smaller cap set.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.641 |
| kata | 2.083 |

**Overhead: ~3.2× cold start** (Reading 12's table quotes ~5×; the gap is the KVM/QEMU micro-VM boot,
lower here because Kata 3.x's boot is well optimized).

### I/O throughput (`dd if=/dev/zero of=/dev/null bs=1M count=1024`)
| Runtime | Throughput |
|---------|-----------|
| runc | 18.8 GB/s |
| kata | 33.4 GB/s |
> Honest caveat (Reading 12 / lab pitfall): `zero → null` never touches a disk — it measures **memory
> bandwidth**, not real I/O, so the numbers are noisy and kata "winning" is measurement artifact, not
> a real speedup. The takeaway is only that CPU/memory-bound work is **near-native on both**; Kata's
> real cost shows up in *startup* and in *disk* I/O (virtio-fs/9p), not in in-memory throughput.

### Trade-off analysis
The security gain (separate guest kernel → the runc-escape CVE class is structurally blocked) is worth
the ~3× cold-start cost whenever you run **untrusted or multi-tenant** code: a shared CI runner
executing arbitrary PRs, a SaaS that runs customer-supplied functions, a malware sandbox. It is **not**
worth it for **trusted, single-tenant** workloads where you control all the code — a nightly internal
batch job or a first-party microservice — because there the escape threat model barely applies and you'd
just pay the boot latency and virtio-fs overhead for nothing.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option B** — privileged container + host bind mount (`--privileged -v /tmp:/host_tmp`).
- **Why:** it's the most common *real* misconfiguration (a `--privileged` container in a CI/K8s
  workload), and the runc-vs-Kata contrast is directly observable from the host.

### runc: escape succeeds
```bash
nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target; cat /host_tmp/lab12-target'
```
Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```
Host verification (`cat /tmp/lab12-target`):
```
OVERWRITTEN BY RUNC CONTAINER      # the host file was modified from inside the container
```

### Kata: escape blocked
```bash
nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target'
```
Host verification (`cat /tmp/lab12-target`):
```
original                            # host file UNCHANGED — the write never reached the host
```

### Why (host device/kernel exposure under `--privileged`)
The deeper reason, shown directly: a `--privileged` **runc** container is handed the host's block
devices and kernel memory; a **kata** one is handed only its micro-VM's:
```
host root device:          /dev/sdf
runc /dev block devices:   sda sdb sdc sdd sde sdf     <- ALL host disks, incl. the root /dev/sdf
kata /dev block devices:   [none]                      <- host disks invisible inside the VM
runc /proc/kcore:          140737471594496 bytes       <- host kernel memory readable
kata /proc/kcore:          (absent)                     <- only the guest kernel exists
```
- **Why Kata blocks what runc allows:** Kata's container filesystem and devices live **inside the
  guest VM**, not on the host. `--privileged` grants privilege *within the VM*; the host's disks,
  `/proc/kcore`, and kernel are simply not present to escalate against. A privileged runc container,
  by contrast, shares the host kernel and sees host block devices — it can mount the host root or read
  host RAM.
- **Real-world threat:** multi-tenant CI runners and Kubernetes pods that ship `--privileged` (far more
  common than they should be) — on runc that's a host takeover; on Kata it's contained to a throwaway VM.
- **What Kata does NOT block:** attacks *on the hypervisor/kernel itself* (a KVM/QEMU 0-day) and
  cross-tenant **side-channel / timing** attacks on shared CPU hardware — those need the memory-
  encryption of Confidential Containers (Intel TDX / AMD SEV-SNP), Reading 12's next layer.
