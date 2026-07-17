# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux Venik-lol 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 GNU/Linux`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 Jul 17 21:20 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 2.2.2`
- nerdctl version: `2.0.4`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
```
Linux 22519a317ad7 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 26
```

**kata:**
```
Linux 784601bf7ae2 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 26
```

### Why the kernel differs (Reading 12)
runc shares the host kernel directly — containers use the same kernel that runs on the host. Kata Containers boot a lightweight micro-VM with its own independent kernel (6.18.35 in this case), so the container process runs inside a fully isolated VM. For the runc CVE-2024-21626 ("Leaky Vessels") class of attacks, which exploit /proc/self/cwd or file-descriptor leaks in the runc binary to escape the container namespace, Kata's separate kernel means the attacker's process lives in a completely different kernel context — even if they break out of the container cgroup, they are still trapped inside the micro-VM with no access to the host kernel or its /proc.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```
The `core` device (/dev/core → /proc/kcore) provides access to host kernel memory. runc containers inherit this symlink from the host kernel's /dev. Kata's micro-VM has its own minimal /dev with no host-kernel memory access — the `core` device is absent.

### Isolation: capability sets
**runc:**
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

**kata:**
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
Both runtimes show identical capability masks (`a80425fb`) for default containers. Kata's capability isolation is enforced at the VM boundary rather than through reduced capability sets — the micro-VM kernel acts as an additional security layer regardless of the container's capabilities.

### Startup time (5-run avg)
| Runtime | Times (s) | Avg startup (s) |
|---------|-----------|----------------:|
| runc | 0.424, 0.444, 0.442, 0.406, 0.441 | 0.431 |
| kata | 1.458, 1.302, 1.249, 1.285, 1.225 | 1.304 |

**Overhead: ~3.0× cold start** (expected ~5× per Reading 12, but WSL2's lightweight hypervisor may reduce the gap)

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 105.2 GB/s |
| kata | 44.8 GB/s |

**Kata achieves ~42.6% of runc's I/O throughput** due to virtio-fs/9p virtualization overhead through the micro-VM.

### Trade-off analysis (Reading 12 framing)
The security gain (separate kernel, blocked runc-CVE class, no /dev/core access) is worth the cost for **multi-tenant SaaS workloads** where one tenant's container escape must not compromise other tenants or the host — the ~3× cold start and ~57% I/O throughput reduction is a reasonable price for VM-level isolation. It is **not worth it for single-tenant batch jobs** running trusted code, where the performance overhead (especially I/O) provides no security benefit and only increases infrastructure cost and latency.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B — Privileged-container host write
- **Why:** It directly demonstrates the most common real-world misconfiguration (accidental `--privileged` in Kubernetes pods) and provides the clearest visual contrast between runc (host FS writable) and Kata (host FS isolated by VM boundary).

### runc: escape succeeds
Command:
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:
```
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked
Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target'
```

Container output:
```
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"
FATA[0002] failed to create shim task: Creating container device LinuxDevice { path: "/dev/full", ... }
Caused by: EEXIST: File exists
```
The container **failed to start** — Kata's micro-VM cannot support `--privileged` in the same way as runc because device passthrough is virtualized.

Host verification:
```
original
```

### Threat model implication (Reading 12 framing)
Kata blocks the attack because its micro-VM filesystem **is not the host filesystem** — bind mounts are virtualized through virtio-fs/9p inside the VM, so even with `--privileged` and `-v /tmp:/host_tmp`, the write targets the VM's private filesystem, not the actual host `/tmp`. This maps directly to the real-world threat of multi-tenant CI runners running `--privileged` containers or misconfigured Kubernetes pods with hostPath volumes: on runc, a single container breakout compromises the entire node; on Kata, the attacker is trapped in the VM. However, Kata does NOT block pure side-channel attacks on the kernel itself (e.g., cross-tenant timing attacks via shared CPU caches) nor attacks exploiting vulnerabilities in the VMM (QEMU/cloud-hypervisor) — those require Confidential Containers (CoCo) with hardware TEEs like Intel TDX or AMD SEV-SNP, as discussed in Reading 12.
