# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- **Kernel (host):** `Linux heroinwater 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux`
- **KVM accessible:** `crw-rw----+ 1 root kvm 10, 232 /dev/kvm` ✅
- **containerd version:** `github.com/containerd/containerd/v2 2.1.6+unknown`

### Kata installation
- **Kata version:** `3.32.0`
- **containerd config snippet:**
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**
```
Linux 3240346c1dac 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

**kata:**
```
Linux fe914e6374f6 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

### Why the kernel differs (Reading 12)

With `runc`, the container shares the **host kernel** directly via Linux namespaces — the kernel version inside is identical to the host (`6.19.14+kali-amd64`). With Kata, each container runs inside a lightweight **micro-VM** (Dragonball VMM in this case), which boots its own dedicated kernel (`6.18.35`) — a minimal, Kata-maintained kernel image. This is the fundamental isolation boundary Reading 12 describes: runc's namespaces are a view of the same kernel, while Kata's micro-VM is a separate kernel instance with a separate memory space and system-call surface.

The implication for CVE-2024-21626 ("Leaky Vessels", Lecture 7 slide 14) is direct: that vulnerability exploited a race condition in runc's own process where a container process could escape to the host by abusing file-descriptor leaks in the `runc` binary's runtime path — it is a **kernel/runtime attack surface** issue. Because Kata containers communicate with the host only via a narrow virtio interface (not via direct runc process attachment), the class of attacks that require manipulating `runc`'s file descriptors or the shared host kernel are structurally unavailable — there is no runc process managing the container's lifecycle from inside the VM's address space.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff

```
1d0
< core
```

runc exposes `core` (a symlink to `/proc/kcore` — the raw kernel memory device) inside the container. Kata does **not** — the micro-VM's `/dev` tree is managed by the guest kernel, which doesn't have a `kcore` device mapped from a host perspective. This is significant: access to `/proc/kcore` from inside a container is a known privilege-escalation primitive on systems where the host `/proc/kcore` is accessible.

Full `/dev` listing for each runtime:

**runc `/dev`:**
```
core  fd  full  mqueue  null  ptmx  pts  random  shm
stderr  stdin  stdout  tty  urandom  zero
```

**kata `/dev`:**
```
fd  full  mqueue  null  ptmx  pts  random  shm
stderr  stdin  stdout  tty  urandom  zero
```

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

Capability sets are **identical** — Kata does not reduce capabilities at the container level. This is expected: Kata's isolation model is VM-boundary isolation, not capability reduction. A `CAP_SYS_ADMIN` process inside a Kata container is privileged within the micro-VM, but that privilege cannot cross the VM boundary to the host. The protection comes from the hypervisor, not from a reduced capability set.

### Startup time (5-run measurements)

| Run | runc (s) | kata (s) |
|-----|----------:|---------:|
| 1 | 0.483 | 1.353 |
| 2 | 0.474 | 1.341 |
| 3 | 0.425 | 1.401 |
| 4 | 0.437 | 1.292 |
| 5 | 0.453 | 1.344 |
| **avg** | **0.454** | **1.346** |

**Overhead: ~3× cold start** (Reading 12 table estimates ~5×; our result is lower because Dragonball VMM with snapshot-based boot is faster than QEMU-based setups).

### I/O throughput (100 MB dd, `/dev/zero` → `/dev/null`)

| Runtime | Throughput |
|---------|----------:|
| runc | 59.6 GB/s |
| kata | 34.4 GB/s |

**~1.7× I/O overhead** — lower than expected because both operations are in-kernel memory operations (`/dev/zero`→`/dev/null` never hits storage); the overhead is virtio-blk path latency inside the micro-VM, not actual disk I/O.

### Trade-off analysis

Kata's security gain (separate kernel per container, VM-boundary isolation, `runc` CVE class structurally blocked) is worth the ~3× startup and ~1.7× I/O overhead in **multi-tenant workloads** where different customers' code runs on shared infrastructure — cloud CI runners, FaaS platforms, Jupyter notebook services — where a container-escape by one tenant is a breach of another tenant's data. The overhead is amortized by long-running workloads (a 2-second boot on a container that runs for hours is irrelevant). Kata is **not** the right choice for single-tenant batch jobs (a data pipeline that spins up 10,000 short-lived containers per hour where the 1-second extra cold start costs ~3 CPU-hours of overhead per day), or for latency-sensitive sidecar patterns where the container lifetime is measured in milliseconds.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option: B** — privileged-container host bind-mount write
- **Why:** The `--privileged -v /host-path:/container-path` misconfiguration is the most common real-world container-escape vector (seen in Kubernetes pods with `hostPath` volumes + `privileged: true`). It demonstrates the threat model clearly without requiring a patched/unpatched runc version. The contrast with Kata is the most visible possible: the host file is either overwritten or it isn't.

### runc: escape succeeds

**Command:**
```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

**Container output:**
```
OVERWRITTEN BY RUNC CONTAINER
```

**Host verification (`sudo cat /tmp/lab12-target`):**
```
OVERWRITTEN BY RUNC CONTAINER
```

The container process wrote directly to the **host filesystem**. The bind-mount gave the container a direct view of `/tmp` on the host, and the file was overwritten — visible from outside the container with no container involved.

### Kata: escape blocked

**Command:**
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

**Container output:** *(empty — write appeared to succeed inside the micro-VM but output went nowhere visible on the host)*

**Host verification (`sudo cat /tmp/lab12-target`):**
```
original
```

The host file is **unchanged**. Kata's `--privileged -v /tmp:/host_tmp` bind-mount is virtualized through **virtio-fs/9p inside the micro-VM** — what the container sees as `/host_tmp` is a virtual filesystem served by the host, but writes go into the VM's view of that mount, not directly to the host kernel's VFS layer. The host `/tmp/lab12-target` is never touched.

### Threat model implication

Kata blocks this because the bind-mount operates through the micro-VM's guest kernel, which communicates with the host via a **virtio-fs** (or 9p) protocol over a narrow hypervisor interface — the guest kernel cannot directly manipulate host kernel data structures the way a runc namespace can. This maps directly to the real-world threat of misconfigured Kubernetes pods with `hostPath` volumes and `privileged: true` (a common finding in cloud-native security audits): on a runc-backed cluster, one such pod can exfiltrate secrets from host paths or overwrite binaries; on a Kata-backed cluster, the same manifest is structurally contained within the VM boundary. What Kata does **not** block: pure side-channel attacks that cross the hypervisor boundary via shared hardware (cache-timing attacks like Spectre/Meltdown variants), cross-tenant timing attacks on shared CPU resources, or attacks against the hypervisor itself (Kata + TDX/SEV-SNP — "Confidential Containers" from Reading 12 — is where those defenses begin).
