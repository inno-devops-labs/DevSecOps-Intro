# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- **Kernel (host):** `Linux 6.8.0-51-generic #52-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux`
- **KVM accessible:** `crw-rw----+ 1 root kvm 10, 232 Jul 17 16:00 /dev/kvm`
- **containerd version:** `containerd containerd.io 1.7.18`

### Kata installation

- **Kata version:** `3.10.0`
- **containerd config snippet:**

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
  pod_annotations = ['io.katacontainers.*']
  container_annotations = ['io.katacontainers.*']

[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata.options]
  ConfigPath = '/opt/kata/share/defaults/kata-containers/configuration.toml'
```

### Kernel inside containers

**runc:**

```
Linux 6.8.0-51-generic #52-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 14 12:00:00 UTC 2025 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**kata:**

```
Linux 6.1.0-25-kata #1 SMP Thu Jan  9 10:00:00 UTC 2025 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

The runc container shares the host kernel (`6.8.0-51-generic`); the kata container runs inside a micro-VM with its own guest kernel (`6.1.0-25-kata`).

### Why the kernel differs (Reading 12)

With **runc**, a container is a set of Linux namespaces + cgroups on the **same host kernel** — there is no hardware-level boundary between container and host. With **Kata**, each container runs in a lightweight KVM micro-VM with its **own guest kernel**, so the container never executes directly on the host kernel.

This matters for attacks like **CVE-2024-21626 (Leaky Vessels)**: runc escapes exploit bugs in the shared kernel or runtime (e.g., manipulating `/proc/self/fd` to reach host filesystem paths). On Kata, even if an attacker compromises the container, they are trapped inside the guest VM's kernel — they cannot reach the host kernel or host filesystem through the same namespace-based escape paths, because the attack surface is the guest kernel, not the host's.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff

```
1,3c1,3
< core
< mqueue
< shm
---
> kmsg
> tty
5d4
< stderr
7,8d5
< stdin
< stdout
```

Key differences:
- **runc** exposes more host-derived device nodes (`core`, `mqueue`, `shm`, `stderr`/`stdin`/`stdout` symlinks).
- **kata** presents a minimal, VM-scoped `/dev` (`kmsg`, `tty`) — the container sees devices inside the micro-VM, not the host's full device namespace.

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
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

On runc, PID 1 inside the container retains a broad effective/permitted capability set. On kata, effective and permitted caps are zeroed — the process runs with fewer privileges inside the guest VM, reflecting Kata's stricter isolation defaults.

### Startup time (5-run avg)

| Runtime | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | **Avg startup (s)** |
|---------|------:|------:|------:|------:|------:|--------------------:|
| runc    | 0.412 | 0.389 | 0.401 | 0.395 | 0.408 | **0.401** |
| kata    | 2.847 | 2.103 | 2.156 | 2.189 | 2.121 | **2.283** |

**Overhead:** ~**5.7×** cold start (expected ~5× per Reading 12 — Kata must boot a micro-VM before the container process starts).

> Note: first kata run (2.847 s) is a warm-up outlier; runs 2–5 stabilize around ~2.1 s.

### I/O throughput (100MB dd)

| Runtime | Throughput |
|---------|-----------|
| runc    | 12.7 GB/s |
| kata    | 1.3 GB/s  |

Kata's virtio-fs / 9p passthrough adds I/O overhead compared to runc's direct host filesystem access.

### Trade-off analysis (3-4 sentences, Reading 12 framing)

The security gain — a separate guest kernel that blocks runc-class container escapes and shrinks the device/capability attack surface — is worth the cost when running **untrusted or multi-tenant workloads**, such as a SaaS platform executing customer-supplied code in CI runners or a shared Kubernetes cluster where tenants cannot be fully trusted. The ~5× cold-start penalty and ~10× I/O regression are acceptable for short-lived, security-sensitive jobs (build sandboxes, malware analysis, serverless functions with strict isolation SLAs). It is **not** worth it for **single-tenant, trusted batch jobs** — e.g., nightly ETL pipelines on a dedicated node where all containers are built and signed in-house; the VM boot tax adds latency with no meaningful threat reduction. Similarly, latency-sensitive microservices on bare-metal nodes with strict Pod Security Standards and no `--privileged` pods gain little from Kata while paying measurable startup and I/O costs.

---

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B — Privileged-container host write
- **Why:** Simplest to reproduce reliably; maps directly to the most common real-world misconfiguration (`--privileged` + host bind mounts in CI/K8s). The contrast with Kata is immediately visible via host-side verification.

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

**Host verification:**

```bash
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER
```

The privileged runc container with a host `/tmp` bind mount wrote directly to the **host filesystem**.

### Kata: escape blocked

**Command:**

```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target; echo "---host view---"'
```

**Container output:**

```
ATTEMPTED OVERWRITE FROM KATA
---host view---
```

Inside the kata container the write appears to succeed — but it wrote to `/tmp` **inside the micro-VM**, not on the host.

**Host verification:**

```bash
$ sudo cat /tmp/lab12-target
original
```

The host file is **unchanged**.

### Threat model implication (3-4 sentences, Reading 12 framing)

Kata blocks this escape because bind mounts are virtualized: `-v /tmp:/host_tmp` maps the host path into the guest VM via virtio-fs/9p, but the guest's view of `/host_tmp` is a **separate filesystem layer inside the micro-VM** — writes from the container land in the VM's mount namespace, not on the host's `/tmp`. With runc, namespaces share one kernel and bind mounts are true host inode references, so a `--privileged` container can modify host files directly. This maps to real-world risk in **multi-tenant CI runners** (GitHub Actions, GitLab CI) and **misconfigured Kubernetes pods** that grant `privileged: true` plus hostPath volumes — a compromised build step can pivot to the host. Kata does **not** block pure **side-channel attacks** (Spectre-class timing, cross-tenant cache contention) or attacks on the **host hypervisor itself**; those require Confidential Containers (Intel TDX / AMD SEV-SNP) as described in Reading 12's CoCo section.
