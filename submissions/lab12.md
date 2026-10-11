# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- Kernel (host): `Linux ashuno-laptop 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2 x86_64 x86_64 x86_64 GNU/Linux`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 ... /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 v2.3.2`

### Kata installation

- Kata version: `3.32.0`
- containerd config snippet:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

- Shim on PATH: `/usr/local/bin/containerd-shim-kata-v2` → `/opt/kata/bin/containerd-shim-kata-v2`



### Kernel inside containers

**runc:**

```
Linux a0f893991bec 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**kata:**

```
Linux 4508577c515f 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```



### Why the kernel differs (Reading 12)

runc shares the **host** kernel with every container (namespaces + cgroups only), so `uname` shows `6.17.0-40-generic` — the same kernel Lecture 7 / Reading 12 associate with host-kernel escape classes such as runc CVE-2024-21626 ("Leaky Vessels"). Kata starts a **per-container micro-VM** with its own guest kernel (`6.18.35` here), so a bug that reaches "the kernel inside the container" hits the guest, not the host. That kernel boundary is exactly why VM-backed isolation defeats the runc-CVE attack class that assumes a shared host kernel.

## Task 2: Isolation + Performance



### Isolation: /dev diff

```
1d0
< core
```

runc exposes a `core` device node that the Kata guest `/dev` listing does not; both still show the usual virtual devices (`null`, `zero`, `tty`, etc.), but the guest device namespace is not a raw mirror of the host's.

### Isolation: capability sets

runc:

```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

kata:

```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

Capability bitmasks match for the default Alpine workload — the stronger isolation signal here is the **separate guest kernel** (Task 1), not Cap* differences.

### Startup time


| Runtime | Runs (s)                          | Avg startup (s) |
| ------- | --------------------------------- | --------------- |
| runc    | 0.372, 0.335, 0.349, 0.346, 0.364 | **0.35**        |
| kata    | 1.051, 0.978, 0.944, 0.944, 0.992 | **0.98**        |


**Overhead: ~2.8× cold start** (Reading 12 cites ~5×; this host was warm / already had the image cached, so absolute times are lower but Kata remains clearly slower.)

### I/O throughput


| Runtime | Throughput |
| ------- | ---------- |
| runc    | 37.8 GB/s  |
| kata    | 18.7 GB/s  |




### Trade-off analysis

The security gain (separate guest kernel, host-kernel CVE / leaky-vessel class blocked) is worth the ~3× cold-start and roughly half the dd throughput when tenants are mutually untrusted — e.g. multi-tenant SaaS CI runners or customer-supplied containers. It is usually **not** worth it for single-tenant batch jobs on a dedicated host where you already trust the image supply chain and need dense packing / fast scale-out. Deploy Kata where a container escape becomes a cross-tenant incident; keep runc where performance density matters more than a second kernel boundary.

## Bonus: Container-Escape PoC



### Vector chosen

- **Option:** B (privileged-container host write via bind mount)
- **Why:** It matches the most common real misconfig (`--privileged` + host path mounts in CI/K8s), is reproducible without an old vulnerable runc, and still shows a sharp runc-vs-Kata difference on this host.



### runc: escape succeeds

Command:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
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
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```
failed to create shim task: Creating container device LinuxDevice { path: "/dev/full", ... }
Caused by: EEXIST: File exists
```

(Kata refuses to materialize the full `--privileged` host-device set inside the guest; the write never runs.)

Host verification:

```
original
```

**Related control experiment (documented for honesty):** Kata **without** `--privileged` but **with** `-v /tmp:/host_tmp` *does* update the host file (`KATA_NO_PRIV_WRITE`). That is expected virtio-fs **shared volume** behavior, not a kernel escape — intentional mounts are shared by design.

### Threat model implication

Kata blocks what runc allows here because `--privileged` tries to expose a host-like device model into a **separate guest kernel/micro-VM**; on this Kata 3.32 setup that hotplug fails (`/dev/full` EEXIST), so the privileged escape path never executes and the host file stays `original`. This maps to multi-tenant CI runners or misconfigured Kubernetes pods that run `--privileged` with host path mounts — on runc, a malicious job can rewrite host files; on Kata, that privileged device surface does not come up the same way. What this does **not** block: deliberate shared volumes (virtio-fs `-v` mounts), pure kernel side-channels, or cross-tenant timing attacks — those need network policy, mount hygiene, and (for memory confidentiality) Confidential Containers as in Reading 12.

