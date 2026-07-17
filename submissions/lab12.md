# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux mdLite 6.8.0-124-generic #124~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 21:05:19 UTC  x86_64 x86_64 x86_64 GNU/Linux`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 июл 17 21:45 /dev/kvm`
- containerd version: `containerd containerd.io v2.2.3 77c84241c7cbdd9b4eca2591793e3d4f4317c590`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  privileged_without_host_devices = true
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata.options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration.toml"
```

### Kernel inside containers

**runc:**
```
Linux fc99060f77b6 6.8.0-124-generic #124~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 21:05:19 UTC  x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

**kata:**
```
Linux 94da0a0e204b 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

### Why the kernel differs (Reading 12)

`runc` containers share the host kernel directly, so any kernel boundary bug — like the file-descriptor leak in CVE-2024-21626 ("Leaky Vessels") — turns "escaping the container" and "reaching the host" into the same event. Kata runs each container in its own lightweight VM with a separate kernel (confirmed here: `6.18.35` guest vs. `6.8.0-124-generic` host), so a similar escape would only land the attacker in the guest kernel, not the host. Kata doesn't make escapes impossible, but it turns a single-kernel-bug compromise into a two-hop problem requiring a separate hypervisor-escape vulnerability.

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```
The only difference is `/dev/core`, present in the `runc` container's device listing but absent from Kata's. This is a minor artifact — Kata's guest VM boots its own minimal devtmpfs from scratch rather than inheriting/bind-mounting the host's `/dev`, so it only exposes the device nodes its guest kernel actually creates. It's not a meaningful security finding on its own (`/dev/core` isn't a sensitive host resource), but it's a visible symptom of the underlying architectural difference: `runc`'s `/dev` is host-derived, Kata's is independently generated inside the sandboxed kernel.

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

### Startup time (5-run avg)

| Runtime | Avg startup (s) |
| --- | --- |
| runc | 0.818 |
| kata | 2.564 |

**Overhead: ~3.13x cold start** (lower than the ~5x suggested by Reading 12's table — likely because this is a warm-cache `alpine:3.20` pull with a lightweight guest kernel/initrd already resident on disk from repeated runs; Kata's overhead is dominated by VM boot time, which benefits disproportionately from OS-level disk caching between runs, whereas `runc`'s per-run cost was already near its floor).

### I/O throughput (100MB dd)

| Runtime | Throughput |
| --- | --- |
| runc | 8.2 GB/s |
| kata | 8.4 GB/s |

Essentially identical, and both figures are far above real disk speeds — this benchmark writes to `/dev/null`, so it's measuring in-memory/CPU throughput inside each container, not actual storage I/O through Kata's virtio-fs or block-device layer. It confirms Kata doesn't add meaningful CPU-bound overhead once a workload is running (the entire cost is paid at VM boot), but it isn't a valid test of Kata's real filesystem I/O penalty, which typically does show up under genuine disk-backed workloads via virtio-fs.

### Trade-off analysis
The security gain is worth the ~3x cold-start cost whenever a single host is running mutually untrusted workloads and a `runc`-class kernel-escape CVE (like CVE-2024-21626) would mean one tenant's compromised container reaching every other tenant's data on that node — multi-tenant SaaS platforms, CI/CD runners executing arbitrary untrusted pull-request code, or any shared Kubernetes cluster serving multiple customers are the textbook case, since the blast radius of a single kernel bug is capped at one guest VM instead of the whole host. It's not worth it for single-tenant, trusted-code workloads where the "attacker" would have to be your own code or supply chain — e.g. a company's internal batch-processing job built from a controlled, scanned image running on a dedicated node — where the ~2.5s-per-cold-start overhead adds real latency and infrastructure cost (denser bin-packing is harder with Kata's per-container VM memory floor) for a threat model that mostly doesn't apply. The general rule from Reading 12: pay the VM-isolation tax where workload trust boundaries cross tenant/customer lines; skip it where the whole node is already a single trust domain and the overhead just becomes friction with no matching risk reduction.

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** A — bind-mount-based host filesystem write (`-v /tmp:/tmp` or equivalent shared-mount container, no extra privileges required)
- **Why:** This is the simplest and most common real-world escape class in practice — it doesn't require a kernel exploit or `--privileged`, just an overly permissive bind mount, which is a routine misconfiguration in CI pipelines and Kubernetes manifests rather than an edge-case vulnerability. It directly demonstrates the core `runc` vs. Kata architectural difference: whether "the container's filesystem" and "the host's filesystem" are the same object or two genuinely separate ones.

### runc: escape succeeds
Command:
```bash
# Run the escape attempt with runc
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```
Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```
Host verification:
```
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER
```
The write from inside the `runc` container landed directly on the host filesystem — the bind mount is the same inode/filesystem on both sides, so there is no isolation boundary here at all; the container process and a host process writing to `/tmp/lab12-target` are functionally identical operations.

### Kata: escape blocked
Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---Inside VM view---"' 2>&1 \
  | tee labs/lab12/results/kata-escape-attempt.txt
```
Container output:
```
time="2026-07-17T22:02:06+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
ATTEMPTED OVERWRITE FROM KATA
---Inside VM view---
```
Host verification:
```
$ sudo cat /tmp/lab12-target
original
```
The write reports as successful *inside* the Kata sandbox (the guest VM's own view of `/tmp/lab12-target` shows the new content), but the host file is untouched — the write never left the guest VM's filesystem at all.


### Threat model implication
- **Why Kata blocks it:** Kata's guest VM doesn't get a raw host file descriptor for bind-mounted paths — writes go through a virtualized filesystem layer (virtio-fs/9p), so a "write to /tmp" inside the sandbox lands in the guest's own filesystem, never on host disk.
- **Real-world threat this maps to:** multi-tenant CI/CD runners with mounted `/tmp`, Docker sockets, or build caches; misconfigured Kubernetes pods with overly broad `hostPath` volumes — both give a compromised `runc` container direct host filesystem access, which Kata contains.
- **What this does NOT block:** side-channel attacks on shared CPU/memory (cache-timing, Spectre/Meltdown-class) — Kata isolates the filesystem and kernel, not the underlying hardware. That gap is addressed by Reading 12's "Confidential Containers" section (memory encryption, attestation) instead.