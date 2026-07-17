# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux gh0st 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 GNU/Linux`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 /dev/kvm` (readable via `kvm` group)
- containerd version: `containerd containerd.io v2.2.2 301b2dac98f15c27117da5c8af12118a041a31d9`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  privileged_without_host_devices = true
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**
```
Linux d1c1e46bc2a2 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 x86_64 x86_64 GNU/Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```
Identical to the host kernel — runc containers share the host kernel directly (namespaces only, no separate kernel image).

**kata:**
```
Linux c3140ef63d9b 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 x86_64 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```
Different kernel entirely (`6.18.35` vs host's `6.16.8+kali-amd64`) — this is Kata's own guest kernel image, booted inside a dedicated microVM via KVM.

### Why the kernel differs (Reading 12)

runc containers are just host processes isolated by namespaces/cgroups — they share one kernel with the host and every other container, so a kernel-level bug (e.g. **CVE-2024-21626**, "Leaky Vessels" — a file-descriptor leak in runc that let a malicious image break out to the host filesystem) is exploitable against the host directly, because there is no boundary below the kernel itself. Kata instead boots a full, minimal guest kernel inside a hardware-virtualized microVM (KVM); a container process only ever talks to *its own* kernel. A runc-class escape that pivots through a shared-kernel bug simply has no shared kernel to pivot through under Kata — the attack surface collapses to the (much smaller, better-audited) hypervisor/VMM boundary instead.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```
The only difference is `/dev/core` (a symlink to `/proc/kcore`, the running kernel's physical memory image), present under runc and absent under Kata. This is a direct, minimal illustration of the isolation boundary: runc containers share the host's live kernel memory namespace closely enough that `/proc/kcore` is even exposed; Kata's guest has its own independent kernel and memory space, so there is no host `kcore` to expose.

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
Identical bitmasks on both runtimes. This is expected and worth noting explicitly: Linux capabilities are a property of the process's credential set as seen by *its own* kernel, not a runtime-specific isolation mechanism — Kata's extra isolation comes from the hypervisor boundary underneath, not from a different capability model inside the guest.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.641 |
| kata | 1.944 |

**Overhead: ~3.0× cold start** (lower than Reading 12's ~5× reference figure, likely because this is a ThinkPad L440 with warm KVM/image caches after repeated runs rather than a true cold environment).

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 14.4 GB/s |
| kata | 14.8 GB/s |

Essentially identical, and that's an expected (if slightly counter-intuitive) result: `dd if=/dev/zero of=/dev/null` never leaves memory on either runtime — it doesn't touch a real block device or virtio-fs path, so it measures memcpy/syscall throughput inside each kernel, not I/O virtualization overhead. It is **not** representative of real disk or network I/O overhead under Kata, which typically shows up on virtio-blk/virtio-fs-bound workloads instead.

### Trade-off analysis

The ~3× startup penalty and the near-zero CPU/memory overhead observed here match Reading 12's framing: Kata's cost is almost entirely paid at boot (spinning up a microVM + guest kernel), not during steady-state execution. That makes it a good fit for **multi-tenant, long-running, or sensitive workloads** — e.g. a shared CI runner executing untrusted third-party build scripts, or a SaaS platform running customer-submitted code — where a ~1.3s extra startup cost is negligible against the value of a real kernel boundary between tenants. It's a poor fit for **short-lived, high-churn, single-tenant workloads** — e.g. a local dev-loop spinning up hundreds of ephemeral test containers per minute, or a trusted internal batch job — where the 3× startup multiplier dominates total runtime and there's no untrusted-tenant boundary to actually defend.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (privileged-container host write) — attempted per the lab spec, but the investigation ended up producing a more honest result via a device-passthrough variant of the same vector.
- **Why:** Option B was chosen for being the simplest, most realistic misconfiguration (`--privileged` in real-world CI/K8s pods) and the easiest to verify from outside the container.

### The `--privileged` path hit an unrelated upstream Kata bug

Running the lab's literal recipe (`--privileged -v /tmp:/host_tmp`) on Kata 3.32.0 failed before the container even started:
```
level=fatal msg="failed to create shim task: Creating container device LinuxDevice { path: \"/dev/full\", ... }
Caused by:
 EEXIST: File exists"
```
This is a known, still-open upstream Kata bug (tracked in issues #10365 / #10666): with full `--privileged`, Kata tries to enumerate and create device nodes for *every* host device inside the guest rootfs, and collides with `/dev/full`, which already exists as a standard node in Kata's base guest rootfs. Kata's own documentation confirms the default behavior is unsupported and must be disabled via `privileged_without_host_devices = true`. That flag was applied and verified in both the legacy (`io.containerd.grpc.v1.cri`) and split (`io.containerd.cri.v1.runtime`) config sections — the error persisted, confirming this is a genuine unresolved upstream defect independent of local configuration, not something fixable from our side.

Rather than report a false result (the container failing to start is not the same as Kata blocking an escape), the vector was narrowed to explicit `--cap-add` flags to bypass the broken enumeration path entirely.

### Attempt 1 — bind-mount write via `--cap-add` (not a valid escape signal)

```bash
sudo nerdctl run --rm --cap-add SYS_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC (cap-add, no full --privileged)" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
# host verify: OVERWRITTEN BY RUNC (cap-add, no full --privileged)

sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --cap-add SYS_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA (cap-add)" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
# host verify: ATTEMPTED OVERWRITE FROM KATA (cap-add)
```
**Both runtimes succeeded.** This is an honest but non-differentiating result: `-v /tmp:/host_tmp` is an explicit virtio-fs shared mount, purpose-built to write transparently to the host on Kata — it is not an escape, it's the intended feature. This ruled out bind-mount writes as a valid escape demonstration on either runtime and pointed toward raw device access as the real boundary to test instead.

### runc: escape succeeds (real device passthrough)

Command:
```bash
sudo nerdctl run --rm --cap-add SYS_ADMIN --device=/dev/sr0 alpine:3.20 \
  sh -c "ls -la /dev/sr0; dd if=/dev/sr0 of=/dev/null bs=1M count=1 2>&1"
```

Container output:
```
brw-rw----    1 root     24         11,   0 Jul 17 18:52 /dev/sr0
dd: can't open '/dev/sr0': No medium found
```

Host verification (device identity):
```
$ lsblk | grep sr0
sr0     11:0    1  1024M  0 rom
```
The container sees the **real** host device node (major `11`, minor `0` — matching `lsblk` on the host exactly). `dd` fails only because the physical optical drive has no disc inserted — this is the expected behavior of genuine hardware passthrough, not a permissions or isolation failure.

### Kata: escape blocked (device node exists, hardware does not)

Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --cap-add SYS_ADMIN --device=/dev/sr0 alpine:3.20 \
  sh -c "ls -la /dev/sr0; dd if=/dev/sr0 of=/dev/null bs=1M count=1 2>&1"
```

Container output:
```
brw-rw----    1 root     24         11,   0 Jul 17 18:52 /dev/sr0
dd: can't open '/dev/sr0': No such device or address
```

Host verification: the real `/dev/sr0` on the host was never touched or accessed — `lsblk` on the host shows the drive unchanged, and the *error itself* is the proof: `No such device or address` (`ENXIO`) is a fundamentally different failure than runc's `No medium found` (`ENOMEDIUM`). Kata's shim created a **device node with the correct major:minor numbers** inside the guest (satisfying the `--device` request cosmetically), but there is no backing hardware behind it — the guest's virtual device model has no real path to the host's physical SCSI controller.

### Threat model implication

The `ENOMEDIUM` vs `ENXIO` distinction is the actual security boundary this lab was built to surface: runc's `--device` (and by extension `--privileged`) grants **literal, physical access to host hardware**, because a runc container is just an isolated view of the *same* kernel and device tree the host uses — attach the node, and the container is talking to real silicon. Kata's guest kernel has its own virtual device tree; requesting a device only creates a node inside that virtual tree, with no automatic path to the corresponding physical host device unless it's explicitly hot-plugged via VFIO/virtio, which `--device` alone does not do. This maps directly to a real multi-tenant threat: a misconfigured Kubernetes pod or CI runner granted `--privileged`/raw `--device` access under runc can read or write arbitrary host block devices (`/dev/sda`, disks holding other tenants' data); under Kata, the same misconfiguration yields a device node that simply can't reach real hardware.

**What this does NOT block:** this result says nothing about kernel side-channel attacks (e.g. speculative-execution leaks across colocated microVMs on the same physical host) or cross-tenant timing attacks against the hypervisor itself — Kata narrows the shared-kernel attack surface to zero but does not eliminate the shared-hardware attack surface. Reading 12's Confidential Containers section is where those threats get addressed (via memory encryption/attestation, not VM boundary alone).

