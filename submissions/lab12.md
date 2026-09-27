# Lab 12 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (two runtimes) · Task 2 (cost) · **Bonus Task** (privileged escape contrast, +2 pts)

## Environment

| Item | Value |
|------|-------|
| Host | Lima `lab12-kata` — Ubuntu 24.04 aarch64 on macOS (VZ + `nestedVirtualization: true`) |
| `/dev/kvm` | present (`crw-rw---- root kvm`) |
| Kata | **4.1.0** (pinned installer) + QEMU (`configuration-qemu-runtime-rs.toml`) |
| containerd / nerdctl | containerd 2.x, nerdctl 2.0.4 |
| Note | Nested aarch64 needed `cpu_features=""` (stock `pmu=off` crashes QEMU) and `--net=none`/`--net=host` (default CNI hotplug hits `pci-bridge-0 does not support hotplugging`). Isolation and timing results below use `--net=none`. |

## Task 1

### Kernels

| Runtime | `uname -r` |
|---------|------------|
| Host | `6.8.0-142-generic` |
| runc | `6.8.0-142-generic` |
| Kata | `6.18.35` |

### Devices and capabilities (unprivileged)

| Runtime | `ls /dev \| wc -l` | `CapEff` |
|---------|-------------------:|----------|
| runc | 15 | `00000000a80425fb` |
| Kata | 14 | `00000000a80425fb` |

### What `uname -r` tells an attacker

On `runc`, the container’s kernel release is the host’s. That single line fingerprints the host kernel for CVE hunting, tells the attacker which module interfaces and `/proc`/`/sys` shapes to expect, and confirms they share the same kernel that enforces namespaces — so a kernel exploit or privileged misconfiguration reaches the host directly. On Kata the answer is a different guest kernel (`6.18.35`): fingerprinting still helps against the guest, but host kernel CVEs and host `/dev` are no longer the same address space; compromise has to cross the hypervisor boundary first.

## Task 2

### Startup (five timed runs after one warm-up)

`/usr/bin/time -f '%e' sudo nerdctl run --rm --net=none … alpine:3.20 true` — includes nerdctl/containerd overhead equally for both.

| # | runc (s) | Kata (s) |
|---|--------:|--------:|
| 1 | 0.11 | 13.35 |
| 2 | 0.12 | 12.25 |
| 3 | 0.11 | 12.33 |
| 4 | 0.10 | 12.11 |
| 5 | 0.10 | 12.20 |
| **median** | **0.11** | **12.25** |

### I/O

`dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync` inside the container filesystem (not `/dev/null`), so the write crosses the storage path where a VM-backed runtime differs.

| Runtime | Result |
|---------|--------|
| runc | 512 MiB in 2.51 s → **204.2 MB/s** |
| Kata | 512 MiB in 7.61 s → **67.3 MB/s** (~3× slower) |

### Memory overhead

Method: start one `sleep 120` container per runtime; record `MemAvailable` from `/proc/meminfo` and `ps` RSS for shim/QEMU.

| Metric | Value |
|--------|------:|
| MemAvailable drop (Kata after runc already running) | **~165 MB** (`164952` kB) |
| QEMU RSS | **~160 MB** (`163380` kB) |
| Kata shim RSS | ~19 MB |
| runc shim RSS | ~10 MB |

### Workload verdicts

| Workload | Verdict | Why |
|----------|---------|-----|
| Long-lived CPU-bound microservice | **Kata** | Cold start amortizes; CPU-bound work barely notices the guest (reading 12); stronger isolation for multi-tenant risk |
| Per-request FaaS / CI job with sub-second SLA | **runc** (or Firecracker/gVisor) | ~12 s median cold start is an order of magnitude too slow |
| Tenant-uploaded untrusted binary with host bind mounts of secrets | **needs more information** | Kata’s guest kernel helps, but a `-v` bind is still shared via virtiofs — isolation of compute ≠ isolation of intentionally shared paths |

### When the order-of-magnitude startup cost does not matter

For **long-lived services** that start once and run for hours or days (API workers, batch processors, always-on sidecars), a ~12 s cold start is noise next to image pull, dependency warm-up, and steady-state CPU/RAM. You pay the VM tax once; you keep the second kernel for the whole lifetime of the workload.

## Bonus

### Privileged bind-mount escape

```bash
echo original | sudo tee /tmp/lab12-target
sudo nerdctl run --rm --privileged --net=none -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN > /host_tmp/lab12-target'
# host file → OVERWRITTEN

sudo nerdctl run --rm --privileged --net=none --runtime=io.containerd.kata.v2 \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN > /host_tmp/lab12-target'
# create failed: get host path failed / No such file or directory
# host file → still "original"
```

| Run | Host `/tmp/lab12-target` after |
|-----|-------------------------------|
| runc `--privileged -v /tmp:/host_tmp` | **OVERWRITTEN** |
| Kata identical command | **original** (container never created) |

### Privileged device count and capability mask

| Runtime | Mode | `ls /dev \| wc -l` | `CapEff` |
|---------|------|-------------------:|----------|
| runc | `--privileged` | **189** | `000001ffffffffff` |
| Kata | `--privileged` | *create failed* (host device passthrough) | — |
| Kata | `--cap-add=ALL` (proxy) | **14** (guest devices only) | `000001ffffffffff` |

### What `--privileged` grants, and to what

On `runc`, `--privileged` relaxes cgroup device restrictions and capability bounding against the **host** kernel: the container sees ~189 host `/dev` nodes and a full capability mask, so a bind of `/tmp` is just another host path write. On Kata, the same flag tries to wire host devices into a **guest** VM; here that path fails outright (`get host path failed`), and even when capabilities are raised with `--cap-add=ALL`, the process still only sees ~14 guest devices — privileges apply to the guest kernel, not the Lima/host kernel. The identical escape therefore does not overwrite the host file.

Partial honesty: a **non-privileged** Kata container with `-v /tmp:/host_tmp` *did* write through (`KATABIND` on the host) because virtiofs shares that path by design. Kata stops host-kernel privilege escalation; it does not make intentional shared mounts private.

### Honest limit

Kata does not protect you from **secrets you deliberately bind-mount into the guest** (or from a compromised host/hypervisor) — shared volumes remain shared.

## Cleanup

Remove the `kata` runtime block from `/etc/containerd/config.toml`, restart containerd, delete `/opt/kata`, and `limactl stop lab12-kata` (or delete the VM) when finished.
