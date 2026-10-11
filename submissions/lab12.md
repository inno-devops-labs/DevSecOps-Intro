# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux ... 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 /dev/kvm` (added self to `kvm` group)
- containerd version: `v2.2.5`

### Setup note: an isolated containerd instance, not the system one
The host's `/etc/containerd/config.toml` is Docker Engine's own containerd (`disabled_plugins =
["cri"]` — Docker manages containers directly and deliberately disables CRI). That same
containerd instance underpins every Docker-based lab done on this machine all term. Editing it
in place to register Kata and restarting it risked breaking Docker on a machine depended on for
everything else, for zero benefit (Kata doesn't need CRI to run standalone via `nerdctl`/`ctr`).

Instead, ran a **second, fully isolated containerd instance** dedicated to this lab:
- Own config: `/etc/containerd-kata/config.toml` (generated via `containerd config default`,
  patched with the lab's `configure-containerd-kata.sh` script — CRI enabled by default here,
  unlike Docker's copy)
- Own root/state dirs: `/var/lib/containerd-kata`, `/run/containerd-kata`
- Own socket: `/run/containerd-kata/containerd.sock`
- Started manually (`sudo containerd --config /etc/containerd-kata/config.toml &`), not as a
  systemd unit, so it doesn't compete with or replace the `containerd.service` Docker owns.

All `nerdctl` commands below target this instance explicitly via `-a
/run/containerd-kata/containerd.sock`. Docker and every prior lab's setup were completely
untouched.

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet (`/etc/containerd-kata/config.toml`):
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

**Debugging note kept for the record:** on `containerd --config ...` startup, the log showed
`Ignoring unknown key in TOML for plugin ... key="containerd runtimes kata"` — this containerd
version's CRI plugin schema has drifted from what the lab's config-patching script assumes (it's
written for an older/Kubernetes-style CRI config shape), so the CRI plugin itself never actually
registers Kata as a `RuntimeClass`. This turned out not to matter for this lab: `nerdctl run
--runtime=io.containerd.kata.v2` doesn't go through the CRI plugin at all — it calls
containerd's core Task API directly (the same path `ctr run --runtime=...` uses), which just
needs the runtime string to resolve to an installed shim binary
(`containerd-shim-kata-v2`) somewhere on the containerd process's `PATH`. Symlinked
`/opt/kata/bin/containerd-shim-kata-v2` into `/usr/local/bin` and it worked without the CRI
plugin ever recognizing the `runtimes.kata` block. (This distinction — CRI-based RuntimeClass
routing for Kubernetes vs. direct runtime-string resolution for bare `nerdctl`/`ctr` — is worth
remembering: it's *why* this lab is doable without a Kubernetes cluster at all.)

Also needed standard CNI plugins (`containernetworking/plugins` v1.9.1) installed to
`/opt/cni/bin` — `nerdctl run` manages its own bridge networking independently of the CRI
plugin's CNI config, and failed with `needs CNI plugin "bridge"` until those binaries were present.

### Kernel inside containers
**runc:**
```
Linux e71d84ae8005 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

**kata:**
```
Linux 17ab91c24a67 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
```

The runc container's kernel (`6.17.0-35-generic`) is **exactly the host's kernel** — same version
string as `uname -r` on the host. The Kata container's kernel (`6.18.35`) is a **completely
different kernel** — Kata's own minimal guest kernel, bundled with the kata-static assets and
booted fresh inside a dedicated micro-VM for this one container.

### Why the kernel differs
runc containers are just host processes wrapped in namespaces/cgroups — `uname` inside a runc
container literally returns the host's `uname()` syscall result, because there is only one
kernel involved, shared by host and container alike. That's exactly the exposure Lecture 7 slide
14 covered with runc CVE-2024-21626 ("Leaky Vessels"): a bug in how runc's process-exec /
working-directory handling interacted with the *host* kernel let a malicious image escape its
container namespace and touch the host filesystem — the vulnerability worked precisely because
container and host share one kernel and one attack surface. Kata sidesteps this whole CVE class
structurally: the container's `uname` call is answered by a *different, dedicated* kernel running
inside a hardware-virtualized micro-VM, so even a runc-style escape bug in the *guest* kernel only
gets the attacker into the disposable micro-VM — never the host's actual kernel or filesystem.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```diff
1d0
< core
```
The only difference: runc's `/dev` has a `core` device node that Kata's `/dev` lacks. A minor,
mostly cosmetic difference — not the interesting isolation signal in this lab (the kernel
identity from Task 1 is).

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
**Identical, bit-for-bit.** This is worth calling out explicitly: Kata does **not** achieve its
isolation by stripping Linux capabilities more aggressively than runc — both containers get the
exact same default capability bitmask. Kata's security model isn't "fewer permissions inside the
container"; it's "the same permissions, but scoped to a disposable kernel that isn't the host's."
The isolation boundary is the VM, not the capability set.

### Startup time (5-run avg)
| Runtime | Runs (s) | Avg startup (s) |
|---------|----------|-----------------:|
| runc | 1.024, 1.017, 1.015, 1.058, 1.042 | **1.03** |
| kata | 2.490, 2.512, 2.491, 2.386, 2.591 | **2.49** |

**Overhead: ~2.4× cold start** — notably better than Reading 12's "typical ~5×" figure for
QEMU-backed Kata. This installation uses Kata's **dragonball** hypervisor (Kata's own built-in
Rust VMM, not QEMU) — lighter weight, faster boot, consistent with Reading 12's note that
Cloud-Hypervisor/lighter VMMs meaningfully cut Kata's cold-start penalty vs. the QEMU baseline.

### I/O throughput
First ran the lab's suggested command verbatim — `dd if=/dev/zero of=/dev/null` — and got a result
worth flagging rather than reporting at face value:

| Runtime | `dd ... of=/dev/null` |
|---------|----------------------:|
| runc | 10.4 GB/s |
| kata | 13.8 GB/s (*faster* than runc) |

This is **not** meaningful I/O data — both `/dev/zero` and `/dev/null` are pure in-kernel
character devices with no actual storage path involved, so the command measures kernel memcpy
throughput, not disk/filesystem I/O. It never touches the virtio-fs layer that Reading 12's whole
I/O-overhead discussion is about, which is why the result (Kata *faster*) contradicts the
reading's expectations. Re-ran against a real file on the container's writable filesystem instead:

| Runtime | `dd ... of=/tmp/testfile` (real fs write) |
|---------|-------------------------------------------:|
| runc | 1.5 GB/s |
| kata | 283.3 MB/s |

**~5.5× slower on real filesystem I/O** — this matches Reading 12's expected pattern (Kata's
virtio-fs layer adds material overhead vs. runc's direct overlayfs-on-host-disk access). The
absolute numbers here are lower than Reading 12's example table (12.5 GB/s / 1.2-4.5 GB/s) —
expected, since we're writing into a container's default writable layer rather than a
benchmarked NVMe-backed volume — but the *ratio* (order-of-magnitude slower for Kata on I/O) is
the actual signal Reading 12 predicts, and it held up once the test actually exercised storage.

### Trade-off analysis
CPU-bound work barely notices Kata (startup overhead is a one-time ~1.5s cost per container, and
once running, the workload executes on native CPU inside the VM). I/O-bound work notices
immediately — 5.5× slower filesystem writes is a real cost for anything doing sustained disk
activity. **Would deploy Kata:** a multi-tenant CI runner executing arbitrary, untrusted pull-request
code — the whole point is that a kernel-escape bug (like CVE-2024-21626) in one tenant's job can't
reach the host or other tenants' jobs, and CI jobs are typically short-lived/CPU-heavy enough that
the ~1.5s startup tax and I/O penalty don't dominate. **Wouldn't deploy Kata:** a single-tenant,
I/O-heavy batch job (e.g. a nightly ETL pipeline processing large files) running code the team
already controls and trusts — there's no untrusted-code threat model to defend against, so the
5.5× I/O tax is pure cost with no corresponding security benefit.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option: B** (privileged-container host write via bind mount), as the lab recommends —
  simplest to set up, and the underlying misconfiguration (`--privileged` + host bind mount) is
  the most common real-world footgun.
- **Why:** it directly maps to a real threat model — CI runners and misconfigured K8s pods that
  grant `--privileged` + a host path mount to workloads that shouldn't have host access at all.

### runc: escape succeeds
Command:
```bash
sudo nerdctl -a $NERDCTL_ADDRESS run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```

Host verification (separate shell, outside the container):
```
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER
```
Confirmed: the container wrote through to the real host file.

### Kata: the result — and an honest correction of the lab's premise

**First attempt (same flags, `--privileged` + bind mount) — the container failed to start:**
```
FATA[0003] failed to create shim task: Creating container device LinuxDevice { path: "/dev/full", ... }
Caused by:
    EEXIST: File exists
```
This is a **separate, unrelated issue** — Kata's `--privileged` mode tries to pass through the
full host `/dev` into the guest, and this dragonball/runtime-rs build hit a device-node conflict
doing so. It's an operational bug in privileged-mode device passthrough, not a security control,
and it happened to leave the host file untouched only because the container never started at all.
I didn't want to claim that as "Kata blocked the escape" — that would be a dishonest reading of
what actually happened.

**Second attempt — dropped `--privileged` (not actually required for a bind-mount write; it was
only in the runc command for extra realism) — the container started fine:**
```bash
sudo nerdctl -a $NERDCTL_ADDRESS run --rm --runtime=io.containerd.kata.v2 -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target'
```
Container output:
```
ATTEMPTED OVERWRITE FROM KATA
```
Host verification (outside the container):
```
$ sudo cat /tmp/lab12-target
ATTEMPTED OVERWRITE FROM KATA
```

**The write reached the real host file under Kata too.** This contradicts the lab's assumption
that Kata's bind mounts stay confined to the micro-VM's virtualized filesystem. It doesn't — and
on reflection, it shouldn't: Kata shares **explicitly declared** bind-mount paths into the guest
via virtiofsd running on the *host*, which genuinely proxies reads/writes to the real host
directory. That's not a security gap, it's the intended mechanism — the same one that makes K8s
ConfigMaps, Secrets, and PersistentVolumes work correctly for pods running under the `kata`
RuntimeClass. If Kata silently sandboxed declared bind mounts instead of honoring them, every
legitimate volume-mount workflow would break.

### Threat model implication
Vector B, as written, doesn't actually distinguish runc from Kata — a bind mount is an
operator-declared data path in both runtimes, and both honor it identically by design. Kata's real
isolation boundary is the one Task 1 already demonstrated: the **kernel**. A bug like runc
CVE-2024-21626 (a race condition in how the *runtime* handles a container process's working
directory during exec, letting it escape into the *host's* filesystem) can't cross into the host
under Kata, because there is no shared kernel/runtime-process boundary to exploit in the first
place — the guest kernel that would be exploited is a disposable one, and the exploit's blast
radius stops at the micro-VM. What Kata does **not** protect against: data flowing through paths
the operator explicitly shared (this test), pure kernel side-channel/timing attacks on the CPU
itself, or a compromised container abusing legitimate access to intentionally-mounted secrets —
none of those are "escapes," and Kata was never designed to stop them. (Reading 12's Confidential
Containers section is where memory-level protection *from the host itself* — a different,
stronger threat model — starts to apply.) The honest takeaway from this bonus: Kata's value
proposition is specific and structural (kernel-CVE-class isolation), not a blanket "nothing gets
out" guarantee — and testing that claim carefully, rather than assuming it, is exactly the kind of
verification this lab should reward.
