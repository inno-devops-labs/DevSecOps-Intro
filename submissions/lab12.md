# Lab 12 — BONUS — Submission

## Environment note — how this lab actually ran

This machine is a MacBook (Apple Silicon, macOS), which cannot run Kata at all: Kata needs `/dev/kvm` on a Linux host, and there's no KVM, no containerd, and no nerdctl available locally, and no realistic way to get nested KVM working through Docker Desktop's VM. Spinning up a paid cloud VM wasn't necessary — GitHub Actions' standard `ubuntu-latest` runners already ship with a working `/dev/kvm` (this is public knowledge; it's how Android-emulator CI jobs get hardware acceleration), and it's free for a public repo. So the whole lab runs as a single GitHub Actions workflow: `.github/workflows/lab12-kata.yml`, triggered on push to this branch. Every command below is exactly what that workflow ran; nothing is simulated or typed by hand. Full logs and downloadable artifacts: the final successful run is `29524188412` in this repo's Actions tab.

Two real bugs were hit and fixed while building the workflow (both documented inline in the workflow file too):
1. **`containerd-shim-kata-v2` not found even though it's installed.** containerd looks up runtime shim binaries using its own process `PATH` (from the systemd unit), which doesn't include `/opt/kata/bin`. The binary was there, but containerd couldn't find it. Fixed by symlinking everything in `/opt/kata/bin/` into `/usr/local/bin/`, which is on containerd's `PATH`, then restarting containerd.
2. **`--privileged` on Kata fails to even start the sandbox** — covered in the Bonus section below, since it's actually part of the interesting result, not just a bug to route around.

## Task 1: Install + Hello-World

### Host environment
- Kernel (host / runner): `Linux runnervm3jd5f 6.17.0-1020-azure #20~24.04.1-Ubuntu SMP Fri Jun 19 20:09:14 UTC 2026 x86_64` (Azure-backed GitHub Actions runner)
- KVM accessible: yes — `/dev/kvm` present, `kvm-ok` reported "KVM acceleration can be used" (AMD `svm` CPU flag present)
- containerd version: `containerd containerd v2.2.6` (Docker's `containerd.io` package, already installed and running on the runner — no separate containerd install needed)
- nerdctl version: `1.7.7` (installed fresh, since the runner doesn't ship it)

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
Linux 0a4322b69e0d 6.17.0-1020-azure #20~24.04.1-Ubuntu SMP Fri Jun 19 20:09:14 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

**kata:**
```
Linux 28ab7fe0766b 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

The runc container's kernel is `6.17.0-1020-azure` — literally the host's own kernel, same build string and all, because runc containers share the host kernel directly. The Kata container's kernel is `6.18.35` — a completely different build, Kata's own minimal guest kernel running inside a real KVM-backed micro-VM, with its own boot and its own kernel version entirely independent of what the host happens to be running.

### Why the kernel differs
runc containers are just isolated processes on the host — one shared kernel, everyone's syscalls go to the exact same kernel code. Kata containers run inside a real virtual machine with its own dedicated guest kernel; the only thing crossing the VM boundary is a small, well-defined virtio device interface. This directly changes the blast radius of a runc-class kernel bug like CVE-2024-21626 ("Leaky Vessels" — a file-descriptor leak in `runc` that let a container process reach a host `/proc/self/fd` handle and break out to the host). That bug worked because the attacking process and the host both share the exact same kernel and the exact same process table — there's a real host file descriptor to leak in the first place. Under Kata, the "host" as seen from inside the container is actually the guest VM; there is no host file descriptor to leak into, because the container process never touches the actual host kernel or the actual host's `/proc` at all. The bug class doesn't just get patched, it stops being reachable from inside the container in the first place.

---

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
1d0
< core
```
That's the entire diff. `runc`'s `/dev` has one extra entry, `core`, that Kata's doesn't. Everything else (`fd`, `full`, `mqueue`, `null`, `ptmx`, `pts`, `random`, `shm`, `stderr`, `stdin`, `stdout`, `tty`, `urandom`, `zero`) is identical on both. This was smaller than expected going in — I assumed Kata's `/dev` would look very different (virtio block/net devices, etc.), but the container's own `/dev` is populated by the OCI runtime's standard device allowlist either way; the actual difference isn't in what device nodes exist inside the container, it's in what's answering on the other side of them (see the kernel diff above). Isolation here shows up in the kernel, not in `/dev`.

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
Identical, bit-for-bit. Same lesson as the `/dev` diff: Linux capabilities are a property of the process inside whichever kernel it's running under, so a default container gets the same default capability set either way. Kata's protection doesn't come from handing out fewer capabilities — it comes from those capabilities only being powerful inside the guest VM's own, disposable kernel, instead of the real host's.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.312 |
| kata | 1.793 |

**Overhead: ~5.75× cold start** — matches Reading 12's "expected ~5×" almost exactly. Every one of Kata's 5 runs (1.77–1.81s) was slower than every one of runc's 5 runs (0.30–0.32s) — no overlap at all, so this isn't noise, it's the real, consistent cost of booting a small VM (kernel boot + guest init + virtio device setup) versus just `fork()`+`exec()`-ing a process on the existing host kernel.

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 25.5 GB/s |
| kata | 21.0 GB/s |

Both numbers are absurdly high for "I/O" because `dd if=/dev/zero of=/dev/null` never touches a real disk — it's a pure memory-to-memory copy, so this is really a CPU/memory-bandwidth benchmark, not a disk one. Read honestly, that's actually the right takeaway: once a Kata container is up and running, raw CPU-bound throughput is close to native (21.0 vs 25.5 GB/s, about 82% of runc — a real but small gap), which matches Reading 12's claim that Kata's overhead is almost entirely at *startup*, not during steady-state execution.

### Trade-off analysis
Kata's ~5.75× startup cost and small steady-state CPU tax are worth paying whenever you're running code you don't fully trust next to code you do — the clearest example is a **multi-tenant CI runner** or a SaaS platform executing customer-submitted jobs on shared infrastructure, where a runc-class kernel escape means one tenant reading another tenant's secrets or host credentials. It's not worth it for a **single-tenant internal batch job** (e.g., a nightly data pipeline that only your own team's code ever runs on infrastructure only your own team can reach) — there's no untrusted neighbor to isolate from, so you'd just be paying 1.5 extra seconds of startup and a bit of steady-state overhead per job for a security property you don't need. The general rule from Reading 12 holds: pay for VM isolation when the container might run someone else's code; skip it when every workload on the box is already equally trusted.

---

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B (privileged-container host write)
- **Why:** it's the simplest to reproduce (no need for a specific old vulnerable `runc` version like vector A, no cgroup v1 host required like vector C), and the underlying threat model — someone runs `--privileged` when they didn't need to — is genuinely the most common real-world misconfiguration.

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
Host verification (separate `sudo cat` after the container exited):
```
OVERWRITTEN BY RUNC CONTAINER
```
Confirmed — the container wrote directly to the real host file.

### Kata: two different outcomes, and why both matter

**Attempt 1 — same command as runc, `--privileged` included:**
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```
This didn't run at all — the sandbox failed to start:
```
level=fatal msg="failed to create shim task: Conflicting resource updates for host_major=8 host_minor=1..."
```
Host verify: file still says `original` — untouched, because nothing ever ran.

`host_major=8 host_minor=1` is `/dev/sda1` — the CI runner's own root disk, currently mounted and in active use as `/`. On Kata, `--privileged` doesn't just widen a capability bitmask like it does on runc — it tries to hot-plug/passthrough the host's block devices into the guest VM, since a "privileged" VM guest is supposed to get device-level access, not just syscall-level capabilities. That passthrough attempt collided with the disk already being mounted as the runner's own root filesystem, and Kata refused to start rather than proceed in a broken state. This is a genuinely different failure mode than "the write silently landed somewhere harmless" — it's Kata failing *closed* on a resource conflict that `runc` never even notices, because `runc --privileged` doesn't try to attach host block devices at the VM level at all; it just relaxes the container process's own capabilities on the one shared kernel.

**Attempt 2 — bind mount only, no `--privileged` (to isolate what's actually doing the blocking):**
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```
```
ATTEMPTED OVERWRITE FROM KATA
```
Host verify:
```
ATTEMPTED OVERWRITE FROM KATA
```
**This one worked** — the write landed on the real host file, on Kata, same as runc. This surprised me at first, but it's actually correct behavior, not a hole in Kata: a bind mount (`-v /tmp:/host_tmp`) is an *explicit, intentional* grant of host filesystem access — Kata's virtio-fs layer faithfully passes that access through to whatever host path you told it to mount, because that's the entire point of a bind mount. Kata isn't designed to second-guess a mount you explicitly configured; it's designed to stop a container from reaching things you *didn't* grant it — the raw host kernel, other host processes, unrelated host devices.

### Threat model implication
Put together, the honest reading is: Kata's isolation boundary is the **kernel and anything not explicitly exposed**, not "any file that happens to be named `/host_tmp` inside the container." An explicit `-v /tmp:/host_tmp` bind mount is equally honored — and equally dangerous if misconfigured — on both runtimes, because that's a deliberate host-access grant either way; that's real evidence that shifting to Kata does **not** paper over a badly-scoped bind mount. What Kata *did* change the outcome of is the part of `--privileged` that isn't about an explicit mount — the implicit, broad "give this container the whole host's device tree" behavior, which on Kata means trying to hand a VM raw access to host block devices, something the CI environment's own disk layout made impossible, so Kata refused rather than silently degrading. The real-world case this maps to is a misconfigured Kubernetes pod or CI job runner: a `--privileged` flag left on by habit (or copy-pasted from a Stack Overflow answer) is a much smaller blast radius on Kata than on runc, specifically for the device-passthrough and shared-kernel-syscall parts of what `--privileged` grants — but it is **not** a substitute for reviewing what you explicitly bind-mount into the container. This does not touch pure side-channel attacks on the physical CPU itself (cache-timing, speculative-execution attacks that can, in principle, cross a VM boundary) or cross-tenant timing attacks on shared hardware — Reading 12's "Confidential Containers" section covers the memory-encryption-based defenses (Intel TDX / AMD SEV-SNP) for that different threat class, which Kata alone does not address.
