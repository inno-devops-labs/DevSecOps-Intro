# Lab 12 — VM-Backed Container Isolation with Kata

> **Environment limitation, stated up front.** This lab was worked on an Apple Silicon (M1) MacBook running macOS 14.6.1. Kata Containers requires `/dev/kvm` — hardware-assisted virtualization exposed to a Linux kernel. I checked this two ways before starting: `ls -l /dev/kvm` on the host has nothing to check against (macOS is Darwin, not Linux, and has no such device by definition), and I stood up a real Linux VM via Colima (`colima start --vm-type vz`, Ubuntu 24.04, Linux 6.8 kernel — the same VM I used successfully for Lab 9's Falco work) and checked *inside* it: `ls -l /dev/kvm` → `No such file or directory`, and `grep -E 'vmx|svm' /proc/cpuinfo` found neither flag. This isn't a missing package — Apple Silicon does not expose nested hardware virtualization to a guest Linux VM under Apple's Virtualization.framework (the hypervisor Colima and Docker Desktop both build on here), so no container running on top of either VM can gain `/dev/kvm` access; a container shares its host's kernel and device nodes, it doesn't add virtualization capability. Kata physically cannot run in this environment.
>
> Per agreement: everything measurable on `runc` alone is measured live, below, with real command output. Everywhere Kata is required, I say so explicitly and either cite `lectures/reading12.md` (the course's own assigned reading, which ships a comparison table) with a direct quote, or reason from Kata's documented architecture — never presenting an invented number as a measurement. `nerdctl`/`containerd` were also unavailable without a from-scratch setup; I used `docker run` in their place for the `runc` measurements (`docker info` confirms `Default Runtime: runc`, `Runtimes: io.containerd.runc.v2 runc` — the same runtime and effectively the same containerd-based path the lab's `nerdctl` commands exercise), noted at each command.

## Task 1

**Kernel versions:**

```
$ docker run --rm alpine:3.20 uname -r
6.10.11-linuxkit
```

This is the kernel of Docker Desktop's own Linux VM (linuxkit) — the "host" as far as any container on this machine is concerned; my Mac's own Darwin kernel (`uname -r` on the Mac itself reports `23.6.0`) is a separate, irrelevant layer that no container ever sees. The `runc` container reports **exactly the linuxkit VM's kernel**, `6.10.11-linuxkit` — identical, because `runc` doesn't create a new kernel, it namespaces processes on the one kernel that's already there.

**Kata's kernel: not measured — could not be run.** Per Kata's architecture (Reading 12, "How Kata Works"): "One micro-VM per container... The micro-VM has its own kernel" — booted by QEMU/Cloud-Hypervisor/Firecracker from Kata's own kernel image (shipped and versioned separately, pinned by the Kata release — the lab's install script pins Kata 4.1.0). So the expected answer under Kata is a `uname -r` that does **not** match the host's `6.10.11-linuxkit` at all — a distinct kernel version built and shipped by the Kata project. I don't have that specific version string to report because I never had an installation to query it from, and I'm not going to invent one.

**Device counts and capability masks, side by side:**

| | `runc` (measured) | Kata (not measured) |
|---|---|---|
| `ls /dev \| wc -l` | **15** | Architecturally expected to differ — Kata's guest exposes `virtio-*` device nodes (virtio-blk, virtio-net, virtio-console, vsock) that a `runc` container's minimal `/dev` doesn't have, and lacks host devices `runc` might expose. No specific count is available to me; Reading 12 and the lab do not publish one. |
| `CapEff` (unprivileged) | **`00000000a80425fb`** | Kata still runs the container process via `kata-agent` inside the guest under the same OCI runtime spec the image/config requests, so the *capability set requested* would be identical (same default Docker/OCI capability drop list) — but I have no way to confirm the guest kernel actually reports the identical mask without running it, so I report this as a reasoned expectation, not a measurement. |

**What a `runc` container's kernel line tells an attacker.** `6.10.11-linuxkit` is not cosmetic information — it's the exact kernel an attacker who has landed a shell in the container needs to look up a matching local-privilege-escalation or container-escape CVE against (e.g. Dirty Pipe class bugs, or `runc`'s own CVE-2024-21626, which the reading calls out by name). Because `runc` containers share the host kernel, that CVE search is a search against the *actual* kernel the attacker is one exploit away from full host compromise on — the container boundary they're inside gives them no cushion if the kernel itself is vulnerable. Under Kata, that same `uname -r` would point them at Kata's own guest kernel — a real, exploitable kernel in its own right, but one where a successful exploit only grants control of a disposable, per-container micro-VM, not the actual host. The line of output is identical in *shape* (a kernel version string) but answers a completely different question about blast radius depending on which runtime produced it.

## Task 2

**Five `runc` startup times after one discarded warm-up run** (measured with `docker run --rm alpine:3.20 true`, timed via wall-clock `time.time()` deltas around the call, since `/usr/bin/time -f` isn't available in this shell environment — the timing method still captures the full `docker run` + container start + exit round trip, the same thing the lab's `/usr/bin/time` invocation measures):

```
0.317
0.292
0.313
0.300
0.312
```

**Median: 0.312s** (sorted: 0.292, 0.300, **0.312**, 0.313, 0.317 — middle value).

**Kata startup: not measured.** Reading 12's performance table (explicitly captioned "typical 2026 measurements... Your mileage varies... Do not take a number from this reading") reports cold start for an empty Alpine container at `0.05s` for `runc` and `2.1s` for Kata+QEMU / `1.2s` for Kata+Cloud-Hypervisor — roughly a 25-40× difference in the reading's own numbers, not the "roughly an order of magnitude" the lab's Task 2 prompt anticipates from a live measurement. I'm citing this only as documented context from the assigned reading, explicitly not as something I measured, per that table's own warning against reusing its numbers.

**I/O throughput** (`dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync`, inside the `runc` container):

```
536870912 bytes (512.0MB) copied, 1.453050 seconds, 352.4MB/s
```

**Why write to a file rather than `/dev/null`:** `/dev/null` is a character device that discards writes without ever touching the container's actual filesystem — writing to it measures how fast the kernel can throw bytes away, not how fast the storage stack the container actually runs on can absorb them. The whole point of comparing `runc` and a VM-backed runtime here is that a VM-backed runtime's writes have to cross an extra layer (virtio-blk or virtio-fs, into the guest, then however the guest's filesystem is backed on the host) that `/dev/null` would never touch, so a `/dev/null` benchmark would show the two runtimes as identical — hiding exactly the cost the lab wants surfaced.

**Memory overhead, and how I measured it:** I started a long-running `runc` container (`docker run -d alpine:3.20 sleep 300`) and read its actual cgroup memory accounting directly, rather than trusting `docker stats`' rounded display:

```
$ docker stats --no-stream lab12-mem-test --format "{{.MemUsage}}"
520KiB / 7.654GiB
$ docker exec lab12-mem-test cat /sys/fs/cgroup/memory.current
1155072
```

`memory.current` (cgroup v2, the authoritative figure) reports **1,155,072 bytes ≈ 1.1 MB** for an idle Alpine container running `sleep`. This is below even Reading 12's `runc` baseline figure of "~5MB" — plausible, since a single `sleep` process in a stripped Alpine base is about as close to a memory floor as `runc` gets. Kata's memory overhead: not measured; Reading 12 cites "~50-300MB" generally and "80 MB" specifically for Kata+QEMU in its table, again explicitly flagged there as illustrative, not something to reuse as a real result.

**Three workloads, judged:**

| Workload | Verdict | Why |
|---|---|---|
| A CI runner executing pull-request-submitted build scripts from external contributors | **Kata** | This is exactly Reading 12's first "you're running untrusted code" category — arbitrary code from people you don't control, where a kernel-level escape (like the `runc` CVE-2024-21626 the reading names) turns one bad PR into a compromised build fleet. The ~5× (or worse) cold-start cost is worth paying once per job, not once per request. |
| The internal microservice that serves this course's own static assets, built and deployed only by course maintainers | **`runc`** | Trusted image, trusted operators, no multi-tenant exposure — this is Reading 12's "general application workloads where you control the image" category, explicitly listed as a case to *not* sandbox. Kata's cold-start and memory tax would be pure overhead with no corresponding risk reduction here. |
| A per-request FaaS-style code execution endpoint (e.g. "run this Python snippet a user just typed") serving thousands of invocations/minute | **Needs more information** — specifically, whether sub-second latency is a hard product requirement. If yes, Reading 12's own comparison points at gVisor or Firecracker instead of Kata (Kata's cold start is "for longer-lived containers," per the reading's "Cold-start sensitive workloads" note) — the untrusted-code case argues for *a* sandbox, but Kata specifically is the wrong choice if the invocation rate can't absorb a multi-second boot per request. |

**The order-of-magnitude startup gap — which workload class doesn't care.** A long-running service (a database, an API backend, anything with a pod lifetime measured in hours or days) amortizes a one-time startup cost of a few seconds into functionally nothing over its actual runtime — the difference between a 0.3s and a 3s boot is invisible once the container has been serving traffic for even a few minutes. It's specifically the *short-lived, high-frequency* invocation pattern — FaaS, per-request sandboxes, ephemeral CI steps — where that gap dominates total cost, because there the boot time isn't amortized against anything; it's paid in full on every single invocation.

## Bonus

**Vector chosen:** the lab's suggested vector — a privileged container with a host bind mount (not a CVE, the common real-world misconfiguration). Run on `runc` only, since Kata was unavailable.

**Both states of the host file:**

```
$ echo original > /tmp/lab12-target
$ cat /tmp/lab12-target
original

$ docker run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
    sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'

$ cat /tmp/lab12-target
OVERWRITTEN
```

The "host" file (in this case, Docker Desktop's linuxkit VM filesystem, which is what `/tmp` on this Mac actually mounts through to for a container) went from `original` to `OVERWRITTEN` — the privileged container reached out through the bind mount and modified a file entirely outside its own container filesystem.

**Device count and capability mask for the privileged container:**

```
$ docker run --rm --privileged alpine:3.20 ls /dev | wc -l
167
$ docker run --rm --privileged alpine:3.20 sh -c 'grep ^CapEff /proc/1/status'
CapEff:	000001ffffffffff
```

(The lab's own reference numbers, from whatever host it was verified on, were 181 devices / `000001ffffffffff` — my capability mask matches exactly; my device count, 167, differs, almost certainly because the reference host's `/dev` had a few more entries than this Docker Desktop VM's does. The capability mask is the meaningful comparison point here — full effective capabilities — and it matches.)

**Kata run: not performed — no Kata installation available in this environment**, for the reasons stated at the top of this document. I'm not fabricating a Kata result for this section.

**What `--privileged` actually grants, and to what.** `--privileged` tells `runc` to skip almost all of the isolation it would otherwise apply: it drops the default capability restrictions (the mask goes from a curated subset to effectively everything, `000001ffffffffff`), removes the seccomp filter, and disables the device cgroup restriction that normally hides most of `/dev` — which is why the device count jumps from 15 to 167. Combined with the `-v /tmp:/host_tmp` bind mount, the container process — which is still, fundamentally, just a process running on the *host's own kernel* — now has full effective capabilities over a directory that *is* host storage, not a copy of it. `--privileged` grants privileges over the one and only kernel that's actually running; there is no second kernel to contain the blast radius, which is the entire point of the contrast Reading 12 draws. On Kata, the identical `--privileged` flag and bind mount would grant the container full privileges over the *guest's* kernel and the guest's view of that mounted directory — but the guest kernel is not the host kernel, so "full privileges" inside the microVM is a much smaller blast radius than "full privileges" on `runc`. I did not get to verify this live, but it follows directly from Reading 12's core claim ("a kernel CVE... escapes the container only escapes into the throwaway micro-VM, not the host") applied to a misconfiguration instead of a CVE — the mechanism argument is the same either way: what's escaped *into* is a disposable VM, not the real host.

**The honest limit of Kata:** Kata protects the *host kernel* from a compromised or misconfigured container; it does nothing about a compromised or malicious *image* doing damage within its own sandbox — stealing secrets mounted into the container, exfiltrating data over the network the container is still allowed to reach, or abusing whatever application-level credentials it was handed. A second kernel contains a kernel escape; it does not contain what the application was already trusted to do.
