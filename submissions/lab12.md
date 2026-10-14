# Lab 12 — VM-Backed Container Isolation with Kata

Kata Containers **4.1.0** (the pinned default; `cat /opt/kata/VERSION` → `4.1.0`), runtime-rs shim with the Dragonball hypervisor, containerd with `nerdctl`, `runc` as the comparison runtime.

## Where this ran, and why it matters for every number below

Docker Desktop's VM does not expose `/dev/kvm`, so this lab ran in a Lima VM: **x86_64, Ubuntu, kernel 7.0.0-28-generic, 4 vCPU, 3.8 GiB RAM**, with `/dev/kvm` present and `svm` in `/proc/cpuinfo`.

That VM is itself emulated — qemu x86_64 on an Apple M3 host. So a Kata container here is a **VM inside an emulated VM**, and the absolute timings are dominated by that emulation, not by Kata. I am saying this before the numbers rather than after, because it changes what they are evidence for: the *direction* and rough *order* of the differences are real, the absolute figures are not comparable with anyone else's. Two consequences showed up in practice and are reported honestly in Task 2 and the Bonus — the 512 MB I/O benchmark took the guest down entirely and had to be reduced to 128 MB, and the memory measurement for Kata could not be completed at all.

Setup, after reading all three shipped scripts:

```bash
$ sudo bash labs/lab12/scripts/install-kata-assets.sh      # pinned 4.1.0
Linked runtime-rs config -> /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml
$ sudo bash labs/lab12/scripts/configure-containerd-kata.sh
Updated /etc/containerd/config.toml with Kata runtime: io.containerd.kata.v2

$ sudo grep -A2 'runtimes.kata' /etc/containerd/config.toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

**One gap in the shipped install.** After both scripts, every Kata run failed with:

```
failed to start shim: failed to resolve runtime path: runtime "io.containerd.kata.v2"
binary not installed "containerd-shim-kata-v2": file does not exist
```

The static tarball puts the hypervisors in `/opt/kata/bin/` (qemu, cloud-hypervisor, openvmm) but the **shim is somewhere else entirely** — `/opt/kata/runtime-rs/bin/containerd-shim-kata-v2` — and nothing adds it to a directory containerd searches. Symlinking the obvious `/opt/kata/bin` path does not help, because the binary is not there. The fix:

```bash
$ sudo ln -sf /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/
$ sudo /usr/local/bin/containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 4.1.0, commit: ddcb1ad8...
```

## Task 1

### Three kernels

```bash
$ sudo nerdctl run --rm alpine:3.20 uname -r
7.0.0-28-generic

$ sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 uname -r
6.18.35

$ uname -r          # the host
7.0.0-28-generic
```

| | Kernel |
|---|---|
| Host | `7.0.0-28-generic` |
| `runc` container | `7.0.0-28-generic` — **identical to the host** |
| Kata container | `6.18.35` — a different kernel entirely |

### Devices and capabilities, side by side

```bash
$ sudo nerdctl run --rm alpine:3.20 ls /dev | wc -l
15
$ sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 ls /dev | wc -l
14

$ sudo nerdctl run --rm alpine:3.20 sh -c 'grep ^CapEff /proc/1/status'
CapEff:	00000000a80425fb
$ sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 sh -c 'grep ^CapEff /proc/1/status'
CapEff:	00000000a80425fb
```

| | `/dev` entries | `CapEff` |
|---|---:|---|
| `runc` | 15 | `00000000a80425fb` |
| Kata | 14 | `00000000a80425fb` |

**The capability masks are identical, and that is the point.** Both runtimes apply the same default capability set — Kata does not drop a single capability relative to `runc`. Whatever Kata buys you, it is not a smaller capability mask, and a report that claimed otherwise would be reading the wrong field. The device counts differ by one, which is noise from a slightly different guest device set rather than a security property.

### What that one line of output tells an attacker

A `runc` container reporting `7.0.0-28-generic` tells an attacker who has just landed there the single most valuable fact available: **the kernel they are talking to is the host's kernel, and they now know its exact version**. Every syscall they make is serviced by the machine that runs every other tenant on that box, so the question "is there an exploitable kernel bug" is the same question as "can I own the host". The version string turns that from research into lookup — `7.0.0-28-generic` goes into a search, and whatever local-privilege-escalation CVEs affect that release are a shopping list with known public exploits. The namespaces and cgroups around them are kernel features enforced *by the kernel they are attacking*, so a bug in it defeats all of them at once.

When the answer is `6.18.35` instead, the economics change. The attacker is talking to a dedicated guest kernel, so an exploit against it gets them root inside a VM that contains nothing but their own workload — and to reach the host they then need a *second* bug, in the hypervisor's virtual device emulation, which is a far smaller and far more scrutinised attack surface than a general-purpose kernel's hundreds of syscalls. The mismatch is also a signal in itself: a kernel version that does not match anything the hosting provider runs tells the attacker they are in a sandbox, and the cheap escapes are not worth trying.

## Task 2

### Startup, five runs each after a discarded warm-up

```
== runc startup ==        == kata startup ==
7.76                      27.19
6.05                      145.25
5.37                      92.38
5.09                        9.36
4.78                       32.16
```

| Runtime | Runs (s) | **Median** |
|---|---|---:|
| `runc` | 7.76, 6.05, 5.37, 5.09, 4.78 | **5.37 s** |
| Kata | 27.19, 145.25, 92.38, 9.36, 32.16 | **32.16 s** |

Median rather than mean, as the lab asks, and here the reason is unusually visible: Kata's mean is 61.3 s, pulled there by a single 145-second run, and no honest reading of that distribution says "a Kata container takes a minute". The ratio of medians is about **6×**.

Two caveats I will not paper over. First, `runc` at 5.37 s is itself absurd — a `runc` container start is normally a few hundred milliseconds — which is the emulated host showing through; on real hardware both columns would be roughly an order of magnitude smaller and the *ratio* would be larger, since Kata's cost is a kernel boot that emulation punishes hardest. Second, the Kata spread (9 s to 145 s) is not Kata being erratic; it is a nested VM competing for four emulated vCPUs. The timing includes `nerdctl` and containerd overhead for both runtimes identically, so the comparison stays fair even though neither absolute number is.

### I/O

```bash
$ sudo nerdctl run --rm alpine:3.20 \
    sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=128 conv=fsync 2>&1 | tail -1'
134217728 bytes (128.0MB) copied, 1.172044 seconds, 109.2MB/s

$ sudo nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
    sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=128 conv=fsync 2>&1 | tail -1'
134217728 bytes (128.0MB) copied, 7.197742 seconds, 17.8MB/s
```

| Runtime | Throughput | Ratio |
|---|---:|---:|
| `runc` | 109.2 MB/s | 1× |
| Kata | 17.8 MB/s | **0.16× (≈6× slower)** |

**Deviation from the lab text, stated plainly:** the benchmark is 128 MB, not 512 MB. The 512 MB run completed on `runc` (44.1 MB/s) and then took the entire guest VM down on Kata — SSH stopped answering and the VM had to be force-stopped and restarted. Reducing to 128 MB made it reproducible. Both runtimes were measured at the same size, so the comparison holds.

**Why the benchmark writes to a file rather than `/dev/null`:** writing to `/dev/null` measures nothing but how fast the kernel can discard bytes — it never touches the storage stack. The whole difference between `runc` and a VM-backed runtime lives in that stack: `runc` writes through the host's overlay filesystem directly, while Kata's write crosses a virtio device into the guest kernel, back out through the hypervisor, and only then reaches the host. `conv=fsync` matters for the same reason — without it, `dd` reports the speed of filling a page cache that has not yet been crossed.

### Memory overhead, and what I could not measure

```bash
$ ps -eo rss,comm --no-headers | grep -E 'containerd-shim|qemu|dragonball' | awk '{s+=$1} END {print s/1024" MiB"}'
```

| Runtime | Per-container host RSS | Method |
|---|---:|---|
| `runc` | **10 MiB** | Baseline measured with no containers running (0 MiB of shim/VMM processes), then one `alpine sleep` container started and the summed RSS of all `containerd-shim*` / hypervisor processes re-read after 8 s |
| Kata | **not measured** | — |

The Kata measurement is the one thing in this lab I could not complete. It requires a *long-lived* container so that the shim and the Dragonball VMM are both resident while `ps` runs, and every attempt to start a detached Kata container took the guest VM down — three times, each needing a force-stop and restart. The honest statement is therefore "not measured in this environment", not an estimate dressed up as a result. For reference, the figure Kata's own documentation and the reading both cite is roughly **50–130 MiB per container** for the VMM plus guest kernel, an order of magnitude above `runc`'s single-digit shim — but that is a citation, not my measurement, and I am labelling it as such.

### Three workloads

| Workload | Verdict | Why |
|---|---|---|
| A CI runner executing untrusted pull-request code | **Kata** | This is the textbook case: arbitrary code from strangers, running with build tooling, on a host that also builds other people's software. Startup cost is amortised over a multi-minute build, and the whole threat model is "the code is hostile". The Lab 9 Falco work detects a breakout; Kata makes the cheap one not work. |
| A latency-sensitive API serving first-party code, scaled by a horizontal autoscaler | **`runc`** | Scaling events happen in response to load spikes, and a 6× slower cold start is felt directly by users who are already queueing. The code is our own, reviewed and scanned by labs 4–7, so the marginal risk Kata removes is small and the cost is paid continuously. |
| A multi-tenant function-as-a-service platform where tenants submit their own handlers | **Needs more information** | The isolation requirement clearly points at Kata, but the viability depends entirely on the invocation pattern. Warm pools of pre-booted sandboxes make the startup number irrelevant; genuine cold-start-per-invocation makes it fatal. I would want p99 invocation frequency and the acceptable cold-start budget before answering — and gVisor is the third option worth measuring here, since it sits between the two on both axes. |

### Where an order of magnitude does not matter

**Anything batch, long-running, or already slower than the startup cost.** A nightly ETL job, a model training run, a CI build, a video encode: the container starts once and then works for minutes or hours, so 5 s versus 32 s is somewhere between 1 % and 0.01 % of wall-clock time and nobody can perceive it. The number only matters when container startup is on a user-facing critical path — scale-out under load, cold-start serverless invocations, per-request sandboxes — because that is where the cost is paid repeatedly and synchronously rather than once and in the background.

Which flips the usual framing in a useful way: the workloads where startup cost is irrelevant are disproportionately the ones that run **untrusted or externally sourced code** — batch jobs processing customer uploads, CI building forks, data pipelines pulling third-party packages. The place Kata costs least is often the place it is needed most.

## Bonus

### The escape on `runc`

```bash
$ echo original | sudo tee /tmp/lab12-target
original
$ sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
    sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
$ cat /tmp/lab12-target
OVERWRITTEN
```

**The host file was rewritten from inside the container.** No CVE, no exploit — just `--privileged` and a bind mount, which is the misconfiguration that shows up in real clusters.

### The same command on Kata

```bash
$ echo original | sudo tee /tmp/lab12-target
original
$ sudo nerdctl run --rm --privileged --runtime=io.containerd.kata.v2 -v /tmp:/host_tmp \
    alpine:3.20 sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'

failed to create shim task: Others("failed to handle message create container
  Caused by:
    0: get host path failed
    1: No such file or directory (os error 2)
  ...
    1: hypervisor::device::util::get_host_path
    2: resource::manager_inner::ResourceManagerInner::handler_devices")

$ cat /tmp/lab12-target
original
```

**The container never started, and the host file is untouched.** This is more absolute than "the write failed": Kata refused at container-creation time, in `hypervisor::device::util::get_host_path` — the code whose job is to translate a host device into something that can be handed to the guest. Reproducible across a clean VM restart.

### Device count and capability mask for a privileged container

| Runtime | `/dev` entries | `CapEff` |
|---|---:|---|
| `runc`, `--privileged` | **199** | `000001ffffffffff` |
| `runc`, unprivileged | 15 | `00000000a80425fb` |
| Kata, `--privileged` | **container does not start** | **container does not start** |

`runc --privileged` is the lab's own figures confirmed on this host: the device count goes from 15 to 199 and the capability mask from `a80425fb` to `000001ffffffffff` — every capability the kernel defines, set. There is no Kata row to fill in, and that absence is the measurement: a privileged container under Kata is not a container with a different mask, it is a container that does not exist.

### What `--privileged` actually grants, and to what

`--privileged` is not one switch; it is roughly three — the full capability set, an unmasked `/dev` with the host's devices passed through, and relaxed seccomp/AppArmor. Under `runc`, all three are granted **over the host kernel**, because that is the only kernel in the picture. `CAP_SYS_ADMIN` over the host's kernel plus a host directory mounted in is not an escape in the exploit sense; the container was simply handed the host's filesystem and the privileges to write to it. There is nothing to break out of.

Under Kata the same request is incoherent, which is why it fails rather than succeeding partially. The capabilities would be granted over the **guest** kernel, where they buy an attacker root over an empty VM containing their own workload. The device passthrough is the part that actually breaks: `--privileged` asks for the host's `/dev` to appear inside the container, and the Kata runtime has to materialise each of those as a virtual device attached to the guest — which is what `get_host_path` was trying and failing to do. The bind mount is the same story: `-v /tmp:/host_tmp` under `runc` is a kernel mount namespace operation costing nothing, while under Kata it has to cross a VM boundary through virtio-fs, so a host path is not something the guest can simply be handed.

**The escape did not partly work. It did not work at all**, and the mechanism is that `--privileged` means "privileges over the kernel you are talking to", and Kata changed which kernel that is.

### The honest limit

**Kata does not protect you from anything that does not need to cross the kernel boundary** — most obviously, whatever you deliberately hand the guest. A secret mounted into a Kata container is still readable by code in that container; an over-permissive service-account token still authenticates to the Kubernetes API; and an application vulnerability like the Lab 5 SQL injection yields the same administrator session whether the process runs on `runc` or inside a VM, because nothing about it involves the kernel. Kata raises the cost of *escaping* the sandbox; it does nothing about the value of what you put inside it.
