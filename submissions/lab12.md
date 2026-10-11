# Lab 12 — VM-Backed Container Isolation with Kata

## Setup

Host: kernel `7.0.0-38-generic`, 16 vCPU, 16 GiB RAM, `/dev/kvm` present. The host already runs Docker and a system `containerd` v2.3.6; Kata was driven through `nerdctl` 2.4.1 against that containerd.

Two things on this host shaped the commands, and I'm stating them so the numbers are honest:

- **The pinned Kata build is `4.1.0`** (`/opt/kata/VERSION` → `4.1.0`), installed by `labs/lab12/scripts/install-kata-assets.sh`. This is the **runtime-rs (Rust) shim with the Dragonball VMM**: the working shim is `/opt/kata/runtime-rs/bin/containerd-shim-kata-v2`, not `/opt/kata/bin/…`. I symlinked it onto `PATH` as `containerd-shim-kata-v2` so `nerdctl --runtime=io.containerd.kata.v2` resolves it.
- **No CNI plugins are installed** (`/opt/cni/bin` is absent), so `nerdctl`'s default bridge network fails for *either* runtime. Every run below uses `--net none`. That removes network setup from the comparison equally for both runtimes, so the startup and I/O figures stay comparable; it doesn't touch the kernel/device/capability results.

`configure-containerd-kata.sh` added the runtime block to `/etc/containerd/config.toml`:

```
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

That block sits under the CRI plugin, and CRI is disabled on this host (`disabled_plugins=["cri"]`), so `nerdctl` actually reaches Kata via the shim on `PATH`, not via this config. It's included because Task 1 asks for it.

## Task 1

### 1. Kernel versions

| Where | `uname -r` |
| ----- | ---------- |
| Host | `7.0.0-38-generic` |
| Container on **runc** | `7.0.0-38-generic` |
| Container on **Kata** | `6.18.35` |

The runc container reports the host's kernel exactly. The Kata container reports `6.18.35` — a **different kernel**, the guest kernel shipped inside the Kata 4.1.0 image, running in its own VM.

### 2. Device counts and capability masks

`nerdctl run --net none [--runtime=…] [--privileged] alpine:3.20 …`

| | runc | runc `--privileged` | Kata | Kata `--privileged` |
| --- | ---: | ---: | ---: | ---: |
| entries in `/dev` | 15 | 236 | 14 | — (container did not start) |
| `CapEff` | `00000000a80425fb` | `000001ffffffffff` | `00000000a80425fb` | — (container did not start) |

(Host `/dev` has 246 entries.) Unprivileged, the two runtimes look almost identical from inside: the same default capability set (`a80425fb`) and ~15 device nodes. The privileged columns are where they split, and not in the way the lab's template expected:

- **runc `--privileged`** behaves as written: `/dev` jumps to 236 (nearly the whole host `/dev`) and `CapEff` becomes `000001ffffffffff` (all 40 capabilities).
- **Kata `--privileged`** does not run at all. The shim aborts at container creation with `failed to create shim task: … get host path failed: No such file or directory` (`hypervisor::device::util::get_host_path`). `--privileged` asks the runtime to pass the host's device nodes into the container; a VM guest has no access to the host's `/dev`, so there is no host path to map and creation fails. This is itself a Task 1 result: the privileged escalation that runc grants can't even be expressed against a VM-backed runtime here.

### 3. What that one line of kernel output tells an attacker

On runc, `uname -r` returning the host's exact kernel release tells an attacker who just landed in the container that any local-privilege-escalation or container-escape exploit targeting `7.0.0-38-generic` will work against the real host kernel, because the container *shares* that kernel — there is one kernel, and the namespace boundary is enforced by it. They can pick a matching public exploit with confidence and aim it straight at the host. When the answer is a different kernel (`6.18.35` under Kata), that confidence disappears: a kernel exploit now only buys code execution inside a throwaway guest kernel in a VM. To reach the host they must additionally escape the hypervisor (a VMEXIT/device-emulation bug), which is a far smaller and harder attack surface than the shared Linux kernel's millions of lines of syscalls. The extra kernel converts "one exploit → host" into "one exploit → a disposable VM, then a second, much rarer exploit → host".

## Task 2

### 1. Startup time (five runs after a discarded warm-up)

| run | runc (s) | Kata (s) |
| --- | ---: | ---: |
| 1 | 0.28 | 6.05 |
| 2 | 0.27 | 6.03 |
| 3 | 0.28 | 6.38 |
| 4 | 0.28 | 6.06 |
| 5 | 0.28 | 6.00 |
| **median** | **0.28** | **6.05** |

Median, not mean, because one slow outlier (the 6.38 run) would drag an average. Kata's median is ~**22×** runc's. These timings include the `nerdctl` + containerd overhead, which is identical for both runtimes, so the comparison is fair even though it isn't the pure runtime cost — the delta is the VM boot (guest kernel + Dragonball + virtiofs).

### 2. I/O throughput (512 MiB, `conv=fsync`)

| runtime | result |
| ------- | ------ |
| runc | 512 MB copied in 0.47 s → **1.1 GB/s** |
| Kata | 512 MB copied in 1.67 s → **306.8 MB/s** |

About **3.5× slower** on Kata. The benchmark writes to a file in the container's filesystem and `fsync`s, rather than to `/dev/null`, because `/dev/null` never touches the storage layer — the whole point is to force the write to cross it. On runc that layer is the host's overlayfs directly; on Kata it crosses the guest kernel and the virtio block/virtiofs path into the host, which is exactly the overhead being measured.

### 3. Memory overhead per container

Method: start one detached `sleep` container per runtime with `--net none`, resolve its sandbox id with `nerdctl inspect`, then sum the RSS of every host process tied to that sandbox (`pgrep -f <id>` → `ps -o rss`). Dragonball runs the guest *inside* the shim process, so the shim's RSS already includes the VM's footprint.

| runtime | processes | host RSS |
| ------- | --------- | -------: |
| runc | `containerd-shim-runc-v2` | **11.3 MiB** |
| Kata | `containerd-shim-kata-v2` (Dragonball VMM in-process) | **175.2 MiB** |

So roughly **~164 MiB of host memory overhead per Kata container** over runc, on an idle `sleep`. (The container's own `alpine sleep` process is negligible on runc; the shim figure is the overhead that scales per container.)

### 4. Three workloads, judged

| Workload | Verdict | Why |
| -------- | ------- | --- |
| A short-lived CI job running **untrusted, attacker-controlled code** (PR builds, autograders, a SaaS "run this snippet" box) | **Kata** | The whole threat is hostile code trying to escape to the host or to neighbours. The VM boundary is the control; a few seconds of startup and ~164 MiB are cheap against a shared-kernel escape. |
| A **latency-sensitive, high-density internal microservice** on a trusted image (thousands of short requests, autoscaled pods) | **runc** | 22× startup and 3.5× I/O directly hurt the SLO and density, and the tenants are already trusted, so the VM buys little. Spend the isolation budget elsewhere (seccomp, NetworkPolicy, non-root). |
| A **multi-tenant platform where each tenant's pod handles that tenant's own data** | **needs more information** | Depends on the real boundary. If tenants only ever touch their own data and the kernel is kept patched, runc + strong policy may be enough; if a kernel escape would expose other tenants' data and that's the stated risk, Kata (or gVisor) earns its cost. The deciding fact is the blast radius of one escaped pod, which isn't given. |

### 5. The order-of-magnitude startup gap — when it doesn't matter

For any **long-lived** workload the ~6 s startup is a one-time cost amortised over the process's lifetime, so it rounds to zero. A web server, database or queue consumer that is scheduled once and runs for hours or days pays 6 s at boot and never again; against an uptime measured in days that's noise. It only bites workloads whose *lifetime is comparable to the startup*: per-request function invocations, fork-per-job batch fan-out, autoscalers that spin pods up and down constantly, and CI matrices launching thousands of short containers. There the startup is a large fraction of total runtime and 22× is felt directly; for a service you start and leave running, it is irrelevant.

## Bonus

### 1. Both runs, and the host file after each

Target created fresh (root-owned) before each run; command identical except the runtime flag.

```
== runc   (nerdctl run --rm --net none --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo … > /host_tmp/…')
   host before: original
   inside-rc=0
   host after:  written from inside the container      <-- host file CHANGED

== kata   (same command + --runtime=io.containerd.kata.v2)
   host before: original
   <fatal> failed to create shim task: … get host path failed: No such file or directory
   host after:  original                                <-- host file UNCHANGED
```

### 2. Device count and capability mask, privileged, under each runtime

| | runc `--privileged` | Kata `--privileged` |
| --- | ---: | ---: |
| `/dev` entries | 236 | container never starts (`get host path failed`) |
| `CapEff` | `000001ffffffffff` (all caps) | n/a |

### 3. Explaining the result in terms of what `--privileged` grants, and to what

`--privileged` grants the container the full capability set, all devices and the relevant LSM/seccomp relaxations — **over whatever kernel owns the container**. On runc there is exactly one kernel, the host's, so "privileged" means privileged over the host: `CapEff` becomes `000001ffffffffff`, `/dev` is populated with the host's 236 device nodes, and with `-v /tmp:/host_tmp` the root process writes straight through the bind mount to the host filesystem — the host file changed. On Kata the container's kernel is the **guest** kernel in a VM, so `--privileged` would grant privilege over that disposable guest, not the host. Here it doesn't even get that far: `--privileged` tries to pass the host's device nodes into the container, and since the guest has no access to the host's `/dev`, the runtime can't resolve a host path for them and **aborts container creation** (`get host path failed`). The escape never runs, and the host file stays `original`.

**But the honest limit** (section 4 below): the bind mount itself is *not* what Kata blocked. I tested a **non-privileged** `-v /tmp:/host_tmp` under both runtimes, with the container creating a fresh file:

```
runc: host sees "write from runc"   kata: host sees "write from kata"
kata guest mount table:  kataShared on /host_tmp type virtiofs (rw,nodev,relatime)
```

An explicit bind mount reaches the host **even on Kata** — it is deliberately shared into the guest over **virtiofs**. So Kata did not stop the lab's escape by containing a bind mount; it stopped it because `--privileged` device passthrough can't be satisfied for a VM. A bind mount you consciously configure is a hole you opened yourself, through the VM boundary, on purpose.

### 4. One honest thing Kata does not protect you from

Kata does not protect you from **what you explicitly share into the guest**: a `-v /host/path` bind mount (virtiofs), a `hostPath` volume, the Docker socket, or `--net host`. Those cross the VM boundary by design, so a container that is handed the host's `/tmp`, `/var/run/docker.sock`, or the host network can still reach and tamper with the host regardless of the second kernel — the VM contains the kernel, not the mounts you opened through its wall. (It also doesn't defend against supply-chain compromise of the image itself or against a hypervisor-level 0-day, but the mount case is the one demonstrated here.)
