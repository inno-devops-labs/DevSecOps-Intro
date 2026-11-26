# Lab 12 — VM-Backed Container Isolation with Kata

Measured on 26 November 2026, on a Linux VPS with working nested KVM. The results below are actual command outputs; [raw measurements](lab12-evidence/measurements.json), [memory samples](lab12-evidence/memory.json), [command transcript](lab12-evidence/transcript.txt), and [environment](lab12-evidence/environment.txt) accompany this report.

## Task 1

### Installation and test conditions

| Component | Configuration |
|---|---|
| Host | Ubuntu 24.04.5 LTS, kernel `6.8.0-39-generic`, x86_64 |
| Resources | 6 vCPU, approximately 11.6 GiB RAM; nested KVM, `/dev/kvm` present and CPU `vmx` exposed |
| containerd / nerdctl / runc | 2.4.2 / 2.4.2 / 1.5.3 |
| Kata | **4.1.0**, Rust shim `io.containerd.kata.v2` |
| Hypervisor and sharing | QEMU 11.0.1, KVM acceleration, `virtio-fs`, overlayfs container snapshotter |
| Kata VM sizing | Default 1 vCPU and 2048 MiB configured guest RAM; no VM templates |
| Image | `alpine:3.20`, pulled once before testing; both runtimes used the same locally cached image |

Image index digest: `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`.
Image config ID: `sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731`.

The three supplied installation/configuration/build scripts were reviewed before installation. The pinned static release was downloaded, its SHA-256 checked against the GitHub release asset digest, and its archive paths inspected before extraction into `/opt/kata`; building from source was unnecessary. Kata's archive SHA-256 was `3dc6b69c4acb787b967b04b64599a20d02a8beb1a8eaab3084110df9d0b08c96`.

Existing applications were already running on the host. A separate transient `lab12-containerd` service used its own root, state, socket, namespace, and nerdctl data directory under `/var/tmp/lab12-alexbittit`; NRI was disabled for that daemon. The supplied configurator was run with `CONF` pointing at that separate configuration, and its legacy table path was adapted for containerd 2.x:

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

The default 10-second effective agent connection budget was too short on this nested VM. `reconnect_timeout_ms` was set to **60000** before successful measurements; this changes the maximum wait, rather than adding a fixed delay. Debug logging was disabled during measurements. Failed setup attempts were excluded from the timed series.

Every measured nerdctl run used `--net=none`, because these tests require no network. Both runtimes used the same common arguments, including the `cgroupfs` manager; commands ran as root, so no interactive `sudo` or password prompt was included. For the commands below, `n` and `TIME` denote:

```bash
LAB=/var/tmp/lab12-alexbittit
n() { "$LAB/bin/nerdctl" --address "$LAB/containerd.sock" \
  --namespace lab12 --data-root "$LAB/nerdctl-data" \
  --cgroup-manager cgroupfs "$@"; }
TIME="$LAB/time/usr/bin/time"
```

GNU Time 1.9 was extracted from Ubuntu package `time_1.9-0.2build1_amd64.deb` into the temporary lab directory, without installing a system package. Its binary was used with `-f '%e'`; the transcript uses a `LAB12_SECONDS=` prefix to distinguish timings from runtime stderr.

### Kernel, devices, and capabilities

```bash
uname -r
n run --rm --net=none alpine:3.20 uname -r
n run --rm --net=none --runtime=io.containerd.kata.v2 alpine:3.20 uname -r
# Device counts: replace uname -r with sh -c 'ls /dev | wc -l'
# Capability masks: replace uname -r with sh -c 'grep ^CapEff /proc/1/status'
```

| Observation | Host | runc | Kata |
|---|---|---|---|
| Kernel release | `6.8.0-39-generic` | `6.8.0-39-generic` | `6.18.35` |
| `/dev` entry count | — | 15 | 14 |
| Effective capabilities (`CapEff`) | — | `00000000a80425fb` | `00000000a80425fb` |

An attacker seeing `6.8.0-39-generic` in the runc container learns the release of the kernel handling that container's system calls, which is also the host kernel. That narrows the kernel exploit candidates and ABI assumptions, although the release string alone cannot prove vulnerability because distribution fixes may be backported. Kata instead reports `6.18.35`, identifying the VM guest's kernel; a guest-kernel exploit would still face the VM boundary before reaching the host. Equal capability masks express similar privileges inside the respective kernels and do not imply equal host isolation.

## Task 2

### Startup after warm-up

One untimed `true` run was discarded for each runtime, followed by **five** successful timed `run --rm ... true` invocations. The [measurement script](lab12-evidence/measure.py) records the warm-up and all five trials. GNU Time wrapped the complete nerdctl command, as in the lab; this includes client, daemon, creation, execution, and removal overhead, rather than timing only the runtime or only VM boot. Image pulling was completed before the warm-up.

| Run | runc (s) | Kata (s) |
|---|---:|---:|
| 1 | 2.38 | 29.20 |
| 2 | 1.66 | 24.86 |
| 3 | 3.02 | 26.47 |
| 4 | 1.84 | 23.37 |
| 5 | 1.74 | 28.49 |
| **Median** | **1.84** | **26.47** |

runc sorted: 1.66, 1.74, 1.84, 2.38, 3.02; Kata sorted: 23.37, 24.86, 26.47, 28.49, 29.20. Each median is the third sorted observation. Kata's median is **14.39×** runc's on this host.

Some short Kata runs logged a signal-forwarding error during teardown after the workload exited. These timed commands still returned exit status 0; their stderr is retained in the transcript, and their teardown time is included. This is a small sample on a shared, nested VPS, so the measurements characterize this setup and are not a general performance guarantee.

### Filesystem I/O

```bash
n run --rm --net=none alpine:3.20 \
  sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1'
n run --rm --net=none --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1'
```

runc:

```text
512+0 records in
512+0 records out
536870912 bytes (512.0MB) copied, 5.872998 seconds, 87.2MB/s
```

Kata:

```text
512+0 records in
512+0 records out
536870912 bytes (512.0MB) copied, 29.403529 seconds, 17.4MB/s
```

The test writes a 512 MiB file and calls `fsync`, so it traverses the container storage layer (including the guest/host sharing path for Kata); `/dev/null` would discard the bytes and bypass that storage work. These are single sequential-write samples, not random-I/O, latency, or durability guarantees; BusyBox's printed throughput units are preserved.

### Memory per idle container

The same `alpine:3.20 sleep 180` workload was started detached, one runtime at a time, with the common arguments above. After a five-second settling period, five samples were collected one second apart from the host's `/proc/<pid>/smaps_rollup`. Each sample sums **PSS** for that container's shim process and all its descendants: the payload for runc, and QEMU/guest memory plus virtiofsd for Kata. The shared containerd daemon was excluded, and the container was removed before starting the other runtime.

| Runtime | Five total PSS samples (KiB) | Median footprint (MiB) |
|---|---|---:|
| runc | 35899, 35899, 35899, 35899, 35899 | 35.06 |
| Kata | 314448, 314448, 314448, 314448, 314448 | 307.08 |

The measured additional footprint of Kata for this identical idle workload is **272.02 MiB**. PSS apportions shared resident pages and avoids summing shared mappings repeatedly; this is a resident process-footprint estimate, not a whole-system memory delta or a measure of all kernel/slab/page-cache costs. The configured 2048 MiB guest RAM limit is not the same thing as physically resident overhead. The [sampling script](lab12-evidence/memory.py) and [memory evidence](lab12-evidence/memory.json) record the process trees and each process's PSS/RSS so the totals can be checked.

### Runtime choices

These examples come from Reading 12's workload classes, rather than claims about a personal production deployment.

| Workload | Verdict | Reason |
|---|---|---|
| Trusted, latency-sensitive first-party API | runc | Avoid repeated VM startup and per-instance memory cost when the threat model accepts a shared kernel and the image is controlled. |
| Long-running CI jobs executing untrusted tenant repositories | Kata | A guest kernel adds a boundary between attacker-controlled builds and the host, while startup is amortized over a long job; avoid writable host mounts and daemon sockets. |
| Multi-tenant, GPU-backed inference | needs more information | Tenant trust, device-passthrough support, driver compatibility, memory pressure, and measured inference/I/O latency must be established first. |

The roughly 14.4× end-to-end startup difference has little practical importance for a long-lived CPU-bound worker or a batch computation running for hours. The VM is started once, so an extra 24.63 seconds is amortized over the whole computation rather than charged to every request. That reasoning does not remove the separate resident-memory or I/O costs. It also does not apply to workloads that scale from zero on every short invocation.

## Bonus

### Identical privileged bind-mount test

The same command was used for both runtimes, adding only Kata's runtime selection. The existing `/tmp/lab12-target` path was checked to be absent before testing, and the file was reset to `original` before **each** attempt:

```bash
echo original > /tmp/lab12-target
n run --rm --net=none --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
cat /tmp/lab12-target

echo original > /tmp/lab12-target
n run --rm --net=none --runtime=io.containerd.kata.v2 \
  --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
cat /tmp/lab12-target
```

| Runtime | Host file before | Command exit status | Host file after |
|---|---|---:|---|
| runc | `original` | 0 | `OVERWRITTEN` |
| Kata | `original` | 1 | `original` |

The literal Kata command failed **before the container workload ran**, with `get host path failed` / `No such file or directory (os error 2)` in the host-device handling path. The same failure occurred for both privileged device/capability probes, so the literal result is recorded as unavailable rather than inventing a mask or claiming the write was blocked by VM isolation.

| Literal nerdctl `--privileged` observation | runc | Kata |
|---|---|---|
| `/dev` entry count | 195 | Not available: creation failed, exit 1 |
| `CapEff` | `000001ffffffffff` | Not available: creation failed, exit 1 |

### Controlled privileged comparison without host-device passthrough

To obtain a working privileged guest and distinguish the device-import failure from filesystem isolation, a second, explicitly different comparison used containerd's supported **`--privileged-without-host-devices`** option ([pinned implementation](https://github.com/containerd/containerd/blob/v2.4.2/cmd/ctr/commands/run/run_unix.go)). It preserves privileged capabilities and removes the automatic import of every host device. Both runtimes used this same restriction, with only the Kata runtime selection added:

```bash
c() { ctr --address "$LAB/containerd.sock" --namespace lab12 "$@"; }
# Reset the host test file to original before each command.
echo original > /tmp/lab12-target
c run --rm --privileged --privileged-without-host-devices \
  --mount type=bind,src=/tmp,dst=/host_tmp,options=rbind:rw \
  docker.io/library/alpine:3.20 lab12-bonus-controlled sh -c \
  'echo "OVERWRITTEN" > /host_tmp/lab12-target; printf "devices="; ls /dev | wc -l; grep ^CapEff /proc/1/status; uname -r'
cat /tmp/lab12-target
# Repeat after resetting the file, inserting --runtime io.containerd.kata.v2.
```

| Controlled privileged observation | runc | Kata |
|---|---|---|
| Command exit status | 0 | 0 |
| Host file before | `original` | `original` |
| Host file after | `OVERWRITTEN` | `OVERWRITTEN` |
| `/dev` entry count | 15 | 14 |
| `CapEff` | `000001ffffffffff` | `000001ffffffffff` |
| Kernel | `6.8.0-39-generic` | `6.18.35` |

The [controlled-run evidence](lab12-evidence/controlled-privileged.json) contains both complete argument lists and their actual outputs; this adjusted run is not presented as a successful execution of the original nerdctl command.

With runc, `--privileged` grants capabilities against the shared host kernel, whereas with Kata those capabilities apply inside the guest kernel. The controlled runs show that a writable bind mount can nevertheless modify the same host file through virtio-fs, without escaping the VM. Therefore the original Kata failure demonstrates a device-import incompatibility, while the adjusted test demonstrates the shared-filesystem limitation; neither is evidence that Kata categorically blocks writable host mounts. The full capability mask inside the guest does not, by itself, grant access to the host kernel or to devices that were not passed through.

Honest limit: Kata does not protect host files that the operator explicitly exposes through writable mounts.

## Cleanup

All measurements were saved before cleanup. The lab containers, isolated daemon, downloaded images and tools, temporary measurement data, host test file, and `/opt/kata` were removed; the temporary SSH public-key entry used for this exercise was also removed. The main `/etc/containerd/config.toml` remained byte-for-byte unchanged. The host containerd service was restarted with its original configuration to restore its default TTRPC socket after setup; existing application containers retained their IDs and start times.

The [cleanup evidence](lab12-evidence/cleanup.txt) records the post-cleanup checks: no lab daemon or Kata/QEMU processes, no test file or lab directories, and existing services still running. No lab service remains to consume CPU or guest RAM.

References: [Lab 12](../labs/lab12.md), [Reading 12](../lectures/reading12.md), [Kata 4.1.0 release](https://github.com/kata-containers/kata-containers/releases/tag/4.1.0), and the [pinned Rust QEMU configuration](https://github.com/kata-containers/kata-containers/blob/4.1.0/src/runtime-rs/config/configuration-qemu-runtime-rs.toml.in).
