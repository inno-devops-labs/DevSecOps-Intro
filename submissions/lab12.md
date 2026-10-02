# Lab 12 — VM-Backed Container Isolation with Kata

I ran the same Alpine image under runc and Kata, compared their kernels and
privileges, and measured startup, filesystem writes, and idle memory. Kata used
a separate guest kernel and added about 1.14 seconds to the median container
lifecycle. The bind-mount experiment also exposed an important limit: a writable
host directory remains writable when it is deliberately shared with the guest.

## Environment and reproducibility

| Item | Version or configuration |
|---|---|
| Measurement date | 2 October 2026 |
| Host | Windows with a disposable Ubuntu 24.04 WSL2 distribution, `Lab12-Kata` |
| CPU / WSL memory | AMD Ryzen 7 8745HS, 16 logical CPUs; approximately 7.4 GiB RAM |
| Host kernel | `6.6.87.2-microsoft-standard-WSL2` |
| containerd / runc | `2.2.1` / `1.3.4-0ubuntu1~24.04.1` |
| nerdctl / CNI plugins | `2.1.6` / `1.7.1` |
| Kata | `4.1.0`, Go runtime, commit `ddcb1ad8d23cbb4323f86c209f132b89592902df` |
| Hypervisor | Bundled QEMU `11.0.1`, KVM acceleration |
| Guest configuration | 1 vCPU, 2048 MiB configured RAM, `virtio-fs` |
| Image | `alpine:3.20`, `linux/amd64`, already pulled before timing |
| Storage | containerd overlayfs on the WSL distribution's ext4 filesystem |

Both runtimes used this locally cached image:

```text
Index:    sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
Manifest: sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

Commands below run as root inside the disposable Linux distribution, so they
do not need `sudo`. Here, “host” means this Linux environment, not Windows.
The distribution had its own containerd; Docker Desktop's containerd
configuration was not edited. This branch starts directly from `main`, and its
only submitted change is this report. Raw logs and measurement scripts were
kept under the ignored `labs/lab12/results/` directory.

### Installation and adjustments

I read all three supplied scripts before running them. I imported an Ubuntu
root filesystem into a disposable WSL2 distribution, installed the prerequisites,
and loaded `kvm_amd`, `vhost_vsock`, and `vhost_net`. `/dev/kvm` was present after
loading the modules; an ioctl probe returned KVM API version `12` and successfully
created a VM. Merely seeing CPU virtualization flags would not have been enough.

I ran the supplied installer and containerd configuration script from copies
with Windows CRLF endings converted to LF. The installer initially selected
the Rust runtime and Dragonball. Dragonball failed with `ttrpc: closed`, and
the Rust/QEMU configuration subsequently hung during repeated lifecycle tests.
I therefore installed the official **Go runtime assets for the same pinned
version, 4.1.0**, selected QEMU, and repeated the measurements. All results below
use that final configuration; failed Rust runs are not included in the timing set.

```bash
bash /root/lab12/install.sh
bash /root/lab12/configure.sh

curl -fL \
  https://github.com/kata-containers/kata-containers/releases/download/4.1.0/kata-go-static-4.1.0-amd64.tar.zst \
  -o /root/lab12/kata-go.tar.zst
zstd -dc /root/lab12/kata-go.tar.zst | tar xf - -C /
ln -sf /opt/kata/bin/containerd-shim-kata-v2 \
  /usr/local/bin/containerd-shim-kata-v2
ln -sf /opt/kata/share/defaults/kata-containers/configuration-qemu.toml \
  /etc/kata-containers/configuration.toml
```

The provided configuration script produced a legacy CRI plugin header on this
containerd version. I corrected it to the v3 header below before starting the
dedicated daemon. I also started `rsyslogd`: without a syslog socket, this Go
runtime failed with `Unix syslog delivery error`. Containerd's startup log
confirmed that the `kata` runtime was registered.

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

```text
$ cat /opt/kata/VERSION
4.1.0
$ /opt/kata/bin/kata-runtime --version
kata-runtime  : 4.1.0
   commit   : ddcb1ad8d23cbb4323f86c209f132b89592902df
   OCI specs: 1.2.1
```

## Task 1

### One image, two kernels

I ran the following with no runtime flag for runc, then with
`--runtime=io.containerd.kata.v2` for Kata:

```bash
uname -r  # Linux host
nerdctl run --rm alpine:3.20 \
  sh -c 'uname -r; ls /dev | wc -l; grep ^CapEff /proc/1/status'
nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -c 'uname -r; ls /dev | wc -l; grep ^CapEff /proc/1/status'
```

| Observation | runc | Kata |
|---|---|---|
| Container kernel | `6.6.87.2-microsoft-standard-WSL2` | `6.18.35` |
| Matches host kernel | Yes | No |
| Entries in `/dev` | 15 | 14 |
| PID 1 `CapEff` | `00000000a80425fb` | `00000000a80425fb` |

These are directory-entry counts, including symlinks and subdirectories, rather
than counts of usable physical devices. Equal capability masks do not imply
equal access to the host: the capabilities are enforced by different kernels.

The runc output tells an attacker that the container uses the host's WSL kernel
release, giving them a concrete target for researching applicable kernel flaws.
The release string alone does not establish exploitability, since patching,
configuration, and reachable interfaces also matter. Kata instead exposes
`6.18.35`, the guest kernel, so compromising that kernel would not automatically
give control of the WSL host kernel. Reaching the host would require another
boundary failure or access that was deliberately granted, such as a writable share.

## Task 2

### Startup measurements

For each runtime I discarded one warm-up and then timed five successful runs.
The image was already cached, the tests ran sequentially, and all ten timed
commands exited successfully. The measured interval includes nerdctl, containerd,
network setup, container execution, and removal; it is not a measurement of
hypervisor boot time alone.

```bash
for rt in runc kata; do
  FLAG=""
  [ "$rt" != kata ] || FLAG="--runtime=io.containerd.kata.v2"
  nerdctl run --rm $FLAG alpine:3.20 true  # discarded warm-up
  for i in 1 2 3 4 5; do
    /usr/bin/time -f '%e' nerdctl run --rm $FLAG alpine:3.20 true
  done
done
```

| Runtime | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Median |
|---|---:|---:|---:|---:|---:|---:|
| runc | 0.78 s | 0.83 s | 0.82 s | 0.79 s | 0.81 s | **0.81 s** |
| Kata | 1.85 s | 1.83 s | 1.95 s | 2.00 s | 2.37 s | **1.95 s** |

Kata's median was **2.41 times** runc's, with **1.14 seconds** of additional
elapsed time. This environment did not produce the order-of-magnitude gap
suggested in the assignment; I have retained the measured result.

### Filesystem I/O

```bash
nerdctl run --rm alpine:3.20 \
  sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1'
nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1'
```

| Runtime | Bytes written | `dd` elapsed time | Throughput reported by Alpine `dd` |
|---|---:|---:|---:|
| runc | 536,870,912 | 0.852468 s | 600.6 MB/s |
| Kata | 536,870,912 | 3.040595 s | 168.4 MB/s |

The throughput labels above are preserved exactly as BusyBox printed them.
Writing a file with `conv=fsync` exercises the container's storage path and
flushes the file, whereas `/dev/null` would discard the bytes and bypass that
comparison. Kata's path includes the guest and virtio-fs. These are single
sequential-write samples on nested virtualization, influenced by host caching
and storage, rather than general disk-performance estimates.

### Memory per idle container

I started one detached `alpine:3.20 sleep 120` container at a time, waited five
seconds, and read `Pss` from `/proc/<pid>/smaps_rollup` for its runtime shim and
every descendant process. I located the shim by its container ID in `cmdline`
and followed parent PIDs recursively. I removed the first container before
starting the second; no other test container was running during these snapshots.

| Host process group | runc PSS, KiB | Kata PSS, KiB |
|---|---:|---:|
| Runtime shim | 10,784 | 33,236 |
| nerdctl logging helper | 28,872 | 28,876 |
| Host `sleep` process | 952 | Included inside guest |
| QEMU, including resident guest memory | — | 267,622 |
| Both virtiofsd processes combined | — | 3,342 |
| **Total per-container process PSS** | **40,608** | **333,076** |
| **Total in MiB** | **39.66** | **325.27** |

On this definition, Kata added **285.61 MiB** per idle container, approximately
**8.20 times** the runc footprint. PSS apportions shared mappings, reducing the
double-counting that summing RSS would introduce. This measurement includes the
logging helper for both runtimes and excludes the shared containerd daemon,
unmapped filesystem cache, and host kernel allocations. It is one steady-state
snapshot, not peak or total-system memory; the configured 2048 MiB guest RAM is
an allocation setting, not the amount physically resident in this measurement.

### Which workloads justify the cost?

| Workload | Verdict | Reason |
|---|---|---|
| Short, trusted maintenance jobs on a dedicated node | runc | Their small amount of work makes startup and per-container memory a large fraction of the total cost. |
| Long-running workers executing untrusted customer code | Kata | A separate guest kernel is useful when tenant code is hostile and each worker performs enough work to amortize startup. |
| Latency-sensitive service with heavy persistent-volume traffic | needs more information | The decision needs realistic tail-latency, storage, concurrency, and threat-model measurements, rather than one sequential write. |

For a worker that runs for hours, a one-off startup delay of roughly one second
has negligible effect on useful throughput. Even an order-of-magnitude startup
gap could be unimportant when startup is outside the request path and happens
infrequently. This is different from spawning a fresh sandbox for every small
request, where the same delay would be visible to users. Memory and sustained
I/O costs still matter for long-lived workers, even when startup does not.

## Bonus

### Exact command required by the assignment

I reset the target file before each run. The second command differs only by the
Kata runtime flag; the host directory and payload are identical.

```bash
echo original >/tmp/lab12-target
nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
echo "exit=$?"
cat /tmp/lab12-target

echo original >/tmp/lab12-target
nerdctl run --rm --runtime=io.containerd.kata.v2 \
  --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
echo "exit=$?"
cat /tmp/lab12-target
```

| Exact test | runc | Kata |
|---|---|---|
| Exit status | 0 | 1 |
| Host file afterward | `OVERWRITTEN` | `original` |
| Privileged `/dev` entry count | 159 | Unavailable: container creation failed |
| Privileged PID 1 `CapEff` | `000001ffffffffff` | Unavailable: no container process started |

The separate privileged device/capability probe used
`sh -c 'ls /dev | wc -l; grep ^CapEff /proc/1/status'` with the same runtime and
privilege flags. Kata failed with the same error in both cases:

```text
failed to create shim task: QMP command failed: Could not open '/dev/sda': Read-only file system
```

This was a host-device passthrough failure while creating the VM, not evidence
that Kata had intercepted the file write. I did not make the WSL disk writable
to work around it.

### Supplementary test: privilege without host-device passthrough

To obtain a working privileged guest and distinguish the device failure from
bind-mount behavior, I repeated the test with nerdctl's documented
`--security-opt privileged-without-host-devices` option **on both runtimes**.
This is explicitly an additional test, not a replacement for the exact run above.
The option preserves privileged mode while omitting host devices from the OCI
configuration; see the [nerdctl command reference](https://github.com/containerd/nerdctl/blob/v2.1.6/docs/command-reference.md)
and [Kata's privileged-container guidance](https://github.com/kata-containers/kata-containers/blob/4.1.0/docs/how-to/privileged.md).

```bash
for rt in runc kata; do
  FLAG=""
  [ "$rt" != kata ] || FLAG="--runtime=io.containerd.kata.v2"
  echo original >/tmp/lab12-target
  nerdctl run --rm $FLAG --privileged \
    --security-opt privileged-without-host-devices \
    -v /tmp:/host_tmp alpine:3.20 \
    sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
  echo "exit=$?"
  cat /tmp/lab12-target
  nerdctl run --rm $FLAG --privileged \
    --security-opt privileged-without-host-devices alpine:3.20 \
    sh -c 'uname -r; ls /dev | wc -l; grep ^CapEff /proc/1/status'
done
```

| Supplementary privileged test | runc | Kata |
|---|---|---|
| Exit status | 0 | 0 |
| Host file afterward | `OVERWRITTEN` | `OVERWRITTEN` |
| Kernel | `6.6.87.2-microsoft-standard-WSL2` | `6.18.35` |
| `/dev` entries | 15 | 14 |
| PID 1 `CapEff` | `000001ffffffffff` | `000001ffffffffff` |

Under runc, privileged mode grants broad capabilities against the shared host
kernel, and the ordinary privileged command also exposes host devices. Under
Kata, those capabilities apply inside the guest kernel, but the literal command
failed here when trying to pass through a read-only WSL disk. Once host-device
passthrough was omitted, the guest still overwrote the target because virtio-fs
deliberately exported a writable host directory. That is authorized access
through a dangerous mount configuration, not a demonstrated VM escape, and
the observed result does not support claiming that Kata blocks this vector.

**Honest limit:** Kata does not protect files that an operator explicitly makes
writable through a host bind mount.

## Cleanup and verification

After collecting the results, I removed the disposable `Lab12-Kata` distribution,
including its containerd configuration, Kata installation, containers, images,
and test file. I unloaded the KVM/vhost modules loaded for this experiment after
the VMs had stopped. Removing this disposable environment serves the same
cleanup purpose as reverting its runtime block and deleting `/opt/kata`, without
leaving a modified Linux installation behind.

The report covers both ordinary runtimes, all ten successful startup timings and
their medians, actual filesystem writes, measured memory with its scope, three
workload decisions, and both the exact and supplementary bonus outcomes. The
exact privileged Kata probe has no device count or mask because it never started;
the additional working privileged probe supplies those observations without
misrepresenting the failed command. Logs and VM disk images are excluded from
the commit.
