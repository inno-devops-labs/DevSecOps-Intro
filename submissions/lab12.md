# Lab 12 — VM-Backed Container Isolation with Kata

I executed the same Alpine image using both runc and Kata, then compared their kernels, privileges, startup times, filesystem performance, and idle memory usage. Kata ran containers with an independent guest kernel and increased the median container lifecycle time by approximately 1.14 seconds. The bind-mount test also demonstrated a key limitation: if a host directory is intentionally shared with the guest with write permissions, the guest can still modify its contents.

## Environment and reproducibility

| Item | Version or configuration |
|---|---|
| Measurement date | 18 October 2026 |
| Host | Windows with a disposable Ubuntu 24.04 WSL2 distribution, `Lab12-Kata` |
| CPU / WSL memory | AMD Ryzen 7 8745HS, 16 logical CPUs; approximately 7.4 GiB RAM |
| Host kernel | `6.6.87.2-microsoft-standard-WSL2` |
| containerd / runc | `2.2.1` / `1.3.4-0ubuntu1~24.04.1` |
| nerdctl / CNI plugins | `2.1.6` / `1.7.1` |
| Kata | `4.1.0`, Go runtime, commit `ddcb1ad8d23cbb4323f86c209f132b89592902df` |
| Hypervisor | Bundled QEMU `11.0.1`, KVM acceleration |
| Guest configuration | 1 vCPU, 2048 MiB configured RAM, `virtio-fs` |
| Image | `alpine:3.20`, `linux/amd64`, pulled before measurements |
| Storage | containerd overlayfs on the WSL distribution's ext4 filesystem |

Both runtimes used the same image already cached locally:

```text
Index:    sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
Manifest: sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

All commands were executed as root inside the disposable Linux distribution, so `sudo` was unnecessary. Throughout this report, the term “host” refers to that Linux environment rather than Windows itself.

The distribution used its own containerd installation, leaving Docker Desktop's containerd configuration untouched. The branch was created directly from `main`, and this report is the only submitted modification. Raw logs and measurement scripts were stored in the ignored `labs/lab12/results/` directory.

### Installation and adjustments

Before executing the supplied scripts, I reviewed all three of them. I imported an Ubuntu root filesystem into a temporary WSL2 distribution, installed the required dependencies, and loaded the `kvm_amd`, `vhost_vsock`, and `vhost_net` modules.

After loading the modules, `/dev/kvm` became available. An ioctl test returned KVM API version `12` and successfully created a virtual machine, providing evidence of working virtualization rather than merely confirming the presence of CPU virtualization flags.

I executed copies of the supplied installer and containerd configuration scripts after converting their Windows CRLF line endings to LF. Initially, the installer configured the Rust runtime with Dragonball. Dragonball failed with `ttrpc: closed`, and subsequent lifecycle tests using the Rust/QEMU setup repeatedly hung.

To obtain a working environment, I installed the official **Go runtime assets for the same pinned version, 4.1.0**, selected QEMU, and repeated the tests. Every result reported below comes from this final configuration; unsuccessful Rust runtime tests were excluded from the timing measurements.

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

The provided configuration script generated a legacy CRI plugin header that was incompatible with this containerd version. Before starting the dedicated daemon, I updated it to the v3 format shown below.

I also started `rsyslogd`, since the Go runtime failed with `Unix syslog delivery error` when the syslog socket was unavailable. Containerd's startup logs subsequently confirmed that the `kata` runtime had been registered successfully.

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

I ran the commands below first with the default runtime, runc, and then with Kata explicitly selected using `--runtime=io.containerd.kata.v2`.

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

The `/dev` figures represent directory entries, including symbolic links and subdirectories, rather than the number of usable physical devices. Although both containers reported the same capability mask, that does not mean they have identical access to the host: each runtime's capabilities are enforced by a different kernel.

With runc, the reported kernel release matches the host's WSL kernel. This provides an attacker with information about the kernel version that could help identify relevant vulnerabilities. However, the version string alone cannot establish whether a particular exploit would work; patch status, kernel configuration, and accessible interfaces are also important.

Kata reports `6.18.35`, corresponding to its guest kernel. Consequently, compromising that kernel would not automatically compromise the WSL host kernel. An attacker would need another security-boundary failure or access that had been deliberately exposed, such as a writable host directory shared with the guest.

## Task 2

### Startup measurements

For each runtime, I executed one warm-up run and excluded it from the measurements. I then recorded five successful runs per runtime. The image was already cached, executions were sequential, and all ten measured commands completed successfully.

The timing includes the entire `nerdctl` command lifecycle: interaction with containerd, network setup, container execution, and removal. It should not be interpreted as a measurement of hypervisor boot time alone.

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

Kata's median lifecycle time was **2.41 times** the runc median, adding **1.14 seconds**. Although the assignment suggested that the difference might be an order of magnitude, these measurements did not show such a gap. The results reported here reflect the actual measurements obtained in this environment.

### Filesystem I/O

I compared the two runtimes by writing 512 MiB of zero-filled data to a temporary file inside each container and using `conv=fsync` to flush the file.

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

The throughput values are reproduced exactly as reported by BusyBox `dd`. Using `conv=fsync` makes the test exercise the storage path and flush the written file, unlike writing to `/dev/null`, which discards the data and would not provide the same comparison.

Kata's storage path includes the guest and `virtio-fs`, introducing additional layers. These results represent individual sequential-write measurements under nested virtualization. Host caching and storage behavior also affect the results, so they should not be treated as general-purpose disk-performance benchmarks.

### Memory per idle container

For each runtime, I started one detached `alpine:3.20 sleep 120` container, waited five seconds, and collected `Pss` values from `/proc/<pid>/smaps_rollup` for the runtime shim and all descendant processes.

I identified the shim through its container ID in `cmdline` and recursively followed parent PIDs to locate its descendants. The first container was removed before the second was started, ensuring that no other test container was active during either snapshot.

| Host process group | runc PSS, KiB | Kata PSS, KiB |
|---|---:|---:|
| Runtime shim | 10,784 | 33,236 |
| nerdctl logging helper | 28,872 | 28,876 |
| Host `sleep` process | 952 | Included inside guest |
| QEMU, including resident guest memory | — | 267,622 |
| Both virtiofsd processes combined | — | 3,342 |
| **Total per-container process PSS** | **40,608** | **333,076** |
| **Total in MiB** | **39.66** | **325.27** |

Under this measurement method, Kata consumed an additional **285.61 MiB** per idle container, giving it approximately **8.20 times** the runc footprint.

PSS accounts for shared memory mappings proportionally, reducing the double-counting that would occur when simply adding RSS values. Both totals include the logging helper. They exclude the shared containerd daemon, unmapped filesystem cache, and host kernel allocations.

These figures are from a single steady-state snapshot rather than a measurement of peak or total-system memory. The configured guest RAM of 2048 MiB is an allocation setting and should not be confused with the amount of memory physically resident in this measurement.

### Which workloads justify the cost?

| Workload | Verdict | Reason |
|---|---|---|
| Short, trusted maintenance jobs on a dedicated node | runc | For small jobs, startup latency and per-container memory account for a significant share of the total resource cost. |
| Long-running workers executing untrusted customer code | Kata | An independent guest kernel offers useful isolation for hostile tenant code, particularly when workers run long enough to amortize startup overhead. |
| Latency-sensitive service with heavy persistent-volume traffic | needs more information | A decision requires representative tail-latency, storage, concurrency, and threat-model measurements instead of relying on a single sequential-write test. |

For a worker that runs for several hours, an additional startup delay of around one second is insignificant relative to its total execution time. Even a tenfold startup increase might be acceptable if startup occurs infrequently and outside the request-processing path.

The situation differs when a new sandbox must be created for every short request: the same delay can become directly visible to users. For long-running workers, memory consumption and sustained I/O performance remain important considerations even when startup overhead is negligible.

## Bonus

### Exact command required by the assignment

Before each test, I restored the target file to its original contents. The Kata command differed from the runc command only by the runtime flag; both used the same host directory and write operation.

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

I also attempted a separate probe for device entries and capabilities using the same runtime and privilege flags:

```bash
sh -c 'ls /dev | wc -l; grep ^CapEff /proc/1/status'
```

Kata failed with the same error in both cases:

```text
failed to create shim task: QMP command failed: Could not open '/dev/sda': Read-only file system
```

The failure occurred while attempting to pass through a host device during VM creation. It does not demonstrate that Kata intercepted or prevented the host-file write. I deliberately did not attempt to make the WSL disk writable as a workaround.

### Supplementary test: privilege without host-device passthrough

To test privileged execution inside a working Kata guest and separate the device-passthrough problem from bind-mount behavior, I repeated the experiment using nerdctl's documented `--security-opt privileged-without-host-devices` option **on both runtimes**.

This was an additional experiment, not a substitute for the exact command required by the assignment.

References: [nerdctl command reference](https://github.com/containerd/nerdctl/blob/v2.1.6/docs/command-reference.md) and [Kata's privileged-container guidance](https://github.com/kata-containers/kata-containers/blob/4.1.0/docs/how-to/privileged.md).

The option maintains privileged mode while excluding host devices from the OCI configuration.

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

With runc, privileged mode provides broad capabilities against the shared host kernel, and the ordinary privileged configuration also exposes host devices.

Kata confines those capabilities to its guest kernel. However, the original privileged command failed in this environment because it attempted to pass through a read-only WSL disk. Once host-device passthrough was disabled, the guest successfully overwrote the host file through the writable `virtio-fs` mount.

This outcome reflects access explicitly granted through the mount configuration. It is not evidence of a VM escape, and it does not justify claiming that Kata prevents this type of host-file modification.

**Honest limit:** Kata cannot protect files that an operator deliberately exposes through a writable host bind mount.

## Cleanup and verification

After completing the measurements, I removed the disposable `Lab12-Kata` distribution. This removed its containerd configuration, Kata installation, containers, images, and test files. I unloaded the KVM/vhost modules used in the experiment after stopping the virtual machines.

Deleting the disposable environment achieved the same cleanup objective as manually removing the runtime configuration block and deleting `/opt/kata`, without leaving the Linux installation modified.

The report includes comparisons of both runtimes, all ten successful startup measurements and their medians, actual filesystem writes, memory measurements with their scope and limitations, workload recommendations, and the outcomes of both bonus experiments.

The exact privileged Kata test does not report device counts or capability masks because the container failed to start. The supplementary test provides those measurements using a working privileged guest without misrepresenting the failed attempt. Logs and VM disk images were excluded from the commit.