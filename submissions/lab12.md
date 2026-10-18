# Lab 12 — VM-Backed Container Isolation with Kata

Author: Irina (`1r444444`). Executed 18 October 2026, Europe/Moscow.
All measurements below come from this run; the reading's illustrative numbers
and other students' measurements are not used as our data.
Compact measurements and process lists: [lab12-evidence.json](lab12-evidence.json).
Full command/stdout/stderr transcripts are retained locally in the gitignored
`labs/lab12/results/` directory.

## Environment and reproducibility

| Component | Actual configuration |
|---|---|
| Physical machine | Apple M3 Pro, macOS 26.6.2, 18 GiB RAM |
| Disposable Linux host | Lima 2.2.1, VZ, `nestedVirtualization: true`, 4 vCPUs, 4 GiB RAM, 12 GiB sparse disk |
| Linux OS/kernel | Ubuntu 26.04.1 LTS, `7.0.0-38-generic`, aarch64 |
| containerd / nerdctl / runc | 2.4.1 / 2.4.1 / 1.5.2 |
| Kata | **4.1.0**, official Go shim, commit `ddcb1ad8d23cbb4323f86c209f132b89592902df` |
| Hypervisor | Bundled QEMU 11.0.1, **KVM**, CPU `host` |
| Kata guest | 1 vCPU, 2048 MiB configured memory, `virtio-fs`, disk image rootfs |
| Image | `alpine:3.20`, linux/arm64, pulled before timing |
| Storage | containerd overlayfs on the disposable Linux host's ext4 `/dev/vda1` |

Here “host” means the disposable **Linux** VM, not macOS. Docker Desktop's
`6.10.14-linuxkit` VM had no `/dev/kvm`; it was not used for these experiments.
The M3 Pro supports nested virtualization through VZ, so a separate Lima VM
provided the required KVM device. No host directories or SSH agent were shared
with the lab VM; existing Docker Desktop containers were left untouched.

Preflight actually opened `/dev/kvm` read/write and used `KVM_GET_API_VERSION`:

```text
Host: 7.0.0-38-generic aarch64
/dev/kvm: opened read/write; KVM API version 12
```

Successful Kata execution with its distinct guest kernel, and the observed QEMU
`accel=kvm` process, establish more than the mere presence of a device node.
The same cached image index was used for both runtimes:

```text
sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
```

### Installation and ARM nested-virtualization adjustments

I read all three supplied setup/build scripts before executing host-changing
commands. The default Rust/Dragonball and Rust/QEMU profiles did not complete
normal container creation in this ARM setup. The final measured configuration
uses the official **Go build of the same pinned Kata 4.1.0**, not a newer Kata
release or software CPU emulation.

The default `pmu=off` CPU feature is not exposed by this nested host, so the CPU
feature string is empty. Direct kernel boot is used, with firmware paths empty.
Most importantly, ITS-backed interrupts did not deliver the guest vsock traffic:
a minimal QEMU/agent probe timed out, while the same probe with ITS disabled
connected successfully. Disabling all MSI also prevents PCIe root-port creation,
so the final configuration selects **`msi=gicv2m`**, retaining MSI/PCIe hotplug
without the failing nested ITS path. This final configuration runs with the
normal nerdctl network, without extra `--net=none` benchmark flags.

```toml
[hypervisor.qemu]
path = "/opt/kata/bin/qemu-system-aarch64"
kernel = "/opt/kata/share/kata-containers/vmlinux.container"
image = "/opt/kata/share/kata-containers/kata-containers.img"
firmware = ""
firmware_volume = ""
cpu_features = ""
machine_accelerators = "msi=gicv2m"
default_vcpus = 1
default_memory = 2048
shared_fs = "virtio-fs"
```

Debug logging was disabled for measurements. The runtime registration in this
Lima-provisioned containerd config is:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

The source config has `version = 2`; containerd 2.4.1 accepts it through automatic
migration. Its effective configuration and successful runtime launches were
checked. nerdctl prints a warning that it cannot set the Kata cgroup manager to
systemd; the successful measured commands still exit 0.

### Reproduce

[setup/lima-vz.yaml](../labs/lab12/setup/lima-vz.yaml) pins the Ubuntu ARM64 image
and checksum and disables host mounts. Install official Lima 2.2.1, then create
the VM with `limactl start --name=lab12 --tty=false labs/lab12/setup/lima-vz.yaml`.
Copy the repository into the guest using `limactl copy`, rather than sharing the
Mac home directory. Inside that disposable Linux VM, with system containerd and
nerdctl available:

```bash
sudo bash labs/lab12/scripts/preflight.sh
# Required packages in the disposable Linux VM: curl, zstd, Python 3.11+.
curl -fL https://github.com/kata-containers/kata-containers/releases/download/4.1.0/kata-go-static-4.1.0-arm64.tar.zst -o /tmp/kata-go.tar.zst
printf '%s  %s\n' 9008fa1acdc6e9f5c86e9f4fa0e22dbaf09106f8ddc62383bfcb7cfa0df42ff3 /tmp/kata-go.tar.zst | sha256sum -c -
sudo tar --zstd -xf /tmp/kata-go.tar.zst -C /
sudo bash labs/lab12/setup/configure-arm64-lima.sh
sudo python3 labs/lab12/scripts/measure.py --output labs/lab12/results
sudo python3 labs/lab12/scripts/memory-and-bind.py --output labs/lab12/results
```

The archive SHA256 matches the release asset digest returned by GitHub's API.
The original Rust archive was downloaded during diagnosis; its kernel, root image
and initrd were compared by SHA256 with the Go archive's corresponding assets and
matched. The final Go shim/configuration and ARM setup helper were exercised in
the VM; no measurements from failed exploratory launches enter the tables.
The collector runs commands as root with a dedicated containerd namespace,
`lab12`. The timeout is 180 seconds per command and nonzero benchmark exits fail
the collector instead of becoming bogus timing samples.

The supplied registration script's `awk` used `\s`, which does not portably
match indentation and could append a duplicate `runtime_type` on a second run.
I replaced it with POSIX `[[:space:]]`; the regression test
`python3 labs/lab12/scripts/test-config.py` runs registration twice against both
v2 and v3 plugin fixtures, parses the resulting TOML and checks runc is preserved.

### Device compatibility for the exact privileged commands

Two upstream device-enumeration issues had to be resolved on this disposable
VM before measuring. Ubuntu creates `/dev/root` and `/dev/vda1` as separate block
nodes for the same major/minor, which Kata rejects as duplicate resource updates.
The setup helper replaces `/dev/root` with a symlink to the identical `/dev/vda1`,
checking the block device identity first.

Kata's [rustjail device creation](https://github.com/kata-containers/kata-containers/blob/4.1.0/src/agent/rustjail/src/mount.rs#L917)
also creates its six standard devices before processing the OCI device list;
receiving those same paths from privileged host-device enumeration causes
`EEXIST`. The helper creates canonical nodes for `null`, `zero`, `full`, `random`,
`urandom` and `tty` under `/dev/lab12-host-devices`, preserving each major/minor,
mode and ownership, and atomically replaces the traditional paths with symlinks.
Host-device enumeration includes those canonical nodes; no host devices are
removed from the privileged OCI list and no `privileged-without-host-devices`
flag is used. All traditional host paths remain usable, and the runtime creates
its normal default devices inside the container. This is an explicit environment
workaround in the throwaway VM, not a claim that an unmodified installation
supports these exact commands on this host.

The helper was executed twice successfully; the final collectors then ran on
this same configuration. Device counts below include the extra canonical
subdirectory, so they are observations for this configured VM rather than
portable constants. Deleting the VM also removes these device-layout changes.

## Task 1

### One image, two runtimes

Equivalent live commands (shown without the collector's namespace argument):

```bash
uname -r
nerdctl run --rm alpine:3.20 uname -r
nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 uname -r
# For each runtime, also: ls -1 /dev; grep ^CapEff /proc/1/status
```

| Observation | runc | Kata |
|---|---|---|
| Linux host kernel | `7.0.0-38-generic` | `7.0.0-38-generic` |
| Container kernel | `7.0.0-38-generic` | `6.18.35` |
| Matches host | Yes | No |
| `/dev` entries | 15 | 14 |
| PID 1 `CapEff` | `00000000a80425fb` | `00000000a80425fb` |

The device counts include symlinks/directories, rather than counting physical
hardware. runc has `/dev/core`; Kata does not. Equal capability masks do not
remove the separate-kernel boundary.

### What the exact kernel output tells an attacker

`7.0.0-38-generic` in runc matches the host, exposing the Ubuntu kernel family
against which an attacker could investigate relevant bugs and accessible attack
surfaces. The release string alone does not establish exploitability because
backported patches, configuration and capabilities also matter. In Kata,
`6.18.35` identifies the guest kernel, so an exploit of that kernel would initially
compromise the disposable guest rather than the Linux host. Reaching the host
would require an additional boundary failure, or access explicitly exported by
the operator, such as a writable host directory.

## Task 2

### Five startup times and medians

The image pull and one complete `true` warm-up per runtime were excluded from
timing. Five successful commands followed sequentially for each runtime:
`nerdctl run --rm [--runtime=io.containerd.kata.v2] alpine:3.20 true`.
The collector uses Python's monotonic `time.perf_counter()` around the subprocess;
JSON saving happens outside the measured interval. Like the assignment's
`/usr/bin/time`, it includes nerdctl, containerd, network setup, execution and
removal, rather than measuring hypervisor boot in isolation. The collector itself
already runs as root, so neither runtime pays a per-command sudo/authentication cost.

| Runtime | Run 1, s | Run 2, s | Run 3, s | Run 4, s | Run 5, s | Median, s |
|---|---:|---:|---:|---:|---:|---:|
| runc | 0.287189 | 0.247112 | 0.300623 | 0.237546 | 0.306349 | **0.287189** |
| kata | 9.600411 | 10.374380 | 12.528694 | 19.343573 | 10.477538 | **10.477538** |

Kata's median full-lifecycle time is **36.48 times** runc's here, adding
**10.190 seconds**.
The actual difference is larger than tenfold; I do not replace it with the
reading's values or another student's measurements. This nested M3/VZ/KVM setup
and IRQ workaround are part of the measurement environment. The figures do not
predict bare-metal x86 or production tail latency, and the lifecycle measurement
cannot attribute all the difference to guest boot alone.

### Actual filesystem I/O

```bash
nerdctl run --rm alpine:3.20 \
  sh -o pipefail -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1 | tail -1'
nerdctl run --rm --runtime=io.containerd.kata.v2 alpine:3.20 \
  sh -o pipefail -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1 | tail -1'
```

```text
runc: 536870912 bytes (512.0MB) copied, 2.098968 seconds, 243.9MB/s
Kata: 536870912 bytes (512.0MB) copied, 12.305138 seconds, 41.6MB/s
```

Each run writes **536,870,912 bytes (512 MiB)**. BusyBox labels its binary-unit
throughput `MB/s`; the complete output lines above are retained without
substituting illustrative throughput values. The file and `conv=fsync` exercise
the storage/flush path, including virtio-fs for Kata; `/dev/null` would discard
writes and skip the layer being compared. These are one sequential-write sample
per runtime with host/VM caches and backing storage involved, not a complete
persistent-volume performance profile.

### Memory per idle container

For each runtime the collector starts a detached `alpine:3.20 sleep 300`, waits
five seconds, then samples `/proc/<pid>/smaps_rollup` three times, one second apart.
It compares the PID set before and after starting the container, summing PSS for
the new long-lived workload processes; their complete command lines and each
sample are in the evidence JSON. The first container is removed before the
second is started, and no other guest commands ran during these memory snapshots.

| Runtime | Three process-PSS totals, KiB | Median, KiB | Median, MiB |
|---|---|---:|---:|
| runc | 41180, 41180, 41180 | **41180** | **40.21** |
| kata | 254080, 254080, 254080 | **254080** | **248.12** |

For clarity, processes included in a snapshot with the median total were:

| Runtime | Host-visible process | PSS, KiB |
|---|---|---:|
| runc | containerd-shim-runc-v2 | 10636 |
| runc | nerdctl logging helper | 29688 |
| runc | sleep | 856 |
| kata | containerd-shim-kata-v2 | 32572 |
| kata | virtiofsd | 1022 |
| kata | qemu-system-aarch64 | 188652 |
| kata | virtiofsd | 2078 |
| kata | nerdctl logging helper | 29756 |

Under this stated process-footprint method, Kata adds **207.91 MiB**
per idle container, approximately **6.17 times** the runc footprint.
PSS apportions shared pages, avoiding the duplication produced by summing RSS
across QEMU and virtiofsd. QEMU includes the resident guest memory and workload;
the configured 2048 MiB allocation is not the same as the observed resident cost.
These figures exclude the shared containerd daemon, host kernel allocations and
unmapped page cache, so they are not a claim about the total host memory delta
or the peak memory of a real workload.

### Three workloads

| Workload | Verdict | Reason |
|---|---|---|
| Trusted first-party FastAPI/Streamlit coursework service on a dedicated node | runc | Its controlled image and operators may justify standard kernel hardening without paying the measured sandbox lifecycle and memory cost. |
| CI runner executing build scripts from untrusted pull requests | Kata | Arbitrary contributor code benefits from a guest-kernel boundary, especially for jobs long enough to amortize boot cost. |
| Multi-tenant GPU inference with a cold-start latency target | needs more information | Representative GPU passthrough, tail latency, memory density and storage tests are needed; this CPU-only Alpine benchmark cannot settle compatibility or latency. |

### When the startup gap does not matter

A prestarted worker or batch service running for hours or days pays the extra
startup delay once, outside its steady-state request path. For a 24-hour worker,
our extra 10.19 seconds is about
0.0118% of that lifetime.
Creating a fresh container per short request would instead expose that delay on
every invocation and materially change the decision. Memory and sustained I/O
costs remain relevant even when startup is amortized.

## Bonus

### Exact command from the assignment

The sentinel was reset to `original` **before each runtime**. The two command
lines differ only by the runtime flag (the collector also uses namespace `lab12`):

```bash
echo original >/tmp/lab12-target
nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
echo "exit=$?"; cat /tmp/lab12-target

echo original >/tmp/lab12-target
nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target'
echo "exit=$?"; cat /tmp/lab12-target
```

| Exact privileged test | runc | Kata |
|---|---|---|
| Exit code | 0 | 0 |
| Host file after run | `OVERWRITTEN` | `OVERWRITTEN` |
| `/dev` count from separate privileged probe | 194 | 192 |
| Privileged `CapEff` | `000001ffffffffff` | `000001ffffffffff` |

The device/capability probe used the same `--privileged` option for each runtime:

```bash
nerdctl run --rm --privileged alpine:3.20 \
  sh -c 'ls /dev | wc -l; grep ^CapEff /proc/1/status'
nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged alpine:3.20 \
  sh -c 'ls /dev | wc -l; grep ^CapEff /proc/1/status'
```

With runc, privileged capabilities are evaluated by the Linux host kernel and
the privileged setup exposes host devices. Kata evaluates those capabilities
inside its separate guest kernel, even with the same full capability mask.
Both exact commands modify the host file through the deliberately writable bind
mount, so this vector does not demonstrate a blocked host write under Kata.
This is operator-granted access through virtio-fs, so guest-kernel isolation
cannot revoke the host access explicitly granted by the operator.

**Honest limitation:** Kata does not protect a host file that an operator
explicitly exports writable to the guest.

## Public PR comparison and acceptance audit

After our own runtime launches, startup/I/O/memory measurements and exact
privileged runs, I compared lab12 reports from
[#1878](https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1878),
[#1798](https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1798) and
[#1553](https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1553).
They are cross-checks, not authoritative reference answers.

- #1878 also uses Go Kata 4.1.0, but records a failed exact privileged launch
  and a working `privileged-without-host-devices` supplement. Comparing the
  reports exposed the need for further device-compatibility work here: our final
  result runs the exact original command successfully for both runtimes, and
  records the environment workaround explicitly. Its timing values are not used.
- #1798 reports that its M1 environment cannot run Kata. That restriction does
  not describe this M3 Pro: our VZ VM has verified KVM and actually executes both
  runtimes, so no Kata values in this report are theoretical substitutions.
- #1553 uses an older Kata release and reports means and `/dev/null` I/O under
  an older task format. The current lab explicitly requires medians and a real
  fsynced file, so our acceptance audit follows today's specification. Its failed
  privileged launch likewise does not establish successful containment of a write.

| Required item | Evidence/result |
|---|---|
| Linux KVM, version recorded | KVM ioctl 12, Kata 4.1.0, observed KVM QEMU launch. |
| Host/runc/Kata kernels | 7.0.0-38-generic / 7.0.0-38-generic / 6.18.35. |
| Device counts and capabilities | Task 1 table and evidence JSON. |
| Specific attacker interpretation | Task 1 explanation tied to those releases. |
| Five warmed timings and median per runtime | Ten exit-0 samples, Task 2 table. |
| Real file I/O | 512 MiB, `conv=fsync`, raw throughput lines. |
| Memory measurement/method | Three process-PSS samples, process list, scope stated. |
| Three workload verdicts | runc / Kata / needs more information with reasons. |
| Startup gap interpretation | Measured 36.48×; amortization for prestarted long-lived workers. |
| Both exact privileged attempts and host state | Both commands exit 0 and write OVERWRITTEN; state recorded. |
| Privileged masks/counts for both runtimes | Both exact privileged probes exit 0; actual counts/full masks recorded. |
| Honest privilege explanation and limitation | Guest kernel scope; explicitly writable export succeeds on both runtimes. |

Syntax checks, the v2/v3 registration regression test and live collectors passed.
All 35 recorded collector commands exit 0, including both exact privileged
writes and both device/capability probes. The unmodified repository verifier
`tools/verify-lab.sh 12 --run` also exits 0 inside the VM: it executes 2 of 8
blocks and guards/skips the others. The live collectors execute the actual
Kata-dependent experiments that the verifier guards. Containerd remained active,
the lab namespace had no remaining containers and the sentinel was removed.

## Cleanup

Remove the namespace's test containers and sentinel, export the measurements,
then delete the dedicated Lima `lab12` instance. Deleting this disposable VM
removes its `/opt/kata`, containerd runtime registration and all guest test
artifacts together, achieving the assignment's cleanup without changing the
Mac's Docker daemon. The provided scripts operate inside Linux; no host-runtime
installation is performed on macOS.
