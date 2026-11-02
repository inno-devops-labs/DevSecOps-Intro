# Lab 12 — Measured runc versus Kata isolation and cost

Executed **2026-11-02**, approximately 14:25–14:31 MSK. **Tasks 1 and 2 were completed on the same KVM-enabled Linux VM.** The prescribed privileged bind-mount bonus was attempted on both runtimes: runc overwrote the host file, while Kata rejected container creation with a device error. An additional host-PID test demonstrates an actual isolation difference, and a writable-share positive control establishes the limit of that protection.

Evidence: [`lab12-evidence.json`](lab12-evidence.json) contains the raw measurements, five memory samples with process lists, effective Kata configuration, command arguments, exit codes and both boundary-test outcomes. The earlier Docker-only baseline is superseded by these same-host nerdctl measurements.

## Task 1

### Working environment and installation

| Component | Observed value |
|---|---|
| Physical machine | Apple M4 Pro, macOS 26.5.2, 24 GiB RAM |
| Linux host for both runtimes | Ubuntu 26.04 arm64 in Lima **2.2.1**, **4 vCPUs, 6 GiB RAM**, 25 GiB virtual disk |
| Linux host kernel | **7.0.0-34-generic** |
| Virtualization | Apple Virtualization.framework, `nestedVirtualization: true`; nested guest uses **KVM**, not TCG |
| containerd / nerdctl | **2.4.1 / 2.4.1** |
| runc | **1.5.2**, commit `v1.5.2-0-g29dd3dc` |
| Kata | **4.1.0**, Go shim, commit `ddcb1ad8d23cbb4323f86c209f132b89592902df` |
| Kata hypervisor | **QEMU 11.0.1 (kata-static)**, one guest vCPU, 2048 MiB configured guest RAM |
| Guest storage | virtio-fs for the container filesystem; virtio-blk for the Kata guest OS image |
| Workload | Same local **alpine:3.20** image for both runtimes |
| Network for every measured container | **`--net=none`** |

The existing Docker Desktop VM lacked `/dev/kvm`; that did not rule out a separate VM on this Mac. Apple supports nested virtualization on M3 and later, and Lima exposes it through `nestedVirtualization: true`. This run used a separate disposable Linux VM with **no macOS directory mounts**. See [Apple's nested-virtualization documentation](https://developer.apple.com/documentation/virtualization/vzgenericplatformconfiguration/isnestedvirtualizationsupported) and [Lima's configuration](https://github.com/lima-vm/lima/blob/master/templates/default.yaml).

```console
$ limactl shell lab12-kata uname -r
7.0.0-34-generic
$ limactl shell lab12-kata ls -l /dev/kvm
crw-rw---- 1 root kvm 10, 232 Nov  2 14:16 /dev/kvm
$ limactl shell lab12-kata sudo /opt/kata/bin/kata-runtime check
System is capable of running Kata Containers
System can currently create Kata Containers
$ limactl shell lab12-kata sudo cat /opt/kata/VERSION
4.1.0
```

The ARM64 **Go/QEMU** release asset was used instead of the starter installer's runtime-rs configuration. Its SHA-256 matched the official GitHub release asset digest:

```text
kata-go-static-4.1.0-arm64.tar.zst
9008fa1acdc6e9f5c86e9f4fa0e22dbaf09106f8ddc62383bfcb7cfa0df42ff3
```

The supplied `configure-containerd-kata.sh` registered `runtime_type = 'io.containerd.kata.v2'`; `containerd config dump` validated the effective runtime table before restart. All installations and containerd changes occurred **inside the disposable VM**, not on macOS or in Docker Desktop.

### ARM nested-virtualization adjustments

The packaged configuration needed the following local overrides, captured in the evidence JSON and reproduced by [`install-lima-kata.sh`](../labs/lab12/setup/install-lima-kata.sh):

```toml
cpu_features = ""
firmware = ""
firmware_volume = ""
disable_image_nvdimm = true
machine_accelerators = "highmem-mmio=off"
kernel_params = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 pci=nomsi"
```

The packaged `pmu=off` option failed with `Property 'host-arm-cpu.pmu' not found`. A direct kernel boot with block-backed guest storage avoided the firmware path; disabling MSI avoided the observed PCI initialization hang. MSI-dependent network hot-plugging consequently failed, so **both runtimes use `--net=none` for these offline experiments**. Debug logging and the temporary diagnostic hypervisor wrapper were removed before measurements; networking performance and general workload compatibility are not established by this run.

### Same image, two kernels

```bash
sudo nerdctl run --rm --net=none --runtime=io.containerd.runc.v2 alpine:3.20 uname -r
sudo nerdctl run --rm --net=none --runtime=io.containerd.kata.v2 alpine:3.20 uname -r
# Repeat with: sh -c 'ls -1 /dev | wc -l'
# Repeat with: sh -c 'grep ^CapEff /proc/1/status'
```

| Observation | runc | Kata |
|---|---|---|
| Host Linux release | `7.0.0-34-generic` | `7.0.0-34-generic` |
| Container kernel | **`7.0.0-34-generic`** | **`6.18.35`** |
| `/dev` entry count | **15** | **14** |
| Effective capability mask | **`00000000a80425fb`** | **`00000000a80425fb`** |

The runc result identifies the exact kernel shared with the Linux host, helping an attacker select candidate kernel exploits and check prerequisites. It does not establish exploitability by itself: patches, configuration, capabilities and seccomp still matter. Kata reports its **guest** kernel instead, so compromising that kernel still leaves the hypervisor boundary before the host. Identical capability bits are interpreted by different kernels; a matching mask does not mean matching access to the physical or Linux host.

## Task 2

### Startup: five timed runs after a discarded warm-up

The collector pulled the image before timing, discarded one `true` warm-up **per runtime**, then timed five successful `nerdctl run --rm --net=none --runtime=... alpine:3.20 true` commands using `time.perf_counter()`. Each value includes nerdctl, containerd, container creation, command execution and teardown; both runtimes use the same frontend and flags. This is end-to-end lifecycle time, not a claim to measure the hypervisor alone.

| Runtime | Run 1 (s) | Run 2 (s) | Run 3 (s) | Run 4 (s) | Run 5 (s) | Median (s) |
|---|---:|---:|---:|---:|---:|---:|
| runc | 0.128925 | 0.122761 | 0.119321 | 0.113381 | 0.122610 | **0.122610** |
| Kata | 10.154782 | 12.081057 | 11.562751 | 10.646922 | 10.886944 | **10.886944** |

The measured ratio is **88.79×**, almost two orders of magnitude rather than the reading's illustrative gap. Nested virtualization, the selected ARM compatibility settings, guest OS initialization and teardown all contribute; these results should not be generalized to bare-metal x86 or other Kata hypervisors.

### File-write throughput

Both runtimes executed:

```bash
sudo nerdctl run --rm --net=none --runtime=RUNTIME alpine:3.20 \
  sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync'
```

```text
runc:
536870912 bytes (512.0MB) copied, 0.339183 seconds, 1.5GB/s

Kata:
536870912 bytes (512.0MB) copied, 7.413452 seconds, 69.1MB/s
```

A file write crosses the container filesystem/storage layer, whereas `/dev/null` discards the data and would bypass the overhead being compared. `conv=fsync` requests a flush before completion; this is still one sequential-write sample within nested virtual storage, not a comprehensive durability or application-throughput test.

### Memory overhead and method

The collector started one Alpine `sleep 120` container per runtime, waited three seconds, and sampled **host PSS of its dedicated containerd shim and every descendant** five times, one second apart. It reads `/proc/<pid>/smaps_rollup`, records every PID/command and sums PSS; the Kata process tree includes QEMU, guest RAM and virtiofsd. PSS apportions shared mapped pages instead of simply summing RSS; the guest's own `free` output or container-only stats would omit important host costs.

| Runtime | Five host-PSS samples (KiB) | Median (KiB) | Median (MiB) |
|---|---|---:|---:|
| runc | 40896, 40896, 40896, 40896, 40896 | **40896** | **39.94** |
| Kata | 240976, 241040, 240920, 240920, 240924 | **240924** | **235.28** |

The additional dedicated resident footprint is **200028 KiB = 195.34 MiB per sandbox** for this idle workload/configuration. These are process-tree totals including the tiny workload, not application heap alone; shared containerd costs, unmapped page cache and the outer Lima/macOS hypervisor cost are excluded. Kata's configured 2048 MiB guest RAM is an allocation limit/reservation, distinct from the observed resident PSS. Measurements are on the same host and workload; assess multiple replicas and real load before capacity planning.

### Workload decisions

| Workload | Verdict | Reason |
|---|---|---|
| Trusted, long-running Juice Shop-like service with controlled images | **runc** | Lower measured memory and lifecycle cost are reasonable with hardening and timely host patching. |
| Long-running workers executing untrusted tenant code | **Kata** | A separate guest kernel buys a useful boundary while startup cost is amortized over long jobs. |
| Short-lived, latency-sensitive functions with heavy filesystem use | **Needs more information** | Measure the real cold-start SLO and I/O pattern; evaluate a different Kata configuration, gVisor or a specialized microVM platform before choosing. |

An extra ten seconds at startup contributes little to a worker that runs for hours or a service that handles millions of requests before replacement. Steady-state memory, I/O and tail latency dominate that class of workload instead. The same delay can still matter during large autoscaling events or recovery, so lifetime alone does not remove every operational effect. For per-invocation functions, the measured cold-start cost would be material.

## Bonus

### Prescribed privileged bind-mount test: actual outcome

The collector creates a fresh directory in the Linux host's `/tmp`, sets `lab12-target` to `original` before **each** runtime, and executes identical commands with only the runtime changed:

```bash
sudo nerdctl run --rm --net=none --runtime=io.containerd.runc.v2 \
  --privileged -v /tmp/lab12-fsiubgzd:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN > /host_tmp/lab12-target'
# Repeat with --runtime=io.containerd.kata.v2
```

Only the newly created directory is shared, rather than all of the host's `/tmp`; it is removed after reading back the file. Observed results:

| Runtime | Exit | Host file before | Host file after | Privileged `/dev` count | Privileged CapEff |
|---|---:|---|---|---|---|
| runc | **0** | `original` | **`OVERWRITTEN`** | **193** | **`000001ffffffffff`** |
| Kata | **1** | `original` | **`original`** | **Not produced: container creation rejected** | **Not produced: container creation rejected** |

Kata's exact rejection, also seen when requesting privileged device/capability output:

```text
failed to create shim task: Creating container device LinuxDevice { path: "/dev/full", typ: C, major: 1, minor: 7, ... }
Caused by:
    EEXIST: File exists
```

That startup/device compatibility failure is **not proof that the VM boundary blocked the file write**: the workload never ran. I therefore do not invent a privileged Kata device count or capability mask. A separate successful `--cap-add=ALL` probe, without host-device pass-through, returned **15 devices / `000001ffffffffff` for runc** and **14 devices / `000001ffffffffff` for Kata**; this is explicitly a different configuration, not a substitute privileged measurement.

### Actual isolation contrast: host PID namespace and ptrace capability

[`probe-boundaries.py`](../labs/lab12/scripts/probe-boundaries.py) creates a new host-only directory/file, grants host-PID access and `CAP_SYS_PTRACE`, and disables the container AppArmor profile identically for both runtimes:

```bash
sudo nerdctl run --rm --net=none --runtime=io.containerd.runc.v2 \
  --cap-add=SYS_PTRACE --pid=host --security-opt=apparmor=unconfined \
  alpine:3.20 sh -c \
  'echo OVERWRITTEN > /proc/1/root/tmp/lab12-boundary-gwjp6g8g/target'
# Repeat the identical command with --runtime=io.containerd.kata.v2.
# No host bind mount is supplied in either run.
```

| Runtime | Exit | Output | Host marker after |
|---|---:|---|---|
| runc | **0** | No error | **`OVERWRITTEN`** |
| Kata | **1** | `nonexistent directory` | **`original`** |

The initial runc test with its default AppArmor profile was denied, so the final contrast explicitly includes `apparmor=unconfined`; without that change, it would not demonstrate an escape on this host. With that deliberately permissive configuration, runc's `/proc/1/root` reaches the Linux host's root filesystem. Kata's equivalent path refers to PID 1 in the guest's environment, where the host-only directory does not exist. No exploit binary or CVE was used, and every attempted write targeted only this run's disposable marker.

### Positive control and honest limit

The same script separately mounts its directory writable **without** `--privileged` and writes `/host_tmp/target`: **both runc and Kata returned 0 and changed the host marker to `OVERWRITTEN`**. Therefore Kata does not protect host data deliberately exported as writable storage. Under runc, privileged operations and host namespaces concern the Linux host kernel; under Kata, capabilities concern the guest kernel and its exposed devices, while explicit filesystem shares remain authorized communication paths. A strong guest boundary cannot undo an operator's writable-share decision; the [Kata architecture documentation](https://github.com/kata-containers/kata-containers/tree/main/docs/design/architecture) describes these environments and storage boundaries.

## Reproduction, validation and cleanup

The pinned [`lima-kata.yaml`](../labs/lab12/setup/lima-kata.yaml) records the VM image, image digest, nerdctl bundle and resource settings. The first VM was created with equivalent `limactl start --vm-type=vz --nested-virt --cpus=4 --memory=6 --disk=25 --containerd=system --mount-none template:default` settings; the checked-in YAML removes dependency on future default-template changes.

```bash
brew install lima
limactl start --name=lab12-kata --tty=false labs/lab12/setup/lima-kata.yaml
limactl shell lab12-kata mkdir -p /tmp/lab12-project/labs/lab12
limactl copy -r labs/lab12/scripts labs/lab12/setup \
  lab12-kata:/tmp/lab12-project/labs/lab12/
limactl shell lab12-kata sudo bash \
  /tmp/lab12-project/labs/lab12/setup/install-lima-kata.sh
limactl shell lab12-kata sudo python3 \
  /tmp/lab12-project/labs/lab12/scripts/collect.py --bonus
limactl shell lab12-kata sudo python3 \
  /tmp/lab12-project/labs/lab12/scripts/probe-boundaries.py
```

The collector completed successfully, saving both runtimes' results and the real rejected privileged commands. The boundary script printed:

```text
runc host-PID exit 0 host file: OVERWRITTEN
runc writable bind exit 0 host file: OVERWRITTEN
kata host-PID exit 1 host file: original
kata writable bind exit 0 host file: OVERWRITTEN
PASS: runc host-PID write, Kata host-PID isolation, explicit writable shares, all-capability probes
```

Both scripts remove their containers and disposable marker directories. After exporting the evidence, the disposable VM was stopped and deleted with `limactl stop lab12-kata` and `limactl delete --tty=false lab12-kata`, also removing the earlier failed diagnostic containers. This removed its Kata installation and containerd edits together; no changes to Docker Desktop's runtime or macOS containerd configuration need undoing. Lima remains installed for reproduction.
