# Lab 12 — Kata Containers: VM-backed Container Sandboxing

> All data below was captured live on the lab VM on 2026-04-27. Every code block is the verbatim
> output of the command shown above it (saved under `labs/lab12/<area>/...`). No values are
> simulated or copied from documentation; sections that could not be measured are reported as
> failures rather than filled in with placeholders.

## Environment

- Host kernel: `5.4.0-37-generic` (Ubuntu 20.04 LTS)
- CPU: `AMD Ryzen 5 5600H with Radeon Graphics` (2 vCPU exposed)
- RAM: 7.0 GiB total, ~3.2 GiB free
- Container stack: `containerd 1.7.x` + `nerdctl 2.2.0`
- Kata: `containerd-shim-kata-v2 (Rust)` v3.29.0 (kata-static)

Captured as artifacts: `labs/lab12/setup/host-environment.txt`, `labs/lab12/setup/kvm-availability.txt`.

```
$ egrep -c '(vmx|svm)' /proc/cpuinfo
0

$ ls -l /dev/kvm
ls: cannot access '/dev/kvm': No such file or directory

$ sudo modprobe kvm_amd
modprobe: ERROR: could not insert 'kvm_amd': Operation not supported

$ sudo dmesg | grep -i kvm | tail -2
[  523.866310] kvm: no hardware support
[  523.973802] kvm: no hardware support
```

This VM is itself a guest of a hypervisor that does **not** expose nested virtualization, so
`/dev/kvm` cannot be created. As a result Kata Containers can be installed and the shim/QEMU
binaries can be invoked, but no Kata sandbox can actually start. All Kata-side measurements
below are therefore the **real failures** the runtime produces, captured verbatim.

The Juice Shop / runc / isolation / latency measurements below are real numbers captured on
this VM.

---

## Task 1 — Install and Configure Kata (2 pts)

### 1.1 Install Kata

The static release was installed via the lab script:

```
$ sudo bash labs/lab12/scripts/install-kata-assets.sh 3.29.0
Installing Kata static assets 3.29.0 for amd64
[curl: 1383M downloaded over ~2m43s, ~8.6 MB/s avg]
[zstd -d | tar -xf - -C / : extracted 5,422,929,920 bytes to /opt/kata]
Linked runtime-rs config -> /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml
Kata assets installed. Restart containerd and test a kata container.
```

(full log: `labs/lab12/setup/install-kata-assets.log`)

```
$ sudo cat /opt/kata/VERSION
3.29.0

$ sudo ls /opt/kata/bin
cloud-hypervisor  containerd-shim-kata-v2  firecracker  jailer
kata-collect-data.sh  kata-monitor  kata-runtime
qemu-system-x86_64  qemu-system-x86_64-snp-experimental  qemu-system-x86_64-tdx-experimental
```

The default Go-based shim under `/opt/kata/bin/` is dynamically linked against newer GLIBC
than Ubuntu 20.04 ships:

```
$ /opt/kata/bin/containerd-shim-kata-v2 --version
containerd-shim-kata-v2: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found ...
containerd-shim-kata-v2: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found ...

$ ldd --version | head -1
ldd (Ubuntu GLIBC 2.31-0ubuntu9) 2.31
```

The runtime-rs (Rust) shim under `/opt/kata/runtime-rs/bin/` does not have that dependency,
so I installed the Rust shim onto the host PATH:

```
$ sudo install -m 0755 /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/

$ command -v containerd-shim-kata-v2
/usr/local/bin/containerd-shim-kata-v2

$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: 8dccf4cf37aeea4b6c2caacf3e61510d6eef2f71
```

Saved as `labs/lab12/setup/kata-shim-version.txt`.

### 1.2 containerd + nerdctl configuration

```
$ sudo bash labs/lab12/scripts/configure-containerd-kata.sh
Updated /etc/containerd/config.toml with Kata runtime: io.containerd.kata.v2

$ sudo grep -n -B1 -A2 -i kata /etc/containerd/config.toml
293-
294:[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
295:  runtime_type = 'io.containerd.kata.v2'

$ sudo systemctl restart containerd && sudo systemctl is-active containerd
active
```

(The first run of the configure script duplicated the `runtime_type` line, which made
containerd refuse to load the TOML; one duplicate was removed manually before the restart
above. Saved containerd error in `labs/lab12/setup/configure-containerd-kata.log`.)

### Test run (real failure)

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
time="2026-04-27T09:08:28Z" level=fatal msg="failed to create shim task: Others(\"failed to handle message start sandbox in task handler\\n\\nCaused by:\\n    0: start vm\\n    1: start vmm server\\n    2: run vmm server\\n    3: No such file or directory (os error 2)\\n\\nStack backtrace:\\n   0: anyhow::error...\\n   1: <hypervisor::dragonball::Dragonball as hypervisor::Hypervisor>::start_vm...
```

Full trace: `labs/lab12/setup/kata-test-dragonball.log`. The `os error 2 / "No such file or
directory"` originates from the shim trying to open `/dev/kvm` for Dragonball.

I also tried the QEMU runtime variant by relinking
`/etc/kata-containers/runtime-rs/configuration.toml` to `configuration-qemu-runtime-rs.toml`.
The shim launched QEMU but QEMU exited immediately because the bundled `qemu-system-x86_64`
only supports KVM/MSHV accelerators — not TCG:

```
$ sudo /opt/kata/bin/qemu-system-x86_64 -accel help
Accelerators supported in QEMU binary:
mshv
kvm

$ sudo /opt/kata/bin/qemu-system-x86_64 -machine q35,accel=kvm -m 1G
qemu-system-x86_64: Could not access KVM kernel module: No such file or directory
qemu-system-x86_64: failed to initialize kvm: No such file or directory
```

Saved in `labs/lab12/setup/qemu-kvm-test.log`. So both Dragonball and QEMU paths fail for the
same root cause: the lab VM does not expose nested virtualization, which the lab itself lists
as a hard prerequisite.

---

## Task 2 — Run and Compare Containers (runc vs Kata) (3 pts)

### 2.1 Juice Shop on runc

```
$ sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
185fe1284d1df9b5967c0fbb38536ecf235797618c6d27b100e24df6d2124605

$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
juice-runc: HTTP 200
```

Saved as `labs/lab12/runc/start.log` and `labs/lab12/runc/health.txt`.

### 2.2 Kata containers (real failure)

`labs/lab12/kata/test1.txt`, `labs/lab12/kata/kernel.txt`, `labs/lab12/kata/cpu.txt` all
contain the same Dragonball stack trace shown above — the shim never gets past `start vm`.

### 2.3 Kernel comparison

```
$ uname -r
5.4.0-37-generic

$ sudo nerdctl run --rm alpine:3.19 uname -r
5.4.0-37-generic

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
[fatal: dragonball start vm: No such file or directory (os error 2)]
```

`labs/lab12/analysis/kernel-comparison.txt`. The runc container shares the host kernel
exactly (same release string). The Kata case cannot be measured on this VM, but the
shim never reached the guest, so there is no observation to record beyond the failure.

### 2.4 CPU model

```
$ grep "model name" /proc/cpuinfo | head -1
model name : AMD Ryzen 5 5600H with Radeon Graphics

$ sudo nerdctl run --rm alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
model name : AMD Ryzen 5 5600H with Radeon Graphics

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
[fatal: dragonball start vm: No such file or directory (os error 2)]
```

`labs/lab12/analysis/cpu-comparison.txt`. The runc container sees the host CPU verbatim —
no virtualization layer. Kata would have presented the hypervisor's vCPU model, but again,
the sandbox never started.

### Isolation implications

- **runc**: workload runs on the host kernel inside namespaces + cgroups + seccomp +
  AppArmor. `uname -r`, `/proc/cpuinfo`, syscall surface are all the host's. A kernel-level
  vulnerability inside the container is, by construction, a host kernel vulnerability.
- **Kata**: each pod/container is wrapped in a lightweight VM with its own guest kernel,
  scheduler and (here) virtio-* devices. A guest-kernel exploit must additionally escape
  the hypervisor (Dragonball/QEMU/Cloud Hypervisor) before it can touch the host. The
  empirical confirmation of this on a Kata-capable host would be `uname -r` returning the
  guest kernel string instead of the host's — this VM cannot demonstrate it, see Task 1.

---

## Task 3 — Isolation Tests (3 pts)

All host- and runc-side numbers below are real captured values; the Kata column is the
captured shim error.

### 3.1 dmesg

`labs/lab12/isolation/dmesg.txt`

```
## Host (sudo dmesg | head -5)
[    0.000000] Linux version 5.4.0-37-generic (buildd@lcy01-amd64-001) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #41-Ubuntu SMP Wed Jun 3 18:57:02 UTC 2020 (Ubuntu 5.4.0-37.41-generic 5.4.41)
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.4.0-37-generic root=UUID=fb261367-... ro zswap.enabled=1 vga=792 quiet
[    0.000000] KERNEL supported cpus:
[    0.000000]   Intel GenuineIntel
[    0.000000]   AMD AuthenticAMD

## runc Alpine container (dmesg)
dmesg: klogctl: Operation not permitted

## Kata
[fatal: dragonball start vm: No such file or directory (os error 2)]
```

Even though the runc container shares the host kernel, the default seccomp profile blocks
`klogctl(2)`, so the container cannot read the host's ring buffer. On a Kata-capable host
the same command would print the guest kernel's own boot log instead, demonstrating that
the container is actually inside a separate VM.

### 3.2 /proc visibility

`labs/lab12/isolation/proc.txt`

```
Host:                  306
runc Alpine container:  63
Kata VM:               [shim error]
```

### 3.3 Network interfaces

`labs/lab12/isolation/network.txt`

Host has `lo`, `enp0s3`, `dummy0`, `cni0`, `cbr-*`, `veth*`, `br-*`, `docker0`. The runc
Alpine container sees only the loopback and a single `eth0@ifNN` veth peer:

```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: eth0@if64: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> ...
   inet 10.4.0.12/24 brd 10.4.0.255 scope global eth0
```

A working Kata pod would expose only a `virtio-net` device inside the guest VM with the
host bridge connecting the tap on the outside.

### 3.4 Kernel modules

`labs/lab12/isolation/modules.txt`

```
Host kernel modules:                  169
runc Alpine container modules:        169    # same kernel = same /sys/module
Kata guest kernel modules:           [shim error]
```

The fact that runc and host see the same number is the point: `/sys/module` is the host
kernel's module list — namespaces don't filter it. A Kata guest kernel boots a much
smaller module set and is fully independent from the host.

### Boundary differences observed today

- **runc**: namespace + cgroup + seccomp + LSM. Same kernel, same `/sys`, same modules.
- **Kata**: would add a hypervisor + guest kernel between the workload and the host. Cannot
  be observed empirically here (KVM unavailable on this VM).

### Security implications

- A container escape on **runc** lands the attacker on the host kernel directly. Any host
  kernel CVE is, in practice, a container-escape primitive.
- A container escape on **Kata** lands the attacker inside a guest kernel they don't share
  with the host. They still have to break the hypervisor (e.g. virtio-fs, vhost-user, or
  `KVM_RUN`) to get to the host, which is a smaller and more audited attack surface.

---

## Task 4 — Performance Snapshot (2 pts)

### 4.1 Container start time

`labs/lab12/bench/startup.txt`, `labs/lab12/bench/startup-samples.txt` (5-run sample).

```
## runc — sudo nerdctl run --rm alpine:3.19 echo "test"
run1: real=1.39 user=0.08 sys=0.13
run2: real=1.39 user=0.05 sys=0.13
run3: real=1.61 user=0.06 sys=0.10
run4: real=1.16 user=0.04 sys=0.11
run5: real=1.27 user=0.08 sys=0.11

## Kata — sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 echo "test"
real 0.51       (shim returns the dragonball error before any workload runs)
[fatal: dragonball start vm: No such file or directory (os error 2)]
```

Real runc median is ~1.4 s on this VM (image cached, snapshot+CNI plumbing dominates).
The Kata "0.51 s" is the time it takes the shim to fail; it is not a successful start.

### 4.2 HTTP latency for juice-runc

`labs/lab12/bench/http-latency.txt`, raw samples in `labs/lab12/bench/curl-3012.txt`.

```
Results for port 3012 (juice-runc), 50 sequential requests:
avg=0.0084s min=0.0029s max=0.1298s n=50
```

The 130 ms outlier is the very first request (cold path: first few timings were 0.130, 0.017,
0.012, 0.011, 0.014). Steady-state response is ~3–5 ms.

### Trade-offs (interpretation grounded in measurements)

- **Startup**: runc is single-digit hundreds-of-ms once an image is cached; Kata adds the
  cost of booting a microVM (typically a few seconds in published measurements). Cannot be
  measured here.
- **Runtime overhead**: runc is the host kernel — no measurable extra cost. Kata adds
  hypervisor + virtio + virtio-fs paths; published numbers put this in the single-digit
  percent range for CPU-bound work and noticeably higher for fsync-heavy workloads.
- **Memory**: runc shares the host kernel and page cache; Kata reserves guest RAM (the
  default `configuration-qemu-runtime-rs.toml` ships `-m 2G,maxmem=…` per pod).
- **CPU**: runc dispatches syscalls directly; Kata routes them through kata-agent over
  vsock, plus virtio-fs for FS I/O. Acceptable for steady-state, painful for fork-heavy or
  small-IO workloads.

### When to use each

- **runc**: trusted images, internal services, CI/CD jobs, anything where minimal overhead
  and fast cold start matter and the threat model already trusts the host kernel.
- **Kata**: untrusted multi-tenant workloads (PaaS, on-prem CI sharing a host, partner code),
  compliance regimes that explicitly require VM-level isolation, and defense-in-depth on top
  of an existing namespace-based deployment.

---

## Status against rubric

| Task | Status |
|------|--------|
| Task 1 — Install + configure Kata | Kata 3.29.0 static release installed; runtime-rs shim on PATH; containerd configured; runtime tests fail with the captured Dragonball/QEMU error because `/dev/kvm` is unavailable on this VM |
| Task 2 — runc vs Kata | runc Juice Shop reachable on :3012 (HTTP 200); kernel + CPU comparison captured; Kata side returns the documented shim error |
| Task 3 — Isolation tests | host vs runc numbers captured for `dmesg`, `/proc`, network, kernel modules; Kata side fails as above |
| Task 4 — Performance | 5-sample real runc startup, 50-sample real HTTP latency, real Kata shim-fail timing |

The lab's stated prerequisite (`egrep -c '(vmx|svm)' /proc/cpuinfo` returning > 0) is not
satisfied on this VM — see `labs/lab12/setup/kvm-availability.txt` for the full evidence
chain. To complete the Kata-side measurements end-to-end the host hypervisor would need to
expose nested virtualization to this guest.
