# Lab 12 — Kata Containers vs runc

## Environment

- OS: Ubuntu 24.04 LTS
- Architecture: x86_64
- CPU: AMD Ryzen 5 7500F
- Host kernel: `6.17.0-35-generic`
- Hardware virtualization: AMD-V
- KVM device: `/dev/kvm`
- containerd: `containerd containerd.io v2.2.3 77c84241c7cbdd9b4eca2591793e3d4f4317c590`
- nerdctl: `nerdctl version 2.3.4`
- Kata Containers: `3.32.0`
- Kata runtime: `io.containerd.kata.v2`
- Hypervisor: QEMU

The host compatibility check reported:

```text
System is capable of running Kata Containers
System can currently create Kata Containers
```

## Task 1 — Installation and hello-world

Kata was registered in containerd 2.x with the following runtime:

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
  privileged_without_host_devices = true
  pod_annotations = ['io.katacontainers.*']
  container_annotations = ['io.katacontainers.*']

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata.options]
  ConfigPath = '/etc/kata-containers/configuration.toml'
```

### runc result

```text
Linux d2038e1bf4b9 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

### Kata result

```text
Linux aef083eec1e2 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

The host and runc container reported kernel `6.17.0-35-generic`. The Kata
container reported kernel `6.18.35`.

runc containers share the physical host kernel. Kata starts the workload
inside a lightweight virtual machine with its own guest kernel. This extra
boundary reduces the direct exposure of the physical host kernel to the
container workload.

For a container-runtime escape such as CVE-2024-21626, runc may expose the
physical host because the container and host share the same kernel and the
runtime operates directly with host namespaces and filesystems. Kata does not
make every attack impossible, but the separate guest kernel and VM boundary
reduce the direct impact of this class of escape on the physical host.

## Task 2 — Isolation comparison

### Devices

runc:

```text
core
fd
full
mqueue
null
ptmx
pts
random
shm
stderr
stdin
stdout
tty
urandom
zero
```

Kata:

```text
fd
full
mqueue
null
ptmx
pts
random
shm
stderr
stdin
stdout
tty
urandom
zero
```

Diff:

```diff
--- labs/lab12/results/runc-devs.txt	2026-07-13 19:22:37.386893607 +0300
+++ labs/lab12/results/kata-devs.txt	2026-07-13 19:22:39.886505692 +0300
@@ -1,4 +1,3 @@
-core
 fd
 full
 mqueue
```

The observed difference was that `/dev/core` existed in the runc container
but was absent from the Kata container.

### Linux capabilities

runc:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

Kata:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The capability masks were identical. This does not mean the isolation level
is identical. Under runc, capabilities apply to processes sharing the
physical host kernel. Under Kata, capabilities apply inside the guest VM and
its separate kernel.

## Startup benchmark

Methodology:

- Alpine 3.20 was downloaded before measurement.
- One unrecorded warm-up was performed for each runtime.
- Five complete container start, execution and removal operations were measured.
- The workload was `alpine:3.20 true`.

```text
=== runc ===
1: 2.235 s
2: 2.135 s
3: 2.102 s
4: 2.052 s
5: 2.036 s
Average: 2.112 s

=== kata ===
1: 2.738 s
2: 2.568 s
3: 2.535 s
4: 2.636 s
5: 2.469 s
Average: 2.589 s
```

| Runtime | Average startup |
|---|---:|
| runc | 2.112 s |
| Kata | 2.589 s |

Kata startup was approximately **1.23x** slower than runc in
this environment. The additional latency is caused by creating a lightweight
VM, starting the guest kernel and preparing communication between the host
and guest.

## I/O benchmark

The workload copied 100 MiB from `/dev/zero` to `/dev/null`.

```text
=== runc I/O ===
100+0 records in
100+0 records out
104857600 bytes (100.0MB) copied, 0.002176 seconds, 44.9GB/s

=== Kata I/O ===
100+0 records in
100+0 records out
104857600 bytes (100.0MB) copied, 0.001840 seconds, 53.1GB/s
```

This test mostly measures memory copying and system-call overhead rather than
persistent storage performance. It is also extremely short, so the difference
between the two results should be treated as measurement noise rather than
evidence that one runtime has faster disk storage.

## Security and performance trade-off

I would use Kata for multi-tenant SaaS workloads, shared CI runners and other
systems that execute untrusted customer code. The separate guest kernel
reduces direct exposure of the physical host kernel and provides a stronger
isolation boundary.

I would keep runc for trusted, single-tenant batch jobs where startup latency,
container density and lower memory usage are more important. In this case the
workload is controlled, so the additional VM cost may provide less practical
benefit.

The trade-off is therefore stronger isolation with Kata versus lower startup
and resource overhead with runc.

## Bonus — privileged host-write PoC

### Selected vector

Option B was selected: a privileged container with a writable host bind mount
attempts to modify a file on the physical host.

The target file was:

```text
/tmp/lab12-target
```

### runc

Command:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

Exit code:

```text
0
```

Host-side verification:

```text
OVERWRITTEN BY RUNC CONTAINER
```

The privileged runc container modified the physical host file.

### Kata

Command:

```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
time="2026-07-13T19:55:29+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-13T19:55:32+03:00" level=fatal msg="failed to create shim task: Creating container device LinuxDevice { path: \"/dev/full\", typ: C, major: 1, minor: 7, file_mode: Some(438), uid: Some(0), gid: Some(0) }\n\nCaused by:\n    EEXIST: File exists\n\nStack backtrace:\n   0: <unknown>\n   1: <unknown>\n   2: <unknown>\n   3: <unknown>\n   4: <unknown>\n   5: <unknown>\n   6: <unknown>\n   7: <unknown>\n   8: <unknown>\n   9: <unknown>\n  10: <unknown>\n\nStack backtrace:\n   0: <unknown>\n   1: <unknown>\n   2: <unknown>\n   3: <unknown>\n   4: <unknown>\n   5: <unknown>\n   6: <unknown>\n   7: <unknown>\n   8: <unknown>\n   9: <unknown>\n  10: <unknown>\n  11: <unknown>\n  12: <unknown>\n  13: <unknown>\n  14: <unknown>\n  15: <unknown>\n  16: <unknown>\n  17: <unknown>\n  18: <unknown>\n  19: <unknown>\n  20: <unknown>\n  21: <unknown>\n  22: <unknown>"
```

Exit code:

```text
1
```

Host-side verification:

```text
original
```

The Kata runtime rejected the equivalent privileged configuration before the payload completed. The physical host target remained unchanged. Kata exit code: 1.

### Threat-model implication

The runc example demonstrates the danger of combining an untrusted workload
with `--privileged` and a writable host bind mount. The container can modify
the physical host directly.

In the observed Kata test, the equivalent attempt did not modify the physical
host target. Kata adds a micro-VM and separate guest kernel, although it still
requires least-privilege configuration, strict host-mount policies and
protection against hypervisor vulnerabilities and side-channel attacks.

## Conclusion

runc had lower startup latency and shared the physical host kernel. Kata had
additional startup overhead but provided a separate guest kernel and a
VM-backed isolation boundary.

runc is appropriate for trusted workloads where performance and density are
the priority. Kata is more appropriate for untrusted and multi-tenant
workloads where stronger isolation justifies the additional resource cost.
