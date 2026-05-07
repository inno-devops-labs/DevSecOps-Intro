# Lab 12 Submission - Kata Containers VM-backed Sandboxing

## Task 1 - Install and Configure Kata

Hardware virtualization is available on this host (`egrep -c '(vmx|svm)' /proc/cpuinfo` returned `32`). `containerd` is active and was configured with the Kata runtime:

```text
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

Kata runtime-rs shim was built from source after updating the provided build script to include missing build dependencies (`g++`, `cmake`, and `jq`) and to copy the binary from the workspace-level Cargo target directory.

Shim evidence:

```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.30.0, commit: 5f6512ac938af9134753dc07e9fd70ccfb69cc26
```

Kata static assets 3.30.0 were installed under `/opt/kata`, and `/etc/kata-containers/runtime-rs/configuration.toml` was linked to:

```text
/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml
```

The direct `nerdctl --runtime io.containerd.kata.v2` test reached VM creation but hit the known runtime-rs/nerdctl issue documented in the lab, leaving the test container in `Unknown` state. The successful Kata execution evidence was therefore captured with the documented workaround, direct `ctr`:

```text
Linux fc6eb5c2bf6a 6.18.15 #1 SMP Sat May  2 16:07:11 UTC 2026 x86_64 Linux
```

Artifacts:

- `labs/lab12/setup/kata-built-version.txt`
- `labs/lab12/setup/kata-test-run.txt`
- `labs/lab12/setup/kata-test-run-ctr.txt`
- `labs/lab12/setup/containerd-kata-config.txt`
- `labs/lab12/setup/kata-config-link.txt`
- `labs/lab12/setup/containerd-journal-tail.txt`

## Task 2 - Run and Compare Containers

The default runc workload was OWASP Juice Shop via `nerdctl`:

```text
juice-runc: HTTP 200
```

Kata short-lived Alpine tests were run with `ctr --runtime io.containerd.kata.v2`:

```text
Linux fc6eb5c2bf6a 6.18.15 #1 SMP Sat May  2 16:07:11 UTC 2026 x86_64 Linux
6.18.15
model name	: 12th Gen Intel(R) Core(TM) i5-1240P
```

Kernel comparison:

```text
Host kernel (runc uses this): 6.17.0-23-generic
Kata guest kernel: Linux version 6.18.15 ... #1 SMP Sat May  2 16:07:11 UTC 2026
```

CPU comparison:

```text
Host CPU:
model name	: 12th Gen Intel(R) Core(TM) i5-1240P
Kata VM CPU:
model name	: 12th Gen Intel(R) Core(TM) i5-1240P
```

Isolation implications:

- **runc**: shares the host kernel. Namespaces/cgroups/seccomp provide isolation, but kernel attack surface remains shared with the host.
- **Kata**: runs the container workload inside a lightweight VM with a separate guest kernel. In this QEMU config the CPU model is passed through as host CPU, but the kernel boundary is still separate.

Artifacts:

- `labs/lab12/runc/health.txt`
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`
- `labs/lab12/kata/cpu.txt`
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/analysis/cpu-comparison.txt`

## Task 3 - Isolation Tests

dmesg from Kata shows guest VM boot logs, proving a separate kernel:

```text
[    0.000000] Linux version 6.18.15 (@a3f44c86bab0) ...
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target ...
[    0.000000] BIOS-provided physical RAM map:
```

`/proc` visibility is much smaller inside the Kata VM:

```text
Host: 719
Kata VM: 54
```

Network interface capture from the direct `ctr` workaround:

```text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    inet 127.0.0.1/8 scope host lo
```

Note: the `nerdctl` path created a CNI-backed network (`eth0` with `10.4.0.2`) according to `containerd-journal-tail.txt`, but the container then hit the known `Unknown` status issue. The stable `ctr` workaround used for evidence does not attach the nerdctl CNI network.

Kernel module counts:

```text
Host kernel modules: 378
Kata guest kernel modules: 79
```

Security implications:

- **Container escape in runc**: a kernel-level escape can become a host compromise because the container and host share the same kernel.
- **Container escape in Kata**: an attacker first lands in the guest VM/kernel boundary; reaching the host generally requires a hypervisor, virtio, VM escape, or host integration flaw, which is a stronger isolation boundary.

Artifacts:

- `labs/lab12/isolation/dmesg.txt`
- `labs/lab12/isolation/proc.txt`
- `labs/lab12/isolation/network.txt`
- `labs/lab12/isolation/modules.txt`

## Task 4 - Performance Comparison

Startup timing:

```text
runc:
real 0.57

Kata:
real 5.95
```

HTTP latency for the runc Juice Shop baseline:

```text
avg=0.0019s min=0.0012s max=0.0040s n=50
```

Performance trade-offs:

- **Startup overhead**: Kata was about 10x slower for this short-lived test because it boots a lightweight VM and guest kernel.
- **Runtime overhead**: once running, Kata should be acceptable for many services, but syscall, filesystem sharing, networking, and VM memory overhead are higher than runc.
- **CPU overhead**: CPU model was passed through, so CPU-bound work should be closer to native than startup-heavy workloads, but VM exits and device virtualization still add overhead.

Recommendations:

- **Use runc when**: workloads are trusted, high-density, latency-sensitive, short-lived, or need the simplest operational model.
- **Use Kata when**: workloads are multi-tenant, less trusted, exposed to untrusted input, or require a stronger boundary than Linux namespaces alone.

Artifacts:

- `labs/lab12/bench/startup.txt`
- `labs/lab12/bench/http-latency.txt`
- `labs/lab12/bench/curl-3012.txt`

## Submission Checklist

- [x] Task 1 - Kata shim built, installed, configured, and verified.
- [x] Task 2 - runc Juice Shop and Kata Alpine runtime comparison captured.
- [x] Task 3 - Isolation tests captured and analyzed.
- [x] Task 4 - Startup and HTTP latency snapshot captured.
- [x] Large local build/download artifacts are ignored via `labs/lab12/setup/.gitignore`.
