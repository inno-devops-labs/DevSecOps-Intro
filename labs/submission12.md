# Kata Containers Sandboxing

## Setup

Kata Containers was installed as the containerd runtime `io.containerd.kata.v2`. The host has hardware virtualization available (`24` virtualization flags in `/proc/cpuinfo`). `nerdctl` is available as version `2.2.2`, and the Kata shim as `3.28.0`.

Kata smoke test succeeded:

```text
Linux abaca499dd9a 6.18.15 #1 SMP Tue Mar 17 01:39:00 UTC 2026 x86_64 Linux
```

Evidence: `labs/lab12/setup/kata-built-version.txt`, `labs/lab12/setup/kata-smoke-test.txt`, `labs/lab12/setup/containerd-version.txt`, `labs/lab12/setup/nerdctl-version.txt`, `labs/lab12/setup/virtualization-check.txt`.

## Runtime Comparison

Juice Shop was started with the default `runc` runtime and was reachable on port `3012`:

```text
juice-runc: HTTP 200
```

Kata short-lived containers also ran successfully with `--runtime io.containerd.kata.v2`. 
The host kernel was `6.18.9-arch1-2`, while the Kata container used a separate guest kernel `6.18.15`. 
This is the main isolation difference: `runc` containers share the host kernel, while Kata containers run inside a lightweight VM with their own kernel.

CPU comparison showed the same exposed CPU model, `12th Gen Intel(R) Core(TM) i5-12450H`, inside the Kata VM. In this setup the CPU model is passed through, but execution still happens behind the VM boundary.

Evidence: `labs/lab12/runc/health.txt`, `labs/lab12/runc/nerdctl-ps.txt`, `labs/lab12/kata/test1.txt`, `labs/lab12/kata/kernel.txt`, `labs/lab12/kata/cpu.txt`, `labs/lab12/analysis/kernel-comparison.txt`, `labs/lab12/analysis/cpu-comparison.txt`.

## Isolation Tests

`dmesg` inside Kata returned VM boot logs starting from the Kata guest kernel, which confirms that the container does not read the host kernel ring buffer. `/proc` visibility was also smaller in Kata: host `/proc` had `492` entries, while the Kata VM had `55`.

The Kata VM had its own `lo` and `eth0` interfaces (`10.4.0.12/24`). Kernel module visibility also differed: host `348`, Kata guest `76`.

Isolation implications:

- `runc`: process, mount, network, and user namespaces isolate the container, but the host kernel is still shared.
- `Kata`: the container is placed inside a lightweight VM, so the first kernel boundary is the guest kernel rather than the host kernel.

Security implications: a successful escape from a normal `runc` container targets the shared host kernel directly. A successful escape from a Kata container should first land in the guest VM; an attacker would still need to cross the VM/hypervisor boundary to reach the host.

Evidence: `labs/lab12/isolation/dmesg.txt`, `labs/lab12/isolation/proc.txt`, `labs/lab12/isolation/network.txt`, `labs/lab12/isolation/modules.txt`.

## Performance Summary

Startup time comparison:

```text
runc: real 0m0.825s
Kata: real 0m1.213s
```

HTTP latency for the `juice-runc` baseline on port `3012` was:

```text
avg=0.0015s min=0.0009s max=0.0028s n=50
```

Kata had higher startup cost because it creates a lightweight VM for the container. Runtime overhead is expected to be workload-dependent: CPU-heavy workloads may be close to native with passthrough CPU, while I/O-heavy workloads can pay more overhead through VM, virtio, and networking layers.

Use `runc` when startup speed, density, and operational simplicity matter most and workloads are already trusted or well-isolated by other controls. Use Kata when stronger isolation is worth the overhead, especially for untrusted workloads, multi-tenant environments, CI sandboxes, or exposed application workloads with higher escape risk.

Evidence: `labs/lab12/bench/startup.txt`, `labs/lab12/bench/http-latency.txt`, `labs/lab12/bench/curl-3012.txt`.
