# Lab 12 Submission

## Task 1 — Install and Configure Kata

```
containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.30.0, commit: 46b46589a699f6e1c31710e55bef304e70e6ab56
```

```
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
Linux 9d3ac4d8d1fe 6.18.22 #1 SMP Sat May  2 16:06:55 UTC 2026 x86_64 Linux
```

## Task 2 — Run and Compare Containers (runc vs kata)

```
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
juice-runc: HTTP 200
```

```
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 746ded522b47 6.18.22 #1 SMP Sat May  2 16:06:55 UTC 2026 x86_64 Linux
```

Kernel comparison:
- Host kernel (runc): `7.0.3-arch1-2`
- Kata guest kernel: `6.18.22`
- Conclusion: runc shares host kernel; Kata runs a separate guest kernel.

CPU model comparison:
- Host CPU: `Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz`
- Kata VM CPU: `Intel(R) Xeon(R) Processor @ 1.30GHz`
- Conclusion: Kata CPU appears virtualized from inside the sandbox.

Isolation implication:
- runc: process is isolated by namespaces/cgroups but still relies on the host kernel boundary.
- Kata: process is isolated by container boundary plus a lightweight VM boundary with its own kernel.

## Task 3 — Isolation Tests

`dmesg` difference (Kata):
```
[    0.000000] Linux version 6.18.22 ...
[    0.000000] Command line: ... systemd.unit=kata-containers.target ...
```
This is guest VM boot output, proving separate kernel execution.

`/proc` visibility:
- Host entries: `364`
- Kata VM entries: `52`

Kata VM network (`ip addr`):
- `lo` (127.0.0.1/8)
- `eth0` (10.4.0.15/24)

Kernel modules count:
- Host kernel modules: `326`
- Kata guest kernel modules: `75`

Isolation boundary difference:
- runc: boundary is Linux container isolation on the same kernel.
- kata: boundary includes a dedicated guest kernel and VM per workload.

Security implications:
- Container escape in runc: can directly impact host kernel and potentially compromise host-level resources.
- Container escape in Kata: attacker must additionally break out of the guest VM/hypervisor layer to reach the host.

## Task 4 — Performance Comparison

Startup time comparison:
- runc: `real 0m0.367s`
- Kata: `real 0m1.051s`

HTTP latency baseline (juice-runc):
- `avg=0.0019s min=0.0012s max=0.0070s n=50`

Performance trade-offs:
- Startup overhead: Kata is slower at cold start due to VM boot/init overhead.
- Runtime overhead: small for this simple workload; HTTP baseline under runc is low-latency.
- CPU overhead: Kata adds virtualization overhead, but buys stronger isolation.

When to use each:
- Use runc when: startup speed and maximum density are priorities in trusted or lower-risk workloads.
- Use Kata when: stronger tenant/workload isolation is required for untrusted code or stricter security boundaries.