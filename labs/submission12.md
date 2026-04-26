# Lab 12 — Kata Containers: VM-backed Container Sandboxing (Local)

## Task 1 — Install and Configure Kata

### 1.1 Kata shim version evidence
From `labs/lab12/setup/kata-built-version.txt`:

```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit:
```

### 1.2 Successful Kata runtime test
From `labs/lab12/kata/test1.txt`:

```text
Linux 7e82d99f7bb2 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

This confirms a successful container run with `--runtime io.containerd.kata.v2`.

## Task 2 — Run and Compare Containers (runc vs kata)

### 2.1 runc Juice Shop health check
From `labs/lab12/runc/health.txt`:

```text
juice-runc: HTTP 200
```

This confirms Juice Shop is reachable on port `3012`.

### 2.2 Kata test containers
Kata test outputs:

- `labs/lab12/kata/kernel.txt`: `6.18.15`
- `labs/lab12/kata/cpu.txt`: `model name : Intel(R) Xeon(R) Processor`

### 2.3 Kernel comparison (host/runc vs Kata guest)
From `labs/lab12/analysis/kernel-comparison.txt`:

- Host kernel (used by runc): `5.15.153.1-microsoft-standard-WSL2`
- Kata guest kernel: `Linux version 6.18.15 ...`

Conclusion:
- **runc** uses the host kernel directly.
- **Kata** uses a separate guest kernel inside a lightweight VM.

### 2.4 CPU model comparison
From `labs/lab12/analysis/cpu-comparison.txt`:

- Host CPU: `13th Gen Intel(R) Core(TM) i9-13900H`
- Kata VM CPU: `Intel(R) Xeon(R) Processor`

Conclusion: Kata exposes a virtualized CPU model to the workload, which is expected for VM-backed isolation.

### 2.5 Isolation implications
- **runc:** process isolation relies on Linux namespaces/cgroups on the same host kernel. Kernel attack surface is shared with the host.
- **Kata:** workload runs in a guest VM with its own kernel, adding hardware virtualization boundary on top of container isolation.

## Task 3 — Isolation Tests

### 3.1 dmesg differences
From `labs/lab12/isolation/dmesg.txt`, Kata shows guest boot logs such as:

```text
[    0.000000] Linux version 6.18.15 ...
[    0.000000] Command line: ... systemd.unit=kata-containers.target ...
```

This is strong evidence of a separate VM kernel.

### 3.2 /proc visibility comparison
From `labs/lab12/isolation/proc.txt`:

- Host `/proc` entries: `107`
- Kata VM `/proc` entries: `51`

Kata guest sees a smaller, VM-scoped process/system view.

### 3.3 Kata VM network configuration
From `labs/lab12/isolation/network.txt`:

- Interfaces observed: `lo`, `eth0`
- Guest IP example: `10.4.0.11/24`

This indicates an isolated virtual network stack inside the Kata VM.

### 3.4 Kernel modules comparison
From `labs/lab12/isolation/modules.txt`:

- Host kernel modules: `114`
- Kata guest kernel modules: `72`

Kata guest runs with a different/minimized kernel module set compared to the host.

### 3.5 Isolation boundary differences
- **runc boundary:** container boundary on shared kernel.
- **kata boundary:** VM boundary + separate kernel + container boundary inside guest.

### 3.6 Security implications
- **Container escape in runc:** likely becomes host-kernel level compromise path because kernel is shared.
- **Container escape in Kata:** attacker typically lands in guest VM first; host escape requires an additional VM/hypervisor breakout step, raising attack complexity.

## Task 4 — Performance Comparison

### 4.1 Startup time comparison
From `labs/lab12/bench/startup.txt`:

```text
=== Startup Time Comparison ===
runc: 0.431s total
kata: 1.232s total
```

Kata startup is slower by about `0.801s` (~`2.86x` versus runc) in this local test.

### 4.2 HTTP latency baseline (juice-runc)
From `labs/lab12/bench/http-latency.txt`:

```text
avg=0.0012s min=0.0007s max=0.0029s n=50
```

Baseline local HTTP latency for the runc-hosted Juice Shop is very low.

### 4.3 Performance trade-off analysis
- **Startup overhead:** observed and significant in this run (`0.431s` for runc vs `1.232s` for Kata, ~`2.86x` slower for Kata).
- **Runtime overhead:** often small for many web workloads; stronger isolation may add some I/O/network/virt overhead depending on workload profile.
- **CPU overhead:** typically modest but workload-dependent; virtualization layer can increase context-switching and system-call path costs.

### 4.4 When to use each runtime
- **Use runc when:** startup speed and maximum density/performance are the top priority, and trust boundary is lower-risk.
- **Use Kata when:** stronger tenant/workload isolation is required (multi-tenant, untrusted code, stricter compliance, defense-in-depth).
