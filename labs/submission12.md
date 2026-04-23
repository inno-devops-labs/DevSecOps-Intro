# Lab 12 — Kata Containers vs runc

## Goal
The goal of this lab was to run OWASP Juice Shop with the default `runc` runtime and compare it with Kata Containers, which provide VM-backed container isolation. The lab focused on setup, isolation characteristics, and basic performance trade-offs.

## Task 1 — Kata Runtime Setup

Kata runtime was successfully built and installed.

### Shim version
```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: 87a33181515396804455b2fc337cfa90b31a81c0
```

### Successful Kata test run
```text
Linux 280852ca65ea 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

### Notes
- Nested virtualization was enabled on a Google Compute Engine VM.
- `containerd` and `nerdctl` were installed and configured.
- Kata assets were installed successfully.
- `io.containerd.kata.v2` was configured as an additional runtime for containerd.

---

## Task 2 — Run and Compare Containers

### runc (default runtime)
Juice Shop was launched with the default runtime and became reachable on port `3012`.

**Health check**
```text
juice-runc: HTTP 200
```

This confirms that the workload runs successfully with the standard runtime.

### Kata runtime
Kata containers were executed successfully using:
```text
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

**Observed output**
```text
Linux 0937004c07e3 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

### Kernel comparison
- **Host kernel (used by runc):** `6.8.0-1053-gcp`
- **Kata guest kernel:** `6.18.15`

This is the key isolation difference:
- **runc** uses the same kernel as the host
- **Kata** runs the container inside a lightweight VM with a separate guest kernel

### CPU comparison
- **Host CPU:** `Intel(R) Xeon(R) CPU @ 2.80GHz`
- **Kata VM CPU:** `Intel(R) Xeon(R) Processor @ 2.80GHz`

The CPU family appears similar, but Kata exposes a virtualized guest environment rather than direct host execution.

### Isolation implications
- **runc:** containers share the host kernel, so a kernel-level escape can directly affect the host
- **Kata:** the container runs inside its own VM boundary, so escaping the container would still leave the attacker inside the guest VM rather than directly on the host

---

## Task 3 — Isolation Tests

### dmesg access
Inside the Kata container, `dmesg` returned VM boot logs:

```text
[    0.000000] Linux version 6.18.15 ...
[    0.000000] BIOS-provided physical RAM map:
```

This strongly confirms that Kata is using a separate guest kernel.

### /proc visibility
- **Host:** `179`
- **Kata VM:** `51`

The Kata guest exposes a much smaller `/proc` view than the host, which indicates reduced visibility into the underlying system.

### Network interfaces
The Kata container showed only isolated guest interfaces:
- `lo`
- `eth0`

with guest addressing on `10.4.0.x`.

This indicates that networking is handled inside the Kata VM boundary.

### Kernel modules
- **Host kernel modules:** `186`
- **Kata guest kernel modules:** `72`

The guest kernel exposes fewer modules, which reduces attack surface and reflects a smaller, more controlled execution environment.

### Isolation boundary differences
- **runc:** process isolation is based on Linux namespaces/cgroups but still depends on the shared host kernel
- **Kata:** process isolation is backed by a lightweight VM, creating a stronger boundary between workload and host

### Security implications
- **Container escape in runc:** may directly expose the host kernel and potentially compromise the host system
- **Container escape in Kata:** would first land inside the guest VM, which adds another barrier before the host could be reached

---

## Task 4 — Performance Snapshot

### Startup time comparison
- **runc:** `0.598s`
- **Kata:** `3.193s`

This shows that Kata has a noticeably higher startup cost because it must initialize a lightweight virtual machine.

### HTTP latency baseline (juice-runc)
```text
avg=0.0032s min=0.0019s max=0.0157s n=50
```

### Performance trade-offs
- **Startup overhead:** significantly higher with Kata because VM-backed execution requires more initialization
- **Runtime overhead:** generally moderate for simple workloads, but Kata still carries additional virtualization cost
- **CPU overhead:** higher than runc in principle due to virtualization, though not extreme for this lab’s simple tests

### When to use each runtime
- **Use runc when:** maximum speed, low overhead, and standard container behavior are the priority
- **Use Kata when:** stronger workload isolation is required, especially for untrusted, multi-tenant, or higher-risk workloads

---

## Artifacts
The following evidence was captured under `labs/lab12/`:

- `labs/lab12/setup/kata-built-version.txt`
- `labs/lab12/setup/kata-test-run.txt`
- `labs/lab12/runc/health.txt`
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`
- `labs/lab12/kata/cpu.txt`
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/analysis/cpu-comparison.txt`
- `labs/lab12/isolation/dmesg.txt`
- `labs/lab12/isolation/proc.txt`
- `labs/lab12/isolation/network.txt`
- `labs/lab12/isolation/modules.txt`
- `labs/lab12/bench/startup.txt`
- `labs/lab12/bench/http-latency.txt`

---

## Conclusion
This lab demonstrated that Kata Containers provide meaningfully stronger isolation than `runc` by placing the workload inside a lightweight VM with its own guest kernel. The main security benefit is that the workload no longer shares the host kernel directly. The main trade-off is increased startup latency and additional operational complexity.

For general-purpose trusted workloads, `runc` remains simpler and faster. For stronger isolation requirements, Kata is a better fit despite the added overhead.
