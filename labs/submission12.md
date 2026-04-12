# Lab 12 — Kata Containers: VM-backed Container Sandboxing (Local)

## Environment

- Host environment: Windows with WSL2 Ubuntu
- Host kernel observed by the default runtime: `6.6.87.2-microsoft-standard-WSL2`
- Container runtime stack used for the lab: `containerd` + `nerdctl`
- Kata shim installed: `containerd-shim-kata-v2`
- Kata shim version:
  - `Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.28.0, commit: 660e3bb6535b141c84430acb25b159857278d596`

---

## Task 1 — Install and Configure Kata

### Setup evidence

I configured Kata for containerd using the provided lab scripts:

- `labs/lab12/scripts/install-kata-assets.sh`
- `labs/lab12/scripts/configure-containerd-kata.sh`

The Kata shim was available and installed into the host PATH:

```bash
/usr/local/bin/containerd-shim-kata-v2
```

Version output:

```bash
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.28.0, commit: 660e3bb6535b141c84430acb25b159857278d596
```

Containerd was updated to include the Kata runtime `io.containerd.kata.v2`, then restarted.

### Kata smoke test

A Kata-backed test container started successfully and returned a separate kernel identity:

```bash
Linux e44889bcc413 6.18.15 #1 SMP Tue Mar 17 01:39:00 UTC 2026 x86_64 Linux
```

This confirms that the runtime was installed and that `nerdctl` could launch a workload through `io.containerd.kata.v2`.

---

## Task 2 — Run and Compare Containers (runc vs kata)

### runc baseline

I used Juice Shop as the baseline workload with the default `runc` runtime.

Initial health-check output captured during the first probe was:

```bash
juice-runc: HTTP 000
```

This indicates the service was not ready at the exact time of that first check. However, the later latency benchmark executed 50 successful HTTP requests against `http://localhost:3012/`, which shows the baseline service became reachable and was serving responses during measurement.

### Kata test containers

Because long-running detached Kata workloads are known to be problematic with `nerdctl` + runtime-rs in this lab setup, I used short-lived Alpine containers for the Kata demonstrations.

Successful Kata outputs:

```bash
Linux 7499e2da5c94 6.18.15 #1 SMP Tue Mar 17 01:39:00 UTC 2026 x86_64 Linux
```

Guest kernel version:

```bash
6.18.15
```

CPU model inside Kata guest:

```bash
model name : Intel(R) Core(TM) i5-10200H CPU @ 2.40GHz
```

### Kernel comparison

```text
Host kernel (runc uses this): 6.6.87.2-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.18.15 (@cc3ea47c641d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Tue Mar 17 01:39:00 UTC 2026
```

This is the key isolation result:

- **runc** uses the host kernel directly.
- **Kata** runs the container inside a lightweight VM with its own guest kernel.

### CPU model comparison

```text
Host CPU:
model name : Intel(R) Core(TM) i5-10200H CPU @ 2.40GHz
Kata VM CPU:
model name : Intel(R) Core(TM) i5-10200H CPU @ 2.40GHz
```

In this environment the guest still reports the same CPU model string, so the most convincing isolation indicator is not the CPU name but the separate guest kernel.

### Isolation implications

- **runc:** process isolation is provided by Linux namespaces and cgroups, but the workload still shares the host kernel.
- **Kata:** the workload runs inside a VM-backed sandbox, so the boundary is stronger because the container no longer executes directly on the host kernel.

---

## Task 3 — Isolation Tests

### Network view inside Kata guest

The Kata guest showed its own loopback and a dedicated `eth0` interface:

```text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 10.4.0.10/24 ...
```

This supports the VM-backed model: the guest has its own network stack rather than directly exposing the host networking internals.

### Isolation summary

The strongest direct isolation evidence collected in this run was:

1. **Separate guest kernel** for Kata (`6.18.15`) versus host/WSL kernel (`6.6.87.2-microsoft-standard-WSL2`).
2. **Dedicated guest network interface layout** inside the Kata VM.
3. **Successful execution through `io.containerd.kata.v2`**, proving the workload ran through the Kata runtime rather than the default host-shared runtime.

### Security implications

- **Container escape in runc:** if a container escape vulnerability is exploited, the attacker reaches the host kernel boundary directly because the container shares that kernel.
- **Container escape in Kata:** the first boundary is the guest VM. An attacker would need to escape the container and then break the VM boundary to reach the host, which is a materially stronger isolation model.

So, compared with `runc`, Kata reduces the blast radius for untrusted or higher-risk workloads.

---

## Task 4 — Performance Comparison

### Startup time comparison

```text
runc:
real    0m0.621s

Kata:
real    0m2.041s
```

Kata startup time in this run was roughly **3.3x slower** than `runc`.

### HTTP latency baseline (juice-runc)

```text
avg=0.0024s min=0.001620s max=0.019069s n=50
```

This shows the baseline `runc` deployment was responsive once ready.

### Performance trade-offs

- **Startup overhead:** noticeably higher with Kata because a lightweight VM has to be created and bootstrapped.
- **Runtime overhead:** usually moderate for simple workloads, but higher than `runc` due to virtualization layers.
- **CPU overhead:** greater than `runc` in principle, especially for short-lived workloads or high churn, though this quick lab focused more on startup cost than deep throughput benchmarking.

### Recommendations

- **Use `runc` when:**
  - fast startup is important,
  - density and minimal overhead matter,
  - workloads are trusted and the standard container isolation model is sufficient.

- **Use Kata when:**
  - stronger isolation is required,
  - workloads are untrusted or multi-tenant,
  - reducing host-kernel exposure is more important than startup speed.

In short, `runc` is better for efficiency, while Kata is better for defense-in-depth.

---

## Final Conclusion

This lab demonstrated the core design difference between the two runtimes:

- `runc` provides standard container isolation while sharing the host kernel.
- Kata provides VM-backed isolation with a separate guest kernel.

The measured results matched the expected trade-off:

- **Better isolation with Kata**
- **Higher startup overhead with Kata**

For sensitive or untrusted workloads, Kata is a strong option. For general-purpose trusted workloads where efficiency matters most, `runc` remains the more practical default.
