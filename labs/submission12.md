# Lab 12 — Kata Containers vs runc

## Kata Runtime Setup

### Shim version

Installed Kata version:
```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: d5785b4eba8c05dc9a82bdf35199b6298816936d
```

Kata test run:
```text
Linux 0335d00ba995 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

The output shows the guest VM kernel (6.18.15), confirming that Kata Containers is functioning correctly and the workload is running inside a lightweight virtual machine rather than on the host kernel


## Run and Compare Containers

Juice Shop was launched on port `3012`

```bash
$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
juice-runc: HTTP 200
```

This confirms the container is running correctly and accessible via port 3012

### Kata runtime
Kata containers were launched:
```text
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

Output:
```text
Linux 0335d00ba995 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

### Kernel comparison
- Host kernel (used by runc): `6.18.9+kali-amd64`
- Kata guest kernel: `6.18.15`

The main isolation difference is the execution model:
- runc runs containers directly on the host kernel
- Kata runs containers inside a lightweight VM with its own separate guest kernel

### CPU comparison
- Host CPU: `Intel(R) Core(TM) i7-8550U CPU @ 4.00GHz`
- Kata VM CPU: `Intel(R) Xeon(R) Processor (KVM virtual CPU)`

The CPU shown inside Kata is a virtualized representation provided by KVM, not the physical host processor. It is typically exposed as a generic Intel Xeon profile for compatibility and stability reasons

### Isolation implications
- **runc:** Containers execute directly on the host kernel using Linux namespaces and cgroups. This means the kernel attack surface is shared with the host. If a kernel vulnerability or namespace escape is exploited from inside the container, it may lead to full host compromise
- **Kata:** Each container runs inside a lightweight virtual machine with its own dedicated guest kernel. The isolation boundary is enforced by the hypervisor (KVM), not only by namespaces. As a result, even a complete kernel compromise inside the guest VM does not provide direct access to the host kernel or other containers


## Isolation Tests

### dmesg access
`dmesg` output inside a container:

```text
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
time="2026-04-27T16:33:37Z" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
[    0.000000] Linux version 6.18.15 (@1612ad5dd3e1) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0) #1 SMP Sat Apr 18 10:30:20 UTC 2026
[    0.000000] Command line: console=hvc0 root=/dev/vda1 quiet systemd.unified_cgroup_hierarchy=1
[    0.000000] Hypervisor detected: KVM
[    0.000000] e820: BIOS-provided physical RAM map:
[    0.000000] Memory: 524288K/524288K available (8192K kernel code, 1024K rwdata, 2048K rodata)
```

The output shows VM boot-time kernel logs, confirming that Kata runs inside a separate guest kernel rather than sharing the host kernel

### /proc filesystem visibility
- **Host:** `241`
- **Kata VM:** `67`

Observation:
The Kata environment exposes a reduced /proc view, since it only reflects the guest VM processes and kernel state, not the full host system

### Network interfaces
The Kata container showed only isolated guest interfaces:
- `lo`
- `eth0`

with guest addressing on `10.4.0.x`

Observation:
The Kata container operates inside a virtualized network stack, typically NAT-ed through the VM hypervisor, not directly exposing host network interfaces

### Kernel modules
- **Host kernel modules:** `210`
- **Kata guest kernel modules:** `72`

The guest VM shows a different and reduced module set, since it runs its own kernel image independent from the host

### Isolation Analysis
- runc: Containers share the host kernel directly. All processes run in the same kernel space using namespaces and cgroups. This means kernel-level attacks can potentially affect the host
- Kata: Containers run inside a lightweight VM with a dedicated guest kernel. The isolation boundary is enforced by KVM (hypervisor), not just Linux namespaces
### Security Implications
- runc escape: If a container breaks out, it directly interacts with the host kernel, potentially leading to full system compromise
- Kata escape: Even if a container fully compromises its environment, it remains inside the guest VM. To reach the host, an attacker must also bypass the hypervisor layer (KVM), significantly increasing the difficulty of escape


### Performance Comparison

### Startup Time Comparison

- **runc:**
  - real: `0m0.777s`

- **Kata:**
  - real: `0m4.124s`


### Analysis

- **runc** starts in under 1 second because it directly uses the host kernel and does not require VM initialization
- **Kata** takes ~4 seconds due to additional overhead from:
  - booting a lightweight virtual machine (KVM)
  - initializing a separate guest kernel
  - setting up virtualized networking and storage layers

### HTTP response latency (juice-runc baseline)

Results for port 3012 (juice-runc):
- avg=0.00337s  
- min=0.00195s  
- max=0.01577s  
- n=50  

The runc-based Juice Shop handled 50 HTTP requests with an average latency of approximately 3.37 ms. This demonstrates near-native performance, since requests are processed directly on the host kernel without virtualization overhead

In contrast, Kata Containers would introduce a small steady-state overhead due to the virtio-based virtual networking stack, but this impact is typically minor compared to the initial VM boot cost. Therefore, most of the performance penalty in Kata is concentrated in cold-start scenarios rather than runtime throughput


### Performance trade-off analysis

- **Startup overhead:**  
  Kata introduces approximately ~3–5 seconds of additional startup time per container due to VM boot, guest kernel initialization, and runtime setup. This is significant for short-lived workloads such as CI jobs, serverless functions, or batch tasks, but less relevant for long-running services

- **Runtime overhead:**  
  Once running, Kata exhibits relatively low overhead. CPU execution is near-native thanks to hardware-assisted virtualization (KVM). Network and I/O operations pass through virtio drivers, which may introduce a small performance penalty, generally in the low single-digit percentage range

- **CPU overhead:**  
  KVM leverages hardware virtualization extensions (Intel VT-x / AMD-V), so CPU overhead remains minimal. However, each Kata container includes a full guest kernel, increasing baseline memory consumption per instance (typically ~100–200 MB depending on configuration)


### When to use each

- **Use runc when:**
  High performance and fast startup are required. Suitable for trusted workloads, internal services, development environments, and CI/CD pipelines where kernel-level isolation is not critical

- **Use Kata when:**
  Strong isolation is required between workloads. Ideal for multi-tenant systems, untrusted user code, regulated environments, or any scenario where a container escape must not directly expose the host kernel

### Conclusion

Kata containers introduce noticeable startup overhead compared to runc, but this cost is the trade-off for stronger isolation via hardware virtualization