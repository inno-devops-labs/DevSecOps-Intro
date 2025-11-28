# Lab 12 — Kata Containers: VM-backed Container Sandboxing (Local)

## Task 1 — Task 1 — Install and Configure Kata

```
$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 8534afb9e8de3a529a537185f0fd55b66d9bc5d5
```

```
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
Linux 98a4d476509a 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```

## Task 2 — Run and Compare Containers (runc vs kata)

```
$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 | tee labs/lab12/runc/health.txt
juice-runc: HTTP 200
```

```
=== Kata Container Tests ===
Linux a884a25ab56e 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux 
6.12.47
model name	: Intel(R) Xeon(R) Processor
```
**Warnings:**
```
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
```

### Kernel Version Comparison
- Host kernel (runc uses this): 6.14.0-36-generic
- Kata guest kernel: Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025

### CPU Model Comparison
- Host CPU:
**Model name:** 13th Gen Intel(R) Core(TM) i7-13620H
- Kata VM CPU:
**Model name:** Intel(R) Xeon(R) Processor

### Isolation implications

runc: 
- Kernel Sharing: Uses the host kernel directly
- Process Visibility: Container processes visible in host's process list
- System Call Access: Direct system calls to host kernel
- Resource Isolation: Namespaces and cgroups only

Kata:
- Kernel Separation: Uses separate guest kernel
- Process Visibility: Container processes isolated within VM, not visible on host
- System Call Access: System calls trapped by hypervisor
- Resource Isolation: Full VM isolation with hardware virtualization

## Task 3 — Isolation Tests

### dmesg Access Test

```
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
time="2025-11-28T15:59:01+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
[    0.000000] Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
```

### /proc Entries Count
- Host: 533
- Kata VM: 52

#### Key Finding: Kata VM has fewer /proc entries (52 vs 533), demonstrating a dramatically reduced attack surface and minimal process namespace.

### Kata VM network

```
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 6e:b3:b0:6d:3b:aa brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.12/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::6cb3:b0ff:fe6d:3baa/64 scope link tentative 
       valid_lft forever preferred_lft forever
```

### Kernel Modules Count

- Host kernel modules: 343
- Kata guest kernel modules: 72

#### Key Finding: Kata VM uses fewer kernel modules (72 vs 343), significantly reducing the kernel attack surface and potential vulnerability exposure.

### Isolation Boundary Analysis

runc:
- Kernel Sharing: Direct host kernel access
- Process Visibility: All container processes visible via ps aux on host
- System Call Interface: Direct system calls to shared host kernel
- Resource Exposure: Full /proc and /sys visibility (533 entries)
- Module Surface: 343 kernel modules with potential vulnerabilities

Kata Isolation Characteristics:
- Kernel Separation: Dedicated minimal guest kernel
- Process Visibility: Complete isolation - no process visibility from host
- System Call Interface: Hypervisor-trapped system calls
- Resource Exposure: Minimal /proc visibility (52 entries)
- Module Surface: Hardened kernel with only 72 essential modules

### Security Implications
Container Escape in runc:
- Impact: Immediate host kernel compromise
- Attack Surface: 343 kernel modules, 533 /proc entries
- Detection Difficulty: High - attacker gains full host access

Container Escape in Kata:
- Impact: VM boundary breach only
- Attack Surface: 72 kernel modules, 52 /proc entries
- Detection Difficulty: Medium - contained within VM boundary

## Task 4 — Performance Comparison

### Startup time comparison

```
=== Startup Time Comparison ===
runc:

real	0m5.898s
user	0m0.003s
sys	0m0.017s
Kata:

real	0m3.618s
user	0m0.010s
sys	0m0.008s
```

I took it from terminal

### HTTP latency
```
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0026s min=0.0013s max=0.0098s n=50
```

### Performance tradeoffs
- Startup overhead: 

    Kata needs less time to start (It shouldn't be this way, but okey. So, we don't have tradeoff for our case :)
- Runtime overhead: 

    Kata typically more runtime overhead due to hypervisor layer, but perfomance ~ the same for most workloads with proper resource allocation
- CPU overhead:

    runc: ~1-2% overhead for container management

    Kata: ~5-10% overhead for hypervisor + guest OS


### When to Use Each:
runc:

- Performance-critical applications requiring minimal overhead
- Trusted workloads within secure environments
- Development and testing environments where fast iteration is key
- Resource-constrained systems where VM overhead is prohibitive
- Legacy applications with specific kernel version requirements

Kata:

- Multi-tenant environments with untrusted workloads
- Compliance requirements mandating hardware-level isolation
- Security-sensitive applications handling sensitive data
- Public cloud deployments with potential hostile neighbors
- Third-party/customer code execution with unknown security posture
- Regulated industries (finance, healthcare, government) requiring strong isolation

