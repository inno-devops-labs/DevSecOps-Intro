# Lab 12 Submission

## Task 1

- Shim:

```bash
labs/lab12/setup/kata-out/containerd-shim-kata-v2 --version
# output
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 5a5c43429e6253126b84a7304486658fd310ced8
```

- Test show

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
# output
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
Linux 5c6a16c028e1 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```
## Task 2

### 2.1: Start runc container (Juice Shop)

```bash
sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
sleep 10
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
# output
juice-runc: HTTP 200
```

### 2.2: Kata container tests

```bash
=== Kata Container Tests ===
Linux kata-container 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
6.12.47
model name	: QEMU Virtual CPU version 2.5+
```

### 2.3: Kernel comparison

```bash
=== Kernel Version Comparison ===
Host kernel (runc uses this): 6.8.0-51-generic

Kata guest kernel: Linux version 6.12.47 (builder@buildkitsandbox) (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42) #1 SMP Fri Nov 14 15:34:06 UTC 2025
```

### 2.4: CPU comparison

```bash
=== CPU Model Comparison ===
Host CPU:
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
Kata VM CPU:
model name	: QEMU Virtual CPU version 2.5+
```

### Isolation implications:

**runc**: Shares the host kernel directly. Containers use the same kernel as the host system (6.8.0-51-generic), providing namespace and cgroup isolation but no kernel-level isolation. Container processes are visible to the host, and kernel vulnerabilities can potentially affect all containers.

**Kata**: Runs each container in a separate lightweight VM with its own guest kernel (6.12.47). Provides strong isolation boundary through hardware virtualization. The QEMU Virtual CPU shows that containers run in a completely virtualized environment, making container escapes significantly harder as they would need to escape both the VM and then the host.

## Task 3

### 3.1: dmesg access test

```bash
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.12.47 (builder@buildkitsandbox) (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42) #1 SMP Fri Nov 14 15:34:06 UTC 2025
[    0.000000] Command line: tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.force_release=1 i8042.noaux=1 i8042.nomux=1 i8042.nopnp=1 i8042.noloop=1 8250.nr_uarts=32 init=/init
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
```

### 3.2: /proc filesystem visibility

```bash
=== /proc Entries Count ===
Host: 387
Kata VM: 298
```

### 3.3: Network interfaces

```bash
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 02:fc:10:00:00:02 brd ff:ff:ff:ff:ff:ff
    inet 10.88.0.2/24 brd 10.88.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::fc:10ff:fe00:2/64 scope link 
       valid_lft forever preferred_lft forever
```

### 3.4: Kernel modules

```bash
=== Kernel Modules Count ===
Host kernel modules: 156
Kata guest kernel modules: 84
```

### Isolation boundary differences:

**runc**: Uses Linux namespaces and cgroups for isolation. Containers share the host kernel (6.8.0-51-generic) and can see host processes in `/proc`. The isolation is process-level - containers are just restricted processes on the host system. Kernel pros and cons affect all containers since they share the same kernel space.

**kata**: Creates a complete isolation boundary using hardware virtualization. Each container runs in a separate lightweight VM with its own guest kernel (6.12.47), own `/proc` filesystem with fewer entries (298 vs 387), and virtualized network interfaces (eth0 with 10.88.0.x addressing). The VM boot logs in dmesg prove complete kernel separation.

### Security implications:

**Container escape in runc**: If a container escapes namespace isolation, it gains direct access to the host kernel and potentially all host resources. The attacker would have the same kernel privileges and could potentially access other containers or host processes.

**Container escape in Kata**: If a container escapes, it only reaches the guest VM kernel, not the host. The attacker would need to perform a second escape (VM escape) to reach the host system. This double isolation barrier (container → VM → host) significantly increases the attack complexity and reduces the impact of container vulnerabilities.

## Task 4

### 4.1: Container startup time comparison

```bash
=== Startup Time Comparison ===
runc:
real	0m0.892s
Kata:
real	0m4.234s
```

### 4.2: HTTP response latency (juice-runc baseline)

```bash
=== HTTP Latency Test (juice-runc) ===
avg=0.0245s min=0.0198s max=0.0456s n=50
```

### Performance tradeoffs analysis:

**Startup overhead**: Kata containers have significantly higher startup times (~4.2s vs ~0.9s for runc) due to VM initialization, guest kernel boot, and hypervisor setup. This 4-5x overhead makes Kata unsuitable for short-lived workloads or functions that require rapid scaling.

**Runtime overhead**: Once running, Kata containers have minimal performance impact for CPU-bound workloads. The virtualization layer adds some memory overhead (~128MB per VM for guest kernel and hypervisor) and slight CPU overhead for VM management, but application performance remains largely unchanged.

**CPU overhead**: Kata uses hardware virtualization extensions (Intel VT-x/AMD-V) efficiently. The QEMU Virtual CPU provides near-native performance for most workloads. However, there's additional overhead from context switching between host and guest, and memory management through the hypervisor.

### When to use each runtime:

**Use runc when**:
- Rapid container startup is critical (CI/CD, serverless functions, auto-scaling)
- Running trusted workloads in controlled environments
- Resource efficiency is paramount (many small containers)
- Legacy applications requiring specific kernel features or modules
- Development environments where isolation is less critical

**Use Kata when**:
- Running untrusted or potentially malicious code
- Multi-tenant environments requiring strong isolation
- Compliance requirements mandate hypervisor-level isolation
- Processing sensitive data requiring additional security boundaries
- Mixed workloads where container escape could affect other tenants
- Long-running services where startup time is amortized over runtime