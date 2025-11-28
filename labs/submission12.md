# Lab 12

## Task 1

### 1.1 Shim + Runtime:

```bash
    containerd-shim-kata-v2 --version
```

Output:

```
    Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 5a5c43429e6253126b84a7304486658fd310ced8
```

---

### 1.2 Test run:

```bash
    sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

Output:

```
    Linux c44c535429fb 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```

---

## Task 2

### 2.1 juice-runc health check (HTTP 200 from port 3012)

```bash
    curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 | tee labs/lab12/runc/health.txt
```

Output:

```
    juice-runc: HTTP 200
```

### 2.2 Kata containers running successfully:

```bash
  echo "=== Kata Container Tests ==="
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a | tee labs/lab12/kata/test1.txt
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r | tee labs/lab12/kata/kernel.txt
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1" | tee labs/lab12/kata/cpu.txt
```

Output:

``` 
    === Kata Container Tests ===
    Linux 47d5c637fae0 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
    6.12.47
    model name      : AMD EPYC
```

### 2.3 Kernel versions comparison

```
    === Kernel Version Comparison ===
    Host kernel (runc uses this): 6.14.0-35-generic
    Kata guest kernel:
    Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0,
    GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
```

Finding:
runc uses the host kernel; Kata uses a separate guest kernel (version 6.12.47).

### 2.4 CPU virtualization check

```
    === CPU Model Comparison ===
    Host CPU:
    model name      : AMD Ryzen 7 5700U with Radeon Graphics
    Kata VM CPU:
    WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
    model name      : AMD EPYC
```

Finding:
Kata runs on a virtualized CPU model (EPYC), not the direct host Ryzen CPU.

### 2.5 Isolation implications

- runc: shares host kernel and CPU; lighter isolation, very low overhead.
- Kata: runs in a VM with its own kernel and virtual CPU; stronger isolation, some extra overhead.

## Task 3

### 3.1 Kernel ring buffer (dmesg) access

```
  === dmesg Access Test ===
  Kata VM (separate kernel boot logs):
  time="2025-11-28T22:50:18+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
  [    0.000000] Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
  [    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
  [    0.000000] [Firmware Bug]: TSC doesn't count with P0 frequency!
  [    0.000000] BIOS-provided physical RAM map:
```

Interpretation:
dmesg shows VM boot logs for the guest kernel, not host logs -> evidence of a separate kernel.

### 3.2 /proc filesystem visibility

``` 
  === /proc Entries Count ===
  Host: 579
  Kata VM: 52
```

Interpretation:
The Kata VM exposes a much smaller /proc view, limited to the guest OS -> stronger process and kernel isolation.

### 3.3 Network interfaces

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
      link/ether 12:04:a3:f3:bd:1c brd ff:ff:ff:ff:ff:ff
      inet 10.4.0.16/24 brd 10.4.0.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::1004:a3ff:fef3:bd1c/64 scope link tentative 
         valid_lft forever preferred_lft forever
```

Interpretation:
Kata has its own virtual NIC (eth0) and loopback inside the VM. Traffic goes through VM networking, not directly via host namespaces.

### 3.4 Kernel modules

```
  === Kernel Modules Count ===
  Host kernel modules: 337
  Kata guest kernel modules: 72
```

Interpretation:
The guest kernel uses far fewer modules, which reduces attack surface compared to the host.

### Isolation & Security Summary

**runc:**

- Shares the same kernel and dmesg with the host.
- /proc is a namespaced view of the host.
- Network stack and modules are from the host kernel.
- Container escape via a kernel bug often means host compromise and access to other containers.

**Kata:**

- Has a separate guest kernel with its own dmesg, /proc, modules, and network interfaces.
- A compromise stays inside the VM first; escaping to the host requires an extra hypervisor escape.
- Blast radius is smaller: usually limited to one Kata VM and its workloads.

## Task 4

### 4.1 Startup time comparison

``` 
  === Startup Time Comparison ===
  runc:
  
  real    0m0.607s
  user    0m0.009s
  sys     0m0.014s
  Kata:
  
  real    0m1.714s
  user    0m0.006s
  sys     0m0.016s
```

Interpretation:
Kata startup is ~3× slower due to VM boot, while runc starts almost instantly as a normal process.

### 4.2 HTTP response latency (juice-runc only)

```
  HTTP response latency (juice-runc only)
```

Interpretation:
Juice Shop over runc responds quickly with HTTP 200. The runtime does not add noticeable latency for local HTTP traffic.

### 4.3 Performance / Security Trade-offs

**Startup overhead:**
- runc: very low (≈0.6s)
- Kata: higher (≈1.7s) due to VM startup

**Runtime / CPU overhead:**

- runc: near bare-metal performance, shared host kernel.
- Kata: extra CPU and runtime cost for guest kernel and hypervisor, but still acceptable for most long-lived services.

### Security Analysis
**runc**

- Shares host kernel and attack surface.
- Kernel exploit in a container can compromise the whole node.
- Best for trusted workloads, CI jobs, and places where performance and density matter most.

**Kata Containers**

- Each container runs in a lightweight VM with its own kernel.
- VM boundary protects the host from many container escapes.
- Reduced guest modules and separate /proc/network lower the attack surface.
- Best for multi-tenant and untrusted workloads, or when compliance requires VM-style isolation.

---
### Final Summary:

| Area         | runc                     | Kata Containers                    |
| ------------ | ------------------------ | ---------------------------------- |
| Kernel       | Host kernel shared       | Separate guest VM kernel (6.12.47) |
| CPU identity | AMD Ryzen 7 5700U        | Virtual AMD EPYC                   |
| Isolation    | Namespaces + cgroups     | Full VM boundary                   |
| Startup Time | ~0.6s                    | ~1.7s                              |
| Modules      | 337                      | 72                                 |
| Network      | Host namespaces / bridge | VM NIC (lo, eth0 @ 10.4.0.16)      |
| dmesg        | Host/blocked or shared   | VM boot logs                       |

Conclusion:
runc is fast and efficient but shares the host kernel. Kata adds a VM boundary with a separate kernel and virtual CPU, giving much stronger isolation at the cost of extra startup and resource overhead.