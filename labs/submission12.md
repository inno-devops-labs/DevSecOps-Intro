### Task 1

```bash
$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 8534afb9e8de3a529a537185f0fd55b66d9bc5d5
```

```bash
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
[sudo] password for bulatgazizov: 
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2" 
Linux 329d9f7433ab 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```

### Task 2

Runc:
```
juice-runc: HTTP 000
```

Kernels version:

- Runc - 6.15.4
- Kata - 6.12.47

=== CPU Model Comparison ===
- Host CPU:
model name      : 12th Gen Intel(R) Core(TM) i5-12450H
- Kata VM CPU:
model name      : Intel(R) Xeon(R) Processor


| Feature | runc | Kata Containers |
| :--- | :--- | :--- |
| **Primary Isolation** | Linux kernel namespaces & cgroups | Hardware-assisted Virtualization (VM) |
| **Security Boundary** | The Linux Kernel (single, shared) | The Hypervisor (dedicated kernel per pod) |
| **Architecture** | Single kernel, multiple isolated processes | Multiple, lightweight Virtual Machines |
| **Performance** | **Native** (very low overhead) | **Near-Native** (low, but higher than runc) |
| **Attack Surface** | Larger (shared kernel syscall interface) | Smaller (hardware-enforced VM isolation) |


### Task 3

#### Kata dmesg output:
```
[    0.000000] Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
```

#### Comparison of /proc filesystem visibility

* Host: 528
* Kata VM: 53

#### Network interface configuration in Kata VM

```
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 7a:70:25:f0:55:84 brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.13/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::7870:25ff:fef0:5584/64 scope link tentative 
       valid_lft forever preferred_lft forever
```

#### Comparison of kernel module counts (host vs guest VM)
* Host kernel modules: 354
* Kata guest kernel modules: 72


#### Explain isolation boundary differences:

runc: All containers share the host kernel. A kernel panic or exploit affects everyone.

Kata: Each pod has its own kernel. A kernel crash/exploit inside Kata only affects that specific pod - the host and other pods remain unaffected.

---
runc: Uses PID namespaces to hide processes, but all containers see the same kernel's /proc structure and potentially can probe kernel state

Kata: The guest VM only sees processes and kernel information from its own isolated kernel instance. It cannot see host processes or other pods' processes at all.

---
runc: Uses network namespaces with veth pairs. Container shares host kernel networking stack.

Kata: Gets a virtual network device (virtio) in its own VM. The network stack is completely isolated at the kernel level - different TCP/IP stack, different routing tables, different connection tracking.

---
runc: Exposes the entire host kernel with 354 loaded modules to each container

Kata: The guest VM uses a minimized, hardened kernel with only essential modules (72). Even if compromised, the attacker only gets a reduced kernel, not the full host kernel.

#### Discuss security implications:
Container escape in runc = Breaking out of Linux namespaces/cgroups to access the host system

Container escape in Kata = Minimal guest kernel with 72 modules + hypervisor

### Task 4

#### Startup time comparison

* Runc - 0.6sec
* Kata - 6.6sec

#### HTTP latency for juice-runc baseline:

avg=0.0003s min=0.0001s max=0.0005s n=50

#### Analyze performance tradeoffs:

Startup Overhead: 10x slower
* runc: 0.6s (near-instant process creation)
* Kata: 6.6s (VM boot + guest kernel initialization)

Runtime overhead: 1-5% runtime overhead for most workloads

CPU overhead: Hypervisor translation layer adds minor instruction overhead

Interpret when to use each:
- Use runc when: High-density microservices OR Serverless functions running on controlled environments.

- Use Kata when: Untrusted code execution, kernel vulnerabilities would be catastrophic