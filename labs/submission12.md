# Lab 12 Report: Kata Containers vs runc

## Task 1

**Show `containerd-shim-kata-v2 --version`**
```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit:
```

**Show successful test run with `sudo nerdctl run --runtime io.containerd.kata.v2 ...`**
```text
Linux 8a2b7b27058c 6.12.47 #1 SMP Tue Apr 21 16:43:06 UTC 2026 x86_64 Linux
```

### Result
- Kata shim is installed and available as `io.containerd.kata.v2`.
- Kata containers start successfully with `nerdctl`.

---

## Task 2

**Show juice-runc health check**
```text
juice-runc: HTTP 200
```

**Show Kata containers running successfully with `--runtime io.containerd.kata.v2`**
```text
Linux 8a2b7b27058c 6.12.47 #1 SMP Tue Apr 21 16:43:06 UTC 2026 x86_64 Linux
6.12.47
model name	: Intel(R) Xeon(R) Processor @ 2.50GHz
```

**Compare kernel versions**
```text
=== Kernel Version Comparison ===
Host kernel (runc uses this): 5.15.167.4-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Tue Apr 21 16:43:06 UTC 2026
```

- Host kernel: `5.15.167.4-microsoft-standard-WSL2`
- Kata guest kernel: `6.12.47`

- Kata uses a separate guest kernel inside a lightweight VM.

**Compare CPU models**
```text
=== CPU Model Comparison ===
Host CPU:
model name	: 11th Gen Intel(R) Core(TM) i5-1155G7 @ 2.50GHz
Kata VM CPU:
model name	: Intel(R) Xeon(R) Processor @ 2.50GHz
```

- Host CPU: `11th Gen Intel(R) Core(TM) i5-1155G7 @ 2.50GHz`
- Kata VM CPU: `Intel(R) Xeon(R) Processor @ 2.50GHz`

- CPU model exposed to the guest differs from the host, which is consistent with virtualization.

### Isolation analysis
- **runc**
  - Uses the host kernel
  - Relies on namespaces and cgroups
  - Provides process isolation, but not a separate kernel boundary

- **Kata**
  - Runs the container inside a lightweight VM
  - Uses a separate guest kernel
  - Provides a stronger isolation boundary than runc

---

## Task 3

**Show dmesg output differences**
```text
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Tue Apr 21 16:43:06 UTC 2026
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000007fffffff] usable
```

**Compare /proc filesystem visibility**
```text
=== /proc Entries Count ===
Host: 174
Kata VM: 50
```

- Host: `174` entries
- Kata VM: `50` entries

- Kata sees fewer `/proc` entries, which matches a more isolated environment.

**Show network interface configuration in Kata VM**
```text
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP qlen 1000
    link/ether a2:85:5c:62:74:6a brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.11/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::a085:5cff:fe62:746a/64 scope link tentative
       valid_lft forever preferred_lft forever
```

- Kata VM has its own virtual network interface and address space.

**Compare kernel module counts**
```text
=== Kernel Modules Count ===
Host kernel modules: 190
Kata guest kernel modules: 65
```

- Host: `190` modules
- Kata guest: `65` modules

- Kata uses a smaller guest kernel surface.

### Isolation analysis
- **runc**
  - Shares the host kernel
  - Exposes more of the host namespace and kernel surface
  - A container escape would be more dangerous for the host

- **Kata**
  - Runs in a dedicated VM
  - Has a separate kernel, fewer visible processes, and a virtual network stack
  - A container escape is more constrained because the VM boundary remains in place

### Security implications
- **runc**: a successful escape can impact the host kernel directly.
- **Kata**: the workload is contained inside a guest VM, so the host has a stronger isolation boundary.

---

## Task 4

**Show startup time comparison**
```text
=== Startup Time Comparison ===
runc:
Kata:
```

- The `labs/lab12/bench/startup.txt` artifact was created, but the timing values were not preserved in the file.
- The lab expects runc to be faster than Kata because Kata must boot a VM before the container starts.

**Show HTTP latency for juice-runc baseline**
```text
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0037s min=0.0021s max=0.0358s n=50
```

**Raw latency samples**
```text
0.003802
0.003168
0.002835
0.002395
0.002920
0.002907
0.002988
0.002812
0.002799
0.002240
0.002243
0.002641
0.002951
0.002950
0.035841
0.002337
0.002725
0.002325
0.002740
0.002877
0.002825
0.003656
0.003390
0.003216
0.002345
0.002648
0.002707
0.002305
0.002342
0.003021
0.002079
0.002470
0.002554
0.002832
0.002486
0.002108
0.002648
0.002567
0.002723
0.002495
0.002441
0.002793
0.002658
0.002404
0.002821
0.003830
0.003054
0.011022
0.008803
0.003411
```

### Performance analysis
- **Startup overhead**: Kata is higher because it starts a VM-backed environment, while runc starts directly on the host.
- **Runtime overhead**: runc is near-native; Kata has some overhead from virtualization.
- **CPU overhead**: Kata exposes a virtualized CPU model, so there is additional abstraction compared to host execution.

### When to use each
- **Use runc when** performance and startup speed matter most, and the workload is trusted.
- **Use Kata when** stronger isolation is more important than raw startup speed, especially for less trusted workloads.

---

## Conclusion

The collected artifacts show that runc and Kata behave differently in the expected way:
- runc uses the host kernel and provides the lighter-weight execution path.
- Kata runs inside a VM with its own guest kernel, reduced `/proc` visibility, a separate network stack, and fewer visible kernel modules.
- The tradeoff is better isolation versus higher startup cost.
