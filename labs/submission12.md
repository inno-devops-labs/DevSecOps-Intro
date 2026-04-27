# Lab 12 — Kata Containers: VM-backed Container Sandboxing

## Environment

This lab was executed inside an Ubuntu Server VM running on a Windows 10 Pro host with Hyper-V.

Setup:

- Windows 10 Pro host with Hyper-V
- Ubuntu-Kata VM
- Ubuntu 22.04 x86_64 guest
- Nested virtualization enabled in Hyper-V
- `/dev/kvm` available inside the Ubuntu VM
- containerd + nerdctl used as the runtime stack
- Kata Containers runtime-rs installed as `io.containerd.kata.v2`

Effective nesting model:

```text
Windows 10 Pro host -> Hyper-V Ubuntu VM -> Kata lightweight VM -> container workload
```

## Task 1 — Install and Configure Kata

### Kata shim version

Command:

```bash
containerd-shim-kata-v2 --version
```

Evidence:

```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: d5785b4eba8c05dc9a82bdf35199b6298816936d
```

### Kata runtime smoke test

Command:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

Evidence:

```text
Linux 2e0adebe9429 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

Kata was successfully registered and used through the containerd runtime `io.containerd.kata.v2`.

During Kata runs, nerdctl printed this warning:

```text
cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"
```

This warning did not prevent Kata containers from running successfully.

## Task 2 — Run and Compare Containers

### runc Juice Shop health check

Juice Shop was started with the default `runc` runtime.

The original lab port was `3012`, but after an initial CNI version mismatch, nerdctl kept a stale allocation for port `3012`. After repairing the CNI configuration, Juice Shop was exposed on port `3013`.

Command:

```bash
sudo nerdctl run -d --name juice-runc -p 3013:3000 bkimminich/juice-shop:v19.0.0
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://127.0.0.1:3013
```

Evidence:

```text
juice-runc: HTTP 200
```

### Kata container tests

Commands:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
```

Evidence:

```text
Linux 3814c470149b 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

```text
6.18.15
```

```text
model name      : Intel(R) Xeon(R) Processor @ 2.90GHz
```

### Kernel comparison

Evidence:

```text
=== Kernel Version Comparison ===
Host kernel (runc uses this): 5.15.0-176-generic
Kata guest kernel: Linux version 6.18.15 (@1612ad5dd3e1) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Sat Apr 18 10:30:20 UTC 2026
```

Analysis:

* `runc` containers share the host kernel.
* Kata containers use a separate guest kernel inside a lightweight VM.
* This is the main isolation difference: `runc` relies on Linux namespaces and cgroups on the host kernel, while Kata adds a VM-backed isolation boundary.

### CPU comparison

Evidence:

```text
=== CPU Model Comparison ===
Host CPU:
model name      : Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz
Kata VM CPU:
model name      : Intel(R) Xeon(R) Processor @ 2.90GHz
```

Analysis:

The host exposes the physical Intel Core i5-9400F CPU model, while the Kata VM exposes a virtualized CPU model. This supports the observation that the Kata workload is running inside a virtualized guest environment.

## Task 3 — Isolation Tests

### dmesg access

Evidence:

```text
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
time="2026-04-27T19:36:41Z" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
[    0.000000] Linux version 6.18.15 (@1612ad5dd3e1) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Sat Apr 18 10:30:20 UTC 2026
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
```

Analysis:

The `dmesg` output shows boot logs from the Kata guest kernel. This proves that the container workload is running behind a separate VM-backed kernel boundary.

### /proc visibility

Evidence:

```text
=== /proc Entries Count ===
Host: 200
Kata VM: 51
```

Analysis:

The Kata container sees the `/proc` view of the guest VM, not the full host environment.

### Network interfaces

Evidence:

```text
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 0a:b5:d2:79:1e:15 brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.15/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::8b5:d2ff:fe79:1e15/64 scope link tentative
       valid_lft forever preferred_lft forever
```

Analysis:

Kata provides container-like networking inside the guest VM. This preserves the container workflow while adding an extra VM boundary.

### Kernel modules

Evidence:

```text
=== Kernel Modules Count ===
Host kernel modules: 208
Kata guest kernel modules: 72
```

Analysis:

The host and Kata guest expose different kernel module views. With `runc`, kernel modules belong to the shared host kernel. With Kata, the workload sees the guest VM kernel module set.

### Isolation boundary comparison

#### runc

`runc` provides isolation through Linux namespaces, cgroups, capabilities, seccomp, AppArmor/LSM profiles, and filesystem restrictions. However, all containers still share the host kernel. A kernel-level container escape could directly affect the host kernel.

#### Kata

Kata adds a lightweight VM boundary around each container or pod. A successful workload compromise first reaches the guest VM. To compromise the host, an attacker would also need to cross the VM/hypervisor boundary.

### Security implications

* Container escape in `runc`: the attacker may directly target the shared host kernel.
* Container escape in Kata: the attacker first lands in the guest VM and then must escape the VM/hypervisor boundary.

Kata is therefore more suitable for untrusted or multi-tenant workloads.

## Task 4 — Performance Comparison

### Startup time

Evidence:

```text
=== Startup Time Comparison ===
runc:
real    0m4.340s
Kata:
real    0m4.849s
```

Analysis:

Kata startup was slower than `runc`, but the difference in this nested Hyper-V lab environment was relatively small. Both measurements include VM overhead, nerdctl/containerd overhead, image handling, and CNI setup. In general, Kata has higher startup cost because it creates and initializes a lightweight VM.

### HTTP latency baseline

Evidence:

```text
=== HTTP Latency Test (juice-runc) ===
Results for port 3013 (juice-runc):
avg=0.0019s min=0.0012s max=0.0146s n=50
```

Analysis:

This is the HTTP response latency baseline for Juice Shop under `runc`. Kata was not used for the long-running Juice Shop container because the lab notes a known issue with nerdctl + Kata runtime-rs and detached long-running containers. Kata was validated with short-lived Alpine containers instead.

## Performance and Operational Trade-offs

### Startup overhead

Kata has higher startup overhead because it launches a VM-backed sandbox. `runc` is usually faster because it only creates namespaces and cgroups on the existing host kernel.

### Runtime overhead

Runtime overhead depends on workload type. CPU-bound workloads can be close to native, while I/O-heavy and network-heavy workloads may experience additional overhead from virtualization and VM networking.

### CPU overhead

Kata introduces additional CPU and memory overhead for the VM boundary. This is acceptable for stronger isolation, but unnecessary for trusted high-density workloads.

## Recommendations

Use `runc` when:

* workloads are trusted or single-tenant;
* startup speed and density are important;
* operational simplicity is preferred;
* the workload is used for local development, CI, or standard internal services.

Use Kata when:

* workloads are untrusted or multi-tenant;
* stronger isolation is required;
* defense-in-depth matters more than startup speed;
* container escape impact would be high;
* the team accepts additional VM/runtime complexity.

## Conclusion

This lab demonstrated the difference between normal Linux container isolation and VM-backed container isolation. With `runc`, containers share the host kernel. With Kata Containers, the workload runs inside a lightweight VM with a separate guest kernel. The main security benefit is a stronger isolation boundary, while the main trade-off is higher startup overhead and additional operational complexity.
