## Task 1 — Install and Configure Kata

Kata Containers was installed and configured for containerd using the `io.containerd.kata.v2` runtime. The runtime shim was built from source, installed to `/usr/local/bin`, Kata static assets were installed, and containerd was configured to recognize the Kata runtime.

### Kata shim version

```text
$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.28.0, commit:
```

### Successful Kata test run

```text
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 --net=none alpine:3.19 uname -a
Linux 66484ebe42d1 6.12.47 #1 SMP Tue Mar 17 01:38:02 UTC 2026 x86_64 Linux
```

This confirms that the Kata runtime is installed correctly and that containerd can launch containers using `io.containerd.kata.v2`.

---

## Task 2 — Run and Compare Containers (runc vs kata)

### runc container health check

Juice Shop was started with the default `runc` runtime and exposed on port `3012`.

```text
$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
juice-runc: HTTP 200
```

This confirms that the `runc`-based Juice Shop container was reachable successfully.

### Kata container tests

```text
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 2c731b3195fe 6.12.47 #1 SMP Tue Mar 17 01:38:02 UTC 2026 x86_64 Linux

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
6.12.47

$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
model name      : AMD EPYC
```

### Kernel comparison

```text
=== Kernel Version Comparison ===
Host kernel (runc uses this): 6.6.87.2-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.12.47 (@8d7cdb68e89d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Tue Mar 17 01:38:02 UTC 2026
```

### CPU comparison

```text
Host CPU:
model name      : AMD EPYC

Kata VM CPU:
model name      : AMD EPYC
```

### Isolation implications

* **runc** uses the host kernel directly. Isolation is based on Linux namespaces, cgroups, seccomp, and capabilities.
* **Kata** runs the container inside a lightweight virtual machine with a separate guest kernel, which adds a stronger isolation boundary.

The key difference is that `runc` shares the host kernel, while Kata introduces a VM boundary between the workload and the host.

---

## Task 3 — Isolation Tests

### dmesg access test

```text
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.12.47 (@8d7cdb68e89d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Tue Mar 17 01:38:02 UTC 2026
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] [Firmware Bug]: TSC doesn't count with P0 frequency!
```

This is the strongest evidence that Kata containers use a **separate guest kernel**. Instead of host kernel logs, the container shows VM boot messages from the guest.

### /proc visibility comparison

```text
=== /proc Entries Count ===
Host: 134
Kata VM: 52
```

The Kata guest sees a smaller and different `/proc` view than the host environment.

### Network interfaces in Kata VM

```text
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host noprefixroute

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 26:53:78:d6:c1:e3 brd ff:ff:ff:ff:ff:ff
    inet 10.88.0.14/16 brd 10.88.255.255 scope global eth0
    inet6 fe80::2453:78ff:fed6:c1e3/64 scope link tentative
```

This shows that the Kata guest has its own virtualized network stack.

### Kernel modules comparison

```text
=== Kernel Modules Count ===
Host kernel modules: 213
Kata guest kernel modules: 72
```

The guest kernel exposes a much smaller kernel module surface than the host.

### Isolation boundary differences

* **runc**: the container is isolated, but it still shares the host kernel. A kernel escape could directly affect the host system.
* **kata**: the workload is isolated inside a lightweight VM with its own guest kernel. An attacker would have to escape the container first and then escape the VM to reach the host.

### Security implications

* **Container escape in runc** means direct exposure to the host kernel boundary, because the container and host share the same kernel.
* **Container escape in Kata** would usually land the attacker inside the guest VM, not directly on the host. This significantly increases attacker workload and improves defense-in-depth.

For untrusted or multi-tenant workloads, Kata provides a stronger security boundary than standard OCI containers.

---

## Task 4 — Performance Comparison

### Startup time comparison

```text
=== Startup Time Comparison ===
runc:
real    0m0.987s

Kata:
real    0m2.104s
```

The Kata container starts noticeably slower than the default `runc` container because it needs to initialize a lightweight VM.

### HTTP latency baseline (juice-runc)

```text
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0019s min=0.0016s max=0.0029s n=50
```

This shows a very low latency baseline for the `runc` deployment of Juice Shop.

### Performance trade-off analysis

* **Startup overhead**: Kata has higher startup latency because it launches a lightweight VM and guest kernel before starting the container workload.
* **Runtime overhead**: Kata generally adds some overhead due to the VM boundary, although for many applications the impact is acceptable.
* **CPU overhead**: Kata may incur additional CPU and memory overhead compared with `runc` because virtualization components must be maintained.

### When to use each runtime

* **Use runc when**:

  * fast startup is more important,
  * workload density matters,
  * the environment is trusted,
  * minimal overhead is required.

* **Use Kata when**:

  * stronger isolation is required,
  * workloads are untrusted,
  * multi-tenant security matters,
  * defense-in-depth is preferred over maximum density and speed.

---

## Warnings and Notes

During execution, `nerdctl` printed warnings such as:

* `default network named "bridge" does not have an internal nerdctl ID`
* `cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"`

These warnings did not prevent successful execution of either `runc` or Kata containers in this environment. The required runtime comparison, isolation tests, and performance measurements still completed successfully.

---

## Conclusion

This lab demonstrated the difference between standard OCI containers and VM-backed sandboxed containers.

Key findings:

* `runc` uses the host kernel directly.
* Kata uses a separate guest kernel (`6.12.47` in this setup).
* Kata clearly showed stronger isolation through:

  * guest kernel boot logs in `dmesg`,
  * different `/proc` visibility,
  * separate network stack,
  * smaller module surface.
* `runc` was faster to start (`0.987s`) than Kata (`2.104s`).
* `runc` remains better for low overhead and fast startup.
* Kata is a better choice when stronger isolation and multi-tenant security are more important than raw performance.

Overall, Kata Containers provide a meaningful security improvement by adding a VM boundary while keeping a container-oriented workflow.