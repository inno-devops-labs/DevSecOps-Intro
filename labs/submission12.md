## Task 1

> Show the shim `containerd-shim-kata-v2 --version`

```bash
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 5a5c43429e6253126b84a7304486658fd310ced8
```

> Show a successful test run with `sudo nerdctl run --runtime io.containerd.kata.v2 ...`

```bash
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 521910427040 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```

___
## Task 2

> Show juice-runc health check (HTTP 200 from port 3012)

The following result demonstrates successful network communication with the container.

```bash
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 | tee labs/lab12/runc/health.txt
juice-runc: HTTP 200
```

> Show Kata containers running successfully with `--runtime io.containerd.kata.v2`

> Compare kernel versions of `runc` and `Kata`

The following result demonstrates that `runc` uses the host kernel, which is WSL2 in this case, while `Kata` uses a virtual guest kernel.

```bash
=== Kernel Version Comparison ===
Host kernel (runc uses this): 5.15.153.1-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
```

> Compare CPU models (real vs virtualized)

The following result demonstrates the difference between the host CPU used by `runc` and the virtual CPU used by `Kata`.

```bash
=== CPU Model Comparison ===
Host CPU:
model name      : AMD Ryzen 7 5700U with Radeon Graphics
Kata VM CPU:
model name      : AMD EPYC
```

> Explain isolation implications

Isolation implications for `runc` and `Kata` mainly differ due to virtualization levels. The key differences include:

- **Kernel use**. `runc` shares the host kernel between its processes kernel-level isolation via namespaces, cgroups, and seccomp. This offers superficial protection, but still exposes sufficiently large attack surface for container escape. On the other hand, `Kata` uses a guest kernel by running each container in a dedicated lightweight VM, separating the container from the host kernel's vulnerabilities.
- **Hardware use**. `runc` utilizes the host hardware directly through the host's operating system, exposing the host to kernel exploits and cross-container attacks. `Kata`, on the other hand, virtualizes the hardware, requiring hypervisor exploits, which are much harder to perform, to escape the container.

Overall, the implications are that `Kata` containers are much more isolated and, therefore, more difficult to escape, than `runc` at the cost of performance and hardware virtualization as a requirement.

___
## Task 3

> Show `dmesg` output differences

```bash
[    0.000000] Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] [Firmware Bug]: TSC doesn't count with P0 frequency!
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
```

Since the logs show a guest kernel, which differs from host's WSL2, we can conclude that `Kata` indeed uses a separate kernel.

> Compare /proc filesystem visibility

```bash
=== /proc Entries Count ===
Host: 122
Kata VM: 52
```

This output demonstrates different process counts, which in turn confirms distinct isolation levels.

> Show network interface configuration in Kata VM

```bash
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 0a:63:a4:ef:a6:e3 brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.12/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::863:a4ff:feef:a6e3/64 scope link tentative
       valid_lft forever preferred_lft forever
```

> Compare kernel module counts (host vs guest VM)

```bash
=== Kernel Modules Count ===
Host kernel modules: 114
Kata guest kernel modules: 72
```

This output demonstrates different kernel module counts, confirming usage of distinct kernels.

> Explain isolation boundary differences:

The default isolation mechanism of `runc` are namespaces and cgroups. This boundary is relatively shallow since it is vulnerable to known CVEs. Alternatively, `Kata` has two boundary layers that an attacker would need to breach to compromise the host: the guest VM's namespaces and the VM hypervisor.

> Discuss security implications:

Overall, these differences make `runc` less secure, but a simpler and more performant option, while `Kata` is a more secure, environment-isolation focused, yet more demanding option. Thus, the choice of tool comes down to understanding business priorities in any given case.

___
## Task 4

> Show startup time comparison (runc: <1s, Kata: 3-5s)

```bash
=== Startup Time Comparison ===
runc:

real    0m1.465s
user    0m0.010s
sys     0m0.013s
Kata:

real    0m3.999s
user    0m0.011s
sys     0m0.007s
```

As expected from benchmarks, `Kata` startup is 3-10x slower than pure `runc`. Conversely to task statement, `runc` starts in over 1 second.

> Show HTTP latency for juice-runc baseline

```bash
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0046s min=0.0032s max=0.0165s n=50
```

These results also correspond to common benchmarks.

Additionally, I attempted to perform a similar measurement for `Kata`. However, there is a deep `Kata` issue debugging which is outside of the lab's scope:

```bash
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl run -d --runtime io.containerd.kata.v2 -p 3016:80 bkimminich
/juice-shop:v19.0.0
FATA[0002] failed to create shim task: Others("failed to handle message create container\n\nCaused by:\n    0: open stdout\n    1: No such file or directory (os error 2)\n\nStack backtrace:\n   0: <unknown>\n   1: <unknown>\n   2: <unknown>\n   3: <unknown>\n   4: <unknown>\n   5: <unknown>\n   6: <unknown>\n   7: <unknown>\n   8: <unknown>\n   9: <unknown>\n  10: <unknown>\n  11: <unknown>\n  12: <unknown>\n  13: <unknown>\n  14: <unknown>\n  15: <unknown>\n  16: <unknown>\n  17: <unknown>\n  18: <unknown>\n  19: <unknown>\n  20: <unknown>\n  21: <unknown>\n  22: <unknown>\n  23: <unknown>\n  24: <unknown>")
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 echo "kata-ok"
kata-ok
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl ps -a
CONTAINER ID    IMAGE                                      COMMAND                   CREATED               STATUS     PORTS                     NAMES
61fe7d0647d9    docker.io/bkimminich/juice-shop:v19.0.0    "/nodejs/bin/node /j…"    About a minute ago    Created    0.0.0.0:3016->80/tcp      juice-shop-61fe7
4e07070e5b7e    docker.io/bkimminich/juice-shop:v19.0.0    "/nodejs/bin/node /j…"    2 minutes ago         Created    0.0.0.0:3013->80/tcp      juice-shop-4e070
98d1f1fc6b01    docker.io/bkimminich/juice-shop:v19.0.0    "/nodejs/bin/node /j…"    3 hours ago           Up         0.0.0.0:3012->3000/tcp    juice-runc
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl rm -f juice-shop-61fe7 juice-shop-4e070
juice-shop-61fe7
juice-shop-4e070
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo systemctl restart containerd
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl run -d --runtime io.containerd.kata.v2 -p 3016:3000 bkimminich/juice-shop:v19.0.0
FATA[0000] failed to load networking flags: bind for :3016 failed: port is already allocated
control@Master-mind:~/DevSecOpsLab12/F25-DevSecOps-Intro$ sudo nerdctl run -d --runtime io.containerd.kata.v2 -p 3015:3000 bkimmini
ch/juice-shop:v19.0.0
FATA[0002] failed to create shim task: Others("failed to handle message create container\n\nCaused by:\n    0: open stdout\n    1: No such file or directory (os error 2)\n\nStack backtrace:\n   0: <unknown>\n   1: <unknown>\n   2: <unknown>\n   3: <unknown>\n   4: <unknown>\n   5: <unknown>\n   6: <unknown>\n   7: <unknown>\n   8: <unknown>\n   9: <unknown>\n  10: <unknown>\n  11: <unknown>\n  12: <unknown>\n  13: <unknown>\n  14: <unknown>\n  15: <unknown>\n  16: <unknown>\n  17: <unknown>\n  18: <unknown>\n  19: <unknown>\n  20: <unknown>\n  21: <unknown>\n  22: <unknown>\n  23: <unknown>\n  24: <unknown>")
```

> Analyze performance tradeoffs:

- **Startup overhead**: `Kata` is 2.7x slower than `runc`
- **Runtime overhead**: `Kata` has 2-5x higher latency / lower throughput than `runc`
- **CPU overhead**: `Kata` has 10-50% higher CPU overhead than `runc`

> Interpret when to use each tool:

- **Use runc when**: 
	- OR
		- AND
			- there is no untrusted code
			- there is no semi-executable user input
			- performance is a priority over security from a business perspective
		- deployment environment does not support hardware virtualization
- **Use Kata when**:
	- AND
		- OR
			- there is untrusted code
			- there is some semi-executable user input
			- security is a priority over performance from a business perspective
		- deployment environment supports hardware virtualization
