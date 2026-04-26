## Install and Configure Kata

**Shim version:**
```
$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: 8dccf4cf37aeea4b6c2caacf3e61510d6eef2f71
```

**Successful test run:**
```
$ nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 1330b40ba404 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

---

## Run and Compare Containers (runc vs kata)

**juice-runc health check:**
```
$ curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
juice-runc: HTTP 200
```

**Kata containers running successfully:**
```
$ nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
Linux 0dfce5370965 6.18.15 #1 SMP Sat Apr 18 10:30:20 UTC 2026 x86_64 Linux
```

**Kernel version comparison:**
```
Host kernel (runc uses this): 5.15.167.4-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.18.15 (@1612ad5dd3e1) (gcc 11.4.0) #1 SMP Sat Apr 18 10:30:20 UTC 2026
```
- runc uses the host kernel (`5.15.167.4-microsoft-standard-WSL2`)
- Kata uses a separate guest kernel (`6.18.15`) booted inside a Dragonball microVM

**CPU model comparison:**
```
Host CPU:    model name : Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz
Kata VM CPU: model name : Intel(R) Xeon(R) Processor @ 2.90GHz
```

**Isolation implications:**
- **runc**: Containers share the host Linux kernel. All processes have access to the same kernel syscall surface. A kernel vulnerability or misconfigured privilege can lead to host compromise.
- **Kata**: Each container runs inside a lightweight Dragonball microVM with its own kernel (6.18.15). The container is isolated by a hardware VM boundary - the host kernel is never directly exposed.

## Isolation Tests

**dmesg output (Kata shows VM boot logs, proving separate kernel):**
```
[    0.000000] Linux version 6.18.15 (@1612ad5dd3e1) #1 SMP Sat Apr 18 10:30:20 UTC 2026
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target root=/dev/vda1 rootfstype=ext4
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000007fffffff] usable
```

**`/proc` filesystem visibility:**
```
Host /proc entries:   141
Kata VM /proc entries: 51
```

**Kata VM network interfaces:**
```
1: lo: inet 127.0.0.1/8
2: eth0: inet 10.4.0.13/24
```

**Kernel module counts:**
```
Host kernel modules:       114
Kata guest kernel modules:  72
```

**Isolation boundary differences:**
- **runc**: Isolation is provided only by Linux namespaces and cgroups on top of a shared kernel. `/proc` exposes host-level process tree; network uses the host kernel stack; all 114 host modules are reachable.
- **kata**: Isolation is provided by a hardware VM boundary. `/proc` shows only 51 VM-internal entries; network stack is fully isolated inside the VM; the guest kernel has a minimal module set (72 modules).

**Security implications:**
- Container escape in runc = attacker gains access to the host kernel directly, potentially compromising all containers on the node with a single exploit.
- Container escape in Kata = attacker lands inside the microVM and must additionally break out of the hypervisor layer to reach the host - a two-step escape with significantly higher complexity.

## Performance Comparison

**Startup time comparison:**
```
runc:   real 0m0.824s
Kata:   real 0m1.589s  (warm run, image cached; cold start ~3–5s)
```

**HTTP latency for juice-runc (50 requests):**
```
avg=0.0017s  min=0.0013s  max=0.0038s  n=50
```

**Performance tradeoffs:**
- **Startup overhead**: Kata adds ~0.8 s overhead on warm runs (VM init, kernel boot, Kata agent startup); cold-start overhead is ~3–5 s vs <1 s for runc.
- **Runtime overhead**: ~5–10% CPU overhead due to hypervisor (Dragonball) and virtio device emulation; negligible for I/O-light workloads.
- **CPU overhead**: Guest sees a virtualized CPU model (generic Xeon vs actual i7-10700F); some CPU features may be unavailable inside the VM.

**When to use each:**
- **Use runc when**: workloads are trusted/internal, startup latency and raw performance are critical, or memory is constrained (~5–20 MB overhead vs ~128 MB per Kata VM).
- **Use Kata when**: running untrusted or third-party code, multi-tenant environments require strong isolation, or compliance mandates hardware-level container separation (e.g., PCI DSS, HIPAA).
