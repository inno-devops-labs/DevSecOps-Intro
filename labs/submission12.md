1# Lab 12 — Kata Containers: VM-backed Container Sandboxing (Local)

## Environment

- Host OS: Ubuntu 24.04 under WSL2 on Windows  
- Host kernel: `6.6.87.2-microsoft-standard-WSL2`
- containerd: `1.7.28`
- nerdctl: `2.2.0`
- Kata Containers: `3.23.0` (kata-static tarball)
- CPU: `13th Gen Intel(R) Core(TM) i7-13700H` with hardware virtualization enabled  
  (`egrep -c '(vmx|svm)' /proc/cpuinfo` → `40`)

All lab artifacts are stored under `labs/lab12/`:
- `setup/` — Kata shim version, uname of guest  
- `kata/` — guest kernel / CPU info, test runs  
- `runc/` — Juice Shop health check  
- `isolation/` — dmesg, /proc, network, kernel modules  
- `bench/` — startup time and HTTP latency  
- `analysis/` — host vs guest comparisons

---

## Task 1 — Install and Configure Kata (2 pts)

### 1.1 Installing Kata shim and assets

I used the prebuilt `kata-static` bundle for version `3.23.0`:

```bash
VERSION=3.23.0
ARCH=amd64
cd /tmp
curl -L -o kata-static.tar.zst \
  "https://github.com/kata-containers/kata-containers/releases/download/${VERSION}/kata-static-${VERSION}-${ARCH}.tar.zst"

sudo tar --zstd -C / -xvf kata-static.tar.zst
````

This populated `/opt/kata` with:

* `/opt/kata/bin/containerd-shim-kata-v2`
* `/opt/kata/runtime-rs/bin/containerd-shim-kata-v2`
* guest kernels and images under `/opt/kata/share/kata-containers/`
* default runtime-rs configs under `/opt/kata/share/defaults/kata-containers/runtime-rs/`

I then copied the shim into my PATH and saved its version:

```bash
sudo install -m 0755 /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/
command -v containerd-shim-kata-v2
containerd-shim-kata-v2 --version | tee labs/lab12/setup/kata-built-version.txt
```

`labs/lab12/setup/kata-built-version.txt` contains:

```text
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.23.0, commit: 650ada7bcc8e47e44b55848765b0eb3ae9240454
```

This confirms that the Kata shim is available as `io.containerd.kata.v2` on the host.

### 1.2 Configure containerd + nerdctl

I generated a default containerd config and enabled the Kata runtime:

```bash
sudo containerd config default | sudo tee /etc/containerd/config.toml >/dev/null

sudo bash -c 'printf "\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"io.containerd.kata.v2\"]\n  runtime_type = \"io.containerd.kata.v2\"\n" >> /etc/containerd/config.toml'

sudo systemctl restart containerd
```

Relevant snippet from `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."io.containerd.kata.v2"]
  runtime_type = "io.containerd.kata.v2"
```

After restarting containerd I verified a simple Kata container:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a \
  | tee labs/lab12/setup/kata-uname.txt
```

Output in `kata-uname.txt`:

```text
Linux 8ddb5674e603 6.12.47 #1 SMP Fri Nov 14 15:34:04 UTC 2025 x86_64 Linux
```

This shows that the Kata runtime starts containers using a separate guest kernel (`6.12.47`) rather than the host WSL2 kernel.

**Task 1 Requirements:**

* ✅ Shim version shown:

  ```text
  containerd-shim-kata-v2 --version
  → Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.23.0, ...
  ```

* ✅ Kata test container run using `--runtime io.containerd.kata.v2` and guest kernel captured in `kata-uname.txt`.

---

## Task 2 — Run and Compare Containers (runc vs kata) (3 pts)

### 2.1 runc: OWASP Juice Shop

I started Juice Shop using the default `runc` runtime via nerdctl:

```bash
sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
# wait for startup
sleep 20

curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 \
  | tee labs/lab12/runc/health.txt
```

`labs/lab12/runc/health.txt`:

```text
juice-runc: HTTP 200
```

So the runc-based Juice Shop instance is reachable on `localhost:3012` and returns HTTP 200.

### 2.2 Kernel and CPU comparison (host vs Kata)

Host kernel vs Kata guest kernel (saved in `labs/lab12/analysis/kernel-comparison.txt`):

```bash
echo "=== Kernel Version Comparison ===" | tee labs/lab12/analysis/kernel-comparison.txt

echo -n "Host kernel (runc uses this): " | tee -a labs/lab12/analysis/kernel-comparison.txt
uname -r | tee -a labs/lab12/analysis/kernel-comparison.txt

echo -n "Kata guest kernel: " | tee -a labs/lab12/analysis/kernel-comparison.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 cat /proc/version \
  | tee -a labs/lab12/analysis/kernel-comparison.txt
```

Result:

```text
=== Kernel Version Comparison ===
Host kernel (runc uses this): 6.6.87.2-microsoft-standard-WSL2
Kata guest kernel: Linux version 6.12.47 (@4b27322dd2ed) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:04 UTC 2025
```

CPU comparison (saved in `labs/lab12/analysis/cpu-comparison.txt`):

```bash
echo "=== CPU Model Comparison ===" | tee labs/lab12/analysis/cpu-comparison.txt

echo "Host CPU:" | tee -a labs/lab12/analysis/cpu-comparison.txt
grep "model name" /proc/cpuinfo | head -1 | tee -a labs/lab12/analysis/cpu-comparison.txt

echo "Kata VM CPU:" | tee -a labs/lab12/analysis/cpu-comparison.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 \
  sh -c "grep 'model name' /proc/cpuinfo | head -1" \
  | tee -a labs/lab12/analysis/cpu-comparison.txt
```

Output:

```text
=== CPU Model Comparison ===
Host CPU:
model name      : 13th Gen Intel(R) Core(TM) i7-13700H
Kata VM CPU:
model name      : 13th Gen Intel(R) Core(TM) i7-13700H
```

Kata presents essentially the same CPU model inside the VM, but the kernel and boot environment are clearly different (see dmesg below), meaning the isolation boundary is at a full virtual machine rather than just host processes/namespaces.

### 2.3 runc vs Kata: isolation implications

* **runc**

  * Shares the host kernel (`6.6.87.2-microsoft-standard-WSL2`).
  * Container processes are regular host processes with namespaces and cgroups.
  * A successful kernel-level container escape effectively becomes a host escape.

* **Kata (`io.containerd.kata.v2`)**

  * Runs a separate guest kernel (`6.12.47`) inside a lightweight VM managed by QEMU/KVM.
  * Container processes run inside that guest OS; from the host they appear as VM processes.
  * A container escape first lands inside the Kata guest, and only then would need an additional hypervisor/host escape, providing a much stronger isolation boundary.

**Task 2 Requirements:**

* ✅ Juice Shop under runc returns HTTP 200 on port 3012.
* ✅ Kata runtime runs containers with `--runtime io.containerd.kata.v2`.
* ✅ Kernel and CPU environment differences recorded and discussed.

---

## Task 3 — Isolation Tests (3 pts)

### 3.1 dmesg differences

For Kata I captured the first lines of `dmesg` inside the VM:

```bash
echo "=== dmesg Access Test ===" | tee labs/lab12/isolation/dmesg.txt

echo "Kata VM (separate kernel boot logs):" | tee -a labs/lab12/isolation/dmesg.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 dmesg 2>&1 | head -20 \
  | tee -a labs/lab12/isolation/dmesg.txt
```

Excerpt from `labs/lab12/isolation/dmesg.txt`:

```text
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.12.47 (@4b27322dd2ed) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:04 UTC 2025
[    0.000000] Command line: ... root=/dev/pmem0p1 ... systemd.unit=kata-containers.target ...
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
...
[    0.000000] DMI: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
[    0.000000] Hypervisor detected: KVM
```

This clearly shows a full VM boot sequence with QEMU/KVM, independent from the host’s WSL2 kernel and dmesg.

*(On the host, dmesg would show the WSL2 kernel and Microsoft-specific entries instead of QEMU/KVM.)*

### 3.2 /proc visibility

I compared the number of entries in `/proc`:

```bash
echo "=== /proc Entries Count ===" | tee labs/lab12/isolation/proc.txt
echo -n "Host: " | tee -a labs/lab12/isolation/proc.txt
ls /proc | wc -l | tee -a labs/lab12/isolation/proc.txt

echo -n "Kata VM: " | tee -a labs/lab12/isolation/proc.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 \
  sh -c "ls /proc | wc -l" \
  | tee -a labs/lab12/isolation/proc.txt
```

`labs/lab12/isolation/proc.txt`:

```text
=== /proc Entries Count ===
Host: 103
Kata VM: 54
```

Inside the Kata VM, `/proc` has fewer entries and only reflects the processes and kernel state of the guest, not the host.

### 3.3 Network interfaces

I checked network interfaces inside the Kata guest:

```bash
echo "=== Network Interfaces (Kata VM) ===" | tee labs/lab12/isolation/network.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 ip addr \
  | tee -a labs/lab12/isolation/network.txt
```

`labs/lab12/isolation/network.txt`:

```text
=== Network Interfaces (Kata VM) ===
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 10.4.0.11/24 brd 10.4.0.255 scope global eth0
```

The VM sees a classic `lo` + `eth0` setup with its own private IP (`10.4.0.11/24`), rather than the host’s WSL2 network interfaces. This reinforces the idea that Kata containers live behind a virtual network boundary.

### 3.4 Kernel modules

Finally, I compared kernel module counts:

```bash
echo "=== Kernel Modules Count ===" | tee labs/lab12/isolation/modules.txt

echo -n "Host kernel modules: " | tee -a labs/lab12/isolation/modules.txt
ls /sys/module | wc -l | tee -a labs/lab12/isolation/modules.txt

echo -n "Kata guest kernel modules: " | tee -a labs/lab12/isolation/modules.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 \
  sh -c "ls /sys/module 2>/dev/null | wc -l" \
  | tee -a labs/lab12/isolation/modules.txt
```

`labs/lab12/isolation/modules.txt`:

```text
=== Kernel Modules Count ===
Host kernel modules: 217
Kata guest kernel modules: 71
```

The Kata guest kernel has its own set of modules which is significantly smaller and independent from the host’s.

### 3.5 Isolation and security implications

* **runc**

  * `/proc`, `dmesg`, network, and modules are all from the host kernel.
  * Container escape ⇒ direct compromise of the host kernel.
  * Strong isolation requires additional mechanisms (seccomp, AppArmor, SELinux, etc.), but the fundamental trust anchor is the host kernel.

* **Kata**

  * `/proc`, `dmesg`, network, and modules belong to the guest kernel inside a QEMU/KVM VM.
  * Container escape from a Kata pod first lands in the Kata guest OS.
  * Attacker needs **two** successful escapes to compromise the real host:

    1. Container → Kata guest
    2. Kata guest → Hypervisor/host
  * This extra boundary is valuable for multi-tenant workloads, untrusted code, or internet-facing services with a high risk of container escape vulnerabilities.

**Task 3 Requirements:**

* ✅ dmesg shows separate VM boot logs for Kata.
* ✅ `/proc` visibility is different (host vs guest).
* ✅ Kata VM network interfaces captured.
* ✅ Kernel module counts compared.
* ✅ Isolation and security implications discussed (runc vs Kata).

---

## Task 4 — Performance Comparison (2 pts)

### 4.1 Startup time: runc vs Kata

I measured the time to start a short-lived `alpine:3.19` container:

```bash
echo "=== Startup Time Comparison ===" | tee labs/lab12/bench/startup.txt

echo "runc:" | tee -a labs/lab12/bench/startup.txt
{ time sudo nerdctl run --rm alpine:3.19 echo "test"; } 2>&1 \
  | tee -a labs/lab12/bench/startup.txt

echo "Kata:" | tee -a labs/lab12/bench/startup.txt
{ time sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 echo "test"; } 2>&1 \
  | tee -a labs/lab12/bench/startup.txt
```

`labs/lab12/bench/startup.txt`:

```text
=== Startup Time Comparison ===
runc:
test

real    0m1.239s
user    0m0.007s
sys     0m0.009s

Kata:
test

real    0m3.127s
user    0m0.004s
sys     0m0.007s
```

Kata startup is ~2.5× slower than runc:

* runc: ~1.24 s
* Kata: ~3.13 s

The difference is mostly in “real” time (VM boot + guest init), while CPU time (`user`, `sys`) is similar.

### 4.2 HTTP latency (Juice Shop on runc)

For the HTTP latency snapshot, I measured 50 HTTP GETs to the runc-based Juice Shop:

```bash
echo "=== HTTP Latency Test (juice-runc) ===" | tee labs/lab12/bench/http-latency.txt

out="labs/lab12/bench/curl-3012.txt"
: > "$out"

for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{time_total}\n" http://localhost:3012/ >> "$out"
done

echo "Results for port 3012 (juice-runc):" | tee -a labs/lab12/bench/http-latency.txt

min=$(sort -n "$out" | head -1)
max=$(sort -n "$out" | tail -1)

awk -v min="$min" -v max="$max" '
  { s += $1; n += 1 }
  END {
    if (n > 0)
      printf "avg=%.4fs min=%.4fs max=%.4fs n=%d\n", s/n, min, max, n;
  }
' "$out" | tee -a labs/lab12/bench/http-latency.txt
```

`labs/lab12/bench/http-latency.txt`:

```text
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0034s min=0.0021s max=0.0060s n=50
```

So typical HTTP response time from Juice Shop on runc is around 3–4 ms on this setup, with minimum ≈2.1 ms and maximum ≈6 ms.

(HTTP latency under Kata was not measured explicitly here; the main focus for Kata was startup cost and isolation characteristics.)

### 4.3 Performance trade-offs and when to use what

* **Startup overhead**

  * runc containers come up faster (~1.2 s).
  * Kata containers pay extra cost for VM boot and guest initialization (~3.1 s, ~2.5× slower).

* **Runtime overhead (for this app)**

  * Juice Shop on runc shows very low latency (≈3 ms per request) locally.
  * For typical web workloads, application-level latency dominates; the additional overhead from Kata is usually acceptable unless ultra-low startup times are critical (e.g., very bursty serverless workloads).

* **CPU overhead**

  * `user`/`sys` times for the simple `echo "test"` benchmark are almost identical.
  * Modern virtualization (KVM) means steady-state CPU overhead is relatively low compared to the upfront cost of starting a VM.

**When to use runc:**

* Short-lived workloads that scale up/down frequently and need fast startup.
* Less sensitive, trusted code where kernel sharing is acceptable.
* Local development environments where simplicity is more important than strong isolation.

**When to use Kata:**

* Multi-tenant environments where an untrusted workload runs next to critical services.
* Internet-facing services with high risk of container escape.
* Compliance or security requirements that demand VM-like isolation (separate kernel, separate dmesg, dedicated network boundary).

**Task 4 Requirements:**

* ✅ Startup time comparison recorded and interpreted (runc vs Kata).
* ✅ HTTP latency snapshot for Juice Shop on runc measured and summarized.
* ✅ Performance trade-offs discussed with clear recommendations.

---

## Summary

In this lab I:

* Installed Kata Containers (kata-static 3.23.0) and exposed the `io.containerd.kata.v2` runtime to containerd/nerdctl.
* Verified the Kata shim and confirmed that Kata uses its own guest kernel (`6.12.47`) instead of the host WSL2 kernel.
* Ran OWASP Juice Shop with runc and checked that it responds with HTTP 200 on `localhost:3012`.
* Ran containers with Kata and captured differences in kernel version, `dmesg`, `/proc`, network, and kernel modules.
* Showed that Kata adds a VM boundary (QEMU/KVM) between containers and the host, improving isolation at the cost of slower startup (~2.5× compared to runc).
* Measured HTTP latency for Juice Shop with runc and discussed where runc vs Kata makes sense in practice.

