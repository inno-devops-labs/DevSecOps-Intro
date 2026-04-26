# Lab 12 Submission — Kata Containers: VM-backed Container Sandboxing (Local)

**Environment:** Apple Silicon host (macOS 26.3, Apple M4) with a writable Lima VM running Ubuntu 25.10 (`aarch64`), `containerd 2.2.1`, `nerdctl 2.2.2`, `curl`, `jq`, and `zstd`  
**Date completed:** 2026-04-26  
**Execution model:** All runtime experiments were executed inside the local `lima` Linux guest because Kata Containers requires a Linux host with hardware virtualization.  

This report documents the work I completed locally for Lab 12 without making any git commits. All generated artifacts were saved under `labs/lab12/`.

## Task 1 — Install and Configure Kata

### What I did

- Used the provided installer to download and unpack the official `kata-static` release for `arm64`
- Installed the Kata shim onto the Linux guest PATH as `/usr/local/bin/containerd-shim-kata-v2`
- Updated `/etc/containerd/config.toml` with the `io.containerd.kata.v2` runtime using the provided configuration script
- Restarted `containerd` and attempted multiple smoke tests with `sudo nerdctl run --runtime io.containerd.kata.v2 ...`

Relevant artifacts:

- `labs/lab12/setup/install-kata-assets.log`
- `labs/lab12/setup/configure-containerd.log`
- `labs/lab12/setup/kata-shim-version.txt`
- `labs/lab12/setup/kata-smoke-failure.txt`
- `labs/lab12/setup/containerd-kata-journal-tail.txt`

### Shim version evidence

The installed shim reports:

```text
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.29.0, commit: 8dccf4cf37aeea4b6c2caacf3e61510d6eef2f71
```

### Configuration result

`containerd` accepted the runtime stanza and exposed a `kata` runtime entry under the CRI plugin after restart. The relevant log is in `labs/lab12/setup/configure-containerd.log`.

### Important environment finding

On this Apple Silicon + Lima + Ubuntu ARM guest stack, Kata did not successfully complete the first container boot. The runtime reached the Kata shim and launched QEMU, but the guest creation path timed out instead of producing a working VM-backed container.

The final smoke-test failure captured in `labs/lab12/setup/kata-smoke-failure.txt` was:

```text
time="2026-04-26T23:41:37+03:00" level=fatal msg="failed to create shim task: CreateContainerRequest timed out: context deadline exceeded"
```

## Task 2 — Run and Compare Containers (runc vs kata)

### runc baseline

I started OWASP Juice Shop with the default `runc` runtime inside the Linux guest:

```text
juice-runc: HTTP 200
```

Evidence:

- `labs/lab12/runc/health.txt`
- `labs/lab12/runc/container-id.txt`

### Kata runtime attempts

I attempted the same basic Kata smoke tests several times with:

- `sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a`
- `sudo nerdctl run --rm --net=none --runtime io.containerd.kata.v2 alpine:3.19 echo kata-test`

In each case, the call reached the shim but did not produce a healthy guest container. Instead, the request timed out while waiting for container creation inside the Kata VM lifecycle.

### Kernel and CPU comparison

The Linux host baseline for the `runc` workload was:

- Host kernel: `6.17.0-19-generic`
- Host CPU signal from `/proc/cpuinfo`: `CPU info unavailable`

Artifacts:

- `labs/lab12/analysis/host-kernel.txt`
- `labs/lab12/analysis/host-cpu.txt`
- `labs/lab12/runc/kernel.txt`
- `labs/lab12/runc/cpu.txt`

Because the Kata guest never reached a usable running state, I could not collect a true in-guest kernel or CPU identity for the Kata side of the comparison. The absence of a successful guest boot is itself the key finding for this environment.

### Isolation implications

- **runc:** The container runs on the Linux guest host kernel directly, so kernel isolation is namespace/cgroup-based rather than VM-backed.
- **Kata (intended):** Each container should boot inside a lightweight VM with a separate guest kernel and a stronger isolation boundary.
- **Kata (observed here):** The VM launch path reached QEMU but failed before a usable guest and agent were available, so the isolation boundary could not be demonstrated end-to-end on this stack.

## Task 3 — Isolation Tests

### Host-side baseline captured

I collected the Linux host-side baseline that a `runc` container would share:

- `/proc` entry count: `209`
- Kernel module count: `212`
- Host network interfaces saved to `labs/lab12/isolation/host-network.txt`
- Host `dmesg` head saved to `labs/lab12/isolation/host-dmesg-head.txt`

Artifacts:

- `labs/lab12/isolation/host-proc-count.txt`
- `labs/lab12/isolation/host-modules-count.txt`
- `labs/lab12/isolation/host-network.txt`
- `labs/lab12/isolation/host-dmesg-head.txt`

### Kata-side isolation blocker

I could not complete the usual Kata-side isolation probes (`dmesg`, `/proc`, modules, network) because the guest VM never became healthy enough to execute a payload command.

The most useful failure evidence is in `labs/lab12/setup/containerd-kata-journal-tail.txt`. The repeated pattern was:

```text
qemu-system-aarch64: global kvm-pit.lost_tick_policy has invalid class name
...
CreateContainerRequest timed out
...
QEMU exited with an error
```

### Security interpretation

- **runc escape impact:** A successful container escape would land an attacker in the Linux guest host context because the container shares that host kernel.
- **Kata escape impact (intended):** A breakout from the container process should still have to cross the lightweight VM boundary to reach the host, which is the core security benefit of Kata.
- **Kata escape impact (observed here):** Not directly testable because the Kata guest did not boot to a functional state on this ARM-on-Lima setup.

## Task 4 — Performance Comparison

### Startup time evidence

Captured in `labs/lab12/bench/startup.txt`:

```text
runc:
test
real 0.25

kata:
...
failed to create shim task: CreateContainerRequest timed out: context deadline exceeded
real 19.43
```

### HTTP latency baseline

Captured in `labs/lab12/bench/http-latency.txt`:

```text
avg=0.0011s min=0.0006s max=0.0019s n=20
```

### Performance interpretation

- **runc startup overhead:** Low. The baseline startup was about a quarter of a second for a tiny Alpine command.
- **Kata startup overhead:** On this environment, effectively unusable for the lab because the runtime never completed guest creation and timed out at about 19 seconds.
- **Runtime overhead:** Not meaningfully measurable for Kata here because there was no successful steady-state workload.
- **CPU overhead:** Not meaningfully measurable for Kata here because the guest VM did not boot far enough to run the test command.

### When to use each

- **Use runc when:** You need the most compatible and lowest-overhead runtime and you trust the shared-kernel isolation model.
- **Use Kata when:** You need a stronger sandbox boundary and are running on a platform where the guest hypervisor, firmware, and agent path are known-good.
- **Do not use this exact local stack for final Kata validation:** The Apple Silicon host plus Lima ARM guest was enough to validate installation and launch attempts, but not enough to produce a stable Kata execution result for this lab.

## Script and portability notes

I made two local improvements while working this lab:

1. `labs/lab12/setup/build-kata-runtime.sh`
   - Added support for `CONTAINER_CMD=nerdctl`
   - Added missing build dependencies for the build container
   - Added `arm64` target handling
2. `labs/lab12/setup/run-lab12-lima.sh`
   - Added a helper script to collect reproducible lab artifacts inside the Lima guest

I also tuned the local Kata configuration to remove the incompatible ARM QEMU CPU flag:

- `labs/lab12/setup/kata-config-tuned.txt`
- `labs/lab12/setup/kata-config-classic-tuned.txt`

This removed the earlier `host-arm-cpu.pmu` failure, but the runtime still timed out later during guest/container creation.

## Files Changed

- `labs/lab12/setup/build-kata-runtime.sh`
- `labs/lab12/setup/run-lab12-lima.sh`
- `labs/submission12.md`

## Deliverables

- Setup and shim evidence: `labs/lab12/setup/`
- runc baseline: `labs/lab12/runc/`
- Isolation and host baseline: `labs/lab12/isolation/`, `labs/lab12/analysis/`
- Performance snapshots: `labs/lab12/bench/`

## Submission Note

The lab instructions expect a branch, commit, and PR as the final delivery step. In this workspace I prepared all required artifacts locally under `labs/lab12/` and `labs/submission12.md`, but I intentionally did not perform any git branch, commit, or PR step here.

## Final Checklist

- [x] Kata shim installed and version captured
- [x] `containerd` updated with `io.containerd.kata.v2`
- [x] `runc` baseline validated with Juice Shop HTTP 200
- [x] Kata launch attempts captured with logs and timing
- [x] Host-side isolation baseline collected
- [x] No git commits created
