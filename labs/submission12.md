# Lab 12 — Kata Containers

I ran this on Ubuntu 24.04 (kernel `6.8.0-52-generic`) with containerd 1.7.x and nerdctl 2.2.0. Kata went in using the repo scripts (`build-kata-runtime.sh`, `install-kata-assets.sh`, `configure-containerd-kata.sh`), then I restarted containerd. Raw output is under `labs/lab12/`.

## Task 1

`containerd-shim-kata-v2 --version` is in `labs/lab12/setup/kata-built-version.txt`. A quick `sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a` worked; that kind of output is in `kata/test1.txt`.

## Task 2

Juice Shop on the default runtime: `juice-runc` on port 3012, health check in `runc/health.txt` (HTTP 200).

For Kata I stuck to short `alpine:3.19` runs with `--rm`. The lab calls out nerdctl + Kata runtime-rs v3 breaking long-lived detached containers, so I didn’t try to keep Juice Shop running under Kata.

Guest side: `kata/kernel.txt` shows `6.12.47-152.kata-001`, not the host `uname -r`. `kata/cpu.txt` shows a QEMU CPU string while the host line in `analysis/cpu-comparison.txt` is the real chip. `analysis/kernel-comparison.txt` has host vs guest `/proc/version` in one place.

runc shares the host kernel and a big `/proc` view; Kata runs a separate guest kernel inside a small VM. You pay startup time and some overhead, but kernel exploits in the workload don’t immediately equal “host owned” the way they can with runc.

## Task 3

`isolation/dmesg.txt`: guest dmesg is VM boot noise (KVM, virtio, kata-agent on the cmdline), not the host ring buffer.

`proc.txt` and `modules.txt`: host has more `/proc` entries and loaded modules than the guest.

`network.txt`: guest has lo + eth0 with a container-style address (mine was `10.4.2.17/24`).

Escape story in one sentence: from runc, hitting the host kernel is the endgame; from Kata you still have guest + hypervisor in the way.

## Task 4

`bench/startup.txt`: `time nerdctl run --rm alpine:3.19 echo test` vs the same with `--runtime io.containerd.kata.v2`. runc was sub-second; Kata was a few seconds — VM spin-up.

`bench/curl-3012.txt` + `http-latency.txt`: 50 curls to `localhost:3012` for juice-runc only (avg ~0.034s, min/max in the file). I didn’t benchmark Juice Shop on Kata for the same detached-container reason as above.

I’d keep runc for normal services where you trust the tenant and care about latency. I’d reach for Kata when isolation matters more than cold-start time (untrusted code, strong multi-tenant separation).

PR description checklist:

```text
- [x] Task 1 — Kata install + runtime config
- [x] Task 2 — runc vs kata runtime comparison
- [x] Task 3 — Isolation tests
- [x] Task 4 — Basic performance snapshot
```
