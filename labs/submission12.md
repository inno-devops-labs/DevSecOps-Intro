# Lab 12 — Kata Containers

I used Ubuntu 24.04 on bare metal (kernel `6.8.0-52-generic`) with containerd `1.7.13` and nerdctl `2.2.0`. Kata was installed with the scripts in this repo (`labs/lab12/setup/build-kata-runtime.sh`, `install-kata-assets.sh`, `configure-containerd-kata.sh`), then I restarted containerd and verified the shim. Raw command output is under `labs/lab12/`.

## Task 1

The shim version from `containerd-shim-kata-v2 --version` is saved in `labs/lab12/setup/kata-built-version.txt`.

Smoke test: `sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a` — output in `labs/lab12/kata/test1.txt`.

## Task 2

Juice Shop ran with the default runtime as `juice-runc` (`-p 3012:3000`). Health check (`curl` to port 3012) is in `labs/lab12/runc/health.txt`; `labs/lab12/runc/nerdctl-ps.txt` shows the container line from `sudo nerdctl ps`.

For Kata I only used short-lived `alpine:3.19` containers with `--rm`. A detached Juice Shop on Kata failed in this setup (nerdctl + Kata runtime-rs v3 issue with long-running containers and logging), so I followed the lab workaround instead of keeping Juice Shop on Kata.

Guest vs host: `labs/lab12/kata/kernel.txt` and `labs/lab12/analysis/kernel-comparison.txt` show the Kata guest kernel (`6.12.47-152.kata-001`) vs host `6.8.0-52-generic`. `labs/lab12/kata/cpu.txt` and `labs/lab12/analysis/cpu-comparison.txt` show the real CPU on the host and QEMU in the guest.

## Task 3

Isolation captures: `labs/lab12/isolation/dmesg.txt` (guest boot / KVM / virtio), `proc.txt`, `modules.txt`, `network.txt` — same comparisons as in the lab instructions.

## Task 4

Startup: `labs/lab12/bench/startup.txt` compares `time sudo nerdctl run --rm alpine:3.19 echo test` to the same command with `--runtime io.containerd.kata.v2` — runc came back in under a second, Kata took a few seconds.

HTTP latency (juice-runc only): 50 requests with `curl -w "%{time_total}"` against `http://127.0.0.1:3012/` — raw times in `labs/lab12/bench/curl-3012.txt`, summary in `labs/lab12/bench/http-latency.txt`.

PR checklist:

```text
- [x] Task 1 — Kata install + runtime config
- [x] Task 2 — runc vs kata runtime comparison
- [x] Task 3 — Isolation tests
- [x] Task 4 — Basic performance snapshot
```
